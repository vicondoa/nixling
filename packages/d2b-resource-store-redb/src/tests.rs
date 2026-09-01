use crate::audit::{DurableMutationAudit, resource_mutation_record};
use crate::metrics::{NoopStoreTelemetry, StoreMetric};
use crate::transaction::INSTALLED_SCHEMA_CATALOG;
use d2b_audit::{
    AuditHash, AuditRecord, AuditRecordError, AuditRecordFields, AuditSink, DurabilityEvidence,
    DurabilityOutcome, OperationIdentity, ZoneOperationKey, genesis_hash,
};
use d2b_contracts_resource::v3::{
    CanonicalJsonValue, ConfigurationGeneration, RESOURCE_ENVELOPE_DOMAIN_TAG, ResourceEnvelope,
    ResourceRef, ResourceTypeName, ResourceUid, Timestamp, ZoneId, canonical_digest,
};
use d2b_resource_store::mutation_seal::{
    MutationSealAcceptor, MutationSealBody, mutation_seal_pair,
};
use d2b_resource_store::{
    AdmittedAuthorization, AdmittedAuthorizationTarget, AdmittedVerb, ExpectedRevision,
    PolicySnapshot, PreparedStoreMutation, ResourceMutationKind, StoreError, StoreErrorKind,
    StoreFilter, StoreGetRequest, StoreListRequest, StoreMutation, StoreOperationContext,
    StoreProjection, StoreSlot, StoreWatchRequest,
};
use redb::{Database, Durability, ReadableDatabase, ReadableTable, ReadableTableMetadata};
use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
use rustix::net::{
    AddressFamily, SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketFlags, SocketType,
    sendmsg, socketpair,
};
use std::fs::OpenOptions;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};

use super::*;

#[derive(Default)]
struct RecordingAudit(Mutex<Vec<AuditRecord>>);

impl RecordingAudit {
    fn records(&self) -> Vec<AuditRecord> {
        self.0.lock().unwrap().clone()
    }
}

impl DurableMutationAudit for RecordingAudit {
    fn previous_hash(&self) -> Result<AuditHash, AuditRecordError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .last()
            .map_or_else(genesis_hash, |record| record.record_hash().clone()))
    }

    fn append_before_commit(&self, record: &AuditRecord) -> Result<(), AuditRecordError> {
        let mut records = self.0.lock().unwrap();
        let previous = records
            .last()
            .map_or_else(genesis_hash, |record| record.record_hash().clone());
        record.verify(&previous)?;
        records.push(record.clone());
        Ok(())
    }

    fn existing_mutation_hash(
        &self,
        key: &d2b_audit::ZoneOperationKey,
        mutation_id: &str,
    ) -> Result<Option<AuditHash>, AuditRecordError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .iter()
            .find(|record| {
                record.mutation_id() == Some(mutation_id)
                    && record.zone_operation_key().ok().as_ref() == Some(key)
            })
            .map(|record| record.record_hash().clone()))
    }

    fn existing_mutation_predecessor(
        &self,
        key: &d2b_audit::ZoneOperationKey,
        mutation_id: &str,
    ) -> Result<Option<AuditHash>, AuditRecordError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .iter()
            .find(|record| {
                record.mutation_id() == Some(mutation_id)
                    && record.zone_operation_key().ok().as_ref() == Some(key)
            })
            .map(|record| record.previous_hash().clone()))
    }
}

struct RejectingAudit(AtomicU64);

impl DurableMutationAudit for RejectingAudit {
    fn append_before_commit(&self, _record: &AuditRecord) -> Result<(), AuditRecordError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Err(AuditRecordError::Serialization)
    }

    fn existing_mutation_hash(
        &self,
        _key: &d2b_audit::ZoneOperationKey,
        _mutation_id: &str,
    ) -> Result<Option<AuditHash>, AuditRecordError> {
        Ok(None)
    }

    fn existing_mutation_predecessor(
        &self,
        _key: &d2b_audit::ZoneOperationKey,
        _mutation_id: &str,
    ) -> Result<Option<AuditHash>, AuditRecordError> {
        Ok(None)
    }
}

fn identity() -> StoreIdentity {
    identity_for(
        StoreSlot::new(0).unwrap(),
        "work",
        "11111111-1111-4111-8111-111111111111",
    )
}

fn identity_for(slot: StoreSlot, zone: &str, store_uuid: &str) -> StoreIdentity {
    StoreIdentity::new(
        slot,
        ResourceUid::parse(store_uuid).unwrap(),
        ZoneId::parse(zone).unwrap(),
        ResourceUid::parse("22222222-2222-4222-8222-222222222222").unwrap(),
        Timestamp::parse("2026-07-31T00:00:00.000Z").unwrap(),
        PolicySnapshot {
            policy_revision: 7,
            api_catalog_revision: 8,
            active_configuration_revision: ConfigurationGeneration::new(9).unwrap(),
            controller_generation: None,
        },
    )
}

fn acceptor(identity: &StoreIdentity) -> MutationSealAcceptor {
    let (_, acceptor) = mutation_seal_pair(identity.seal_identity());
    acceptor
}

async fn provision_store(
    file: File,
    marker: File,
    identity: StoreIdentity,
) -> Result<RedbResourceStore, d2b_resource_store::StoreError> {
    RedbResourceStore::provision_owned(file, marker, identity.clone(), acceptor(&identity)).await
}

async fn open_store(
    file: File,
    identity: StoreIdentity,
) -> Result<RedbResourceStore, d2b_resource_store::StoreError> {
    RedbResourceStore::open_owned(file, identity.clone(), acceptor(&identity)).await
}

fn empty_seal_body() -> MutationSealBody {
    MutationSealBody {
        mutations: Vec::new(),
        authorization: d2b_resource_store::AdmittedAuthorization {
            zone: ZoneId::parse("work").unwrap(),
            subject_ref: ResourceRef::parse("Provider/system-core").unwrap(),
            subject_uid: ResourceUid::parse("33333333-3333-4333-8333-333333333333").unwrap(),
            targets: Vec::new(),
        },
        policy_snapshot: PolicySnapshot {
            policy_revision: 7,
            api_catalog_revision: 8,
            active_configuration_revision: ConfigurationGeneration::new(9).unwrap(),
            controller_generation: None,
        },
        operation: operation("seal"),
    }
}

fn create_seal_body(operation_id: &str, name: &str, payload_digest: String) -> MutationSealBody {
    create_seal_body_with_resource(operation_id, name, create_body(name), payload_digest)
}

fn create_seal_body_with_resource(
    operation_id: &str,
    name: &str,
    canonical_resource: Vec<u8>,
    payload_digest: String,
) -> MutationSealBody {
    create_seal_body_for_type(
        operation_id,
        "Host",
        name,
        canonical_resource,
        payload_digest,
    )
}

fn create_seal_body_for_type(
    operation_id: &str,
    resource_type: &str,
    name: &str,
    canonical_resource: Vec<u8>,
    payload_digest: String,
) -> MutationSealBody {
    create_seal_body_for_type_as(
        operation_id,
        resource_type,
        name,
        canonical_resource,
        payload_digest,
        "Provider/system-core",
    )
}

fn create_seal_body_for_type_as(
    operation_id: &str,
    resource_type: &str,
    name: &str,
    canonical_resource: Vec<u8>,
    payload_digest: String,
    subject_ref: &str,
) -> MutationSealBody {
    let target = ResourceRef::parse(&format!("{resource_type}/{name}")).unwrap();
    MutationSealBody {
        mutations: vec![PreparedStoreMutation::new(
            StoreMutation {
                kind: ResourceMutationKind::Create,
                zone: ZoneId::parse("work").unwrap(),
                target: target.clone(),
                expected: ExpectedRevision::CreateAbsent,
                expected_uid: None,
                owner: None,
                canonical_resource: Some(canonical_resource),
                add_finalizers: Vec::new(),
                remove_finalizers: Vec::new(),
                wait_for_reconcile: false,
                reconcile_deadline_ms: None,
                configuration_generation: None,
                assignment: None,
            },
            None,
            Some(payload_digest),
        )],
        authorization: AdmittedAuthorization {
            zone: ZoneId::parse("work").unwrap(),
            subject_ref: ResourceRef::parse(subject_ref).unwrap(),
            subject_uid: ResourceUid::parse("33333333-3333-4333-8333-333333333333").unwrap(),
            targets: vec![AdmittedAuthorizationTarget {
                resource_type: ResourceTypeName::parse(resource_type).unwrap(),
                resource_name: Some(target.name().clone()),
                verb: AdmittedVerb::Create,
                subresource: None,
                execution_ref: None,
            }],
        },
        policy_snapshot: PolicySnapshot {
            policy_revision: 7,
            api_catalog_revision: 8,
            active_configuration_revision: ConfigurationGeneration::new(9).unwrap(),
            controller_generation: None,
        },
        operation: operation(operation_id),
    }
}

fn create_provider_resource_body(resource_type: &str, name: &str) -> Vec<u8> {
    let mut value: serde_json::Value = serde_json::from_slice(&stored_body(name)).unwrap();
    value["type"] = serde_json::Value::String(resource_type.to_owned());
    let spec = value["spec"].as_object_mut().unwrap();
    match resource_type {
        "Device" => {
            spec.insert("deviceClass".to_owned(), serde_json::json!("emulated"));
            spec.insert("arbitration".to_owned(), serde_json::json!("exclusive"));
            spec.insert("maxConcurrentClaims".to_owned(), serde_json::json!(1));
            spec.insert("inventory".to_owned(), serde_json::json!({}));
        }
        "Volume" => {
            spec.insert(
                "source".to_owned(),
                serde_json::json!({
                    "executionRef": "Host/host-system",
                    "settings": {
                        "kind": "local-path",
                        "sourcePolicyId": "state-root"
                    }
                }),
            );
            spec.insert("kind".to_owned(), serde_json::json!("durable"));
            spec.insert("layout".to_owned(), serde_json::json!([]));
            spec.insert(
                "views".to_owned(),
                serde_json::json!({
                    "controller": {
                        "path": "",
                        "rights": ["read", "write", "traverse"]
                    }
                }),
            );
            spec.insert("attachments".to_owned(), serde_json::json!([]));
            spec.insert("quota".to_owned(), serde_json::Value::Null);
        }
        other => panic!("provider resource fixture not defined for {other}"),
    }
    value["metadata"].as_object_mut().unwrap().remove("uid");
    let bytes = serde_json::to_vec(&value).unwrap();
    CanonicalJsonValue::parse(&bytes)
        .unwrap()
        .to_canonical_bytes()
}

fn owned_file() -> (tempfile::TempDir, File) {
    let directory = tempfile::tempdir().unwrap();
    let file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(directory.path().join("store.redb"))
        .unwrap();
    assert!(fcntl_getfd(&file).unwrap().contains(FdFlags::CLOEXEC));
    (directory, file)
}

fn provisioned_store() -> (tempfile::TempDir, File, File) {
    let (directory, file) = owned_file();
    let mut marker = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(directory.path().join("store.marker"))
        .unwrap();
    write_provisioning_marker(&mut marker, &identity()).unwrap();
    (directory, file, marker)
}

fn insert_legacy_outbox(directory: &tempfile::TempDir, operation_id: &str) {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join("store.redb"))
        .unwrap();
    let database = Database::builder()
        .set_cache_size(crate::REDB_CACHE_SIZE)
        .create_with_backend(redb::backends::FileBackend::new(file).unwrap())
        .unwrap();
    let operation = crate::transaction::OperationRecord {
        request_digest: format!("sha256:{}", "a".repeat(64)),
        resource_uids: Vec::new(),
        resources: Vec::new(),
        outcome: "committed".to_owned(),
        error_code: None,
        accepted_revision: 0,
        finished_revision: 0,
        audit_outbox: Some(crate::transaction::AuditOutboxRecord {
            zone: identity().zone.as_str().to_owned(),
            operation_id: String::new(),
            operation_identity: None,
            correlation_id: "legacy-correlation".to_owned(),
            subject_digest: "legacy-subject".to_owned(),
            policy_revision: 7,
            resulting_revision: 0,
            requires_broker: false,
            defer_broker_evidence: false,
            mutations: vec![crate::transaction::AuditOutboxMutation {
                verb: "create".to_owned(),
                resource_type: "Host".to_owned(),
                resource_uid: None,
                target_digest: "legacy-target".to_owned(),
                generation: 1,
                expected_revision: 0,
                mutation_id: String::new(),
                ordinal: 9,
                timestamp_ms: 0,
                outcome: String::new(),
                error_code: None,
                previous_hash: None,
                record_hash: None,
            }],
        }),
        authority: None,
    };
    let key = crate::keys::encode_key(
        crate::keys::KeySpace::Operations,
        &[crate::keys::KeyComponent::Text(operation_id)],
    )
    .unwrap();
    let value = crate::transaction::encode(crate::ValueKind::OperationRecord, &operation).unwrap();
    let mut write = database.begin_write().unwrap();
    write.set_durability(Durability::Immediate).unwrap();
    write
        .open_table(crate::transaction::OPERATIONS)
        .unwrap()
        .insert(key.as_bytes(), value.as_slice())
        .unwrap();
    write.commit().unwrap();
}

fn operation(id: &str) -> StoreOperationContext {
    StoreOperationContext {
        operation_id: id.to_owned(),
        idempotency_key: Some(format!("key-{id}")),
        correlation_id: format!("correlation-{id}"),
        trace_id: None,
        deadline_ms: 1_000,
    }
}

fn stored_body(name: &str) -> Vec<u8> {
    format!(
        r#"{{"apiVersion":"resources.d2bus.org/v3","metadata":{{"configurationGeneration":7,"createdAt":"2026-07-22T00:00:00.000Z","deletionRequestedAt":null,"finalizers":[],"generation":1,"managedBy":"configuration","name":"{name}","ownerRef":null,"revision":1,"uid":"123e4567-e89b-42d3-a456-426614174000","updatedAt":"2026-07-22T00:00:00.000Z","zone":"work"}},"spec":{{"providerRef":"Provider/system-core","updatePolicy":{{"disruptive":"manual","nonDisruptive":"automatic"}}}},"status":{{"completedAt":null,"conditions":[],"lastReconciledAt":null,"observedGeneration":0,"outcome":null,"phase":"Pending","resource":{{}},"startedAt":null,"update":{{"dependencies":{{"count":0,"refs":[]}},"disruption":"None","lastAssessedAt":null,"observedGeneration":0,"operationId":null,"owned":{{"count":0,"refs":[]}},"preserveState":true,"reasons":[],"state":"Unknown","targetGeneration":1}}}},"type":"Host"}}"#
    )
    .into_bytes()
}

fn create_body(name: &str) -> Vec<u8> {
    let mut value = CanonicalJsonValue::parse(&stored_body(name)).unwrap();
    let CanonicalJsonValue::Object(root) = &mut value else {
        unreachable!()
    };
    let CanonicalJsonValue::Object(metadata) = root.get_mut("metadata").unwrap() else {
        unreachable!()
    };
    metadata.remove("uid");
    value.to_canonical_bytes()
}

fn owned_guest_body(name: &str) -> Vec<u8> {
    let mut value: serde_json::Value = serde_json::from_slice(&stored_body(name)).unwrap();
    value["type"] = serde_json::Value::String("Guest".to_owned());
    value["metadata"].as_object_mut().unwrap().remove("uid");
    value["spec"] =
        serde_json::to_value(d2b_contracts_resource::v3::guest::GuestSpec::system_default())
            .unwrap();
    CanonicalJsonValue::parse(&serde_json::to_vec(&value).unwrap())
        .unwrap()
        .to_canonical_bytes()
}

fn owned_process_body(name: &str, owner: &ResourceRef) -> Vec<u8> {
    let mut value: serde_json::Value = serde_json::from_slice(&stored_body(name)).unwrap();
    value["type"] = serde_json::Value::String("Process".to_owned());
    value["metadata"]["ownerRef"] = serde_json::Value::String(owner.to_canonical_string());
    value["metadata"].as_object_mut().unwrap().remove("uid");
    let execution = d2b_contracts_resource::v3::process::ExecutionSpec::minimal(
        ResourceRef::parse("Host/host-system").unwrap(),
        d2b_contracts_resource::v3::process::ProcessClass::Service,
        d2b_contracts_resource::v3::execution_policy::BoundedToken::parse("test").unwrap(),
    )
    .unwrap();
    value["spec"] = serde_json::to_value(
        d2b_contracts_resource::v3::process::ProcessSpec::minimal(execution),
    )
    .unwrap();
    CanonicalJsonValue::parse(&serde_json::to_vec(&value).unwrap())
        .unwrap()
        .to_canonical_bytes()
}

fn create_owned_seal_body(
    operation_id: &str,
    target: ResourceRef,
    owner: ResourceRef,
    canonical_resource: Vec<u8>,
) -> MutationSealBody {
    let payload_digest = canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &canonical_resource);
    MutationSealBody {
        mutations: vec![PreparedStoreMutation::new(
            StoreMutation {
                kind: ResourceMutationKind::Create,
                zone: ZoneId::parse("work").unwrap(),
                target: target.clone(),
                expected: ExpectedRevision::CreateAbsent,
                expected_uid: None,
                owner: Some(owner),
                canonical_resource: Some(canonical_resource),
                add_finalizers: Vec::new(),
                remove_finalizers: Vec::new(),
                wait_for_reconcile: false,
                reconcile_deadline_ms: None,
                configuration_generation: None,
                assignment: None,
            },
            None,
            Some(payload_digest),
        )],
        authorization: AdmittedAuthorization {
            zone: ZoneId::parse("work").unwrap(),
            subject_ref: ResourceRef::parse("Provider/system-core").unwrap(),
            subject_uid: ResourceUid::parse("33333333-3333-4333-8333-333333333333").unwrap(),
            targets: vec![AdmittedAuthorizationTarget {
                resource_type: target.resource_type().clone(),
                resource_name: Some(target.name().clone()),
                verb: AdmittedVerb::Create,
                subresource: None,
                execution_ref: None,
            }],
        },
        policy_snapshot: PolicySnapshot {
            policy_revision: 7,
            api_catalog_revision: 8,
            active_configuration_revision: ConfigurationGeneration::new(9).unwrap(),
            controller_generation: None,
        },
        operation: operation(operation_id),
    }
}

fn create_body_for_type(resource_type: &str, name: &str) -> Vec<u8> {
    let mut value: serde_json::Value =
        serde_json::from_slice(&create_body(name)).expect("resource fixture");
    value["type"] = serde_json::Value::String(resource_type.to_owned());
    if resource_type == "Provider" {
        value["spec"] = serde_json::json!({
            "artifactId": "provider-wayland",
            "config": {},
        });
    }
    CanonicalJsonValue::parse(&serde_json::to_vec(&value).expect("resource fixture json"))
        .expect("canonical resource fixture")
        .to_canonical_bytes()
}

fn broker_evidence(operation_id: &str, outcome: DurabilityOutcome) -> DurabilityEvidence {
    DurabilityEvidence {
        key: ZoneOperationKey::derive("work", operation_id).unwrap(),
        outcome,
        effect_durable: outcome == DurabilityOutcome::Success,
    }
}

fn seed_host(directory: &tempfile::TempDir, name: &str) {
    use crate::transaction::{
        CONTROLLER_INDEX, RESOURCES, REVISION_LOG, ResourceRecord, STORE_META, TYPE_INDEX, encode,
        resource_key, revision_key, type_index_key,
    };

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join("store.redb"))
        .unwrap();
    let backend = redb::backends::FileBackend::new(file).unwrap();
    let database = Database::builder().create_with_backend(backend).unwrap();
    crate::transaction::initialize(&database, &identity()).unwrap();
    let target = ResourceRef::parse(&format!("Host/{name}")).unwrap();
    let canonical_json = stored_body(name);
    let envelope =
        d2b_contracts_resource::v3::ResourceEnvelope::from_json(&canonical_json).unwrap();
    let record = ResourceRecord {
        canonical_json,
        owner_uid: None,
        controller_binding_id: "Provider/system-core".to_owned(),
        payload_digest: envelope.digest().unwrap(),
        assignment: None,
    };
    let value = encode(ValueKind::ResourceRecord, &record).unwrap();
    let type_value = encode(
        ValueKind::TypeIndexRecord,
        &envelope.metadata().uid().as_str(),
    )
    .unwrap();
    let controller_value = encode(
        ValueKind::ControllerIndexRecord,
        &envelope.metadata().uid().as_str(),
    )
    .unwrap();
    let batch =
        ChangeBatch::new(d2b_contracts_resource::v3::ZoneRevision::new(1), Vec::new()).unwrap();
    let batch_value = encode(ValueKind::ChangeBatch, &batch).unwrap();
    let mut meta = crate::transaction::current_meta(&database).unwrap();
    meta.current_revision = 1;
    let meta_value = encode(ValueKind::StoreMetaScalar, &meta).unwrap();
    let mut write = database.begin_write().unwrap();
    write.set_durability(Durability::Immediate).unwrap();
    write
        .open_table(RESOURCES)
        .unwrap()
        .insert(resource_key(&target).unwrap().as_slice(), value.as_slice())
        .unwrap();
    write
        .open_table(TYPE_INDEX)
        .unwrap()
        .insert(
            type_index_key(&target).unwrap().as_slice(),
            type_value.as_slice(),
        )
        .unwrap();
    let controller_key = crate::encode_key(
        KeySpace::ControllerIndex,
        &[
            KeyComponent::Text("Provider/system-core"),
            KeyComponent::Text("Host"),
            KeyComponent::Text(name),
        ],
    )
    .unwrap();
    write
        .open_table(CONTROLLER_INDEX)
        .unwrap()
        .insert(controller_key.as_bytes(), controller_value.as_slice())
        .unwrap();
    write
        .open_table(REVISION_LOG)
        .unwrap()
        .insert(revision_key(1).unwrap().as_slice(), batch_value.as_slice())
        .unwrap();
    write
        .open_table(STORE_META)
        .unwrap()
        .insert(
            crate::encode_key(KeySpace::StoreMeta, &[KeyComponent::Text("store")])
                .unwrap()
                .as_bytes(),
            meta_value.as_slice(),
        )
        .unwrap();
    write.commit().unwrap();
}

fn seed_two_hosts(directory: &tempfile::TempDir) {
    seed_host(directory, "host-system");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join("store.redb"))
        .unwrap();
    let backend = redb::backends::FileBackend::new(file).unwrap();
    let database = Database::builder().create_with_backend(backend).unwrap();
    let second = ResourceRef::parse("Host/host-worker").unwrap();
    let canonical_json = String::from_utf8(stored_body("host-worker"))
        .unwrap()
        .replace(
            "123e4567-e89b-42d3-a456-426614174000",
            "123e4567-e89b-42d3-a456-426614174001",
        )
        .into_bytes();
    let envelope =
        d2b_contracts_resource::v3::ResourceEnvelope::from_json(&canonical_json).unwrap();
    let record = crate::transaction::ResourceRecord {
        canonical_json,
        owner_uid: None,
        controller_binding_id: "Provider/system-core".to_owned(),
        payload_digest: envelope.digest().unwrap(),
        assignment: None,
    };
    let write = database.begin_write().unwrap();
    let value = crate::transaction::encode(ValueKind::ResourceRecord, &record).unwrap();
    write
        .open_table(crate::transaction::RESOURCES)
        .unwrap()
        .insert(
            crate::transaction::resource_key(&second)
                .unwrap()
                .as_slice(),
            value.as_slice(),
        )
        .unwrap();
    let type_value = crate::transaction::encode(
        ValueKind::TypeIndexRecord,
        &envelope.metadata().uid().as_str(),
    )
    .unwrap();
    write
        .open_table(crate::transaction::TYPE_INDEX)
        .unwrap()
        .insert(
            crate::transaction::type_index_key(&second)
                .unwrap()
                .as_slice(),
            type_value.as_slice(),
        )
        .unwrap();
    let controller_key = crate::encode_key(
        KeySpace::ControllerIndex,
        &[
            KeyComponent::Text("Provider/system-core"),
            KeyComponent::Text("Host"),
            KeyComponent::Text("host-worker"),
        ],
    )
    .unwrap();
    let controller_value = crate::transaction::encode(
        ValueKind::ControllerIndexRecord,
        &envelope.metadata().uid().as_str(),
    )
    .unwrap();
    write
        .open_table(crate::transaction::CONTROLLER_INDEX)
        .unwrap()
        .insert(controller_key.as_bytes(), controller_value.as_slice())
        .unwrap();
    write.commit().unwrap();
}

fn seed_replay_log(directory: &tempfile::TempDir, rows: u64) {
    use crate::transaction::{REVISION_LOG, STORE_META, encode, revision_key};

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join("store.redb"))
        .unwrap();
    let backend = redb::backends::FileBackend::new(file).unwrap();
    let database = Database::builder().create_with_backend(backend).unwrap();
    crate::transaction::initialize(&database, &identity()).unwrap();
    let mut meta = crate::transaction::current_meta(&database).unwrap();
    meta.current_revision = rows;
    let mut write = database.begin_write().unwrap();
    write.set_durability(Durability::Immediate).unwrap();
    {
        let mut revisions = write.open_table(REVISION_LOG).unwrap();
        for revision in 1..=rows {
            let batch = ChangeBatch::new(
                d2b_contracts_resource::v3::ZoneRevision::new(revision),
                Vec::new(),
            )
            .unwrap();
            let value = encode(ValueKind::ChangeBatch, &batch).unwrap();
            revisions
                .insert(revision_key(revision).unwrap().as_slice(), value.as_slice())
                .unwrap();
        }
    }
    let value = encode(ValueKind::StoreMetaScalar, &meta).unwrap();
    write
        .open_table(STORE_META)
        .unwrap()
        .insert(
            crate::encode_key(KeySpace::StoreMeta, &[KeyComponent::Text("store")])
                .unwrap()
                .as_bytes(),
            value.as_slice(),
        )
        .unwrap();
    write.commit().unwrap();
}

#[test]
fn contract_constants_are_exact() {
    assert_eq!(WRITE_QUEUE_CAPACITY, 256);
    assert_eq!(GROUP_COMMIT_MAX, 16);
    assert_eq!(READ_POOL_THREADS, 4);
    assert_eq!(MAX_CONCURRENT_READS, 16);
    assert_eq!(READ_LIFETIME, std::time::Duration::from_millis(250));
    assert_eq!(REDB_CACHE_SIZE, 4 * 1024 * 1024);
}

#[test]
fn backup_capture_limits_are_accounted_cumulatively() {
    let mut rows = MAX_LOGICAL_BACKUP_ROWS - 1;
    let mut bytes = 0;
    crate::backup::account_capture_row(&mut rows, &mut bytes, 1, 0)
        .expect("the final row below the count bound is admitted");
    assert_eq!(
        crate::backup::account_capture_row(&mut rows, &mut bytes, 1, 0)
            .unwrap_err()
            .reason_code(),
        "backup-row-count-over-limit"
    );

    let mut rows = 0;
    let mut bytes = MAX_LOGICAL_BACKUP_BYTES;
    assert_eq!(
        crate::backup::account_capture_row(&mut rows, &mut bytes, 1, 0)
            .unwrap_err()
            .reason_code(),
        "backup-size-over-limit"
    );
}

#[test]
fn production_ports_use_real_telemetry_and_durable_audit_adapters() {
    let (directory, file) = owned_file();
    let owned_audit = directory.path().join("owned-audit");
    let sink = Arc::new(AuditSink::open(&owned_audit).expect("owner-provisioned audit sink"));
    let production = super::StorePorts::production_with_audit(
        &file,
        sink,
        Arc::new(super::BrokerEvidenceIndex::default()),
    )
    .expect("production ports");
    assert!(production.audit.enabled());
    assert!(owned_audit.is_dir());

    let owned_audit = directory.path().join("test-owned-audit");
    let sink = Arc::new(AuditSink::open(&owned_audit).expect("owner-provisioned audit sink"));
    let ports = super::StorePorts::with_audit_sink(&file, sink).expect("owned audit ports");
    assert!(ports.audit.enabled());
    assert!(owned_audit.is_dir());
    ports.telemetry.metric(
        StoreMetric::QueueDepth,
        std::collections::BTreeMap::from([("operation".to_owned(), "write".to_owned())]),
        1.0,
    );
}

#[test]
fn broker_evidence_index_is_live_after_startup_snapshot() {
    let index = Arc::new(crate::BrokerEvidenceIndex::default());
    let reader = Arc::clone(&index);
    let evidence = DurabilityEvidence {
        key: ZoneOperationKey::derive("work", "operation").unwrap(),
        outcome: DurabilityOutcome::Success,
        effect_durable: true,
    };
    assert!(index.is_empty().unwrap());
    index.insert(evidence.clone()).unwrap();
    assert_eq!(reader.len().unwrap(), 1);
    assert_eq!(reader.get(&evidence.key).unwrap(), Some(evidence));
    assert_eq!(
        index
            .insert(DurabilityEvidence {
                key: ZoneOperationKey::derive("work", "operation").unwrap(),
                outcome: DurabilityOutcome::Failure,
                effect_durable: false,
            })
            .unwrap_err()
            .kind(),
        d2b_resource_store::StoreErrorKind::StoreIntegrityFailure
    );
}

#[test]
fn broker_evidence_index_allows_retry_failure_to_become_durable_success() {
    let index = crate::BrokerEvidenceIndex::default();
    let key = ZoneOperationKey::derive("work", "retry-operation").unwrap();
    index
        .insert(DurabilityEvidence {
            key: key.clone(),
            outcome: DurabilityOutcome::Failure,
            effect_durable: false,
        })
        .unwrap();
    let success = DurabilityEvidence {
        key: key.clone(),
        outcome: DurabilityOutcome::Success,
        effect_durable: true,
    };
    index.insert(success.clone()).unwrap();
    assert_eq!(index.get(&key).unwrap(), Some(success));
}

#[test]
fn resource_mutation_audit_class_is_not_privileged_by_default() {
    let standard = resource_mutation_record(
        1,
        "work",
        "op-standard",
        "corr-standard",
        "resource-store",
        genesis_hash(),
        "create",
        "Host",
        "sha256:0000000000000000000000000000000000000000000000000000000000000001",
        1,
        0,
        1,
        "sha256:0000000000000000000000000000000000000000000000000000000000000002",
        7,
        "ok",
        None,
    )
    .unwrap();
    assert_eq!(
        super::audit_write_class(&standard),
        d2b_audit::AuditWriteClass::Standard
    );

    let denied = resource_mutation_record(
        1,
        "work",
        "op-denied",
        "corr-denied",
        "resource-store",
        genesis_hash(),
        "create",
        "Host",
        "sha256:0000000000000000000000000000000000000000000000000000000000000001",
        0,
        0,
        0,
        "sha256:0000000000000000000000000000000000000000000000000000000000000002",
        7,
        "denied",
        Some("authorization-denied".to_owned()),
    )
    .unwrap();
    assert_eq!(
        super::audit_write_class(&denied),
        d2b_audit::AuditWriteClass::Privileged
    );

    let role = resource_mutation_record(
        1,
        "work",
        "op-role",
        "corr-role",
        "resource-store",
        genesis_hash(),
        "create",
        "Role",
        "sha256:0000000000000000000000000000000000000000000000000000000000000001",
        1,
        0,
        1,
        "sha256:0000000000000000000000000000000000000000000000000000000000000002",
        7,
        "ok",
        None,
    )
    .unwrap();
    assert_eq!(
        super::audit_write_class(&role),
        d2b_audit::AuditWriteClass::Privileged
    );
}

#[tokio::test]
async fn serialized_commit_fence_rejects_revoked_mutation() {
    let (_directory, file, marker) = provisioned_store();
    let store_identity = identity();
    let (issuer, acceptor) = mutation_seal_pair(store_identity.seal_identity());
    let store = RedbResourceStore::provision_owned(file, marker, store_identity, acceptor)
        .await
        .unwrap();
    let canonical = create_body("revoked");
    let payload_digest = canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &canonical);
    let error = store
        .commit_verified_with_fence(
            issuer.seal(create_seal_body(
                "revoked-commit",
                "revoked",
                payload_digest,
            )),
            |_| Ok(()),
            || {
                Err(StoreError::new(
                    StoreErrorKind::ResourcePlaneUnavailable,
                    None,
                    None,
                    d2b_contracts_resource::v3::RetryClass::AfterDelay,
                    "session-revoked",
                ))
            },
        )
        .await
        .expect_err("revoked mutation must not reach the writer");
    assert_eq!(error.reason_code(), "session-revoked");
    assert_eq!(
        store
            .get(StoreGetRequest {
                operation: operation("revoked-read"),
                zone: ZoneId::parse("work").unwrap(),
                target: ResourceRef::parse("Host/revoked").unwrap(),
                expected_uid: None,
                projection: StoreProjection::Full,
            })
            .await
            .expect_err("revoked resource must not be committed")
            .reason_code(),
        "resource-not-found"
    );
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn initialized_schema_catalog_is_digest_bound_and_complete() {
    let (_directory, file, marker) = provisioned_store();
    let store = provision_store(file, marker, identity()).await.unwrap();
    let backup = store.logical_backup().await.unwrap();
    let table = backup
        .tables
        .iter()
        .find(|table| table.name == "api_schemas")
        .expect("schema table");
    assert_eq!(table.rows.len(), INSTALLED_SCHEMA_CATALOG.len());

    let mut resource_types = std::collections::BTreeSet::new();
    for row in &table.rows {
        let key = DecodedKey::decode(&row.key).unwrap();
        let [DecodedKeyComponent::Text(schema_digest)] = key.components() else {
            panic!("schema key shape");
        };
        let value = DecodedValue::decode(&row.value).unwrap();
        let json: serde_json::Value = serde_json::from_slice(value.canonical_json()).unwrap();
        assert_eq!(
            json.get("schemaDigest").and_then(serde_json::Value::as_str),
            Some(schema_digest.as_str())
        );
        resource_types.insert(
            json.get("resourceType")
                .and_then(serde_json::Value::as_str)
                .unwrap()
                .to_owned(),
        );
    }
    assert_eq!(
        resource_types,
        INSTALLED_SCHEMA_CATALOG
            .into_iter()
            .map(str::to_owned)
            .collect()
    );

    let schema = store
        .inspect_schema(StoreInspectSchemaRequest {
            operation: operation("inspect-host-schema"),
            zone: ZoneId::parse("work").unwrap(),
            resource_type: ResourceTypeName::parse("Host").unwrap(),
        })
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&schema.canonical_json).unwrap();
    assert_eq!(
        schema.payload_digest,
        json.get("schemaDigest")
            .and_then(serde_json::Value::as_str)
            .unwrap()
    );
    assert_eq!(
        store
            .inspect_schema(StoreInspectSchemaRequest {
                operation: operation("inspect-unknown-schema"),
                zone: ZoneId::parse("work").unwrap(),
                resource_type: ResourceTypeName::parse("vendor.d2bus.org.Unknown").unwrap(),
            })
            .await
            .unwrap_err()
            .reason_code(),
        "resource-not-found"
    );
}

#[tokio::test]
async fn logical_backup_restore_preserves_device_and_volume_identity_before_adoption() {
    let (_source_directory, source_file, source_marker) = provisioned_store();
    let store_identity = identity();
    let (issuer, source_acceptor) = mutation_seal_pair(store_identity.seal_identity());
    let source = RedbResourceStore::provision_owned(
        source_file,
        source_marker,
        store_identity.clone(),
        source_acceptor,
    )
    .await
    .unwrap();

    let mut originals = Vec::new();
    for (resource_type, name, operation_id) in [
        ("Device", "tpm-host", "backup-device"),
        ("Volume", "tpm-host-state", "backup-volume"),
    ] {
        let canonical = create_provider_resource_body(resource_type, name);
        let payload_digest = canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &canonical);
        source
            .commit_verified(issuer.seal(create_seal_body_for_type(
                operation_id,
                resource_type,
                name,
                canonical,
                payload_digest,
            )))
            .await
            .unwrap();
        originals.push(
            source
                .get(StoreGetRequest {
                    operation: operation(&format!("{operation_id}-read")),
                    zone: ZoneId::parse("work").unwrap(),
                    target: ResourceRef::parse(&format!("{resource_type}/{name}")).unwrap(),
                    expected_uid: None,
                    projection: StoreProjection::Full,
                })
                .await
                .unwrap(),
        );
    }

    let backup = source.logical_backup().await.unwrap();
    assert_eq!(backup.backup_generation, 0);
    source.shutdown().await.unwrap();

    let (_target_directory, target_file, target_marker) = provisioned_store();
    let restored = RedbResourceStore::restore_owned(
        target_file,
        target_marker,
        backup,
        store_identity.clone(),
        acceptor(&store_identity),
    )
    .await
    .unwrap();

    for original in originals {
        let restored_resource = restored
            .get(StoreGetRequest {
                operation: operation(&format!(
                    "restore-{}",
                    original.resource_ref.to_canonical_string()
                )),
                zone: ZoneId::parse("work").unwrap(),
                target: original.resource_ref.clone(),
                expected_uid: None,
                projection: StoreProjection::Full,
            })
            .await
            .unwrap();
        assert_eq!(restored_resource.resource_ref, original.resource_ref);
        assert_eq!(restored_resource.uid, original.uid);
        assert_eq!(restored_resource.generation, original.generation);
        assert_eq!(restored_resource.canonical_json, original.canonical_json);
        assert_eq!(restored_resource.payload_digest, original.payload_digest);
    }

    let restored_backup = restored.logical_backup().await.unwrap();
    assert_eq!(restored_backup.current_revision, 2);
    assert_eq!(restored_backup.backup_generation, 1);
    assert_eq!(restored.identity(), &store_identity);
    restored.shutdown().await.unwrap();
}

#[tokio::test]
async fn mutation_audit_uses_result_identity_and_failure_revision() {
    let (_directory, file, marker) = provisioned_store();
    let store_identity = identity();
    let (issuer, store_acceptor) = mutation_seal_pair(store_identity.seal_identity());
    let audit = Arc::new(RecordingAudit::default());
    let store = RedbResourceStore::provision_owned_with_test_ports(
        file,
        marker,
        store_identity,
        store_acceptor,
        Arc::new(NoopStoreTelemetry),
        audit.clone(),
    )
    .await
    .unwrap();

    let name = "audited-create";
    let canonical = create_body(name);
    let payload_digest = canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &canonical);
    let created = store
        .commit_verified(issuer.seal(create_seal_body_with_resource(
            "audited-create",
            name,
            canonical.clone(),
            payload_digest.clone(),
        )))
        .await
        .unwrap();

    let conflict = store
        .commit_verified(issuer.seal(create_seal_body_with_resource(
            "audited-conflict",
            name,
            canonical.clone(),
            payload_digest.clone(),
        )))
        .await
        .unwrap_err();
    assert_eq!(conflict.reason_code(), "resource-already-exists");

    let denied_canonical = create_body("audited-denied");
    let denied_payload_digest = canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &denied_canonical);
    let mut denied_body = create_seal_body_with_resource(
        "audited-denied",
        "audited-denied",
        denied_canonical,
        denied_payload_digest,
    );
    denied_body.authorization.targets.clear();
    let denied = store
        .commit_verified(issuer.seal(denied_body))
        .await
        .unwrap_err();
    assert_eq!(
        denied.kind(),
        d2b_resource_store::StoreErrorKind::AuthorizationDenied
    );
    store.shutdown().await.unwrap();

    let records = audit.records();
    assert_eq!(records.len(), 3);
    let fields = records
        .iter()
        .map(|record| match record.fields() {
            AuditRecordFields::ResourceMutation(fields) => fields,
            _ => panic!("resource mutation audit record"),
        })
        .collect::<Vec<_>>();
    assert_eq!(fields[0].outcome, "ok");
    assert_eq!(fields[0].resource_uid, created.resources[0].uid.as_str());
    assert_eq!(fields[0].generation, 1);
    assert_eq!(fields[0].resulting_revision, 1);
    assert_eq!(fields[1].outcome, "error");
    assert_eq!(
        fields[1].resource_uid,
        crate::audit::opaque_digest("Host/audited-create")
    );
    assert_eq!(fields[1].resulting_revision, 1);
    assert_eq!(
        fields[1].error_code.as_deref(),
        Some("resource-already-exists")
    );
    assert_eq!(fields[2].outcome, "denied");
    assert_eq!(
        fields[2].resource_uid,
        crate::audit::opaque_digest("Host/audited-denied")
    );
    assert_eq!(fields[2].resulting_revision, 1);
}

#[tokio::test]
async fn successful_activation_mutation_defers_missing_broker_evidence() {
    let (_directory, file, marker) = provisioned_store();
    let store_identity = identity();
    let (issuer, store_acceptor) = mutation_seal_pair(store_identity.seal_identity());
    let store = RedbResourceStore::provision_owned_with_test_ports(
        file,
        marker,
        store_identity,
        store_acceptor,
        Arc::new(NoopStoreTelemetry),
        Arc::new(RecordingAudit::default()),
    )
    .await
    .unwrap();
    let operation_id = "system-core-bootstrap-zone";
    let canonical = create_body_for_type("Provider", "activation-provider");
    let result = store
        .commit_verified(issuer.seal(create_seal_body_for_type(
            operation_id,
            "Provider",
            "activation-provider",
            canonical.clone(),
            canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &canonical),
        )))
        .await
        .unwrap();

    assert_eq!(result.revision.get(), 1);
    assert!(store.audit_outbox_pending(operation_id).await.unwrap());
    assert_eq!(
        store
            .pending_deferred_activation_operation_ids()
            .await
            .unwrap(),
        vec![operation_id.to_owned()]
    );
    assert!(store.runtime_metadata().await.is_ok());
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn caller_activation_shaped_operation_does_not_defer_missing_broker_evidence() {
    let (_directory, file, marker) = provisioned_store();
    let store_identity = identity();
    let (issuer, store_acceptor) = mutation_seal_pair(store_identity.seal_identity());
    let store = RedbResourceStore::provision_owned_with_test_ports(
        file,
        marker,
        store_identity,
        store_acceptor,
        Arc::new(NoopStoreTelemetry),
        Arc::new(RecordingAudit::default()),
    )
    .await
    .unwrap();
    let operation_id = format!("resource-bundle-materialization:sha256:{}", "c".repeat(64));
    let canonical = create_body_for_type("Provider", "caller-provider");
    let error = store
        .commit_verified(issuer.seal(create_seal_body_for_type_as(
            &operation_id,
            "Provider",
            "caller-provider",
            canonical.clone(),
            canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &canonical),
            "Provider/caller",
        )))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), StoreErrorKind::StoreIntegrityFailure);
    drop(store);
}

#[tokio::test]
async fn successful_non_activation_evidence_gated_mutation_still_fails_closed() {
    let (_directory, file, marker) = provisioned_store();
    let store_identity = identity();
    let (issuer, store_acceptor) = mutation_seal_pair(store_identity.seal_identity());
    let store = RedbResourceStore::provision_owned_with_test_ports(
        file,
        marker,
        store_identity,
        store_acceptor,
        Arc::new(NoopStoreTelemetry),
        Arc::new(RecordingAudit::default()),
    )
    .await
    .unwrap();
    let operation_id = "provider-resource-mutation";
    let canonical = create_body_for_type("Provider", "provider-resource");
    let error = store
        .commit_verified(issuer.seal(create_seal_body_for_type(
            operation_id,
            "Provider",
            "provider-resource",
            canonical.clone(),
            canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &canonical),
        )))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), StoreErrorKind::StoreIntegrityFailure);
}

#[tokio::test]
async fn failed_evidence_gated_mutation_appends_without_broker_evidence() {
    let (_directory, file, marker) = provisioned_store();
    let store_identity = identity();
    let (issuer, store_acceptor) = mutation_seal_pair(store_identity.seal_identity());
    let audit = Arc::new(RecordingAudit::default());
    let store = RedbResourceStore::provision_owned_with_test_ports(
        file,
        marker,
        store_identity,
        store_acceptor,
        Arc::new(NoopStoreTelemetry),
        audit.clone(),
    )
    .await
    .unwrap();
    let operation_id = "provider-resource-denied";
    let canonical = create_body_for_type("Provider", "provider-denied");
    let mut body = create_seal_body_for_type(
        operation_id,
        "Provider",
        "provider-denied",
        canonical.clone(),
        canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &canonical),
    );
    body.authorization.targets.clear();
    let error = store.commit_verified(issuer.seal(body)).await.unwrap_err();

    assert_eq!(error.kind(), StoreErrorKind::AuthorizationDenied);
    assert!(!store.audit_outbox_pending(operation_id).await.unwrap());
    let records = audit.records();
    assert_eq!(records.len(), 1);
    let AuditRecordFields::ResourceMutation(fields) = records[0].fields() else {
        panic!("resource mutation audit record");
    };
    assert_eq!(fields.outcome, "denied");
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn matching_broker_evidence_drains_activation_outbox() {
    let (_directory, file, marker) = provisioned_store();
    let store_identity = identity();
    let (issuer, store_acceptor) = mutation_seal_pair(store_identity.seal_identity());
    let audit = Arc::new(RecordingAudit::default());
    let store = RedbResourceStore::provision_owned_with_test_ports(
        file,
        marker,
        store_identity,
        store_acceptor,
        Arc::new(NoopStoreTelemetry),
        audit.clone(),
    )
    .await
    .unwrap();
    let operation_id = format!("resource-bundle-materialization:sha256:{}", "a".repeat(64));
    let canonical = create_body_for_type("Provider", "materialized-provider");
    store
        .commit_verified(issuer.seal(create_seal_body_for_type(
            &operation_id,
            "Provider",
            "materialized-provider",
            canonical.clone(),
            canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &canonical),
        )))
        .await
        .unwrap();
    assert!(store.audit_outbox_pending(&operation_id).await.unwrap());

    store
        .ingest_broker_evidence(
            &operation_id,
            broker_evidence(&operation_id, DurabilityOutcome::Success),
        )
        .await
        .unwrap();

    assert!(!store.audit_outbox_pending(&operation_id).await.unwrap());
    assert_eq!(audit.records().len(), 1);
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn evidence_ingestion_targets_one_operation_and_rejects_key_mismatch() {
    let (_directory, file, marker) = provisioned_store();
    let store_identity = identity();
    let (issuer, store_acceptor) = mutation_seal_pair(store_identity.seal_identity());
    let store = RedbResourceStore::provision_owned_with_test_ports(
        file,
        marker,
        store_identity,
        store_acceptor,
        Arc::new(NoopStoreTelemetry),
        Arc::new(RecordingAudit::default()),
    )
    .await
    .unwrap();
    let operation_a = format!("resource-bundle-materialization:sha256:{}", "a".repeat(64));
    let operation_b = format!("resource-bundle-materialization:sha256:{}", "b".repeat(64));
    for (operation_id, name) in [
        (&operation_a, "targeted-provider-a"),
        (&operation_b, "targeted-provider-b"),
    ] {
        let canonical = create_body_for_type("Provider", name);
        store
            .commit_verified(issuer.seal(create_seal_body_for_type(
                operation_id,
                "Provider",
                name,
                canonical.clone(),
                canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &canonical),
            )))
            .await
            .unwrap();
    }

    let mismatch = store
        .ingest_broker_evidence(
            &operation_b,
            broker_evidence(&operation_a, DurabilityOutcome::Success),
        )
        .await
        .unwrap_err();
    assert_eq!(mismatch.kind(), StoreErrorKind::StoreIntegrityFailure);
    assert!(store.audit_outbox_pending(&operation_a).await.unwrap());
    assert!(store.audit_outbox_pending(&operation_b).await.unwrap());

    store
        .ingest_broker_evidence(
            &operation_a,
            broker_evidence(&operation_a, DurabilityOutcome::Success),
        )
        .await
        .unwrap();
    assert!(!store.audit_outbox_pending(&operation_a).await.unwrap());
    assert!(store.audit_outbox_pending(&operation_b).await.unwrap());
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn pending_activation_ids_include_prior_hashes_until_each_is_drained() {
    let (_directory, file, marker) = provisioned_store();
    let store_identity = identity();
    let (issuer, store_acceptor) = mutation_seal_pair(store_identity.seal_identity());
    let store = RedbResourceStore::provision_owned_with_test_ports(
        file,
        marker,
        store_identity,
        store_acceptor,
        Arc::new(NoopStoreTelemetry),
        Arc::new(RecordingAudit::default()),
    )
    .await
    .unwrap();
    let operation_a = format!("resource-bundle-materialization:sha256:{}", "a".repeat(64));
    let operation_b = format!("resource-bundle-materialization:sha256:{}", "b".repeat(64));
    for (operation_id, name) in [
        (&operation_a, "prior-hash-provider"),
        (&operation_b, "current-hash-provider"),
    ] {
        let canonical = create_body_for_type("Provider", name);
        store
            .commit_verified(issuer.seal(create_seal_body_for_type(
                operation_id,
                "Provider",
                name,
                canonical.clone(),
                canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &canonical),
            )))
            .await
            .unwrap();
    }

    assert_eq!(
        store
            .pending_deferred_activation_operation_ids()
            .await
            .unwrap(),
        vec![operation_a.clone(), operation_b.clone()]
    );
    assert_eq!(
        store
            .require_no_pending_deferred_activation_outboxes()
            .await
            .unwrap_err()
            .reason_code(),
        "audit-deferred-evidence-pending"
    );
    store
        .ingest_broker_evidence(
            &operation_b,
            broker_evidence(&operation_b, DurabilityOutcome::Success),
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .pending_deferred_activation_operation_ids()
            .await
            .unwrap(),
        vec![operation_a.clone()]
    );
    store
        .ingest_broker_evidence(
            &operation_a,
            broker_evidence(&operation_a, DurabilityOutcome::Success),
        )
        .await
        .unwrap();
    assert!(
        store
            .pending_deferred_activation_operation_ids()
            .await
            .unwrap()
            .is_empty()
    );
    store
        .require_no_pending_deferred_activation_outboxes()
        .await
        .unwrap();
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn conflicting_broker_evidence_quarantines_store() {
    let (_directory, file, marker) = provisioned_store();
    let store_identity = identity();
    let (issuer, store_acceptor) = mutation_seal_pair(store_identity.seal_identity());
    let store = RedbResourceStore::provision_owned_with_test_ports(
        file,
        marker,
        store_identity,
        store_acceptor,
        Arc::new(NoopStoreTelemetry),
        Arc::new(RecordingAudit::default()),
    )
    .await
    .unwrap();
    let operation_id = "system-core-bootstrap-zone";
    let canonical = create_body_for_type("Provider", "conflicting-provider");
    store
        .commit_verified(issuer.seal(create_seal_body_for_type(
            operation_id,
            "Provider",
            "conflicting-provider",
            canonical.clone(),
            canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &canonical),
        )))
        .await
        .unwrap();

    let error = store
        .ingest_broker_evidence(
            operation_id,
            broker_evidence(operation_id, DurabilityOutcome::Failure),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), StoreErrorKind::StoreIntegrityFailure);
}

#[tokio::test]
async fn cold_open_defers_activation_and_drains_matching_evidence() {
    let (directory, file, marker) = provisioned_store();
    let store_identity = identity();
    let (issuer, store_acceptor) = mutation_seal_pair(store_identity.seal_identity());
    let store = RedbResourceStore::provision_owned_with_test_ports(
        file,
        marker,
        store_identity.clone(),
        store_acceptor,
        Arc::new(NoopStoreTelemetry),
        Arc::new(RecordingAudit::default()),
    )
    .await
    .unwrap();
    let operation_id = "system-core-bootstrap-zone";
    let canonical = create_body_for_type("Provider", "cold-activation-provider");
    store
        .commit_verified(issuer.seal(create_seal_body_for_type(
            operation_id,
            "Provider",
            "cold-activation-provider",
            canonical.clone(),
            canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &canonical),
        )))
        .await
        .unwrap();
    drop(store);

    let reopened = RedbResourceStore::open_owned_with_test_ports(
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(directory.path().join("store.redb"))
            .unwrap(),
        store_identity.clone(),
        acceptor(&store_identity),
        Arc::new(NoopStoreTelemetry),
        Arc::new(RecordingAudit::default()),
    )
    .await
    .unwrap();
    assert!(reopened.audit_outbox_pending(operation_id).await.unwrap());
    assert_eq!(
        reopened
            .pending_deferred_activation_operation_ids()
            .await
            .unwrap(),
        vec![operation_id.to_owned()]
    );
    reopened
        .ingest_broker_evidence(
            operation_id,
            broker_evidence(operation_id, DurabilityOutcome::Success),
        )
        .await
        .unwrap();
    assert!(!reopened.audit_outbox_pending(operation_id).await.unwrap());
    reopened.shutdown().await.unwrap();
}

#[tokio::test]
async fn malformed_deferred_marker_fails_closed() {
    let (directory, file, marker) = provisioned_store();
    let store_identity = identity();
    let (issuer, store_acceptor) = mutation_seal_pair(store_identity.seal_identity());
    let store = RedbResourceStore::provision_owned_with_test_ports(
        file,
        marker,
        store_identity,
        store_acceptor,
        Arc::new(NoopStoreTelemetry),
        Arc::new(RecordingAudit::default()),
    )
    .await
    .unwrap();
    let operation_id = "system-core-bootstrap-zone";
    let canonical = create_body_for_type("Provider", "malformed-marker-provider");
    store
        .commit_verified(issuer.seal(create_seal_body_for_type(
            operation_id,
            "Provider",
            "malformed-marker-provider",
            canonical.clone(),
            canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &canonical),
        )))
        .await
        .unwrap();
    store.shutdown().await.unwrap();

    let database = Database::builder()
        .set_cache_size(crate::REDB_CACHE_SIZE)
        .create_with_backend(
            redb::backends::FileBackend::new(
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(directory.path().join("store.redb"))
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    let key = crate::keys::encode_key(
        crate::keys::KeySpace::Operations,
        &[crate::keys::KeyComponent::Text(operation_id)],
    )
    .unwrap();
    let mut operation = {
        let read = database.begin_read().unwrap();
        let table = read.open_table(crate::transaction::OPERATIONS).unwrap();
        let value = table.get(key.as_bytes()).unwrap().unwrap();
        crate::transaction::decode::<crate::transaction::OperationRecord>(
            crate::ValueKind::OperationRecord,
            value.value(),
        )
        .unwrap()
    };
    operation.audit_outbox.as_mut().unwrap().subject_digest =
        crate::audit::opaque_digest("Provider/caller");
    let value = crate::transaction::encode(crate::ValueKind::OperationRecord, &operation).unwrap();
    let mut write = database.begin_write().unwrap();
    write.set_durability(Durability::Immediate).unwrap();
    write
        .open_table(crate::transaction::OPERATIONS)
        .unwrap()
        .insert(key.as_bytes(), value.as_slice())
        .unwrap();
    write.commit().unwrap();

    let error = crate::transaction::pending_deferred_activation_operation_ids(
        &database,
        &ZoneId::parse("work").unwrap(),
    )
    .unwrap_err();
    assert_eq!(
        error.reason_code(),
        "audit-deferred-evidence-marker-invalid"
    );
}

#[tokio::test]
async fn audit_failure_after_commit_returns_error_and_retains_the_outbox() {
    let (directory, file, marker) = provisioned_store();
    let store_identity = identity();
    let (issuer, store_acceptor) = mutation_seal_pair(store_identity.seal_identity());
    let audit = Arc::new(RejectingAudit(AtomicU64::new(0)));
    let store = RedbResourceStore::provision_owned_with_test_ports(
        file,
        marker,
        store_identity,
        store_acceptor,
        Arc::new(NoopStoreTelemetry),
        audit.clone(),
    )
    .await
    .unwrap();

    let canonical = create_body("audit-outbox");
    let digest = canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &canonical);
    let error = store
        .commit_verified(issuer.seal(create_seal_body_with_resource(
            "audit-outbox",
            "audit-outbox",
            canonical,
            digest,
        )))
        .await
        .unwrap_err();
    assert_eq!(
        error.kind(),
        d2b_resource_store::StoreErrorKind::StoreIntegrityFailure
    );
    assert_eq!(audit.0.load(Ordering::Relaxed), 1);
    drop(store);

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join("store.redb"))
        .unwrap();
    let database = Database::builder()
        .create_with_backend(redb::backends::FileBackend::new(file).unwrap())
        .unwrap();
    assert_eq!(
        crate::transaction::current_meta(&database)
            .unwrap()
            .current_revision,
        1
    );
    assert_eq!(
        crate::transaction::pending_audit_outboxes(&database)
            .unwrap()
            .len(),
        1
    );
    let outbox = crate::transaction::pending_audit_outboxes(&database)
        .unwrap()
        .pop()
        .expect("pending outbox");
    assert_eq!(
        outbox.operation_identity.as_ref(),
        Some(&OperationIdentity::derive("audit-outbox").unwrap())
    );
    drop(database);

    let audit = Arc::new(RecordingAudit::default());
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join("store.redb"))
        .unwrap();
    let recovered = RedbResourceStore::open_owned_with_test_ports(
        file,
        identity(),
        acceptor(&identity()),
        Arc::new(NoopStoreTelemetry),
        audit.clone(),
    )
    .await
    .unwrap();
    assert_eq!(audit.records().len(), 1);
    recovered.shutdown().await.unwrap();
}

#[tokio::test]
async fn audit_outbox_clear_failure_is_replayable_after_restart() {
    let (directory, file, marker) = provisioned_store();
    let store_identity = identity();
    let (issuer, store_acceptor) = mutation_seal_pair(store_identity.seal_identity());
    let audit = Arc::new(RecordingAudit::default());
    let store = RedbResourceStore::provision_owned_with_test_ports(
        file,
        marker,
        store_identity,
        store_acceptor,
        Arc::new(NoopStoreTelemetry),
        audit.clone(),
    )
    .await
    .unwrap();

    crate::transaction::fail_next_audit_outbox_clear_for_test();
    let canonical = create_body("audit-clear-retry");
    let digest = canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &canonical);
    let error = store
        .commit_verified(issuer.seal(create_seal_body_with_resource(
            "audit-clear-retry",
            "audit-clear-retry",
            canonical,
            digest,
        )))
        .await
        .unwrap_err();
    assert_eq!(
        error.kind(),
        d2b_resource_store::StoreErrorKind::StoreIntegrityFailure
    );
    assert_eq!(audit.records().len(), 1);
    drop(store);

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join("store.redb"))
        .unwrap();
    let recovered = RedbResourceStore::open_owned_with_test_ports(
        file,
        identity(),
        acceptor(&identity()),
        Arc::new(NoopStoreTelemetry),
        audit,
    )
    .await
    .unwrap();
    recovered.shutdown().await.unwrap();
}

#[test]
fn open_rejects_seal_from_a_foreign_pair() {
    let first = identity();
    let second = identity_for(
        StoreSlot::new(1).unwrap(),
        "work",
        "33333333-3333-4333-8333-333333333333",
    );
    let (issuer, _) = mutation_seal_pair(first.seal_identity());
    let (_, acceptor) = mutation_seal_pair(second.seal_identity());

    let error = acceptor
        .open(issuer.seal(empty_seal_body()))
        .err()
        .expect("a foreign seal must be refused");
    assert_eq!(error.reason_code(), "mutation-seal-authority-mismatch");
    assert_eq!(error.store_slot(), Some(StoreSlot::new(1).unwrap()));
}

#[test]
fn open_rejects_seal_bound_to_another_store_identity() {
    let first = identity();
    let sibling = identity_for(
        StoreSlot::new(0).unwrap(),
        "work",
        "44444444-4444-4444-8444-444444444444",
    );
    let (issuer, acceptor) = mutation_seal_pair(first.seal_identity());

    assert_eq!(
        acceptor.diagnose(&sibling.seal_identity()),
        Err(d2b_resource_store::SealIdentityMismatch::Store)
    );
    let (_, sibling_acceptor) = mutation_seal_pair(sibling.seal_identity());
    let error = sibling_acceptor
        .open(issuer.seal(empty_seal_body()))
        .err()
        .expect("a seal for another store must be refused");
    assert_eq!(error.reason_code(), "mutation-seal-authority-mismatch");
}

#[tokio::test]
async fn open_owned_rejects_acceptor_bound_to_another_zone() {
    let (_directory, file) = owned_file();
    let expected = identity();
    let foreign = identity_for(
        StoreSlot::new(0).unwrap(),
        "personal",
        "11111111-1111-4111-8111-111111111111",
    );
    let (_, acceptor) = mutation_seal_pair(foreign.seal_identity());

    let error = RedbResourceStore::open_owned(file, expected, acceptor)
        .await
        .expect_err("a cross-zone acceptor must be refused");
    assert_eq!(error.reason_code(), "mutation-seal-acceptor-zone-mismatch");
    assert_eq!(error.store_slot(), Some(StoreSlot::new(0).unwrap()));
}

#[tokio::test]
async fn open_owned_rejects_acceptor_bound_to_another_store_in_the_same_zone() {
    let (_directory, file) = owned_file();
    let expected = identity();
    let sibling = identity_for(
        StoreSlot::new(0).unwrap(),
        "work",
        "44444444-4444-4444-8444-444444444444",
    );
    let (_, acceptor) = mutation_seal_pair(sibling.seal_identity());

    let error = RedbResourceStore::open_owned(file, expected, acceptor)
        .await
        .expect_err("a sibling-store acceptor must be refused");
    assert_eq!(error.reason_code(), "mutation-seal-acceptor-store-mismatch");
    assert_eq!(error.store_slot(), Some(StoreSlot::new(0).unwrap()));
}

#[tokio::test]
async fn open_owned_rejects_acceptor_declaring_another_slot() {
    let (_directory, file) = owned_file();
    let expected = identity();
    let wrong_slot = identity_for(
        StoreSlot::new(1).unwrap(),
        "work",
        "11111111-1111-4111-8111-111111111111",
    );
    let (_, acceptor) = mutation_seal_pair(wrong_slot.seal_identity());

    let error = RedbResourceStore::open_owned(file, expected, acceptor)
        .await
        .expect_err("a wrong-slot acceptor must be refused");
    assert_eq!(error.reason_code(), "mutation-seal-acceptor-slot-mismatch");
    assert_eq!(error.store_slot(), Some(StoreSlot::new(0).unwrap()));
}

#[test]
fn diagnose_names_the_disagreeing_component_without_rendering_it() {
    let expected = identity();
    let matching = mutation_seal_pair(expected.seal_identity()).1;
    assert_eq!(matching.diagnose(&expected.seal_identity()), Ok(()));

    let zone = identity_for(
        StoreSlot::new(0).unwrap(),
        "personal",
        "11111111-1111-4111-8111-111111111111",
    );
    assert_eq!(
        matching.diagnose(&zone.seal_identity()),
        Err(d2b_resource_store::SealIdentityMismatch::Zone)
    );

    let store = identity_for(
        StoreSlot::new(0).unwrap(),
        "work",
        "44444444-4444-4444-8444-444444444444",
    );
    assert_eq!(
        matching.diagnose(&store.seal_identity()),
        Err(d2b_resource_store::SealIdentityMismatch::Store)
    );
    let epoch = identity().with_store_epoch(2);
    assert_eq!(
        matching.diagnose(&epoch.seal_identity()),
        Err(d2b_resource_store::SealIdentityMismatch::Epoch)
    );
    assert_eq!(
        d2b_resource_store::SealIdentityMismatch::Zone.reason_code(),
        "mutation-seal-acceptor-zone-mismatch"
    );
    assert_eq!(
        d2b_resource_store::SealIdentityMismatch::Store.reason_code(),
        "mutation-seal-acceptor-store-mismatch"
    );
    assert_eq!(
        d2b_resource_store::SealIdentityMismatch::Epoch.reason_code(),
        "mutation-seal-acceptor-store-epoch-mismatch"
    );
}

#[tokio::test]
async fn errors_from_a_multi_store_startup_carry_distinct_slots() {
    let (_first_dir, first_file) = owned_file();
    let (_second_dir, second_file) = owned_file();
    let first = identity_for(
        StoreSlot::new(0).unwrap(),
        "work",
        "11111111-1111-4111-8111-111111111111",
    );
    let second = identity_for(
        StoreSlot::new(1).unwrap(),
        "work",
        "33333333-3333-4333-8333-333333333333",
    );
    let first_wrong = identity_for(
        StoreSlot::new(0).unwrap(),
        "personal",
        "11111111-1111-4111-8111-111111111111",
    );
    let second_wrong = identity_for(
        StoreSlot::new(1).unwrap(),
        "personal",
        "33333333-3333-4333-8333-333333333333",
    );
    let (_, first_acceptor) = mutation_seal_pair(first_wrong.seal_identity());
    let (_, second_acceptor) = mutation_seal_pair(second_wrong.seal_identity());

    let first_error = RedbResourceStore::open_owned(first_file, first, first_acceptor)
        .await
        .expect_err("slot zero startup must refuse its mismatched acceptor");
    let second_error = RedbResourceStore::open_owned(second_file, second, second_acceptor)
        .await
        .expect_err("slot one startup must refuse its mismatched acceptor");

    assert_eq!(first_error.store_slot(), Some(StoreSlot::new(0).unwrap()));
    assert_eq!(second_error.store_slot(), Some(StoreSlot::new(1).unwrap()));
    assert_eq!(
        first_error
            .clone()
            .with_store_slot(StoreSlot::new(1).unwrap()),
        second_error
    );
}

#[tokio::test]
async fn commit_rejects_seal_from_another_store() {
    let (_first_dir, first_file, first_marker) = provisioned_store();
    let first_identity = identity();
    let first = provision_store(first_file, first_marker, first_identity.clone())
        .await
        .unwrap();

    let second_identity = identity_for(
        StoreSlot::new(1).unwrap(),
        "work",
        "33333333-3333-4333-8333-333333333333",
    );
    let (second_dir, second_file) = owned_file();
    let mut second_marker = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(second_dir.path().join("store.marker"))
        .unwrap();
    write_provisioning_marker(&mut second_marker, &second_identity).unwrap();
    let _second = provision_store(second_file, second_marker, second_identity.clone())
        .await
        .unwrap();

    let (issuer, _) = mutation_seal_pair(second_identity.seal_identity());
    let error = first
        .commit_verified(issuer.seal(empty_seal_body()))
        .await
        .expect_err("cross-store evidence must be refused");
    assert_eq!(error.reason_code(), "mutation-seal-authority-mismatch");
    assert_eq!(error.store_slot(), Some(first_identity.slot()));
}

#[tokio::test]
async fn sealed_create_mints_uid_in_the_store_and_replays_without_it() {
    let (_directory, file, marker) = provisioned_store();
    let store_identity = identity();
    let (issuer, acceptor) = mutation_seal_pair(store_identity.seal_identity());
    let store = RedbResourceStore::provision_owned(file, marker, store_identity.clone(), acceptor)
        .await
        .unwrap();
    let name = "sealed-create";
    let canonical = create_body(name);
    assert!(!String::from_utf8_lossy(&canonical).contains("\"uid\""));
    let payload_digest = canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &canonical);

    let result = store
        .commit_verified(issuer.seal(create_seal_body(
            "sealed-create",
            name,
            payload_digest.clone(),
        )))
        .await
        .unwrap();
    let uid = result.resources[0].uid.clone();
    assert_eq!(uid.as_str().as_bytes()[14], b'4');
    assert!(matches!(
        uid.as_str().as_bytes()[19],
        b'8' | b'9' | b'a' | b'b'
    ));
    assert_eq!(result.resources[0].uid, uid);
    let final_digest = result.resources[0].payload_digest.clone();
    assert_eq!(
        ResourceEnvelope::from_json(&result.resources[0].canonical_json)
            .unwrap()
            .digest()
            .unwrap(),
        final_digest
    );
    let persisted = store
        .get(StoreGetRequest {
            operation: operation("read-sealed-create"),
            zone: ZoneId::parse("work").unwrap(),
            target: ResourceRef::parse("Host/sealed-create").unwrap(),
            expected_uid: Some(uid.clone()),
            projection: StoreProjection::Full,
        })
        .await
        .unwrap();
    assert_eq!(persisted.uid, uid);
    assert_eq!(persisted.payload_digest, final_digest);

    let replay = store
        .commit_verified(issuer.seal(create_seal_body_with_resource(
            "sealed-create",
            name,
            canonical.clone(),
            payload_digest,
        )))
        .await
        .unwrap();
    assert_eq!(replay.resources[0].uid, uid);
    assert_eq!(replay.resources[0].payload_digest, final_digest);

    let changed_canonical = String::from_utf8(canonical.clone())
        .unwrap()
        .replace(
            "\"nonDisruptive\":\"automatic\"",
            "\"nonDisruptive\":\"manual\"",
        )
        .into_bytes();
    let changed_payload_digest = canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &changed_canonical);
    let error = store
        .commit_verified(issuer.seal(create_seal_body_with_resource(
            "sealed-create",
            name,
            changed_canonical,
            changed_payload_digest,
        )))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), "operation-id-reused");

    let replacement = format!("sha256:{}", "f".repeat(64));
    let replay = store
        .commit_verified(issuer.seal(create_seal_body("sealed-create", name, replacement)))
        .await
        .unwrap();
    assert_eq!(replay.resources[0].uid, uid);
}

#[tokio::test]
async fn owned_file_open_initializes_and_reopens_only_matching_identity() {
    let (directory, file, marker) = provisioned_store();
    let store = provision_store(file, marker, identity()).await.unwrap();
    assert_eq!(store.identity().zone().as_str(), "work");
    store.shutdown().await.unwrap();

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join("store.redb"))
        .unwrap();
    open_store(file, identity()).await.unwrap();

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join("store.redb"))
        .unwrap();
    let mut mismatch = identity();
    mismatch.zone = ZoneId::parse("personal").unwrap();
    let error = open_store(file, mismatch).await.unwrap_err();
    assert_eq!(
        error.kind(),
        d2b_resource_store::StoreErrorKind::StoreIntegrityFailure
    );
}

#[tokio::test]
async fn current_v2_legacy_outbox_normalizes_before_cold_open_validation() {
    let (directory, file, marker) = provisioned_store();
    let store = provision_store(file, marker, identity()).await.unwrap();
    store.shutdown().await.unwrap();
    insert_legacy_outbox(&directory, "cold-legacy-outbox");

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join("store.redb"))
        .unwrap();
    let store = open_store(file, identity()).await.unwrap();
    store.shutdown().await.unwrap();

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join("store.redb"))
        .unwrap();
    let database = Database::builder()
        .create_with_backend(redb::backends::FileBackend::new(file).unwrap())
        .unwrap();
    crate::transaction::validate_consistency(&database).unwrap();
}

#[tokio::test]
async fn legacy_v1_reopen_backfills_the_catalog_without_losing_resources() {
    let (directory, file, marker) = provisioned_store();
    let store_identity = identity();
    let (issuer, acceptor) = mutation_seal_pair(store_identity.seal_identity());
    let store = RedbResourceStore::provision_owned(file, marker, store_identity.clone(), acceptor)
        .await
        .unwrap();
    let canonical = create_body("legacy-reopen");
    let digest = canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &canonical);
    store
        .commit_verified(issuer.seal(create_seal_body_with_resource(
            "legacy-reopen",
            "legacy-reopen",
            canonical,
            digest,
        )))
        .await
        .unwrap();
    store.shutdown().await.unwrap();

    let legacy_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join("store.redb"))
        .unwrap();
    let database = Database::builder()
        .create_with_backend(redb::backends::FileBackend::new(legacy_file).unwrap())
        .unwrap();
    let keys = {
        let read = database.begin_read().unwrap();
        read.open_table(crate::transaction::API_SCHEMAS)
            .unwrap()
            .iter()
            .unwrap()
            .map(|row| row.unwrap().0.value().to_vec())
            .collect::<Vec<_>>()
    };
    let mut write = database.begin_write().unwrap();
    write.set_durability(Durability::Immediate).unwrap();
    let mut schemas = write.open_table(crate::transaction::API_SCHEMAS).unwrap();
    for key in keys {
        schemas.remove(key.as_slice()).unwrap();
    }
    drop(schemas);
    write.commit().unwrap();
    drop(database);

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join("store.redb"))
        .unwrap();
    let store = open_store(file, store_identity.clone()).await.unwrap();
    let backup = store.logical_backup().await.unwrap();
    let schemas = backup
        .tables
        .iter()
        .find(|table| table.name == "api_schemas")
        .unwrap();
    assert_eq!(
        schemas.rows.len(),
        crate::transaction::INSTALLED_SCHEMA_CATALOG.len()
    );
    assert!(
        store
            .get(StoreGetRequest {
                operation: operation("legacy-reopen-read"),
                zone: ZoneId::parse("work").unwrap(),
                target: ResourceRef::parse("Host/legacy-reopen").unwrap(),
                expected_uid: None,
                projection: StoreProjection::MetadataOnly,
            })
            .await
            .is_ok()
    );
    store.shutdown().await.unwrap();

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join("store.redb"))
        .unwrap();
    let reopened = open_store(file, store_identity).await.unwrap();
    assert_eq!(
        reopened
            .logical_backup()
            .await
            .unwrap()
            .tables
            .iter()
            .find(|table| table.name == "api_schemas")
            .unwrap()
            .rows
            .len(),
        crate::transaction::INSTALLED_SCHEMA_CATALOG.len()
    );
    reopened.shutdown().await.unwrap();
}

#[tokio::test]
async fn legacy_v1_reopen_backfills_qualified_schema_rows() {
    let (directory, file, marker) = provisioned_store();
    let store_identity = identity();
    let store = provision_store(file, marker, store_identity.clone())
        .await
        .unwrap();
    store.shutdown().await.unwrap();

    let qualified_types = [
        "display-wayland.d2bus.org.WaylandPolicy",
        "display-wayland.d2bus.org.WaylandSession",
    ]
    .into_iter()
    .map(|resource_type| ResourceTypeName::parse(resource_type).unwrap())
    .collect::<Vec<_>>();
    let keys = qualified_types
        .iter()
        .map(crate::transaction::api_schema_key_for_type)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let legacy_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join("store.redb"))
        .unwrap();
    let database = Database::builder()
        .create_with_backend(redb::backends::FileBackend::new(legacy_file).unwrap())
        .unwrap();
    let mut write = database.begin_write().unwrap();
    write.set_durability(Durability::Immediate).unwrap();
    let mut schemas = write.open_table(crate::transaction::API_SCHEMAS).unwrap();
    for key in &keys {
        schemas.remove(key.as_slice()).unwrap();
    }
    assert_eq!(
        schemas.len().unwrap(),
        crate::transaction::STANDARD_SCHEMA_CATALOG.len() as u64
    );
    drop(schemas);
    write.commit().unwrap();
    drop(database);

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join("store.redb"))
        .unwrap();
    let reopened = open_store(file, store_identity).await.unwrap();
    reopened.shutdown().await.unwrap();

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join("store.redb"))
        .unwrap();
    let database = Database::builder()
        .create_with_backend(redb::backends::FileBackend::new(file).unwrap())
        .unwrap();
    let read = database.begin_read().unwrap();
    let schemas = read.open_table(crate::transaction::API_SCHEMAS).unwrap();
    assert_eq!(
        schemas.len().unwrap(),
        crate::transaction::INSTALLED_SCHEMA_CATALOG.len() as u64
    );
    for key in &keys {
        assert!(schemas.get(key.as_slice()).unwrap().is_some());
    }
}
#[tokio::test]
async fn empty_existing_store_is_quarantined_without_publication_marker() {
    let (_directory, file) = owned_file();
    let error = open_store(file, identity()).await.unwrap_err();
    assert_eq!(
        error.kind(),
        d2b_resource_store::StoreErrorKind::StoreQuarantined
    );
    assert_eq!(error.reason_code(), "provisioned-store-empty");
}

#[tokio::test]
async fn clean_drop_reopens_without_crash_recovery_and_dirty_open_is_reported() {
    let (directory, file) = owned_file();
    let backend = redb::backends::FileBackend::new(file).unwrap();
    let database = Database::builder().create_with_backend(backend).unwrap();
    crate::transaction::initialize(&database, &identity()).unwrap();
    drop(database);

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join("store.redb"))
        .unwrap();
    let store = open_store(file, identity()).await.unwrap();
    assert!(store.recovered_after_crash());
    store.shutdown().await.unwrap();

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join("store.redb"))
        .unwrap();
    let store = open_store(file, identity()).await.unwrap();
    assert!(!store.recovered_after_crash());
}

#[tokio::test]
async fn direct_owned_fd_without_cloexec_fails_closed() {
    let (_directory, file) = owned_file();
    fcntl_setfd(&file, FdFlags::empty()).unwrap();
    let error = open_store(file, identity()).await.unwrap_err();
    assert_eq!(
        error.kind(),
        d2b_resource_store::StoreErrorKind::StoreIntegrityFailure
    );
}

#[tokio::test]
async fn owned_open_rejects_a_non_regular_fd() {
    let pipe = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
    let file = File::from(pipe.0);
    let error = open_store(file, identity()).await.unwrap_err();
    assert_eq!(
        error.kind(),
        d2b_resource_store::StoreErrorKind::StoreIntegrityFailure
    );
}

#[test]
fn scm_rights_receipt_is_atomic_cloexec_and_not_inherited_across_exec() {
    let (_directory, file) = owned_file();
    let (sender, receiver) = socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();
    let descriptors = [file.as_fd()];
    let mut control_bytes = vec![0_u8; rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut control_bytes);
    assert!(control.push(SendAncillaryMessage::ScmRights(&descriptors)));
    assert_eq!(
        sendmsg(
            &sender,
            &[rustix::io::IoSlice::new(b"x")],
            &mut control,
            SendFlags::empty(),
        )
        .unwrap(),
        1
    );
    let received = receive_database_file(&receiver).unwrap();
    assert!(fcntl_getfd(&received).unwrap().contains(FdFlags::CLOEXEC));
    let fd = received.as_raw_fd();
    let status = Command::new("test")
        .args(["!", "-e"])
        .arg(format!("/proc/self/fd/{fd}"))
        .status()
        .unwrap();
    assert!(status.success(), "database fd survived exec");
}

#[test]
fn scm_rights_receipt_rejects_multiple_descriptors() {
    let (_first_directory, first) = owned_file();
    let (_second_directory, second) = owned_file();
    let (sender, receiver) = socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();
    let descriptors = [first.as_fd(), second.as_fd()];
    let mut control_bytes = vec![0_u8; rustix::cmsg_space!(ScmRights(2))];
    let mut control = SendAncillaryBuffer::new(&mut control_bytes);
    assert!(control.push(SendAncillaryMessage::ScmRights(&descriptors)));
    sendmsg(
        &sender,
        &[rustix::io::IoSlice::new(b"x")],
        &mut control,
        SendFlags::empty(),
    )
    .unwrap();
    let error = receive_database_file(&receiver).unwrap_err();
    assert_eq!(
        error.kind(),
        d2b_resource_store::StoreErrorKind::StoreIntegrityFailure
    );
}

#[test]
fn scm_rights_receipt_exec_status_helper() {
    const HELPER_ENV: &str = "D2B_RESOURCE_STORE_EXEC_STATUS_HELPER";
    const STATUS_DUP_MIN_FD: i32 = 10;

    if std::env::var_os(HELPER_ENV).is_none() {
        return;
    }

    // `Command::stderr` safely hands the status pipe to fd 2, but that dup
    // clears CLOEXEC. Preserve the pipe on a high descriptor before replacing
    // fd 2 with /dev/null, then let exec close the preserved descriptor.
    let status = rustix::io::fcntl_dupfd_cloexec(rustix::stdio::stderr(), STATUS_DUP_MIN_FD)
        .expect("duplicate exec status fd");
    let error = Command::new("sleep")
        .arg("1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .exec();
    let _ = rustix::io::write(&status, &[1]);
    eprintln!("exec status helper could not exec sleep: {error}");
    std::process::exit(1);
}

#[test]
fn scm_rights_receipt_racing_fork_exec_never_leaks_the_database_inode() {
    const HELPER_ENV: &str = "D2B_RESOURCE_STORE_EXEC_STATUS_HELPER";
    const HELPER_TEST: &str = "tests::scm_rights_receipt_exec_status_helper";

    for _ in 0..32 {
        let (_directory, file) = owned_file();
        let metadata = file.metadata().unwrap();
        let inode = format!("{}:{}", metadata.dev(), metadata.ino());
        let (sender, receiver) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        let descriptors = [file.as_fd()];
        let mut control_bytes = vec![0_u8; rustix::cmsg_space!(ScmRights(1))];
        let mut control = SendAncillaryBuffer::new(&mut control_bytes);
        assert!(control.push(SendAncillaryMessage::ScmRights(&descriptors)));
        sendmsg(
            &sender,
            &[rustix::io::IoSlice::new(b"x")],
            &mut control,
            SendFlags::empty(),
        )
        .unwrap();

        let barrier = Arc::new(Barrier::new(2));
        let receiver_barrier = Arc::clone(&barrier);
        let receipt = std::thread::spawn(move || {
            receiver_barrier.wait();
            receive_database_file(&receiver)
        });
        barrier.wait();
        let status_pipe =
            rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).expect("exec status pipe");
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", HELPER_TEST])
            .env(HELPER_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(status_pipe.1));
        let mut child = command.spawn().unwrap();
        // `Command` retains its parent-side stdio descriptors after spawn.
        // Release the status writer so EOF means the helper's exec completed.
        drop(command);

        let mut status_byte = [0_u8; 1];
        let status_len = rustix::io::read(&status_pipe.0, &mut status_byte).unwrap();
        assert_eq!(
            status_len, 0,
            "exec status helper reported failure byte {:?}",
            status_byte[0]
        );
        let leaked = std::fs::read_dir(format!("/proc/{}/fd", child.id()))
            .unwrap()
            .filter_map(Result::ok)
            .filter_map(|entry| std::fs::metadata(entry.path()).ok())
            .any(|metadata| format!("{}:{}", metadata.dev(), metadata.ino()) == inode);
        let received = receipt.join().unwrap().unwrap();
        assert!(fcntl_getfd(&received).unwrap().contains(FdFlags::CLOEXEC));
        let status = child.wait().unwrap();
        assert!(!leaked, "database inode survived racing exec");
        assert!(status.success(), "database inode survived racing exec");
    }
}

#[tokio::test(start_paused = true)]
async fn read_lifetime_is_enforced_by_the_paused_clock() {
    let (_directory, file, marker) = provisioned_store();
    let store = provision_store(file, marker, identity()).await.unwrap();
    let store = Arc::new(store);
    let (started, started_receiver) = tokio::sync::oneshot::channel();
    let (release, release_receiver) = std::sync::mpsc::channel();
    let (completed, completed_receiver) = tokio::sync::oneshot::channel();
    let probe_store = Arc::clone(&store);
    let probe = tokio::spawn(async move {
        probe_store
            .reads
            .expiry_probe(started, release_receiver, completed)
            .await
    });
    started_receiver.await.unwrap();
    tokio::time::advance(READ_LIFETIME + std::time::Duration::from_millis(1)).await;
    let error = probe.await.unwrap().unwrap_err();
    assert_eq!(error.kind(), d2b_resource_store::StoreErrorKind::Timeout);
    assert_eq!(store.reads.available_permits(), MAX_CONCURRENT_READS - 1);
    release.send(()).unwrap();
    completed_receiver.await.unwrap();
    assert_eq!(store.reads.available_permits(), MAX_CONCURRENT_READS);
}

#[tokio::test]
async fn range_seek_skips_every_older_row() {
    let (_directory, file, marker) = provisioned_store();
    let store = provision_store(file, marker, identity()).await.unwrap();
    let process = ResourceTypeName::parse("Process").unwrap();
    let first = store
        .replay_backend(0, [process.clone()], |_| Ok(()))
        .await
        .unwrap();
    let second = store
        .replay_backend(0, [process], |_| Ok(()))
        .await
        .unwrap();
    assert_eq!(first.get(), 0);
    assert_eq!(second.get(), 0);
    let signals = loop {
        let signals = store.signals();
        if signals.revision_range_seeks == 2 {
            break signals;
        }
        tokio::task::yield_now().await;
    };
    assert_eq!(signals.revision_range_seeks, 2);
    assert_eq!(signals.replay_rows_scanned, 0);
    assert_eq!(signals.replay_rows_decoded, 0);
    assert_eq!(signals.writer_queue_capacity, 256);
}

#[tokio::test]
async fn replay_primitive_scans_larger_history_without_a_backend_queue() {
    let (directory, file) = owned_file();
    drop(file);
    seed_replay_log(&directory, 300);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join("store.redb"))
        .unwrap();
    let store = open_store(file, identity()).await.unwrap();
    let high_water = store
        .replay_backend(0, [ResourceTypeName::parse("Process").unwrap()], |_| Ok(()))
        .await
        .unwrap();
    assert_eq!(high_water.get(), 300);
    while {
        let signals = store.signals();
        signals.replay_rows_scanned < 300 || signals.replay_rows_decoded < 300
    } {
        tokio::task::yield_now().await;
    }
    let signals = store.signals();
    assert_eq!(signals.replay_rows_scanned, 300);
    assert_eq!(signals.replay_rows_decoded, 300);
}

#[tokio::test]
async fn public_read_path_enforces_zone_and_projection() {
    let (directory, file) = owned_file();
    drop(file);
    seed_two_hosts(&directory);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join("store.redb"))
        .unwrap();
    let store = open_store(file, identity()).await.unwrap();
    let target = ResourceRef::parse("Host/host-system").unwrap();
    let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
    let request = |zone: &str, projection| StoreGetRequest {
        operation: operation("get-host"),
        zone: ZoneId::parse(zone).unwrap(),
        target: target.clone(),
        expected_uid: Some(uid.clone()),
        projection,
    };

    let full = store
        .get(request("work", StoreProjection::Full))
        .await
        .unwrap();
    assert!(
        std::str::from_utf8(&full.canonical_json)
            .unwrap()
            .contains("\"status\"")
    );
    let base = store
        .get(request("work", StoreProjection::BaseOnly))
        .await
        .unwrap();
    assert_eq!(base.canonical_json, full.canonical_json);
    let metadata = store
        .get(request("work", StoreProjection::MetadataOnly))
        .await
        .unwrap();
    let metadata = std::str::from_utf8(&metadata.canonical_json).unwrap();
    assert!(metadata.contains("\"metadata\""));
    assert!(!metadata.contains("\"spec\""));
    assert!(!metadata.contains("\"status\""));
    let wrong_zone = store
        .get(request("personal", StoreProjection::Full))
        .await
        .unwrap_err();
    assert_eq!(
        wrong_zone.kind(),
        d2b_resource_store::StoreErrorKind::StoreIntegrityFailure
    );
}

#[tokio::test]
async fn list_cursor_is_bound_to_snapshot_and_selector() {
    let (directory, file) = owned_file();
    drop(file);
    seed_two_hosts(&directory);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join("store.redb"))
        .unwrap();
    let store = open_store(file, identity()).await.unwrap();
    let request = |cursor, resource_types| StoreListRequest {
        operation: operation("list-host"),
        zone: ZoneId::parse("work").unwrap(),
        resource_types,
        resource_names: Vec::new(),
        filters: Vec::new(),
        page_size: 1,
        cursor,
        projection: StoreProjection::MetadataOnly,
    };
    let first = store.list(request(None, Vec::new())).await.unwrap();
    assert!(first.truncated);
    let first_json = std::str::from_utf8(&first.resources[0].canonical_json).unwrap();
    assert!(first_json.contains("\"metadata\""));
    assert!(!first_json.contains("\"spec\""));
    assert!(!first_json.contains("\"status\""));
    let cursor = first.next_cursor.unwrap();
    let error = store
        .list(request(
            Some(cursor.clone()),
            vec![ResourceTypeName::parse("Host").unwrap()],
        ))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), "list-cursor-selector-mismatch");

    let mut stale = cursor.split('.').map(str::to_owned).collect::<Vec<_>>();
    stale[1] = "0".to_owned();
    let error = store
        .list(request(Some(stale.join(".")), Vec::new()))
        .await
        .unwrap_err();
    assert_eq!(
        error.kind(),
        d2b_resource_store::StoreErrorKind::RevisionExpired
    );
}

#[tokio::test]
async fn public_watch_replays_and_delivers_one_shared_committed_batch() {
    let (directory, file) = owned_file();
    let store_identity = identity();
    let (issuer, acceptor) = mutation_seal_pair(store_identity.seal_identity());
    let mut marker = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(directory.path().join("store.marker"))
        .unwrap();
    write_provisioning_marker(&mut marker, &store_identity).unwrap();
    let store = RedbResourceStore::provision_owned(file, marker, store_identity, acceptor)
        .await
        .unwrap();
    let receipt = store
        .watch(StoreWatchRequest {
            operation: operation("watch-host"),
            zone: ZoneId::parse("work").unwrap(),
            resource_types: vec![ResourceTypeName::parse("Host").unwrap()],
            resource_names: Vec::new(),
            filters: Vec::new(),
            after_revision: d2b_contracts_resource::v3::ZoneRevision::new(0),
            initial_credits: 1,
            projection: StoreProjection::Full,
        })
        .await
        .unwrap();
    let mut stream = store
        .take_watch_stream_named(&receipt.stream_name)
        .unwrap()
        .expect("receipt stream is retained until transfer");
    assert!(
        store
            .take_watch_stream_named(&receipt.stream_name)
            .unwrap()
            .is_none()
    );
    let (_second_receipt, mut second_stream) = store
        .watch_stream(StoreWatchRequest {
            operation: operation("watch-host-second"),
            zone: ZoneId::parse("work").unwrap(),
            resource_types: vec![ResourceTypeName::parse("Host").unwrap()],
            resource_names: Vec::new(),
            filters: Vec::new(),
            after_revision: d2b_contracts_resource::v3::ZoneRevision::new(0),
            initial_credits: 1,
            projection: StoreProjection::Full,
        })
        .await
        .unwrap();
    assert_eq!(receipt.snapshot_revision.get(), 0);

    let canonical = create_body("watch-host");
    let payload_digest = canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &canonical);
    let result = store
        .commit_verified(issuer.seal(create_seal_body("watch-host", "watch-host", payload_digest)))
        .await
        .unwrap();
    let batch = stream.recv().await.expect("committed batch is delivered");
    let second_batch = second_stream
        .recv()
        .await
        .expect("the second watcher receives the same batch");
    assert_eq!(batch.revision(), result.revision);
    assert!(batch.shares_batch_with(&second_batch));
    assert_eq!(batch.entries().len(), 1);
    assert!(batch.shares_batch_with(&batch));
    assert_eq!(store.watch_signals().unwrap().budget_used, 2);
    let backend_signals = store.signals();
    assert_eq!(backend_signals.shared_immutable_batches, 1);
    assert_eq!(backend_signals.fanout_references, 2);

    store
        .acknowledge_watch(stream.id(), result.revision)
        .await
        .unwrap();
    store
        .acknowledge_watch(second_stream.id(), result.revision)
        .await
        .unwrap();
    assert_eq!(store.watch_signals().unwrap().budget_used, 0);
}

#[tokio::test]
async fn public_owner_child_list_and_watch_are_bound_to_one_owner_uid() {
    let (directory, file) = owned_file();
    let store_identity = identity();
    let (issuer, acceptor) = mutation_seal_pair(store_identity.seal_identity());
    let mut marker = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(directory.path().join("store.marker"))
        .unwrap();
    write_provisioning_marker(&mut marker, &store_identity).unwrap();
    let store = RedbResourceStore::provision_owned(file, marker, store_identity, acceptor)
        .await
        .unwrap();

    let guest = ResourceRef::parse("Guest/guest").unwrap();
    let sibling = ResourceRef::parse("Guest/sibling").unwrap();
    for (operation_id, target, body) in [
        ("owner-list-guest", guest.clone(), owned_guest_body("guest")),
        (
            "owner-list-sibling",
            sibling.clone(),
            owned_guest_body("sibling"),
        ),
    ] {
        let payload_digest = canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &body);
        store
            .commit_verified(issuer.seal(create_seal_body_for_type(
                operation_id,
                target.resource_type().as_str(),
                target.name().as_str(),
                body,
                payload_digest,
            )))
            .await
            .unwrap();
    }

    let guest_child = ResourceRef::parse("Process/guest-child").unwrap();
    let sibling_child = ResourceRef::parse("Process/sibling-child").unwrap();
    for (operation_id, target, owner) in [
        ("owner-list-guest-child", guest_child.clone(), guest.clone()),
        ("owner-list-sibling-child", sibling_child, sibling.clone()),
    ] {
        store
            .commit_verified(issuer.seal(create_owned_seal_body(
                operation_id,
                target.clone(),
                owner.clone(),
                owned_process_body(target.name().as_str(), &owner),
            )))
            .await
            .unwrap();
    }

    let guest_uid = store
        .get(StoreGetRequest {
            operation: operation("owner-list-get"),
            zone: ZoneId::parse("work").unwrap(),
            target: guest,
            expected_uid: None,
            projection: StoreProjection::MetadataOnly,
        })
        .await
        .unwrap()
        .uid;

    let listed = store
        .list(StoreListRequest {
            operation: operation("owner-list"),
            zone: ZoneId::parse("work").unwrap(),
            resource_types: vec![ResourceTypeName::parse("Process").unwrap()],
            resource_names: Vec::new(),
            filters: vec![StoreFilter {
                field: "owner.resourceUid".to_owned(),
                values: vec![guest_uid.as_str().to_owned()],
            }],
            page_size: 10,
            cursor: None,
            projection: StoreProjection::Full,
        })
        .await
        .unwrap();
    assert_eq!(
        listed
            .resources
            .iter()
            .map(|resource| resource.resource_ref.clone())
            .collect::<Vec<_>>(),
        vec![guest_child.clone()]
    );

    let (_receipt, mut stream) = store
        .watch_stream(StoreWatchRequest {
            operation: operation("owner-watch"),
            zone: ZoneId::parse("work").unwrap(),
            resource_types: vec![ResourceTypeName::parse("Process").unwrap()],
            resource_names: Vec::new(),
            filters: vec![StoreFilter {
                field: "owner.resourceUid".to_owned(),
                values: vec![guest_uid.as_str().to_owned()],
            }],
            after_revision: ZoneRevision::new(0),
            initial_credits: 4,
            projection: StoreProjection::Full,
        })
        .await
        .unwrap();
    let batch = stream.recv().await.unwrap();
    assert_eq!(batch.entries().len(), 1);
    assert_eq!(
        batch.entries().next().unwrap().resource_name(),
        guest_child.name()
    );
    store
        .acknowledge_watch(stream.id(), batch.revision())
        .await
        .unwrap();
    assert_eq!(store.watch_signals().unwrap().budget_used, 0);
    store.unregister_watch(stream.id()).await.unwrap();
}

#[test]
fn persisted_dtos_reject_unknown_fields() {
    let mut value = serde_json::to_value(crate::transaction::StoreMeta {
        store_uuid: "11111111-1111-4111-8111-111111111111".to_owned(),
        zone_name: "work".to_owned(),
        zone_uid: "22222222-2222-4222-8222-222222222222".to_owned(),
        store_epoch: 1,
        created_at: "2026-07-31T00:00:00.000Z".to_owned(),
        schema_version: 1,
        current_revision: 0,
        compaction_floor: 0,
        active_configuration_revision: 9,
        policy_revision: 7,
        api_catalog_revision: 8,
        controller_generation: None,
        clean_shutdown: false,
        backup_generation: 0,
    })
    .unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("extra".to_owned(), serde_json::Value::Bool(true));
    let canonical = d2b_contracts_resource::v3::canonical_json_bytes(&value).unwrap();
    let framed = encode_value(ValueKind::StoreMetaScalar, &canonical).unwrap();
    let error = crate::transaction::decode::<crate::transaction::StoreMeta>(
        ValueKind::StoreMetaScalar,
        framed.as_bytes(),
    )
    .unwrap_err();
    assert_eq!(
        error.kind(),
        d2b_resource_store::StoreErrorKind::StoreIntegrityFailure
    );
}

#[test]
fn source_policy_pins_redb_features_and_forbids_reduced_durability_calls() {
    let manifest = include_str!("../Cargo.toml");
    assert!(manifest.contains("redb = { version = \"=4.1.0\", default-features = false }"));
    let sources = [
        include_str!("lib.rs"),
        include_str!("actor.rs"),
        include_str!("transaction.rs"),
    ];
    for source in sources {
        assert!(!source.contains("Durability::None"));
        assert!(!source.contains("Durability::Paranoid"));
        assert!(!source.contains("set_two_phase_commit"));
    }
    assert_eq!(
        include_str!("transaction.rs")
            .matches("set_durability(Durability::Immediate)")
            .count(),
        1
    );
}

#[test]
fn checked_mutation_constructors_and_raw_commit_path_are_not_public() {
    let source = include_str!("lib.rs");
    assert!(!source.contains("pub struct CheckedMutation"));
    assert!(!source.contains("pub struct CheckedPreparedMutation"));
    assert!(!source.contains("pub async fn commit_checked"));
    assert!(source.contains("pub struct RedbResourceStore"));
    assert!(source.contains("SealedMutation"));
    assert!(!source.contains("MutationView"));
    assert!(!source.contains("type_name"));
}

const PRODUCTION_RSS_RESOURCE_COUNT: usize = 10_000;
const PRODUCTION_RSS_WATCH_COUNT: usize = 100;
const PRODUCTION_RSS_THRESHOLD_KIB: u64 = 24_576;
const PRODUCTION_RSS_REVISION_BATCH_SIZE: usize =
    GROUP_COMMIT_MAX * d2b_contracts_resource::v3::MAX_BATCH_MUTATIONS;
const PRODUCTION_RSS_CHILD_ENV: &str = "D2B_REDB_PRODUCTION_RSS_CHILD";
const PRODUCTION_RSS_FIXTURE_ENV: &str = "D2B_REDB_PRODUCTION_RSS_FIXTURE";
const PRODUCTION_RSS_CHILD_MARKER: &str = "PRODUCTION_REDB_FIXTURE";

#[test]
#[ignore = "run the whole-process production RSS fixture through the public heavy gate"]
fn production_backend_hard_fixture_rss() {
    if std::env::var_os(PRODUCTION_RSS_CHILD_ENV).is_some() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("production RSS child runtime");
        runtime.block_on(production_backend_hard_fixture_child());
        return;
    }

    let executable = std::env::current_exe().expect("production RSS test executable");
    let mut raw_runs = Vec::with_capacity(3);
    for run in 1..=3 {
        let fixture = prepare_production_rss_fixture();
        let output = Command::new(gnu_time_program())
            .args([
                "-v",
                executable.to_str().expect("test executable is UTF-8"),
                "--exact",
                "tests::production_backend_hard_fixture_rss",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(PRODUCTION_RSS_CHILD_ENV, "1")
            .env(
                PRODUCTION_RSS_FIXTURE_ENV,
                fixture.path().to_str().expect("fixture path is UTF-8"),
            )
            .output()
            .expect("GNU time is required for the production RSS fixture");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "production RSS child failed (run {run}):\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        assert!(
            stdout.contains(&format!(
                "{PRODUCTION_RSS_CHILD_MARKER} resources={PRODUCTION_RSS_RESOURCE_COUNT} watches={PRODUCTION_RSS_WATCH_COUNT}"
            )),
            "production RSS child did not report the hard fixture (run {run}):\n{stdout}"
        );
        for line in stdout.lines() {
            if line.contains(PRODUCTION_RSS_CHILD_MARKER) {
                println!("production fixture signals run {run}: {line}");
            }
        }
        let rss = parse_maximum_rss_kib(&stderr);
        assert!(
            rss <= PRODUCTION_RSS_THRESHOLD_KIB,
            "production whole-process RSS run {run} was {rss} KiB, above the unchanged {PRODUCTION_RSS_THRESHOLD_KIB} KiB threshold"
        );
        println!("production whole-process RSS run {run}: {rss} KiB");
        raw_runs.push(rss);
    }

    raw_runs.sort_unstable();
    let median = raw_runs[1];
    assert!(
        median <= PRODUCTION_RSS_THRESHOLD_KIB,
        "production whole-process RSS median was {median} KiB, above the unchanged {PRODUCTION_RSS_THRESHOLD_KIB} KiB threshold"
    );
    println!(
        "production whole-process RSS raw runs: {:?}; median: {median} KiB; threshold: {PRODUCTION_RSS_THRESHOLD_KIB} KiB; baseline subtraction: none",
        raw_runs
    );
}

fn parse_maximum_rss_kib(stderr: &str) -> u64 {
    const FIELD: &str = "Maximum resident set size (kbytes):";
    stderr
        .lines()
        .find_map(|line| {
            let value = line
                .find(FIELD)
                .map(|offset| &line[offset + FIELD.len()..])?;
            value.trim().parse::<u64>().ok()
        })
        .expect("GNU time did not report whole-process maximum RSS")
}

fn gnu_time_program() -> String {
    if let Some(program) = std::env::var_os("D2B_GNU_TIME") {
        return program.to_string_lossy().into_owned();
    }
    for candidate in [
        "/usr/bin/time",
        "/bin/time",
        "/run/current-system/sw/bin/time",
    ] {
        if std::path::Path::new(candidate).is_file() {
            return candidate.to_owned();
        }
    }
    "time".to_owned()
}

fn prepare_production_rss_fixture() -> tempfile::TempDir {
    let (directory, file) = owned_file();
    drop(file);
    let store_identity = identity();
    let mut marker = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(directory.path().join("store.marker"))
        .expect("production RSS fixture marker");
    write_provisioning_marker(&mut marker, &store_identity)
        .expect("production RSS fixture marker write");

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join("store.redb"))
        .expect("production RSS fixture database");
    let backend = redb::backends::FileBackend::new(file).expect("production RSS fixture backend");
    let database = Database::builder()
        .create_with_backend(backend)
        .expect("production RSS fixture database create");
    crate::transaction::initialize(&database, &store_identity)
        .expect("production RSS fixture initialization");

    let mut write = database
        .begin_write()
        .expect("production RSS fixture write transaction");
    crate::transaction::set_full_durability(&mut write).expect("production RSS fixture durability");
    {
        let mut resources = write
            .open_table(crate::transaction::RESOURCES)
            .expect("production RSS fixture resources table");
        for index in 0..PRODUCTION_RSS_RESOURCE_COUNT {
            let (target, _, canonical, payload_digest) = hard_seed_resource(index);
            let record = crate::transaction::ResourceRecord {
                canonical_json: canonical,
                owner_uid: None,
                controller_binding_id: "Provider/system-core".to_owned(),
                payload_digest,
                assignment: None,
            };
            let value = crate::transaction::encode(ValueKind::ResourceRecord, &record)
                .expect("production RSS fixture resource encoding");
            resources
                .insert(
                    crate::transaction::resource_key(&target)
                        .expect("production RSS fixture resource key")
                        .as_slice(),
                    value.as_slice(),
                )
                .expect("production RSS fixture resource row");
        }
    }
    {
        let mut type_index = write
            .open_table(crate::transaction::TYPE_INDEX)
            .expect("production RSS fixture type index table");
        for index in 0..PRODUCTION_RSS_RESOURCE_COUNT {
            let (target, uid, _, _) = hard_seed_resource(index);
            let value = crate::transaction::encode(ValueKind::TypeIndexRecord, &uid.as_str())
                .expect("production RSS fixture type-index encoding");
            type_index
                .insert(
                    crate::transaction::type_index_key(&target)
                        .expect("production RSS fixture type-index key")
                        .as_slice(),
                    value.as_slice(),
                )
                .expect("production RSS fixture type-index row");
        }
    }
    {
        let mut controller_index = write
            .open_table(crate::transaction::CONTROLLER_INDEX)
            .expect("production RSS fixture controller index table");
        for index in 0..PRODUCTION_RSS_RESOURCE_COUNT {
            let (target, uid, _, _) = hard_seed_resource(index);
            let key = crate::encode_key(
                KeySpace::ControllerIndex,
                &[
                    KeyComponent::Text("Provider/system-core"),
                    KeyComponent::Text("Host"),
                    KeyComponent::Text(target.name().as_str()),
                ],
            )
            .expect("production RSS fixture controller-index key");
            let value = crate::transaction::encode(ValueKind::ControllerIndexRecord, &uid.as_str())
                .expect("production RSS fixture controller-index encoding");
            controller_index
                .insert(key.as_bytes(), value.as_slice())
                .expect("production RSS fixture controller-index row");
        }
    }
    {
        let mut revisions = write
            .open_table(crate::transaction::REVISION_LOG)
            .expect("production RSS fixture revision table");
        for (batch_index, batch_start) in (0..PRODUCTION_RSS_RESOURCE_COUNT)
            .step_by(PRODUCTION_RSS_REVISION_BATCH_SIZE)
            .enumerate()
        {
            let batch_end = (batch_start + PRODUCTION_RSS_REVISION_BATCH_SIZE)
                .min(PRODUCTION_RSS_RESOURCE_COUNT);
            let entries = (batch_start..batch_end)
                .enumerate()
                .map(|(ordinal, index)| {
                    let (target, uid, _, payload_digest) = hard_seed_resource(index);
                    ChangeEntry::new(
                        u32::try_from(ordinal).expect("production RSS fixture ordinal"),
                        ResourceTypeName::parse("Host").unwrap(),
                        target.name().clone(),
                        uid,
                        ChangeEvent::Created,
                        None,
                        Some(d2b_contracts_resource::v3::ResourceGeneration::new(1).unwrap()),
                        None,
                        payload_digest,
                        None,
                        "production-seed-operation".to_owned(),
                        "production-seed-correlation".to_owned(),
                    )
                    .expect("production RSS fixture change entry")
                })
                .collect();
            let batch = ChangeBatch::new(
                d2b_contracts_resource::v3::ZoneRevision::new((batch_index + 1) as u64),
                entries,
            )
            .expect("production RSS fixture change batch");
            let value = crate::transaction::encode(ValueKind::ChangeBatch, &batch)
                .expect("production RSS fixture revision encoding");
            revisions
                .insert(
                    crate::transaction::revision_key((batch_index + 1) as u64)
                        .expect("production RSS fixture revision key")
                        .as_slice(),
                    value.as_slice(),
                )
                .expect("production RSS fixture revision row");
        }
    }
    let mut meta =
        crate::transaction::current_meta(&database).expect("production RSS fixture metadata");
    meta.current_revision =
        PRODUCTION_RSS_RESOURCE_COUNT.div_ceil(PRODUCTION_RSS_REVISION_BATCH_SIZE) as u64;
    meta.clean_shutdown = true;
    let meta_value = crate::transaction::encode(ValueKind::StoreMetaScalar, &meta)
        .expect("production RSS fixture metadata encoding");
    write
        .open_table(crate::transaction::STORE_META)
        .expect("production RSS fixture metadata table")
        .insert(
            crate::transaction::meta_key().as_slice(),
            meta_value.as_slice(),
        )
        .expect("production RSS fixture metadata row");
    write
        .commit()
        .expect("production RSS fixture transaction commit");
    crate::transaction::validate_consistency(&database)
        .expect("production RSS fixture consistency");
    directory
}

fn hard_seed_resource(index: usize) -> (ResourceRef, ResourceUid, Vec<u8>, String) {
    let name = format!("hard-host-{index:05}");
    let uid = ResourceUid::parse(format!("123e4567-e89b-42d3-a456-{index:012x}"))
        .expect("production RSS fixture UID");
    let canonical = String::from_utf8(stored_body(&name))
        .expect("production RSS fixture resource UTF-8")
        .replace("123e4567-e89b-42d3-a456-426614174000", uid.as_str())
        .into_bytes();
    let envelope =
        ResourceEnvelope::from_json(&canonical).expect("production RSS fixture envelope");
    let payload_digest = envelope
        .digest()
        .expect("production RSS fixture payload digest");
    (
        ResourceRef::parse(&format!("Host/{name}")).expect("production RSS fixture resource ref"),
        uid,
        canonical,
        payload_digest,
    )
}

async fn production_backend_hard_fixture_child() {
    let fixture = std::env::var(PRODUCTION_RSS_FIXTURE_ENV).expect("production RSS fixture path");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(std::path::Path::new(&fixture).join("store.redb"))
        .expect("production RSS fixture database open");
    let store_identity = identity();
    let (issuer, acceptor) = mutation_seal_pair(store_identity.seal_identity());
    let store = Arc::new(
        RedbResourceStore::open_owned(file, store_identity, acceptor)
            .await
            .expect("production backend hard fixture store"),
    );
    let issuer = Arc::new(issuer);
    let mut current_revision =
        PRODUCTION_RSS_RESOURCE_COUNT.div_ceil(PRODUCTION_RSS_REVISION_BATCH_SIZE) as u64;

    assert_eq!(WRITE_QUEUE_CAPACITY, 256);
    assert_eq!(GROUP_COMMIT_MAX, 16);
    assert_eq!(READ_POOL_THREADS, 4);
    assert_eq!(MAX_CONCURRENT_READS, 16);
    assert_eq!(READ_LIFETIME, std::time::Duration::from_millis(250));
    let listed = store
        .list(StoreListRequest {
            operation: operation("production-hard-list"),
            zone: ZoneId::parse("work").unwrap(),
            resource_types: vec![ResourceTypeName::parse("Host").unwrap()],
            resource_names: Vec::new(),
            filters: Vec::new(),
            page_size: 1,
            cursor: None,
            projection: StoreProjection::MetadataOnly,
        })
        .await
        .expect("production backend hard fixture list");
    assert_eq!(listed.resources.len(), 1);
    while store.reads.available_permits() != MAX_CONCURRENT_READS {
        tokio::task::yield_now().await;
    }
    assert_eq!(store.reads.available_permits(), MAX_CONCURRENT_READS);

    let backend_before_replay = store.signals();
    let replay_batches = Arc::new(AtomicU64::new(0));
    let replay_entries = Arc::new(AtomicU64::new(0));
    let replay_batches_for_visit = Arc::clone(&replay_batches);
    let replay_entries_for_visit = Arc::clone(&replay_entries);
    store
        .replay_backend(
            d2b_contracts_resource::v3::ZoneRevision::new(current_revision.saturating_sub(1)).get(),
            [ResourceTypeName::parse("Host").unwrap()],
            move |batch| {
                replay_batches_for_visit.fetch_add(1, Ordering::Relaxed);
                replay_entries_for_visit.fetch_add(
                    u64::try_from(batch.entries().len()).expect("replay entry count"),
                    Ordering::Relaxed,
                );
                Ok(())
            },
        )
        .await
        .expect("production backend hard fixture replay");
    let backend_after_replay = store.signals();
    assert_eq!(
        backend_after_replay.revision_range_seeks - backend_before_replay.revision_range_seeks,
        1
    );
    assert_eq!(
        backend_after_replay.replay_rows_scanned - backend_before_replay.replay_rows_scanned,
        1
    );
    assert_eq!(
        backend_after_replay.replay_rows_decoded - backend_before_replay.replay_rows_decoded,
        1
    );
    assert_eq!(replay_batches.load(Ordering::Relaxed), 1);
    assert!(replay_entries.load(Ordering::Relaxed) > 0);

    let (replay_receipt, mut replay_stream) = store
        .watch_stream(StoreWatchRequest {
            operation: operation("production-hard-replay-watch"),
            zone: ZoneId::parse("work").unwrap(),
            resource_types: vec![ResourceTypeName::parse("Host").unwrap()],
            resource_names: Vec::new(),
            filters: Vec::new(),
            after_revision: d2b_contracts_resource::v3::ZoneRevision::new(current_revision - 1),
            initial_credits: 2,
            projection: StoreProjection::Full,
        })
        .await
        .expect("production watch replay registration");
    let replay_batch = replay_stream
        .recv()
        .await
        .expect("production watch replay delivery");
    assert_eq!(replay_batch.revision(), replay_receipt.snapshot_revision);
    store
        .acknowledge_watch(replay_stream.id(), replay_receipt.snapshot_revision)
        .await
        .expect("production watch replay acknowledgement");
    assert_eq!(
        store
            .watch_signals()
            .expect("production watch replay signals")
            .replay_work,
        1
    );
    store
        .unregister_watch(replay_stream.id())
        .await
        .expect("production watch replay unregister");

    let mut watchers = Vec::with_capacity(PRODUCTION_RSS_WATCH_COUNT);
    for index in 0..PRODUCTION_RSS_WATCH_COUNT {
        let (receipt, stream) = store
            .watch_stream(StoreWatchRequest {
                operation: operation(&format!("production-hard-watch-{index:03}")),
                zone: ZoneId::parse("work").unwrap(),
                resource_types: vec![ResourceTypeName::parse("Host").unwrap()],
                resource_names: Vec::new(),
                filters: Vec::new(),
                after_revision: d2b_contracts_resource::v3::ZoneRevision::new(current_revision),
                initial_credits: 2,
                projection: StoreProjection::Full,
            })
            .await
            .expect("production watch hard fixture registration");
        assert_eq!(
            receipt.snapshot_revision,
            d2b_contracts_resource::v3::ZoneRevision::new(current_revision)
        );
        watchers.push(stream);
    }
    let registered = store
        .watch_signals()
        .expect("production watch registration signals");
    assert_eq!(
        registered.current_registrations,
        PRODUCTION_RSS_WATCH_COUNT as u64
    );
    assert_eq!(registered.budget_used, 0);
    assert_eq!(registered.budget_capacity, WATCH_ADMISSION_CAPACITY as u64);

    let backend_before_fanout = store.signals();
    let fanout_commit =
        commit_fixture_resource(&store, &issuer, "production-hard-fanout", "hard-fanout").await;
    let mut shared_batch: Option<SharedChangeBatch> = None;
    for watcher in &mut watchers {
        let batch = watcher
            .recv()
            .await
            .expect("production watch hard fixture fan-out delivery");
        assert_eq!(batch.revision(), fanout_commit.revision);
        if let Some(first) = &shared_batch {
            assert!(first.shares_batch_with(&batch));
        } else {
            shared_batch = Some(batch);
        }
    }
    let after_fanout = store.watch_signals().expect("production fan-out signals");
    assert_eq!(after_fanout.budget_used, PRODUCTION_RSS_WATCH_COUNT as u64);
    assert_eq!(
        after_fanout.current_registrations,
        PRODUCTION_RSS_WATCH_COUNT as u64
    );
    let backend_after_fanout = store.signals();
    assert_eq!(
        backend_after_fanout.shared_immutable_batches
            - backend_before_fanout.shared_immutable_batches,
        1
    );
    assert_eq!(
        backend_after_fanout.fanout_references - backend_before_fanout.fanout_references,
        PRODUCTION_RSS_WATCH_COUNT as u64
    );
    assert_eq!(backend_after_fanout.writer_queue_depth, 0);
    current_revision = fanout_commit.revision.get();

    for watcher in watchers.drain(..) {
        let id = watcher.id();
        store
            .acknowledge_watch(id, fanout_commit.revision)
            .await
            .expect("production watch hard fixture acknowledgement");
        store
            .unregister_watch(id)
            .await
            .expect("production watch hard fixture unregister");
    }
    assert_eq!(
        store
            .watch_signals()
            .expect("production watch post-fan-out signals")
            .budget_used,
        0
    );

    let rejected = store
        .watch_stream(StoreWatchRequest {
            operation: operation("production-hard-rejected-watch"),
            zone: ZoneId::parse("work").unwrap(),
            resource_types: vec![ResourceTypeName::parse("Host").unwrap()],
            resource_names: Vec::new(),
            filters: Vec::new(),
            after_revision: d2b_contracts_resource::v3::ZoneRevision::new(current_revision),
            initial_credits: 0,
            projection: StoreProjection::Full,
        })
        .await
        .expect_err("zero-credit production watch must be rejected");
    assert_eq!(
        rejected.kind(),
        d2b_resource_store::StoreErrorKind::StoreBackpressure
    );

    let slow_start = current_revision;
    let (_slow_receipt, slow_stream) = store
        .watch_stream(StoreWatchRequest {
            operation: operation("production-hard-slow-watch"),
            zone: ZoneId::parse("work").unwrap(),
            resource_types: vec![ResourceTypeName::parse("Host").unwrap()],
            resource_names: Vec::new(),
            filters: Vec::new(),
            after_revision: d2b_contracts_resource::v3::ZoneRevision::new(slow_start),
            initial_credits: 1,
            projection: StoreProjection::Full,
        })
        .await
        .expect("production slow watch registration");
    let slow_id = slow_stream.id();
    let _slow_first = commit_fixture_resource(
        &store,
        &issuer,
        "production-hard-slow-first",
        "hard-slow-first",
    )
    .await;
    let _slow_second = commit_fixture_resource(
        &store,
        &issuer,
        "production-hard-slow-second",
        "hard-slow-second",
    )
    .await;
    let watch_signals = store.watch_signals().expect("production watch signals");
    assert!(watch_signals.admission_rejections >= 1);
    assert!(watch_signals.slow_watcher_evictions >= 1);
    assert_eq!(watch_signals.current_registrations, 0);
    assert_eq!(watch_signals.budget_used, 0);
    assert_eq!(
        store
            .watch_coordinator
            .lock()
            .expect("production watch coordinator")
            .take_resume_cursor(slow_id),
        Some(d2b_contracts_resource::v3::ZoneRevision::new(slow_start))
    );
    assert_eq!(store.signals().writer_queue_depth, 0);

    let backend_signals = store.signals();
    println!(
        "{PRODUCTION_RSS_CHILD_MARKER} resources={PRODUCTION_RSS_RESOURCE_COUNT} watches={PRODUCTION_RSS_WATCH_COUNT} range_seeks={} scanned_rows={} decoded_rows={} shared_batches={} fanout_references={} queue_depth={} queue_capacity={} read_pool_threads={} max_concurrent_reads={} cache_bytes={} watch_registrations={} watch_budget_used={} watch_budget_capacity={} slow_watcher_evictions={} admission_rejections={} replay_work={}",
        backend_signals.revision_range_seeks,
        backend_signals.replay_rows_scanned,
        backend_signals.replay_rows_decoded,
        backend_signals.shared_immutable_batches,
        backend_signals.fanout_references,
        backend_signals.writer_queue_depth,
        backend_signals.writer_queue_capacity,
        READ_POOL_THREADS,
        MAX_CONCURRENT_READS,
        REDB_CACHE_SIZE,
        watch_signals.current_registrations,
        watch_signals.budget_used,
        watch_signals.budget_capacity,
        watch_signals.slow_watcher_evictions,
        watch_signals.admission_rejections,
        watch_signals.replay_work,
    );
    drop(slow_stream);
    drop(replay_stream);
    drop(issuer);
    let store = Arc::try_unwrap(store).expect("production hard fixture store references");
    store
        .shutdown()
        .await
        .expect("production hard fixture store shutdown");
}

async fn commit_fixture_resource(
    store: &RedbResourceStore,
    issuer: &d2b_resource_store::mutation_seal::MutationSealIssuer,
    operation_id: &str,
    name: &str,
) -> d2b_resource_store::StoreCommitResult {
    let canonical = create_body(name);
    let payload_digest = canonical_digest(RESOURCE_ENVELOPE_DOMAIN_TAG, &canonical);
    store
        .commit_verified(issuer.seal(create_seal_body_with_resource(
            operation_id,
            name,
            canonical,
            payload_digest,
        )))
        .await
        .expect("production fixture mutation")
}

#[tokio::test]
async fn authority_operation_lifecycle_is_durable_and_restart_visible() {
    let (directory, file, marker) = provisioned_store();
    let identity = identity();
    let store = std::sync::Arc::new(
        provision_store(file, marker, identity.clone())
            .await
            .unwrap(),
    );
    let claim_digest = "sha256:".to_owned() + &"0".repeat(64);
    let binding_digest = store.authority_binding_digest(&claim_digest);
    let payload = serde_json::to_vec(&serde_json::json!({
        "operationId": "authority-owner",
        "claim": "opaque",
        "state": "pending",
        "claimDigest": claim_digest.clone(),
        "storeBindingDigest": binding_digest.clone(),
    }))
    .unwrap();
    let capability = store
        .prepare_authority_operation("authority-owner".to_owned(), payload, &claim_digest)
        .await
        .unwrap();
    let duplicate_payload = serde_json::to_vec(&serde_json::json!({
        "operationId": "authority-owner",
        "claim": "opaque",
        "state": "pending",
        "claimDigest": claim_digest.clone(),
        "storeBindingDigest": store.authority_binding_digest(&claim_digest),
    }))
    .unwrap();
    store
        .prepare_authority_operation(
            "authority-owner".to_owned(),
            duplicate_payload,
            &claim_digest,
        )
        .await
        .expect("same accepted operation is idempotent");
    capability
        .record_effect(AuthorityOperationState::EffectConfirmed)
        .await
        .unwrap();
    drop(capability);
    std::sync::Arc::try_unwrap(store)
        .unwrap()
        .shutdown()
        .await
        .unwrap();

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join("store.redb"))
        .unwrap();
    let reopened = std::sync::Arc::new(open_store(file, identity).await.unwrap());
    let rows = reopened.authority_operations().await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].operation_id, "authority-owner");
    let payload: serde_json::Value = serde_json::from_slice(&rows[0].payload).unwrap();
    assert_eq!(
        payload.get("state").and_then(serde_json::Value::as_str),
        Some("effect-confirmed")
    );
    assert_eq!(rows[0].state, AuthorityOperationState::EffectConfirmed);

    let capability = reopened
        .resume_authority_operation("authority-owner".to_owned(), &binding_digest)
        .await
        .unwrap();
    capability.record_close().await.unwrap();
    capability.release().await.unwrap();
    let released = reopened.authority_operations().await.unwrap();
    assert_eq!(released[0].state, AuthorityOperationState::Released);
    let closed_payload = serde_json::to_vec(&serde_json::json!({
        "operationId": "authority-owner",
        "claim": "opaque",
        "state": "pending",
        "claimDigest": claim_digest.clone(),
        "storeBindingDigest": binding_digest.clone(),
    }))
    .unwrap();
    assert_eq!(
        reopened
            .prepare_authority_operation(
                "authority-owner".to_owned(),
                closed_payload,
                &claim_digest
            )
            .await
            .unwrap_err()
            .kind(),
        d2b_resource_store::StoreErrorKind::ResourceConflict
    );
    drop(capability);
    std::sync::Arc::try_unwrap(reopened)
        .unwrap()
        .shutdown()
        .await
        .unwrap();
}
