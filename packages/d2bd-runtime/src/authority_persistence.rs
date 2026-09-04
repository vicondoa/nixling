//! Durable Host-global authority operation ownership.
//!
//! The Zone redb store owns the bytes and commit boundary. Core owns the
//! typed row and recovery validation. Only this adapter can turn storage rows
//! into the private receipt consumed by `HostGlobalAuthorityIndex`.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use crate::zone_authority::ZONE_GENERATION_PUBLICATION_OPERATION_PREFIX;
use d2b_contracts_resource::v3::ResourceUid;
use d2b_core_controller::authority::{
    AuthorityOperationState, AuthorityStorageClaim, AuthorityStorageOperation,
    ExternalNicRecoveryInventory, claim_digest,
};
use d2b_core_controller::authority_persistence::{
    AuthorityFuture, AuthorityOperationCapability, AuthorityPersistence, AuthorityPersistenceError,
    AuthorityRecoveryData, AuthorityRecoveryProvenance, PreparedAuthorityOperation,
};
use d2b_resource_store::{StoreOperationContext, StoreResolveRequest};
use d2b_resource_store_redb::{
    AuthorityOperation, AuthorityOperationState as StoreAuthorityOperationState, RedbResourceStore,
};

/// Production authority persistence owner for one Zone redb store.
pub struct RedbAuthorityPersistence {
    store: Arc<RedbResourceStore>,
    operation_capabilities:
        Mutex<BTreeMap<String, Arc<d2b_resource_store_redb::AuthorityOperationCapability>>>,
    external_inventory: Option<Arc<dyn ExternalNicRecoveryInventory>>,
}

impl core::fmt::Debug for RedbAuthorityPersistence {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("RedbAuthorityPersistence(<store-bound>)")
    }
}

impl RedbAuthorityPersistence {
    /// Bind the port to the already opened, broker-owned Zone store.
    pub fn new(store: Arc<RedbResourceStore>) -> Self {
        Self {
            store,
            operation_capabilities: Mutex::new(BTreeMap::new()),
            external_inventory: None,
        }
    }

    pub fn with_external_inventory(
        mut self,
        inventory: Arc<dyn ExternalNicRecoveryInventory>,
    ) -> Self {
        self.external_inventory = Some(inventory);
        self
    }
}

impl AuthorityPersistence for RedbAuthorityPersistence {
    fn prepare<'a>(
        &'a self,
        operation_id: &'a str,
        claim: &'a AuthorityStorageClaim,
    ) -> AuthorityFuture<'a, PreparedAuthorityOperation> {
        Box::pin(async move {
            let claim_digest =
                claim_digest(claim).map_err(|_| AuthorityPersistenceError::RowInvalid)?;
            let owner_ref_present = match claim {
                AuthorityStorageClaim::Generic(claim) => {
                    claim.owner_proof().resource_ref().is_some()
                }
                AuthorityStorageClaim::ExternalNic(claim) => {
                    claim.owner_proof().resource_ref().is_some()
                }
            };
            if !owner_ref_present {
                return Err(AuthorityPersistenceError::RowInvalid);
            }
            let binding_digest = self.store.authority_binding_digest(&claim_digest);
            let row = AuthorityStorageOperation {
                operation_id: operation_id.to_owned(),
                claim: claim.clone(),
                state: AuthorityOperationState::Pending,
                claim_digest: claim_digest.clone(),
                store_binding_digest: binding_digest.clone(),
            };
            AuthorityRecoveryProvenance::validate(self, &row).await?;
            let payload =
                serde_json::to_vec(&row).map_err(|_| AuthorityPersistenceError::RowInvalid)?;
            let capability = self
                .store
                .prepare_authority_operation(operation_id.to_owned(), payload, &claim_digest)
                .await
                .map_err(|_| AuthorityPersistenceError::CommitUnknown)?;
            let nonce = capability.nonce();
            self.operation_capabilities
                .lock()
                .map_err(|_| AuthorityPersistenceError::StateInvalid)?
                .insert(operation_id.to_owned(), Arc::new(capability));
            PreparedAuthorityOperation::new(operation_id.to_owned(), binding_digest, nonce)
        })
    }

    fn record_effect<'a>(
        &'a self,
        capability: &'a AuthorityOperationCapability,
        state: AuthorityOperationState,
    ) -> AuthorityFuture<'a, ()> {
        Box::pin(async move {
            let state = match state {
                AuthorityOperationState::Pending => StoreAuthorityOperationState::Pending,
                AuthorityOperationState::EffectConfirmed => {
                    StoreAuthorityOperationState::EffectConfirmed
                }
                AuthorityOperationState::EffectRetryable => {
                    StoreAuthorityOperationState::EffectRetryable
                }
                AuthorityOperationState::EffectTerminal => {
                    StoreAuthorityOperationState::EffectTerminal
                }
                AuthorityOperationState::Closing => StoreAuthorityOperationState::Closing,
                AuthorityOperationState::Closed | AuthorityOperationState::Released => {
                    return Err(AuthorityPersistenceError::StateInvalid);
                }
            };
            let store_capability = self.validate_capability(capability)?;
            store_capability
                .record_effect(state)
                .await
                .map_err(|_| AuthorityPersistenceError::StoreUnavailable)
        })
    }

    fn record_close<'a>(
        &'a self,
        capability: &'a AuthorityOperationCapability,
    ) -> AuthorityFuture<'a, ()> {
        Box::pin(async move {
            let store_capability = self.validate_capability(capability)?;
            store_capability
                .record_close()
                .await
                .map_err(|_| AuthorityPersistenceError::StoreUnavailable)
        })
    }

    fn release<'a>(
        &'a self,
        capability: &'a AuthorityOperationCapability,
    ) -> AuthorityFuture<'a, ()> {
        Box::pin(async move {
            let store_capability = self.validate_capability(capability)?;
            store_capability
                .release()
                .await
                .map_err(|_| AuthorityPersistenceError::StoreUnavailable)?;
            self.operation_capabilities
                .lock()
                .map_err(|_| AuthorityPersistenceError::StateInvalid)?
                .remove(capability.operation_id());
            Ok(())
        })
    }

    fn recover<'a>(&'a self) -> AuthorityFuture<'a, AuthorityRecoveryData> {
        Box::pin(async move {
            let rows = self
                .store
                .authority_operations()
                .await
                .map_err(|_| AuthorityPersistenceError::StoreUnavailable)?;
            recovery_receipt(rows, &self.store, &self.operation_capabilities).await
        })
    }
}

impl AuthorityRecoveryProvenance for RedbAuthorityPersistence {
    fn validate<'a>(&'a self, operation: &'a AuthorityStorageOperation) -> AuthorityFuture<'a, ()> {
        Box::pin(async move {
            let claim_digest = claim_digest(&operation.claim)
                .map_err(|_| AuthorityPersistenceError::RowInvalid)?;
            if claim_digest != operation.claim_digest
                || self.store.authority_binding_digest(&claim_digest)
                    != operation.store_binding_digest
            {
                return Err(AuthorityPersistenceError::RowInvalid);
            }
            if !matches!(
                operation.state,
                AuthorityOperationState::Closed | AuthorityOperationState::Released
            ) {
                let owner_proof = match &operation.claim {
                    AuthorityStorageClaim::Generic(claim) => claim.owner_proof(),
                    AuthorityStorageClaim::ExternalNic(claim) => claim.owner_proof(),
                };
                let Some(owner_ref) = owner_proof.resource_ref() else {
                    return Err(AuthorityPersistenceError::RowInvalid);
                };
                let resolved = self
                    .store
                    .resolve_ref(StoreResolveRequest {
                        operation: StoreOperationContext {
                            operation_id: format!("authority-recovery:{}", operation.operation_id),
                            idempotency_key: None,
                            correlation_id: "authority-recovery".to_owned(),
                            trace_id: None,
                            deadline_ms: 1,
                        },
                        zone: self.store.identity().zone().clone(),
                        target: owner_ref.clone(),
                        expected_uid: Some(owner_proof.resource_uid().clone()),
                    })
                    .await
                    .map_err(|_| AuthorityPersistenceError::RowInvalid)?;
                if resolved.uid != *owner_proof.resource_uid()
                    || resolved.generation != owner_proof.generation()
                {
                    return Err(AuthorityPersistenceError::RowInvalid);
                }
            }
            if !matches!(
                operation.state,
                AuthorityOperationState::Closed | AuthorityOperationState::Released
            ) && matches!(operation.claim, AuthorityStorageClaim::ExternalNic(_))
            {
                let AuthorityStorageClaim::ExternalNic(claim) = &operation.claim else {
                    unreachable!();
                };
                let Some(inventory) = &self.external_inventory else {
                    return Err(AuthorityPersistenceError::RowInvalid);
                };
                if !inventory.contains_identity(claim.host_uid(), claim.identity_digest()) {
                    return Err(AuthorityPersistenceError::RowInvalid);
                }
            }
            Ok(())
        })
    }
}

impl RedbAuthorityPersistence {
    fn validate_capability(
        &self,
        capability: &AuthorityOperationCapability,
    ) -> Result<Arc<d2b_resource_store_redb::AuthorityOperationCapability>, AuthorityPersistenceError>
    {
        let store_capability = self
            .operation_capabilities
            .lock()
            .map_err(|_| AuthorityPersistenceError::StateInvalid)?
            .get(capability.operation_id())
            .cloned()
            .ok_or(AuthorityPersistenceError::StateInvalid)?;
        if capability.store_binding_digest().is_empty()
            || capability.nonce() != store_capability.nonce()
            || !store_capability.matches_binding_digest(capability.store_binding_digest())
        {
            return Err(AuthorityPersistenceError::StateInvalid);
        }
        Ok(store_capability)
    }
}

async fn recovery_receipt(
    rows: Vec<AuthorityOperation>,
    store: &Arc<RedbResourceStore>,
    operation_capabilities: &Mutex<
        BTreeMap<String, Arc<d2b_resource_store_redb::AuthorityOperationCapability>>,
    >,
) -> Result<AuthorityRecoveryData, AuthorityPersistenceError> {
    let mut operations = Vec::new();
    let mut prepared_operations = BTreeMap::new();
    let mut operation_ids = std::collections::BTreeSet::new();

    for row in rows {
        // The all-Zone publication marker shares the store's durable
        // operation transaction but is not a Host-global authority claim.
        if is_zone_generation_publication(&row) || is_controller_effect_operation(&row) {
            continue;
        }
        if !operation_ids.insert(row.operation_id.clone()) {
            return Err(AuthorityPersistenceError::RowInvalid);
        }
        let mut stored: AuthorityStorageOperation = serde_json::from_slice(&row.payload)
            .map_err(|_| AuthorityPersistenceError::RowInvalid)?;
        if stored.operation_id != row.operation_id {
            return Err(AuthorityPersistenceError::RowInvalid);
        }
        if stored.store_binding_digest != store.authority_binding_digest(&stored.claim_digest) {
            return Err(AuthorityPersistenceError::RowInvalid);
        }
        // The redb lifecycle column is the authoritative state. The payload
        // is an untrusted claim envelope and older physical rows may carry
        // the prepare-time state, so never let it override the committed
        // transition.
        stored.state = match row.state {
            StoreAuthorityOperationState::Pending => AuthorityOperationState::Pending,
            StoreAuthorityOperationState::EffectConfirmed => {
                AuthorityOperationState::EffectConfirmed
            }
            StoreAuthorityOperationState::EffectRetryable => {
                AuthorityOperationState::EffectRetryable
            }
            StoreAuthorityOperationState::EffectTerminal => AuthorityOperationState::EffectTerminal,
            StoreAuthorityOperationState::Closing => AuthorityOperationState::Closing,
            StoreAuthorityOperationState::Closed => AuthorityOperationState::Closed,
            StoreAuthorityOperationState::Released => AuthorityOperationState::Released,
        };
        if !matches!(
            stored.state,
            AuthorityOperationState::Closed | AuthorityOperationState::Released
        ) {
            let store_capability = store
                .resume_authority_operation(
                    stored.operation_id.clone(),
                    &stored.store_binding_digest,
                )
                .await
                .map_err(|_| AuthorityPersistenceError::RowInvalid)?;
            let nonce = store_capability.nonce();
            operation_capabilities
                .lock()
                .map_err(|_| AuthorityPersistenceError::StateInvalid)?
                .insert(stored.operation_id.clone(), Arc::new(store_capability));
            let prepared = PreparedAuthorityOperation::new(
                stored.operation_id.clone(),
                stored.store_binding_digest.clone(),
                nonce,
            )?;
            prepared_operations.insert(stored.operation_id.clone(), prepared);
        }
        operations.push(stored);
    }

    Ok(AuthorityRecoveryData::new(operations, prepared_operations))
}

fn is_zone_generation_publication(row: &AuthorityOperation) -> bool {
    row.operation_id
        .starts_with(ZONE_GENERATION_PUBLICATION_OPERATION_PREFIX)
        && serde_json::from_slice::<serde_json::Value>(&row.payload)
            .ok()
            .is_some_and(|value| {
                value.get("publication").and_then(serde_json::Value::as_str)
                    == Some("zone-resource-plane")
            })
}

fn is_controller_effect_operation(row: &AuthorityOperation) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&row.payload) else {
        return false;
    };
    value.get("version").and_then(serde_json::Value::as_u64) == Some(1)
        && value.get("kind").and_then(serde_json::Value::as_str) == Some("controller-effect")
        && value
            .get("state")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|state| {
                matches!(
                    state,
                    "pending"
                        | "effect-confirmed"
                        | "effect-retryable"
                        | "effect-terminal"
                        | "closing"
                        | "closed"
                        | "released"
                )
            })
        && value
            .get("operationClass")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|class| !class.is_empty())
        && value
            .get("effectIds")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|effect_ids| {
                !effect_ids.is_empty()
                    && effect_ids.len() <= 64
                    && effect_ids.iter().all(|effect_id| {
                        effect_id
                            .as_str()
                            .is_some_and(|id| !id.is_empty() && id.len() <= 256)
                    })
            })
        && value
            .get("resourceUid")
            .and_then(serde_json::Value::as_str)
            .and_then(|uid| ResourceUid::parse(uid.to_owned()).ok())
            .is_some()
        && value
            .get("generation")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|generation| generation != 0)
        && value
            .get("operationId")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|operation_id| {
                operation_id == row.operation_id && operation_id.starts_with("effect:")
            })
        && value
            .get("claimDigest")
            .and_then(serde_json::Value::as_str)
            .is_some_and(d2b_contracts_resource::v3::is_canonical_digest)
        && value
            .get("storeBindingDigest")
            .and_then(serde_json::Value::as_str)
            .is_some_and(d2b_contracts_resource::v3::is_canonical_digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::OpenOptions, sync::Arc};

    use d2b_contracts_resource::v3::{ConfigurationGeneration, ResourceUid, Timestamp, ZoneId};
    use d2b_resource_store::{PolicySnapshot, StoreSlot, mutation_seal::mutation_seal_pair};
    use d2b_resource_store_redb::{StoreIdentity, write_provisioning_marker};

    fn controller_effect_row(
        operation_id: &str,
        payload: serde_json::Value,
        state: StoreAuthorityOperationState,
    ) -> AuthorityOperation {
        AuthorityOperation {
            operation_id: operation_id.to_owned(),
            payload: serde_json::to_vec(&payload).expect("controller effect payload"),
            state,
        }
    }

    fn valid_controller_effect_payload(operation_id: &str) -> serde_json::Value {
        serde_json::json!({
            "version": 1,
            "kind": "controller-effect",
            "state": "pending",
            "operationClass": "reconcile",
            "effectIds": ["observe"],
            "resourceUid": "123e4567-e89b-42d3-a456-426614174000",
            "generation": 1,
            "operationId": operation_id,
            "claimDigest": format!("sha256:{}", "a".repeat(64)),
            "storeBindingDigest": format!("sha256:{}", "b".repeat(64)),
        })
    }

    fn valid_host_global_payload(store: &RedbResourceStore) -> Vec<u8> {
        let claim = serde_json::from_value::<AuthorityStorageClaim>(serde_json::json!({
            "generic": {
                "scope": {
                    "host": "11111111-1111-4111-8111-111111111111"
                },
                "class": "kvm",
                "opaqueDigest": format!("sha256:{}", "d".repeat(64)),
                "arbitration": "exclusive",
                "maxHolders": 1,
                "providerCardinality": null,
                "ownerProof": {
                    "resourceRef": "Host/owner",
                    "resourceUid": "123e4567-e89b-42d3-a456-426614174000",
                    "generation": 1
                },
                "dependentGuest": null
            }
        }))
        .expect("Host-global claim");
        let claim_digest = claim_digest(&claim).expect("Host-global claim digest");
        serde_json::to_vec(&AuthorityStorageOperation {
            operation_id: "host-operation".to_owned(),
            claim,
            state: AuthorityOperationState::Closed,
            claim_digest: claim_digest.clone(),
            store_binding_digest: store.authority_binding_digest(&claim_digest),
        })
        .expect("Host-global authority payload")
    }

    async fn test_store() -> (tempfile::TempDir, Arc<RedbResourceStore>) {
        let directory = tempfile::tempdir().expect("store directory");
        let identity = StoreIdentity::new(
            StoreSlot::new(0).expect("store slot"),
            ResourceUid::parse("11111111-1111-4111-8111-111111111111").expect("store UID"),
            ZoneId::parse("work").expect("Zone"),
            ResourceUid::parse("22222222-2222-4222-8222-222222222222").expect("Zone UID"),
            Timestamp::parse("2026-08-31T00:00:00.000Z").expect("timestamp"),
            PolicySnapshot {
                policy_revision: 7,
                api_catalog_revision: 8,
                active_configuration_revision: ConfigurationGeneration::new(9)
                    .expect("configuration generation"),
                controller_generation: None,
            },
        );
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(directory.path().join("store.redb"))
            .expect("store file");
        let mut marker = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(directory.path().join("store.marker"))
            .expect("store marker");
        write_provisioning_marker(&mut marker, &identity).expect("provisioning marker");
        let (_, acceptor) = mutation_seal_pair(identity.seal_identity());
        let store = RedbResourceStore::provision_owned(file, marker, identity, acceptor)
            .await
            .expect("provision store");
        (directory, Arc::new(store))
    }

    #[test]
    fn generation_publication_rows_are_not_rehydrated_as_host_authority() {
        let row = AuthorityOperation {
            operation_id: format!(
                "{ZONE_GENERATION_PUBLICATION_OPERATION_PREFIX}sha256:{}",
                "a".repeat(64)
            ),
            payload: serde_json::to_vec(&serde_json::json!({
                "publication": "zone-resource-plane"
            }))
            .expect("publication payload"),
            state: StoreAuthorityOperationState::Pending,
        };
        assert!(is_zone_generation_publication(&row));
    }

    #[test]
    fn malformed_or_other_operation_rows_still_fail_closed() {
        for row in [
            AuthorityOperation {
                operation_id: format!(
                    "{ZONE_GENERATION_PUBLICATION_OPERATION_PREFIX}sha256:{}",
                    "b".repeat(64)
                ),
                payload: b"not-json".to_vec(),
                state: StoreAuthorityOperationState::Pending,
            },
            AuthorityOperation {
                operation_id: "authority-operation".to_owned(),
                payload: serde_json::to_vec(&serde_json::json!({
                    "publication": "zone-resource-plane"
                }))
                .expect("payload"),
                state: StoreAuthorityOperationState::Pending,
            },
        ] {
            assert!(!is_zone_generation_publication(&row));
        }
    }

    #[test]
    fn controller_effect_discriminator_requires_a_validated_envelope() {
        let valid = controller_effect_row(
            "effect:controller",
            valid_controller_effect_payload("effect:controller"),
            StoreAuthorityOperationState::Pending,
        );
        assert!(is_controller_effect_operation(&valid));

        for payload in [
            serde_json::json!({
                "version": 1,
                "kind": "controller-effect",
                "operationId": "effect:controller",
            }),
            {
                let mut payload = valid_controller_effect_payload("effect:controller");
                payload["effectIds"] = serde_json::json!([]);
                payload
            },
            serde_json::json!({
                "version": 1,
                "kind": "unknown",
                "operationId": "effect:controller",
            }),
        ] {
            let row = controller_effect_row(
                "effect:controller",
                payload,
                StoreAuthorityOperationState::Pending,
            );
            assert!(!is_controller_effect_operation(&row));
        }

        let malformed = AuthorityOperation {
            operation_id: "effect:controller".to_owned(),
            payload: b"not-json".to_vec(),
            state: StoreAuthorityOperationState::Pending,
        };
        assert!(!is_controller_effect_operation(&malformed));
    }

    #[tokio::test]
    async fn mixed_authority_ledger_recovers_host_claim_and_skips_controller_effect() {
        let (_directory, store) = test_store().await;
        let rows = vec![
            AuthorityOperation {
                operation_id: "host-operation".to_owned(),
                payload: valid_host_global_payload(&store),
                state: StoreAuthorityOperationState::Closed,
            },
            controller_effect_row(
                "effect:controller",
                valid_controller_effect_payload("effect:controller"),
                StoreAuthorityOperationState::Pending,
            ),
        ];

        let recovered = recovery_receipt(rows, &store, &Mutex::new(BTreeMap::new()))
            .await
            .expect("mixed authority ledger recovery");
        let _ = recovered;

        Arc::try_unwrap(store)
            .expect("only test owner remains")
            .shutdown()
            .await
            .expect("shutdown store");
    }

    #[tokio::test]
    async fn malformed_or_unknown_controller_effect_rows_fail_closed() {
        let (_directory, store) = test_store().await;
        for payload in [
            serde_json::json!({
                "version": 1,
                "kind": "controller-effect",
                "operationId": "effect:controller",
            }),
            serde_json::json!({
                "version": 1,
                "kind": "unknown",
                "state": "pending",
                "operationClass": "reconcile",
                "effectIds": ["observe"],
                "resourceUid": "123e4567-e89b-42d3-a456-426614174000",
                "generation": 1,
                "operationId": "effect:controller",
                "claimDigest": format!("sha256:{}", "a".repeat(64)),
                "storeBindingDigest": format!("sha256:{}", "b".repeat(64)),
            }),
        ] {
            let error = match recovery_receipt(
                vec![controller_effect_row(
                    "effect:controller",
                    payload,
                    StoreAuthorityOperationState::Pending,
                )],
                &store,
                &Mutex::new(BTreeMap::new()),
            )
            .await
            {
                Ok(_) => panic!("malformed controller effect row must fail closed"),
                Err(error) => error,
            };
            assert_eq!(error, AuthorityPersistenceError::RowInvalid);
        }

        Arc::try_unwrap(store)
            .expect("only test owner remains")
            .shutdown()
            .await
            .expect("shutdown store");
    }

    #[tokio::test]
    async fn generation_publication_rows_remain_excluded_from_recovery() {
        let (_directory, store) = test_store().await;
        let row = AuthorityOperation {
            operation_id: format!(
                "{ZONE_GENERATION_PUBLICATION_OPERATION_PREFIX}sha256:{}",
                "e".repeat(64)
            ),
            payload: serde_json::to_vec(&serde_json::json!({
                "publication": "zone-resource-plane"
            }))
            .expect("publication payload"),
            state: StoreAuthorityOperationState::Pending,
        };
        recovery_receipt(vec![row], &store, &Mutex::new(BTreeMap::new()))
            .await
            .expect("Zone publication row remains excluded");

        Arc::try_unwrap(store)
            .expect("only test owner remains")
            .shutdown()
            .await
            .expect("shutdown store");
    }
}
