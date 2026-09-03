//! Credential service dispatch for the injected managed identity client.

use d2b_contracts_provider::v3::credential::{
    CredentialAuthorization, CredentialLeaseState, CredentialMetadata, CredentialMethod,
    CredentialOutcomeCode, CredentialProvider, CredentialRequest, CredentialResponse,
    CredentialServiceError, CredentialServiceErrorCode, CredentialSessionBinding, DeliveryResponse,
    MetadataResponse,
};

use crate::{
    LeaseRecord, ManagedIdentityCredentialProvider, ManagedIdentityLeaseRef,
    ManagedIdentityLeaseRequest,
};

#[async_trait::async_trait]
impl CredentialProvider for ManagedIdentityCredentialProvider {
    fn dispatch(
        &self,
        method: CredentialMethod,
        request: &CredentialRequest,
        authorization: &CredentialAuthorization,
    ) -> Result<CredentialResponse, CredentialServiceError> {
        match method {
            CredentialMethod::AcquireToken => self.acquire(request, authorization),
            CredentialMethod::RefreshToken => self.refresh(request, authorization),
            CredentialMethod::RevokeToken => self.revoke(request, authorization),
            CredentialMethod::InspectMetadata => self.inspect(request, authorization),
            CredentialMethod::SignChallenge => Err(CredentialServiceError::new(
                CredentialServiceErrorCode::Malformed,
            )),
        }
    }

    async fn dispatch_async(
        &self,
        method: CredentialMethod,
        request: &CredentialRequest,
        authorization: &CredentialAuthorization,
    ) -> Result<CredentialResponse, CredentialServiceError> {
        let _mutation = self.async_mutation_gate.lock().await;
        match method {
            CredentialMethod::AcquireToken => self.acquire_async(request, authorization).await,
            CredentialMethod::RefreshToken => self.refresh_async(request, authorization).await,
            CredentialMethod::RevokeToken => self.revoke_async(request, authorization).await,
            CredentialMethod::InspectMetadata => self.inspect_async(request, authorization).await,
            CredentialMethod::SignChallenge => Err(CredentialServiceError::new(
                CredentialServiceErrorCode::Malformed,
            )),
        }
    }
}

impl ManagedIdentityCredentialProvider {
    async fn acquire_async(
        &self,
        request: &CredentialRequest,
        authorization: &CredentialAuthorization,
    ) -> Result<CredentialResponse, CredentialServiceError> {
        let delivery = authorization
            .delivery_session_params()
            .cloned()
            .ok_or_else(operation_denied)?;
        let session = self.validate_authenticated_session(
            CredentialMethod::AcquireToken,
            request,
            authorization,
        )?;
        let requested_expiry = ManagedIdentityCredentialProvider::bounded_expiry(
            request.requested_expiry_unix_ms(),
            session.expires_at_unix_ms(),
            delivery.expiry_unix_ms(),
        )?;
        let deadline = Self::operation_deadline(request.deadline_unix_ms())?;
        let key = request.credential_ref().to_canonical_string();
        let now = Self::now_unix_ms();
        let rotation_generation = {
            let mut leases = self.leases.lock().map_err(|_| invariant())?;
            Self::mark_expired_locked(&mut leases, now);
            let records = leases.get(&key);
            if let Some(records) = records
                && let Some(existing) = records.iter().find(|record| {
                    !record.cleanup_only
                        && record.metadata.state == CredentialLeaseState::Active
                        && record.idempotency_key == request.idempotency_key()
                        && Self::same_session(
                            &record.authenticated_subject,
                            session.authenticated_subject(),
                        )
                })
            {
                return Ok(CredentialResponse::AcquireToken(DeliveryResponse {
                    metadata: existing.metadata.clone(),
                    delivery_session_params: delivery,
                }));
            }
            let active_for_owner = records
                .into_iter()
                .flatten()
                .filter(|record| {
                    !record.cleanup_only
                        && record.metadata.state == CredentialLeaseState::Active
                        && Self::same_owner(
                            &record.authenticated_subject,
                            session.authenticated_subject(),
                        )
                })
                .count();
            if Self::active_lease_count(&leases).saturating_sub(active_for_owner)
                >= self.config.max_leases() as usize
            {
                return Err(CredentialServiceError::new(
                    CredentialServiceErrorCode::ProviderUnavailable,
                ));
            }
            let prior_generation = records
                .into_iter()
                .flatten()
                .filter(|record| {
                    Self::same_owner(
                        &record.authenticated_subject,
                        session.authenticated_subject(),
                    )
                })
                .map(|record| record.metadata.rotation_generation)
                .max()
                .unwrap_or(0);
            prior_generation.checked_add(1).ok_or_else(invariant)?
        };
        let stale_records = {
            let leases = self.leases.lock().map_err(|_| invariant())?;
            leases
                .get(&key)
                .into_iter()
                .flatten()
                .filter(|record| {
                    matches!(
                        record.metadata.state,
                        CredentialLeaseState::Active | CredentialLeaseState::Expired
                    ) && Self::same_owner(
                        &record.authenticated_subject,
                        session.authenticated_subject(),
                    )
                })
                .cloned()
                .collect::<Vec<_>>()
        };
        for stale_record in stale_records {
            let lease = ManagedIdentityLeaseRef {
                credential_ref: request.credential_ref().clone(),
                metadata: stale_record.metadata.clone(),
            };
            let revocation =
                await_client(self.client.revoke_lease(&lease), deadline).await?;
            let outcome = match revocation {
                crate::ManagedIdentityLeaseRevocation::Revoked => CredentialOutcomeCode::Revoked,
                crate::ManagedIdentityLeaseRevocation::AlreadyRevoked => {
                    CredentialOutcomeCode::AlreadyRevoked
                }
            };
            let mut leases = self.leases.lock().map_err(|_| invariant())?;
            let records = leases.get_mut(&key).ok_or_else(invariant)?;
            let record = records
                .iter_mut()
                .find(|record| {
                    record.metadata == stale_record.metadata
                        && record.authenticated_subject == stale_record.authenticated_subject
                })
                .ok_or_else(invariant)?;
            record.metadata.state = CredentialLeaseState::Revoked;
            record.metadata.outcome = outcome;
        }
        let client_request = ManagedIdentityLeaseRequest {
            credential_ref: request.credential_ref().clone(),
            operation_id: request.operation_id().to_owned(),
            idempotency_key: request.idempotency_key().to_owned(),
            requested_expiry_unix_ms: requested_expiry,
            rotation_generation,
        };
        let grant = await_client(self.client.issue_lease(&client_request), deadline).await?;
        let cleanup_lease = lease_ref_from_grant(request.credential_ref(), &grant);
        let metadata = match Self::grant_metadata(grant, requested_expiry, rotation_generation) {
            Ok(metadata) => metadata,
            Err(error) => {
                return Err(self
                    .cleanup_or_track_issue_async(
                        request,
                        session,
                        cleanup_lease.metadata.clone(),
                        &cleanup_lease,
                        deadline,
                        error,
                    )
                    .await);
            }
        };
        let mut leases = self.leases.lock().map_err(|_| invariant())?;
        let records = leases.entry(key).or_default();
        records.retain(|record| {
            !Self::same_owner(
                &record.authenticated_subject,
                session.authenticated_subject(),
            )
        });
        records.push(LeaseRecord {
            idempotency_key: request.idempotency_key().to_owned(),
            metadata: metadata.clone(),
            authenticated_subject: session.authenticated_subject().clone(),
            session_expires_at_unix_ms: session.expires_at_unix_ms(),
            cleanup_only: false,
        });
        Ok(CredentialResponse::AcquireToken(DeliveryResponse {
            metadata,
            delivery_session_params: delivery,
        }))
    }

    async fn refresh_async(
        &self,
        request: &CredentialRequest,
        authorization: &CredentialAuthorization,
    ) -> Result<CredentialResponse, CredentialServiceError> {
        let delivery = authorization
            .delivery_session_params()
            .cloned()
            .ok_or_else(operation_denied)?;
        let session = self.validate_authenticated_session(
            CredentialMethod::RefreshToken,
            request,
            authorization,
        )?;
        let requested_expiry = ManagedIdentityCredentialProvider::bounded_expiry(
            request.requested_expiry_unix_ms(),
            session.expires_at_unix_ms(),
            delivery.expiry_unix_ms(),
        )?;
        let deadline = Self::operation_deadline(request.deadline_unix_ms())?;
        let key = request.credential_ref().to_canonical_string();
        let record = {
            let mut leases = self.leases.lock().map_err(|_| invariant())?;
            Self::mark_expired_locked(&mut leases, Self::now_unix_ms());
            let records = leases.get(&key).ok_or_else(expired)?;
            let record = records
                .iter()
                .find(|record| {
                    !record.cleanup_only
                        && Self::same_session(
                            &record.authenticated_subject,
                            session.authenticated_subject(),
                        )
                })
                .ok_or_else(operation_denied)?;
            ensure_active(record)?;
            record.clone()
        };
        let lease = ManagedIdentityLeaseRef {
            credential_ref: request.credential_ref().clone(),
            metadata: record.metadata.clone(),
        };
        let inspection = await_client(self.client.inspect_lease(&lease), deadline).await?;
        if inspection.state != CredentialLeaseState::Active {
            self.update_state(
                &key,
                &record,
                inspection.state,
                CredentialOutcomeCode::Success,
            )?;
            return Err(error_for_state(inspection.state));
        }
        if Self::is_expired(inspection.expires_at_unix_ms, Self::now_unix_ms()) {
            self.update_state(
                &key,
                &record,
                CredentialLeaseState::Expired,
                CredentialOutcomeCode::Success,
            )?;
            return Err(expired());
        }
        if inspection.rotation_generation != record.metadata.rotation_generation {
            return Err(invariant());
        }
        let grant = await_client(self.client.refresh_lease(&lease), deadline).await?;
        let cleanup_lease = lease_ref_from_grant(request.credential_ref(), &grant);
        let metadata = match Self::grant_metadata(
            grant,
            requested_expiry,
            record.metadata.rotation_generation,
        ) {
            Ok(metadata) => metadata,
            Err(error) => {
                return Err(self
                    .cleanup_or_track_issue_async(
                        request,
                        session,
                        cleanup_lease.metadata.clone(),
                        &cleanup_lease,
                        deadline,
                        error,
                    )
                    .await);
            }
        };
        self.replace_record(&key, &record, request.idempotency_key(), metadata.clone())?;
        Ok(CredentialResponse::RefreshToken(DeliveryResponse {
            metadata,
            delivery_session_params: delivery,
        }))
    }

    async fn revoke_async(
        &self,
        request: &CredentialRequest,
        authorization: &CredentialAuthorization,
    ) -> Result<CredentialResponse, CredentialServiceError> {
        let session = self.validate_authenticated_session(
            CredentialMethod::RevokeToken,
            request,
            authorization,
        )?;
        let deadline = Self::operation_deadline(request.deadline_unix_ms())?;
        let key = request.credential_ref().to_canonical_string();
        let record = {
            let mut leases = self.leases.lock().map_err(|_| invariant())?;
            Self::mark_expired_locked(&mut leases, Self::now_unix_ms());
            let records = leases.get(&key).ok_or_else(expired)?;
            records
                .iter()
                .find(|record| {
                    !record.cleanup_only
                        && Self::same_session(
                            &record.authenticated_subject,
                            session.authenticated_subject(),
                        )
                })
                .ok_or_else(operation_denied)?
                .clone()
        };
        if record.metadata.state == CredentialLeaseState::Revoked {
            return Ok(CredentialResponse::RevokeToken(MetadataResponse {
                metadata: record.metadata,
            }));
        }
        ensure_active(&record)?;
        let lease = ManagedIdentityLeaseRef {
            credential_ref: request.credential_ref().clone(),
            metadata: record.metadata.clone(),
        };
        let revocation = await_client(self.client.revoke_lease(&lease), deadline).await?;
        let outcome = match revocation {
            crate::ManagedIdentityLeaseRevocation::Revoked => CredentialOutcomeCode::Revoked,
            crate::ManagedIdentityLeaseRevocation::AlreadyRevoked => {
                CredentialOutcomeCode::AlreadyRevoked
            }
        };
        let mut metadata = record.metadata.clone();
        metadata.state = CredentialLeaseState::Revoked;
        metadata.outcome = outcome;
        self.replace_record(&key, &record, request.idempotency_key(), metadata.clone())?;
        Ok(CredentialResponse::RevokeToken(MetadataResponse { metadata }))
    }

    async fn inspect_async(
        &self,
        request: &CredentialRequest,
        authorization: &CredentialAuthorization,
    ) -> Result<CredentialResponse, CredentialServiceError> {
        let session = self.validate_authenticated_session(
            CredentialMethod::InspectMetadata,
            request,
            authorization,
        )?;
        let deadline = Self::operation_deadline(request.deadline_unix_ms())?;
        let key = request.credential_ref().to_canonical_string();
        let record = {
            let mut leases = self.leases.lock().map_err(|_| invariant())?;
            Self::mark_expired_locked(&mut leases, Self::now_unix_ms());
            let records = leases.get(&key).ok_or_else(expired)?;
            let record = records
                .iter()
                .find(|record| {
                    !record.cleanup_only
                        && Self::same_session(
                            &record.authenticated_subject,
                            session.authenticated_subject(),
                        )
                })
                .ok_or_else(operation_denied)?;
            ensure_active_or_observable(record)?;
            record.clone()
        };
        if record.metadata.state != CredentialLeaseState::Active {
            return Ok(CredentialResponse::InspectMetadata(MetadataResponse {
                metadata: record.metadata,
            }));
        }
        let lease = ManagedIdentityLeaseRef {
            credential_ref: request.credential_ref().clone(),
            metadata: record.metadata.clone(),
        };
        let inspection = await_client(self.client.inspect_lease(&lease), deadline).await?;
        let mut metadata = record.metadata.clone();
        metadata.state = inspection.state;
        metadata.source_version = inspection.source_version;
        if inspection.rotation_generation < metadata.rotation_generation {
            return Err(invariant());
        }
        metadata.rotation_generation = inspection.rotation_generation;
        metadata.expires_at_unix_ms = inspection.expires_at_unix_ms;
        if Self::is_expired(metadata.expires_at_unix_ms, Self::now_unix_ms())
            && metadata.state == CredentialLeaseState::Active
        {
            metadata.state = CredentialLeaseState::Expired;
        }
        self.replace_record(&key, &record, request.idempotency_key(), metadata.clone())?;
        Ok(CredentialResponse::InspectMetadata(MetadataResponse { metadata }))
    }

    fn acquire(
        &self,
        request: &CredentialRequest,
        authorization: &CredentialAuthorization,
    ) -> Result<CredentialResponse, CredentialServiceError> {
        let delivery = authorization
            .delivery_session_params()
            .cloned()
            .ok_or_else(operation_denied)?;
        let session = self.validate_authenticated_session(
            CredentialMethod::AcquireToken,
            request,
            authorization,
        )?;
        let requested_expiry = ManagedIdentityCredentialProvider::bounded_expiry(
            request.requested_expiry_unix_ms(),
            session.expires_at_unix_ms(),
            delivery.expiry_unix_ms(),
        )?;
        let deadline = Self::operation_deadline(request.deadline_unix_ms())?;
        let _mutation = self.mutation_guard()?;
        let key = request.credential_ref().to_canonical_string();
        let now = Self::now_unix_ms();
        let rotation_generation = {
            let mut leases = self.leases.lock().map_err(|_| invariant())?;
            Self::mark_expired_locked(&mut leases, now);
            let records = leases.get(&key);
            if let Some(records) = records
                && let Some(existing) = records.iter().find(|record| {
                    !record.cleanup_only
                        && record.metadata.state == CredentialLeaseState::Active
                        && record.idempotency_key == request.idempotency_key()
                        && Self::same_session(
                            &record.authenticated_subject,
                            session.authenticated_subject(),
                        )
                })
            {
                return Ok(CredentialResponse::AcquireToken(DeliveryResponse {
                    metadata: existing.metadata.clone(),
                    delivery_session_params: delivery,
                }));
            }
            let active_for_owner = records
                .into_iter()
                .flatten()
                .filter(|record| {
                    !record.cleanup_only
                        && record.metadata.state == CredentialLeaseState::Active
                        && Self::same_owner(
                            &record.authenticated_subject,
                            session.authenticated_subject(),
                        )
                })
                .count();
            if Self::active_lease_count(&leases).saturating_sub(active_for_owner)
                >= self.config.max_leases() as usize
            {
                return Err(CredentialServiceError::new(
                    CredentialServiceErrorCode::ProviderUnavailable,
                ));
            }
            let prior_generation = records
                .into_iter()
                .flatten()
                .filter(|record| {
                    Self::same_owner(
                        &record.authenticated_subject,
                        session.authenticated_subject(),
                    )
                })
                .map(|record| record.metadata.rotation_generation)
                .max()
                .unwrap_or(0);
            prior_generation.checked_add(1).ok_or_else(invariant)?
        };
        let stale_records = {
            let leases = self.leases.lock().map_err(|_| invariant())?;
            leases
                .get(&key)
                .into_iter()
                .flatten()
                .filter(|record| {
                    matches!(
                        record.metadata.state,
                        CredentialLeaseState::Active | CredentialLeaseState::Expired
                    ) && Self::same_owner(
                        &record.authenticated_subject,
                        session.authenticated_subject(),
                    )
                })
                .cloned()
                .collect::<Vec<_>>()
        };
        for stale_record in stale_records {
            let lease = ManagedIdentityLeaseRef {
                credential_ref: request.credential_ref().clone(),
                metadata: stale_record.metadata.clone(),
            };
            let revocation = Self::poll_client_sync(self.client.revoke_lease(&lease), deadline)?;
            let outcome = match revocation {
                crate::ManagedIdentityLeaseRevocation::Revoked => CredentialOutcomeCode::Revoked,
                crate::ManagedIdentityLeaseRevocation::AlreadyRevoked => {
                    CredentialOutcomeCode::AlreadyRevoked
                }
            };
            let mut leases = self.leases.lock().map_err(|_| invariant())?;
            let records = leases.get_mut(&key).ok_or_else(invariant)?;
            let record = records
                .iter_mut()
                .find(|record| {
                    record.metadata == stale_record.metadata
                        && record.authenticated_subject == stale_record.authenticated_subject
                })
                .ok_or_else(invariant)?;
            record.metadata.state = CredentialLeaseState::Revoked;
            record.metadata.outcome = outcome;
        }
        let client_request = ManagedIdentityLeaseRequest {
            credential_ref: request.credential_ref().clone(),
            operation_id: request.operation_id().to_owned(),
            idempotency_key: request.idempotency_key().to_owned(),
            requested_expiry_unix_ms: requested_expiry,
            rotation_generation,
        };
        let grant = Self::poll_client_sync(self.client.issue_lease(&client_request), deadline)?;
        let cleanup_lease = lease_ref_from_grant(request.credential_ref(), &grant);
        let metadata = match Self::grant_metadata(grant, requested_expiry, rotation_generation) {
            Ok(metadata) => metadata,
            Err(error) => {
                return Err(self.cleanup_or_track_issue(
                    request,
                    session,
                    cleanup_lease.metadata.clone(),
                    &cleanup_lease,
                    deadline,
                    error,
                ));
            }
        };
        let mut leases = match self.leases.lock() {
            Ok(leases) => leases,
            Err(_) => {
                return Err(self.cleanup_or_track_issue(
                    request,
                    session,
                    metadata.clone(),
                    &cleanup_lease,
                    deadline,
                    invariant(),
                ));
            }
        };
        let records = leases.entry(key).or_default();
        records.retain(|record| {
            !Self::same_owner(
                &record.authenticated_subject,
                session.authenticated_subject(),
            )
        });
        records.push(LeaseRecord {
            idempotency_key: request.idempotency_key().to_owned(),
            metadata: metadata.clone(),
            authenticated_subject: session.authenticated_subject().clone(),
            session_expires_at_unix_ms: session.expires_at_unix_ms(),
            cleanup_only: false,
        });
        Ok(CredentialResponse::AcquireToken(DeliveryResponse {
            metadata,
            delivery_session_params: delivery,
        }))
    }

    fn cleanup_or_track_issue(
        &self,
        request: &CredentialRequest,
        session: &CredentialSessionBinding,
        metadata: CredentialMetadata,
        lease: &ManagedIdentityLeaseRef,
        deadline: std::time::Instant,
        error: CredentialServiceError,
    ) -> CredentialServiceError {
        if Self::poll_client_sync(self.client.revoke_lease(lease), deadline).is_ok() {
            return error;
        }
        let unresolved = LeaseRecord {
            idempotency_key: request.idempotency_key().to_owned(),
            metadata,
            authenticated_subject: session.authenticated_subject().clone(),
            session_expires_at_unix_ms: session.expires_at_unix_ms(),
            cleanup_only: true,
        };
        match self.leases.lock() {
            Ok(mut leases) => {
                let records = leases
                    .entry(request.credential_ref().to_canonical_string())
                    .or_default();
                if let Some(existing) = records
                    .iter_mut()
                    .find(|existing| Self::same_record_identity(existing, &unresolved))
                {
                    *existing = unresolved;
                } else {
                    records.push(unresolved);
                }
                error
            }
            Err(_) => invariant(),
        }
    }

    async fn cleanup_or_track_issue_async(
        &self,
        request: &CredentialRequest,
        session: &CredentialSessionBinding,
        metadata: CredentialMetadata,
        lease: &ManagedIdentityLeaseRef,
        deadline: std::time::Instant,
        error: CredentialServiceError,
    ) -> CredentialServiceError {
        if await_client(self.client.revoke_lease(lease), deadline)
            .await
            .is_ok()
        {
            return error;
        }
        let unresolved = LeaseRecord {
            idempotency_key: request.idempotency_key().to_owned(),
            metadata,
            authenticated_subject: session.authenticated_subject().clone(),
            session_expires_at_unix_ms: session.expires_at_unix_ms(),
            cleanup_only: true,
        };
        match self.leases.lock() {
            Ok(mut leases) => {
                let records = leases
                    .entry(request.credential_ref().to_canonical_string())
                    .or_default();
                if let Some(existing) = records
                    .iter_mut()
                    .find(|existing| Self::same_record_identity(existing, &unresolved))
                {
                    *existing = unresolved;
                } else {
                    records.push(unresolved);
                }
                error
            }
            Err(_) => invariant(),
        }
    }

    fn refresh(
        &self,
        request: &CredentialRequest,
        authorization: &CredentialAuthorization,
    ) -> Result<CredentialResponse, CredentialServiceError> {
        let delivery = authorization
            .delivery_session_params()
            .cloned()
            .ok_or_else(operation_denied)?;
        let session = self.validate_authenticated_session(
            CredentialMethod::RefreshToken,
            request,
            authorization,
        )?;
        let requested_expiry = ManagedIdentityCredentialProvider::bounded_expiry(
            request.requested_expiry_unix_ms(),
            session.expires_at_unix_ms(),
            delivery.expiry_unix_ms(),
        )?;
        let deadline = Self::operation_deadline(request.deadline_unix_ms())?;
        let _mutation = self.mutation_guard()?;
        let key = request.credential_ref().to_canonical_string();
        let now = Self::now_unix_ms();
        let record = {
            let mut leases = self.leases.lock().map_err(|_| invariant())?;
            Self::mark_expired_locked(&mut leases, now);
            let records = leases.get(&key).ok_or_else(expired)?;
            let record = records
                .iter()
                .find(|record| {
                    !record.cleanup_only
                        && Self::same_session(
                            &record.authenticated_subject,
                            session.authenticated_subject(),
                        )
                })
                .ok_or_else(operation_denied)?;
            ensure_active(record)?;
            record.clone()
        };
        let lease = ManagedIdentityLeaseRef {
            credential_ref: request.credential_ref().clone(),
            metadata: record.metadata.clone(),
        };
        let inspection = Self::poll_client_sync(self.client.inspect_lease(&lease), deadline)?;
        if inspection.state != CredentialLeaseState::Active {
            self.update_state(
                &key,
                &record,
                inspection.state,
                CredentialOutcomeCode::Success,
            )?;
            return Err(error_for_state(inspection.state));
        }
        if Self::is_expired(inspection.expires_at_unix_ms, Self::now_unix_ms()) {
            self.update_state(
                &key,
                &record,
                CredentialLeaseState::Expired,
                CredentialOutcomeCode::Success,
            )?;
            return Err(expired());
        }
        if inspection.rotation_generation != record.metadata.rotation_generation {
            return Err(invariant());
        }
        let grant = Self::poll_client_sync(self.client.refresh_lease(&lease), deadline)?;
        let cleanup_lease = lease_ref_from_grant(request.credential_ref(), &grant);
        let metadata = match Self::grant_metadata(
            grant,
            requested_expiry,
            record.metadata.rotation_generation,
        ) {
            Ok(metadata) => metadata,
            Err(error) => {
                return Err(self.cleanup_or_track_issue(
                    request,
                    session,
                    cleanup_lease.metadata.clone(),
                    &cleanup_lease,
                    deadline,
                    error,
                ));
            }
        };
        if let Err(error) =
            self.replace_record(&key, &record, request.idempotency_key(), metadata.clone())
        {
            return Err(self.cleanup_or_track_issue(
                request,
                session,
                metadata.clone(),
                &cleanup_lease,
                deadline,
                error,
            ));
        }
        Ok(CredentialResponse::RefreshToken(DeliveryResponse {
            metadata,
            delivery_session_params: delivery,
        }))
    }

    fn revoke(
        &self,
        request: &CredentialRequest,
        authorization: &CredentialAuthorization,
    ) -> Result<CredentialResponse, CredentialServiceError> {
        let session = self.validate_authenticated_session(
            CredentialMethod::RevokeToken,
            request,
            authorization,
        )?;
        let deadline = Self::operation_deadline(request.deadline_unix_ms())?;
        let _mutation = self.mutation_guard()?;
        let key = request.credential_ref().to_canonical_string();
        let now = Self::now_unix_ms();
        let record = {
            let mut leases = self.leases.lock().map_err(|_| invariant())?;
            Self::mark_expired_locked(&mut leases, now);
            let records = leases.get(&key).ok_or_else(expired)?;
            let record = records
                .iter()
                .find(|record| {
                    !record.cleanup_only
                        && Self::same_session(
                            &record.authenticated_subject,
                            session.authenticated_subject(),
                        )
                })
                .ok_or_else(operation_denied)?;
            record.clone()
        };
        if record.metadata.state == CredentialLeaseState::Revoked {
            return Ok(CredentialResponse::RevokeToken(MetadataResponse {
                metadata: record.metadata,
            }));
        }
        ensure_active(&record)?;
        let lease = ManagedIdentityLeaseRef {
            credential_ref: request.credential_ref().clone(),
            metadata: record.metadata.clone(),
        };
        let revocation = Self::poll_client_sync(self.client.revoke_lease(&lease), deadline)?;
        let outcome = match revocation {
            crate::ManagedIdentityLeaseRevocation::Revoked => CredentialOutcomeCode::Revoked,
            crate::ManagedIdentityLeaseRevocation::AlreadyRevoked => {
                CredentialOutcomeCode::AlreadyRevoked
            }
        };
        let mut metadata = record.metadata.clone();
        metadata.state = CredentialLeaseState::Revoked;
        metadata.outcome = outcome;
        self.replace_record(&key, &record, request.idempotency_key(), metadata.clone())?;
        Ok(CredentialResponse::RevokeToken(MetadataResponse {
            metadata,
        }))
    }

    fn inspect(
        &self,
        request: &CredentialRequest,
        authorization: &CredentialAuthorization,
    ) -> Result<CredentialResponse, CredentialServiceError> {
        let session = self.validate_authenticated_session(
            CredentialMethod::InspectMetadata,
            request,
            authorization,
        )?;
        let deadline = Self::operation_deadline(request.deadline_unix_ms())?;
        let _mutation = self.mutation_guard()?;
        let key = request.credential_ref().to_canonical_string();
        let now = Self::now_unix_ms();
        let record = {
            let mut leases = self.leases.lock().map_err(|_| invariant())?;
            Self::mark_expired_locked(&mut leases, now);
            let records = leases.get(&key).ok_or_else(expired)?;
            let record = records
                .iter()
                .find(|record| {
                    !record.cleanup_only
                        && Self::same_session(
                            &record.authenticated_subject,
                            session.authenticated_subject(),
                        )
                })
                .ok_or_else(operation_denied)?;
            ensure_active_or_observable(record)?;
            record.clone()
        };
        if record.metadata.state != CredentialLeaseState::Active {
            return Ok(CredentialResponse::InspectMetadata(MetadataResponse {
                metadata: record.metadata,
            }));
        }
        let lease = ManagedIdentityLeaseRef {
            credential_ref: request.credential_ref().clone(),
            metadata: record.metadata.clone(),
        };
        let inspection = Self::poll_client_sync(self.client.inspect_lease(&lease), deadline)?;
        let mut metadata = record.metadata.clone();
        metadata.state = inspection.state;
        metadata.source_version = inspection.source_version;
        if inspection.rotation_generation < metadata.rotation_generation {
            return Err(invariant());
        }
        metadata.rotation_generation = inspection.rotation_generation;
        metadata.expires_at_unix_ms = inspection.expires_at_unix_ms;
        if Self::is_expired(metadata.expires_at_unix_ms, Self::now_unix_ms())
            && metadata.state == CredentialLeaseState::Active
        {
            metadata.state = CredentialLeaseState::Expired;
        }
        self.replace_record(&key, &record, request.idempotency_key(), metadata.clone())?;
        if matches!(
            metadata.state,
            CredentialLeaseState::Expired | CredentialLeaseState::Revoked
        ) {
            return Ok(CredentialResponse::InspectMetadata(MetadataResponse {
                metadata,
            }));
        }
        Ok(CredentialResponse::InspectMetadata(MetadataResponse {
            metadata,
        }))
    }

    fn update_state(
        &self,
        key: &str,
        record: &LeaseRecord,
        state: CredentialLeaseState,
        outcome: CredentialOutcomeCode,
    ) -> Result<(), CredentialServiceError> {
        let mut metadata = record.metadata.clone();
        metadata.state = state;
        metadata.outcome = outcome;
        self.replace_record(key, record, &record.idempotency_key, metadata)
    }

    fn replace_record(
        &self,
        key: &str,
        old: &LeaseRecord,
        idempotency_key: &str,
        metadata: d2b_contracts_provider::v3::credential::CredentialMetadata,
    ) -> Result<(), CredentialServiceError> {
        let mut leases = self.leases.lock().map_err(|_| invariant())?;
        let records = leases.get_mut(key).ok_or_else(invariant)?;
        let record = records
            .iter_mut()
            .find(|record| {
                record.metadata == old.metadata
                    && record.authenticated_subject == old.authenticated_subject
            })
            .ok_or_else(invariant)?;
        record.idempotency_key = idempotency_key.to_owned();
        record.metadata = metadata;
        Ok(())
    }
}

fn ensure_active(record: &LeaseRecord) -> Result<(), CredentialServiceError> {
    match record.metadata.state {
        CredentialLeaseState::Active => Ok(()),
        state => Err(error_for_state(state)),
    }
}

fn ensure_active_or_observable(record: &LeaseRecord) -> Result<(), CredentialServiceError> {
    match record.metadata.state {
        CredentialLeaseState::Active
        | CredentialLeaseState::Expired
        | CredentialLeaseState::Revoked => Ok(()),
        CredentialLeaseState::Unknown => Err(invariant()),
    }
}

fn lease_ref_from_grant(
    credential_ref: &d2b_contracts_resource::v3::ResourceRef,
    grant: &crate::ManagedIdentityLeaseGrant,
) -> ManagedIdentityLeaseRef {
    ManagedIdentityLeaseRef {
        credential_ref: credential_ref.clone(),
        metadata: CredentialMetadata {
            lease_handle: grant.lease_handle.clone(),
            rotation_generation: grant.rotation_generation,
            source_version: grant.source_version.clone(),
            expires_at_unix_ms: grant.expires_at_unix_ms,
            state: CredentialLeaseState::Active,
            outcome: CredentialOutcomeCode::Success,
        },
    }
}

fn error_for_state(state: CredentialLeaseState) -> CredentialServiceError {
    match state {
        CredentialLeaseState::Expired => expired(),
        CredentialLeaseState::Revoked => {
            CredentialServiceError::new(CredentialServiceErrorCode::LeaseRevoked)
        }
        CredentialLeaseState::Active | CredentialLeaseState::Unknown => invariant(),
    }
}

async fn await_client<T: Send>(
    future: crate::ManagedIdentityFuture<'_, T>,
    deadline: std::time::Instant,
) -> Result<T, CredentialServiceError> {
    let remaining = deadline
        .checked_duration_since(std::time::Instant::now())
        .ok_or_else(|| CredentialServiceError::new(CredentialServiceErrorCode::DeadlineExceeded))?;
    tokio::time::timeout(remaining, future)
        .await
        .map_err(|_| CredentialServiceError::new(CredentialServiceErrorCode::DeadlineExceeded))?
        .map_err(ManagedIdentityCredentialProvider::map_client_error)
}

fn invariant() -> CredentialServiceError {
    CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure)
}

fn operation_denied() -> CredentialServiceError {
    CredentialServiceError::new(CredentialServiceErrorCode::OperationDenied)
}

fn expired() -> CredentialServiceError {
    CredentialServiceError::new(CredentialServiceErrorCode::LeaseExpired)
}
