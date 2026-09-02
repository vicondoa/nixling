//! Credential service dispatch for Secret Service.

use std::collections::{BTreeMap, BTreeSet};

use d2b_contracts_provider::v3::credential::{
    CredentialAuthorization, CredentialLeaseState, CredentialMethod, CredentialOutcomeCode,
    CredentialProvider, CredentialRequest, CredentialResponse, CredentialServiceError,
    CredentialServiceErrorCode, DeliveryResponse, MetadataResponse,
};

use crate::{
    LeaseRecord, OperationKind, SecretServiceCredentialProvider, SecretServiceLeaseRef,
    SecretServiceLeaseRequest, SecretServicePollError, SecretServicePortError, SessionKey,
};

impl CredentialProvider for SecretServiceCredentialProvider {
    fn dispatch(
        &self,
        method: CredentialMethod,
        request: &CredentialRequest,
        authorization: &CredentialAuthorization,
    ) -> Result<CredentialResponse, CredentialServiceError> {
        let _lifecycle = self.mutation_guard()?;
        let session_key = self
            .authorize_session_locked(authorization)
            .or_else(|_| {
                matches!(
                    method,
                    CredentialMethod::RevokeToken | CredentialMethod::InspectMetadata
                )
                .then(|| self.authorize_controller_session_locked(authorization))
                .unwrap_or_else(|| {
                    Err(CredentialServiceError::new(
                        CredentialServiceErrorCode::OperationDenied,
                    ))
                })
            })?;
        match method {
            CredentialMethod::AcquireToken => self.acquire(request, authorization, session_key),
            CredentialMethod::RefreshToken => self.refresh(request, authorization, session_key),
            CredentialMethod::RevokeToken => self.revoke(request, session_key),
            CredentialMethod::InspectMetadata => self.inspect(request, session_key),
            CredentialMethod::SignChallenge => Err(CredentialServiceError::new(
                CredentialServiceErrorCode::Malformed,
            )),
        }
    }
}

impl SecretServiceCredentialProvider {
    fn validate_delivery(
        &self,
        method: CredentialMethod,
        request: &CredentialRequest,
        delivery: &d2b_contracts_provider::v3::credential::DeliverySessionParams,
    ) -> Result<(), CredentialServiceError> {
        if delivery.credential_ref() != request.credential_ref()
            || delivery.consumer_provider_ref() != &self.consumer_ref
            || delivery.operation_class() != method.operation_class()
            || delivery.deadline_unix_ms() > request.deadline_unix_ms()
            || delivery.expiry_unix_ms() > request.requested_expiry_unix_ms()
        {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::OperationDenied,
            ));
        }
        Ok(())
    }

    fn acquire(
        &self,
        request: &CredentialRequest,
        authorization: &CredentialAuthorization,
        session_key: SessionKey,
    ) -> Result<CredentialResponse, CredentialServiceError> {
        let delivery = authorization
            .delivery_session_params()
            .cloned()
            .ok_or_else(invariant)?;
        self.validate_delivery(CredentialMethod::AcquireToken, request, &delivery)?;
        let deadline = Self::operation_deadline(request.deadline_unix_ms())?;
        let key = request.credential_ref().to_canonical_string();
        self.ensure_unlocked(deadline)?;
        if self.has_ambiguous_credential(session_key, &key)? {
            return Err(invariant());
        }
        let lease_key = (session_key, key.clone());
        {
            let mut leases = self.leases.lock().map_err(|_| invariant())?;
            if let Some(existing) = leases.get(&lease_key) {
                match existing.metadata.state {
                    CredentialLeaseState::Active => {
                        return Ok(CredentialResponse::AcquireToken(DeliveryResponse {
                            metadata: existing.metadata.clone(),
                            delivery_session_params: delivery,
                        }));
                    }
                    CredentialLeaseState::Unknown => return Err(invariant()),
                    CredentialLeaseState::Expired | CredentialLeaseState::Revoked => {
                        leases.remove(&lease_key);
                    }
                }
            }
        }
        if self.ambiguous_lease_count()? >= self.config.max_leases() as usize {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::ProviderUnavailable,
            ));
        }
        let port_request = SecretServiceLeaseRequest {
            credential_ref: request.credential_ref().clone(),
            operation_id: request.operation_id().to_owned(),
            idempotency_key: request.idempotency_key().to_owned(),
            requested_expiry_unix_ms: request.requested_expiry_unix_ms(),
        };
        Self::deadline_remaining(deadline)?;
        let grant = match Self::poll_port_raw(self.port.issue_lease(&port_request), deadline) {
            Ok(grant) => grant,
            Err(SecretServicePollError::Port(SecretServicePortError::CompletionUnknown)) => {
                self.remember_ambiguous_acquire(session_key, port_request.clone())?;
                return Err(invariant());
            }
            Err(SecretServicePollError::Deadline) => {
                self.remember_ambiguous_acquire(session_key, port_request.clone())?;
                return Err(CredentialServiceError::new(
                    CredentialServiceErrorCode::DeadlineExceeded,
                ));
            }
            Err(error) => return Err(map_poll_error(error)),
        };
        let metadata = match Self::grant_metadata(grant.clone(), request.requested_expiry_unix_ms())
        {
            Ok(metadata) => metadata,
            Err(error) => {
                self.leases.lock().map_err(|_| invariant())?.insert(
                    lease_key,
                    LeaseRecord {
                        refresh_results: BTreeMap::new(),
                        metadata: Self::unknown_metadata(&grant),
                    },
                );
                self.mark_ambiguous(
                    session_key,
                    &key,
                    request.idempotency_key(),
                    OperationKind::Acquire,
                )?;
                return Err(error);
            }
        };
        self.leases.lock().map_err(|_| invariant())?.insert(
            lease_key,
            LeaseRecord {
                refresh_results: BTreeMap::new(),
                metadata: metadata.clone(),
            },
        );
        Ok(CredentialResponse::AcquireToken(DeliveryResponse {
            metadata,
            delivery_session_params: delivery,
        }))
    }

    fn refresh(
        &self,
        request: &CredentialRequest,
        authorization: &CredentialAuthorization,
        session_key: SessionKey,
    ) -> Result<CredentialResponse, CredentialServiceError> {
        let delivery = authorization
            .delivery_session_params()
            .cloned()
            .ok_or_else(invariant)?;
        self.validate_delivery(CredentialMethod::RefreshToken, request, &delivery)?;
        let deadline = Self::operation_deadline(request.deadline_unix_ms())?;
        let key = request.credential_ref().to_canonical_string();
        self.ensure_unlocked(deadline)?;
        if self.has_ambiguous_credential(session_key, &key)? {
            return Err(invariant());
        }
        let lease_key = (session_key, key.clone());
        let current = self
            .leases
            .lock()
            .map_err(|_| invariant())?
            .get(&lease_key)
            .cloned()
            .ok_or_else(expired)?;
        match current.metadata.state {
            CredentialLeaseState::Active => {
                if let Some(metadata) = current.refresh_results.get(request.idempotency_key()) {
                    return Ok(CredentialResponse::RefreshToken(DeliveryResponse {
                        metadata: metadata.clone(),
                        delivery_session_params: delivery,
                    }));
                }
            }
            CredentialLeaseState::Expired => return Err(expired()),
            CredentialLeaseState::Revoked => return Err(revoked()),
            CredentialLeaseState::Unknown => return Err(invariant()),
        }
        let lease = SecretServiceLeaseRef {
            credential_ref: request.credential_ref().clone(),
            metadata: current.metadata.clone(),
        };
        let inspected = match Self::poll_port_raw(self.port.inspect_lease(&lease), deadline) {
            Ok(inspected) => inspected,
            Err(SecretServicePollError::Port(SecretServicePortError::CompletionUnknown)) => {
                self.mark_metadata_unknown(&lease_key)?;
                self.mark_ambiguous(
                    session_key,
                    &key,
                    request.idempotency_key(),
                    OperationKind::Inspect,
                )?;
                return Err(invariant());
            }
            Err(SecretServicePollError::Deadline) => {
                self.mark_metadata_unknown(&lease_key)?;
                self.mark_ambiguous(
                    session_key,
                    &key,
                    request.idempotency_key(),
                    OperationKind::Inspect,
                )?;
                return Err(CredentialServiceError::new(
                    CredentialServiceErrorCode::DeadlineExceeded,
                ));
            }
            Err(SecretServicePollError::Port(SecretServicePortError::LeaseExpired)) => {
                self.set_lease_state(&lease_key, CredentialLeaseState::Expired)?;
                return Err(expired());
            }
            Err(SecretServicePollError::Port(SecretServicePortError::LeaseRevoked)) => {
                self.set_lease_state(&lease_key, CredentialLeaseState::Revoked)?;
                return Err(revoked());
            }
            Err(error) => return Err(map_poll_error(error)),
        };
        let mut inspected_metadata = lease.metadata.clone();
        inspected_metadata.state = inspected.state;
        inspected_metadata.source_version = inspected.source_version;
        inspected_metadata.rotation_generation = inspected.rotation_generation;
        inspected_metadata.expires_at_unix_ms = inspected.expires_at_unix_ms;
        match inspected_metadata.state {
            CredentialLeaseState::Active => {
                if inspected_metadata.rotation_generation != lease.metadata.rotation_generation {
                    self.mark_metadata_unknown(&lease_key)?;
                    self.mark_ambiguous(
                        session_key,
                        &key,
                        request.idempotency_key(),
                        OperationKind::Inspect,
                    )?;
                    return Err(invariant());
                }
            }
            CredentialLeaseState::Expired => {
                self.leases
                    .lock()
                    .map_err(|_| invariant())?
                    .get_mut(&lease_key)
                    .ok_or_else(expired)?
                    .metadata = inspected_metadata;
                return Err(expired());
            }
            CredentialLeaseState::Revoked => {
                self.leases
                    .lock()
                    .map_err(|_| invariant())?
                    .get_mut(&lease_key)
                    .ok_or_else(expired)?
                    .metadata = inspected_metadata;
                return Err(revoked());
            }
            CredentialLeaseState::Unknown => {
                self.leases
                    .lock()
                    .map_err(|_| invariant())?
                    .get_mut(&lease_key)
                    .ok_or_else(expired)?
                    .metadata = inspected_metadata;
                self.mark_ambiguous(
                    session_key,
                    &key,
                    request.idempotency_key(),
                    OperationKind::Inspect,
                )?;
                return Err(invariant());
            }
        }
        self.leases
            .lock()
            .map_err(|_| invariant())?
            .get_mut(&lease_key)
            .ok_or_else(expired)?
            .metadata = inspected_metadata.clone();
        let lease = SecretServiceLeaseRef {
            credential_ref: request.credential_ref().clone(),
            metadata: inspected_metadata,
        };
        let recovery_lease = lease.clone();
        let grant = match Self::poll_port_raw(self.port.refresh_lease(&lease), deadline) {
            Ok(grant) => grant,
            Err(SecretServicePollError::Port(SecretServicePortError::CompletionUnknown)) => {
                self.mark_metadata_unknown(&lease_key)?;
                self.remember_ambiguous_refresh(session_key, request, recovery_lease)?;
                return Err(invariant());
            }
            Err(SecretServicePollError::Deadline) => {
                self.mark_metadata_unknown(&lease_key)?;
                self.remember_ambiguous_refresh(session_key, request, recovery_lease)?;
                return Err(CredentialServiceError::new(
                    CredentialServiceErrorCode::DeadlineExceeded,
                ));
            }
            Err(SecretServicePollError::Port(SecretServicePortError::LeaseExpired)) => {
                self.set_lease_state(&lease_key, CredentialLeaseState::Expired)?;
                return Err(expired());
            }
            Err(SecretServicePollError::Port(SecretServicePortError::LeaseRevoked)) => {
                self.set_lease_state(&lease_key, CredentialLeaseState::Revoked)?;
                return Err(revoked());
            }
            Err(error) => return Err(map_poll_error(error)),
        };
        let metadata = match Self::grant_metadata(grant.clone(), request.requested_expiry_unix_ms())
        {
            Ok(metadata) => metadata,
            Err(error) => {
                let mut leases = self.leases.lock().map_err(|_| invariant())?;
                let record = leases.get_mut(&lease_key).ok_or_else(expired)?;
                record.metadata = Self::unknown_metadata(&grant);
                self.remember_ambiguous_refresh(session_key, request, recovery_lease)?;
                return Err(error);
            }
        };
        let mut record = current;
        record.metadata = metadata.clone();
        record
            .refresh_results
            .insert(request.idempotency_key().to_owned(), metadata.clone());
        self.leases
            .lock()
            .map_err(|_| invariant())?
            .insert(lease_key, record);
        Ok(CredentialResponse::RefreshToken(DeliveryResponse {
            metadata,
            delivery_session_params: delivery,
        }))
    }

    fn revoke(
        &self,
        request: &CredentialRequest,
        session_key: SessionKey,
    ) -> Result<CredentialResponse, CredentialServiceError> {
        let deadline = Self::operation_deadline(request.deadline_unix_ms())?;
        let key = request.credential_ref().to_canonical_string();
        self.ensure_unlocked(deadline)?;
        if self.has_ambiguous_credential(session_key, &key)? {
            return Err(invariant());
        }
        let lease_key = (session_key, key.clone());
        let current = self
            .leases
            .lock()
            .map_err(|_| invariant())?
            .get(&lease_key)
            .cloned()
            .ok_or_else(expired)?;
        match current.metadata.state {
            CredentialLeaseState::Revoked => {
                let mut metadata = current.metadata;
                metadata.outcome = CredentialOutcomeCode::AlreadyRevoked;
                self.leases
                    .lock()
                    .map_err(|_| invariant())?
                    .get_mut(&lease_key)
                    .ok_or_else(expired)?
                    .metadata = metadata.clone();
                return Ok(CredentialResponse::RevokeToken(MetadataResponse {
                    metadata,
                }));
            }
            CredentialLeaseState::Expired => return Err(expired()),
            CredentialLeaseState::Unknown => return Err(invariant()),
            CredentialLeaseState::Active => {}
        }

        let lease = SecretServiceLeaseRef {
            credential_ref: request.credential_ref().clone(),
            metadata: current.metadata,
        };
        let result = match Self::poll_port_raw(self.port.revoke_lease(&lease), deadline) {
            Ok(result) => result,
            Err(SecretServicePollError::Port(SecretServicePortError::CompletionUnknown)) => {
                self.mark_metadata_unknown(&lease_key)?;
                self.mark_ambiguous(
                    session_key,
                    &key,
                    request.idempotency_key(),
                    OperationKind::Revoke,
                )?;
                return Err(invariant());
            }
            Err(SecretServicePollError::Deadline) => {
                self.mark_metadata_unknown(&lease_key)?;
                self.mark_ambiguous(
                    session_key,
                    &key,
                    request.idempotency_key(),
                    OperationKind::Revoke,
                )?;
                return Err(CredentialServiceError::new(
                    CredentialServiceErrorCode::DeadlineExceeded,
                ));
            }
            Err(SecretServicePollError::Port(SecretServicePortError::LeaseExpired)) => {
                self.set_lease_state(&lease_key, CredentialLeaseState::Expired)?;
                return Err(expired());
            }
            Err(SecretServicePollError::Port(SecretServicePortError::LeaseRevoked)) => {
                crate::SecretServiceLeaseRevocation::AlreadyRevoked
            }
            Err(error) => return Err(map_poll_error(error)),
        };
        let outcome = match result {
            crate::SecretServiceLeaseRevocation::Revoked => CredentialOutcomeCode::Revoked,
            crate::SecretServiceLeaseRevocation::AlreadyRevoked => {
                CredentialOutcomeCode::AlreadyRevoked
            }
        };
        let mut leases = self.leases.lock().map_err(|_| invariant())?;
        let record = leases.get_mut(&lease_key).ok_or_else(expired)?;
        record.metadata.state = CredentialLeaseState::Revoked;
        record.metadata.outcome = outcome;
        Ok(CredentialResponse::RevokeToken(MetadataResponse {
            metadata: record.metadata.clone(),
        }))
    }

    fn inspect(
        &self,
        request: &CredentialRequest,
        session_key: SessionKey,
    ) -> Result<CredentialResponse, CredentialServiceError> {
        let deadline = Self::operation_deadline(request.deadline_unix_ms())?;
        let key = request.credential_ref().to_canonical_string();
        self.ensure_unlocked(deadline)?;
        if self.has_ambiguous_credential(session_key, &key)? {
            return Err(invariant());
        }
        let lease_key = (session_key, key.clone());
        let record = self
            .leases
            .lock()
            .map_err(|_| invariant())?
            .get(&lease_key)
            .cloned()
            .ok_or_else(expired)?;
        match record.metadata.state {
            CredentialLeaseState::Active => {}
            CredentialLeaseState::Expired => return Err(expired()),
            CredentialLeaseState::Revoked => return Err(revoked()),
            CredentialLeaseState::Unknown => return Err(invariant()),
        }
        let lease = SecretServiceLeaseRef {
            credential_ref: request.credential_ref().clone(),
            metadata: record.metadata.clone(),
        };
        let inspection = match Self::poll_port_raw(self.port.inspect_lease(&lease), deadline) {
            Ok(inspection) => inspection,
            Err(SecretServicePollError::Port(SecretServicePortError::LeaseExpired)) => {
                self.leases
                    .lock()
                    .map_err(|_| invariant())?
                    .get_mut(&lease_key)
                    .ok_or_else(expired)?
                    .metadata
                    .state = CredentialLeaseState::Expired;
                return Err(expired());
            }
            Err(SecretServicePollError::Port(SecretServicePortError::LeaseRevoked)) => {
                self.leases
                    .lock()
                    .map_err(|_| invariant())?
                    .get_mut(&lease_key)
                    .ok_or_else(expired)?
                    .metadata
                    .state = CredentialLeaseState::Revoked;
                return Err(revoked());
            }
            Err(SecretServicePollError::Port(SecretServicePortError::CompletionUnknown)) => {
                self.mark_metadata_unknown(&lease_key)?;
                self.mark_ambiguous(
                    session_key,
                    &key,
                    request.idempotency_key(),
                    OperationKind::Inspect,
                )?;
                return Err(invariant());
            }
            Err(SecretServicePollError::Deadline) => {
                self.mark_metadata_unknown(&lease_key)?;
                self.mark_ambiguous(
                    session_key,
                    &key,
                    request.idempotency_key(),
                    OperationKind::Inspect,
                )?;
                return Err(CredentialServiceError::new(
                    CredentialServiceErrorCode::DeadlineExceeded,
                ));
            }
            Err(error) => return Err(map_poll_error(error)),
        };
        let mut metadata = lease.metadata;
        metadata.state = inspection.state;
        metadata.source_version = inspection.source_version;
        metadata.rotation_generation = inspection.rotation_generation;
        metadata.expires_at_unix_ms = inspection.expires_at_unix_ms;
        self.leases
            .lock()
            .map_err(|_| invariant())?
            .get_mut(&lease_key)
            .ok_or_else(expired)?
            .metadata = metadata.clone();
        if metadata.state == CredentialLeaseState::Unknown {
            self.mark_ambiguous(
                session_key,
                &key,
                request.idempotency_key(),
                OperationKind::Inspect,
            )?;
            return Err(invariant());
        }
        Ok(CredentialResponse::InspectMetadata(MetadataResponse {
            metadata,
        }))
    }

    fn mark_metadata_unknown(
        &self,
        lease_key: &(SessionKey, String),
    ) -> Result<(), CredentialServiceError> {
        self.set_lease_state(lease_key, CredentialLeaseState::Unknown)
    }

    fn set_lease_state(
        &self,
        lease_key: &(SessionKey, String),
        state: CredentialLeaseState,
    ) -> Result<(), CredentialServiceError> {
        self.leases
            .lock()
            .map_err(|_| invariant())?
            .get_mut(lease_key)
            .ok_or_else(expired)?
            .metadata
            .state = state;
        Ok(())
    }

    /// Revoke every active lease owned by one admitted session and release its
    /// capability authority.
    pub fn disconnect(
        &self,
        authorization: &CredentialAuthorization,
    ) -> Result<(), CredentialServiceError> {
        let _mutation = self.blocking_mutation_guard()?;
        let session_key = self.session_capability(authorization)?.session_key();
        if !self
            .sessions
            .lock()
            .map_err(|_| invariant())?
            .contains_key(&session_key)
        {
            self.discard_session_key(session_key)?;
            return Ok(());
        }
        let deadline = Self::operation_deadline(1_000)?;
        self.close_session_locked(session_key, deadline)
    }

    /// Finalize one admitted session using the same revocation semantics as a
    /// transport disconnect, then prevent further capability minting.
    pub fn finalize_session(
        &self,
        authorization: &CredentialAuthorization,
    ) -> Result<(), CredentialServiceError> {
        let _mutation = self.blocking_mutation_guard()?;
        self.session_capability(authorization)?;
        self.finalized
            .store(true, std::sync::atomic::Ordering::Release);
        self.close_all_sessions_locked(Self::operation_deadline(1_000)?)?;
        self.authority.clear().map_err(|_| invariant())?;
        Ok(())
    }

    /// Finalize every admitted session and prevent later capability minting.
    pub fn drain(&self) -> Result<(), CredentialServiceError> {
        let _mutation = self.blocking_mutation_guard()?;
        self.finalized
            .store(true, std::sync::atomic::Ordering::Release);
        let deadline = Self::operation_deadline(1_000)?;
        self.close_all_sessions_locked(deadline)?;
        self.authority.clear().map_err(|_| invariant())?;
        Ok(())
    }

    fn close_all_sessions_locked(
        &self,
        deadline: std::time::Instant,
    ) -> Result<(), CredentialServiceError> {
        let keys = self
            .sessions
            .lock()
            .map_err(|_| invariant())?
            .keys()
            .copied()
            .collect::<Vec<_>>();
        let mut first_error = None;
        for session_key in keys {
            if let Err(error) = self.close_session_locked(session_key, deadline) {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn close_session_locked(
        &self,
        session_key: SessionKey,
        deadline: std::time::Instant,
    ) -> Result<(), CredentialServiceError> {
        let pending_acquires = self.ambiguous_acquires(session_key)?;
        let mut first_error = None;
        for (credential, idempotency_key, request) in pending_acquires {
            match Self::poll_port_raw(self.port.revoke_ambiguous_lease(&request), deadline) {
                Ok(_)
                | Err(SecretServicePollError::Port(SecretServicePortError::LeaseExpired))
                | Err(SecretServicePollError::Port(SecretServicePortError::LeaseRevoked)) => {
                    self.clear_ambiguous_acquire(session_key, &credential, &idempotency_key)?;
                }
                Err(SecretServicePollError::Deadline) => {
                    first_error.get_or_insert_with(|| {
                        CredentialServiceError::new(CredentialServiceErrorCode::DeadlineExceeded)
                    });
                }
                Err(error) => {
                    first_error.get_or_insert_with(|| map_poll_error(error));
                }
            }
        }

        let pending_refreshes = self.ambiguous_refreshes(session_key)?;
        let pending_refresh_credentials = pending_refreshes
            .iter()
            .map(|(credential, _, _)| credential.clone())
            .collect::<BTreeSet<_>>();
        for (credential, idempotency_key, refresh) in pending_refreshes {
            match Self::poll_port_raw(
                self.port.revoke_ambiguous_refresh(
                    &refresh.lease,
                    &refresh.operation_id,
                    &refresh.idempotency_key,
                ),
                deadline,
            ) {
                Ok(_)
                | Err(SecretServicePollError::Port(SecretServicePortError::LeaseExpired))
                | Err(SecretServicePollError::Port(SecretServicePortError::LeaseRevoked)) => {
                    self.leases
                        .lock()
                        .map_err(|_| invariant())?
                        .remove(&(session_key, credential.clone()));
                    self.clear_ambiguous_refresh(session_key, &credential, &idempotency_key)?;
                }
                Err(SecretServicePollError::Deadline) => {
                    first_error.get_or_insert_with(|| {
                        CredentialServiceError::new(CredentialServiceErrorCode::DeadlineExceeded)
                    });
                }
                Err(error) => {
                    first_error.get_or_insert_with(|| map_poll_error(error));
                }
            }
        }

        let records = self
            .leases
            .lock()
            .map_err(|_| invariant())?
            .iter()
            .filter(|((key, credential), record)| {
                *key == session_key
                    && matches!(
                        record.metadata.state,
                        CredentialLeaseState::Active | CredentialLeaseState::Unknown
                    )
                    && !pending_refresh_credentials.contains(credential)
            })
            .map(|((_, credential), record)| (credential.clone(), record.clone()))
            .collect::<Vec<_>>();

        for (credential, record) in records {
            let lease_key = (session_key, credential.clone());
            let lease = SecretServiceLeaseRef {
                credential_ref: d2b_contracts_resource::v3::ResourceRef::parse(&credential)
                    .map_err(|_| invariant())?,
                metadata: record.metadata,
            };
            match Self::poll_port_raw(self.port.revoke_lease(&lease), deadline) {
                Ok(_)
                | Err(SecretServicePollError::Port(SecretServicePortError::LeaseExpired))
                | Err(SecretServicePollError::Port(SecretServicePortError::LeaseRevoked)) => {
                    self.leases
                        .lock()
                        .map_err(|_| invariant())?
                        .remove(&lease_key);
                    self.clear_ambiguous_for_credential(session_key, &credential)?;
                }
                Err(SecretServicePollError::Port(SecretServicePortError::CompletionUnknown)) => {
                    self.mark_metadata_unknown(&lease_key)?;
                    first_error.get_or_insert_with(invariant);
                }
                Err(SecretServicePollError::Deadline) => {
                    self.mark_metadata_unknown(&lease_key)?;
                    first_error.get_or_insert_with(|| {
                        CredentialServiceError::new(CredentialServiceErrorCode::DeadlineExceeded)
                    });
                }
                Err(error) => {
                    first_error.get_or_insert_with(|| map_poll_error(error));
                }
            }
        }

        let unresolved_leases =
            self.leases
                .lock()
                .map_err(|_| invariant())?
                .iter()
                .any(|((key, _), record)| {
                    *key == session_key
                        && matches!(
                            record.metadata.state,
                            CredentialLeaseState::Active | CredentialLeaseState::Unknown
                        )
                });
        let unresolved_operations = self.has_ambiguous_session(session_key)?;
        if let Some(error) = first_error {
            return Err(error);
        }
        if unresolved_leases || unresolved_operations {
            return Err(invariant());
        }

        self.leases
            .lock()
            .map_err(|_| invariant())?
            .retain(|(key, _), _| *key != session_key);
        self.clear_ambiguous_session(session_key)?;
        self.release_session_key(session_key)?;
        self.sessions
            .lock()
            .map_err(|_| invariant())?
            .remove(&session_key);
        Ok(())
    }
}

fn invariant() -> CredentialServiceError {
    CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure)
}

fn expired() -> CredentialServiceError {
    CredentialServiceError::new(CredentialServiceErrorCode::LeaseExpired)
}

fn revoked() -> CredentialServiceError {
    CredentialServiceError::new(CredentialServiceErrorCode::LeaseRevoked)
}

fn map_poll_error(error: SecretServicePollError) -> CredentialServiceError {
    match error {
        SecretServicePollError::Port(error) => {
            SecretServiceCredentialProvider::map_port_error(error)
        }
        SecretServicePollError::Deadline => {
            CredentialServiceError::new(CredentialServiceErrorCode::DeadlineExceeded)
        }
    }
}
