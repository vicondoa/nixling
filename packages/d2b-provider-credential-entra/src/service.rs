//! Credential service dispatch for the identity-Guest client.

use d2b_contracts_provider::v3::credential::{
    CREDENTIAL_SERVICE_NAME, CredentialAuthorization, CredentialLeaseState, CredentialMetadata,
    CredentialMethod, CredentialOutcomeCode, CredentialProvider, CredentialRequest,
    CredentialResponse, CredentialServiceError, CredentialServiceErrorCode, DeliveryResponse,
    MetadataResponse,
};
use d2b_contracts_resource::v3::ResourceRef;
use d2b_contracts_resource::v3::identity::Locality;

use crate::{
    CREDENTIAL_SESSION_PURPOSE, EntraClientState, EntraCredentialProvider, EntraLeaseInspection,
    EntraLeaseRef, EntraLeaseRequest, LeaseRecord,
};

#[async_trait::async_trait]
impl CredentialProvider for EntraCredentialProvider {
    fn dispatch(
        &self,
        method: CredentialMethod,
        request: &CredentialRequest,
        authorization: &CredentialAuthorization,
    ) -> Result<CredentialResponse, CredentialServiceError> {
        self.authorize_request(method, request, authorization)?;
        match method {
            CredentialMethod::AcquireToken => self.acquire(request, authorization),
            CredentialMethod::RefreshToken => self.refresh(request, authorization),
            CredentialMethod::RevokeToken => self.revoke(request),
            CredentialMethod::InspectMetadata => self.inspect(request),
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
        self.authorize_request(method, request, authorization)?;
        let _mutation = self.async_mutation_gate.lock().await;
        match method {
            CredentialMethod::AcquireToken => self.acquire_async(request, authorization).await,
            CredentialMethod::RefreshToken => self.refresh_async(request, authorization).await,
            CredentialMethod::RevokeToken => self.revoke_async(request).await,
            CredentialMethod::InspectMetadata => self.inspect_async(request).await,
            CredentialMethod::SignChallenge => Err(CredentialServiceError::new(
                CredentialServiceErrorCode::Malformed,
            )),
        }
    }
}

#[async_trait::async_trait]
impl CredentialProvider for &EntraCredentialProvider {
    fn dispatch(
        &self,
        method: CredentialMethod,
        request: &CredentialRequest,
        authorization: &CredentialAuthorization,
    ) -> Result<CredentialResponse, CredentialServiceError> {
        (*self).dispatch(method, request, authorization)
    }

    async fn dispatch_async(
        &self,
        method: CredentialMethod,
        request: &CredentialRequest,
        authorization: &CredentialAuthorization,
    ) -> Result<CredentialResponse, CredentialServiceError> {
        (*self)
            .dispatch_async(method, request, authorization)
            .await
    }
}

impl EntraCredentialProvider {
    fn authorize_request(
        &self,
        method: CredentialMethod,
        request: &CredentialRequest,
        authorization: &CredentialAuthorization,
    ) -> Result<(), CredentialServiceError> {
        if authorization.user_ref().is_some() {
            return Err(denied());
        }
        let subject = authorization
            .authenticated_subject_context()
            .ok_or_else(denied)?;
        let session = authorization.authenticated_session().ok_or_else(denied)?;
        if session.authenticated_subject() != subject {
            return Err(denied());
        }
        let controller_session = self.is_controller_session(subject);
        let consumer_session = subject.transport_binding().locality() == Locality::Local
            && subject.subject_ref() == self.consumer_ref()
            && subject.execution_ref() == Some(self.placement.execution_ref())
            && subject
                .execution_ref()
                .is_some_and(|execution| execution.resource_type().as_str() == "Guest")
            && subject
                .provider_ref()
                .is_some_and(|provider| provider.to_canonical_string() == crate::PROVIDER_REF)
            && subject.provider_generation().is_some()
            && subject.service().as_str() == CREDENTIAL_SERVICE_NAME
            && subject.session_purpose().as_str() == CREDENTIAL_SESSION_PURPOSE;
        if !controller_session && !consumer_session {
            return Err(denied());
        }
        self.placement
            .validate_zone(subject.zone_ref())
            .map_err(|_| denied())?;
        if request.credential_ref().resource_type().as_str() != "Credential" {
            return Err(denied());
        }
        Self::time_bound_instant(request.requested_expiry_unix_ms())?;
        Self::operation_deadline(request.deadline_unix_ms())?;
        Self::time_bound_instant(session.expires_at_unix_ms()).map_err(|_| denied())?;
        if !Self::time_bounds_not_after(
            request.deadline_unix_ms(),
            request.requested_expiry_unix_ms(),
        )? || !Self::time_bounds_not_after(
            request.deadline_unix_ms(),
            session.expires_at_unix_ms(),
        )
        .map_err(|_| denied())?
        {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::DeadlineExceeded,
            ));
        }
        if method.requires_delivery() {
            let delivery = authorization
                .delivery_session_params()
                .ok_or_else(invariant)?;
            Self::time_bound_instant(delivery.expiry_unix_ms())?;
            Self::operation_deadline(delivery.deadline_unix_ms())?;
            if delivery.credential_ref() != request.credential_ref()
                || delivery.operation_class() != method.operation_class()
                || delivery.consumer_provider_ref() != self.consumer_ref()
                || subject.provider_generation() != Some(delivery.consumer_component_generation())
                || !Self::time_bounds_not_after(
                    delivery.deadline_unix_ms(),
                    delivery.expiry_unix_ms(),
                )?
                || !Self::time_bounds_not_after(
                    delivery.deadline_unix_ms(),
                    request.deadline_unix_ms(),
                )?
                || !Self::time_bounds_not_after(
                    delivery.expiry_unix_ms(),
                    request.requested_expiry_unix_ms(),
                )?
                || !Self::time_bounds_not_after(
                    delivery.deadline_unix_ms(),
                    session.expires_at_unix_ms(),
                )
                .map_err(|_| denied())?
            {
                return Err(denied());
            }
        } else if authorization.delivery_session_params().is_some() {
            return Err(invariant());
        }
        Ok(())
    }

    async fn acquire_async(
        &self,
        request: &CredentialRequest,
        authorization: &CredentialAuthorization,
    ) -> Result<CredentialResponse, CredentialServiceError> {
        let delivery = authorization
            .delivery_session_params()
            .cloned()
            .ok_or_else(invariant)?;
        let deadline = Self::operation_deadline(request.deadline_unix_ms())?;
        let key = request.credential_ref().to_canonical_string();
        self.ensure_client_ready_async(deadline).await?;
        self.ensure_lifecycle_active(&key)?;
        if self
            .cleanup_leases
            .lock()
            .map_err(|_| invariant())?
            .get(&key)
            .is_some_and(|records| !records.is_empty())
        {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::ProviderUnavailable,
            ));
        }
        let existing = {
            let leases = self.leases.lock().map_err(|_| invariant())?;
            leases.get(&key).cloned()
        };
        let active_leases = self
            .leases
            .lock()
            .map_err(|_| invariant())?
            .values()
            .filter(|record| record.metadata.state == CredentialLeaseState::Active)
            .count();
        if let Some(ref existing) = existing {
            if existing.pending_acquire_idempotency.as_deref() == Some(request.idempotency_key()) {
            } else if existing.pending_acquire_idempotency.is_some() {
                return Err(CredentialServiceError::new(
                    CredentialServiceErrorCode::ProviderUnavailable,
                ));
            } else if existing.metadata.state == CredentialLeaseState::Active
                && existing.idempotency_key == request.idempotency_key()
            {
                return Ok(CredentialResponse::AcquireToken(DeliveryResponse {
                    metadata: existing.metadata.clone(),
                    delivery_session_params: delivery,
                }));
            }
            let active_after_replacement = active_leases.saturating_sub(usize::from(
                existing.metadata.state == CredentialLeaseState::Active,
            ));
            if active_after_replacement >= self.config.max_leases() as usize {
                return Err(CredentialServiceError::new(
                    CredentialServiceErrorCode::ProviderUnavailable,
                ));
            }
        } else if active_leases >= self.config.max_leases() as usize {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::ProviderUnavailable,
            ));
        }
        let client_request = EntraLeaseRequest {
            credential_ref: request.credential_ref().clone(),
            operation_id: request.operation_id().to_owned(),
            idempotency_key: request.idempotency_key().to_owned(),
            requested_expiry_unix_ms: request.requested_expiry_unix_ms(),
            endpoint_generation: self.placement.endpoint_generation(),
        };
        let grant = match await_client(self.client.issue_lease(&client_request), deadline).await {
            Ok(grant) => grant,
            Err(error) => {
                if existing.as_ref().is_some_and(|record| {
                    record.metadata.state == CredentialLeaseState::Active
                        && matches!(
                            error.code(),
                            CredentialServiceErrorCode::DeadlineExceeded
                                | CredentialServiceErrorCode::InvariantFailure
                        )
                }) {
                    self.mark_pending_acquire(&key, request.idempotency_key());
                }
                return Err(error);
            }
        };
        let metadata = match Self::grant_metadata(grant.clone(), request.requested_expiry_unix_ms())
        {
            Ok(metadata) => metadata,
            Err(error) => {
                self.cleanup_uncommitted_grant_async(
                    request.credential_ref(),
                    request.idempotency_key(),
                    grant,
                    request.requested_expiry_unix_ms(),
                    deadline,
                )
                .await;
                return Err(error);
            }
        };
        if let Some(existing) = existing.as_ref()
            && existing.metadata.state != CredentialLeaseState::Revoked
        {
            let lease = EntraLeaseRef {
                credential_ref: request.credential_ref().clone(),
                metadata: existing.metadata.clone(),
                endpoint_generation: self.placement.endpoint_generation(),
            };
            if let Err(error) = await_client(self.client.revoke_lease(&lease), deadline).await
                && !matches!(
                    error.code(),
                    CredentialServiceErrorCode::LeaseExpired
                        | CredentialServiceErrorCode::LeaseRevoked
                )
            {
                return Err(error);
            }
        }
        self.leases
            .lock()
            .map_err(|_| invariant())?
            .insert(
                key,
                LeaseRecord {
                    idempotency_key: request.idempotency_key().to_owned(),
                    pending_acquire_idempotency: None,
                    metadata: metadata.clone(),
                    refresh_attempts: 0,
                    health: crate::EntraResourceHealth::Ready,
                },
            );
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
            .ok_or_else(invariant)?;
        let deadline = Self::operation_deadline(request.deadline_unix_ms())?;
        let key = request.credential_ref().to_canonical_string();
        self.ensure_client_ready_async(deadline).await?;
        self.ensure_lifecycle_active(&key)?;
        let record = self
            .leases
            .lock()
            .map_err(|_| invariant())?
            .get(&key)
            .cloned()
            .ok_or_else(expired)?;
        if record.metadata.state != CredentialLeaseState::Active {
            return Err(error_for_state(record.metadata.state));
        }
        if record.refresh_attempts >= crate::MAX_REFRESH_ATTEMPTS {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::ProviderUnavailable,
            ));
        }
        let lease = EntraLeaseRef {
            credential_ref: request.credential_ref().clone(),
            metadata: record.metadata.clone(),
            endpoint_generation: self.placement.endpoint_generation(),
        };
        let inspection = match await_client(self.client.inspect_lease(&lease), deadline).await {
            Ok(inspection) => inspection,
            Err(error) => {
                self.record_refresh_failure(&key);
                return Err(error);
            }
        };
        let inspected_metadata = self.adopt_inspection(&key, inspection, true)?;
        if inspected_metadata.state != CredentialLeaseState::Active {
            return Err(error_for_state(inspected_metadata.state));
        }
        let lease = EntraLeaseRef {
            credential_ref: request.credential_ref().clone(),
            metadata: inspected_metadata,
            endpoint_generation: self.placement.endpoint_generation(),
        };
        let grant = match await_client(self.client.refresh_lease(&lease), deadline).await {
            Ok(grant) => grant,
            Err(error) => {
                self.record_refresh_failure(&key);
                return Err(error);
            }
        };
        if grant.rotation_generation < lease.metadata.rotation_generation {
            self.record_refresh_failure(&key);
            return Err(invariant());
        }
        let metadata = match Self::grant_metadata(grant.clone(), request.requested_expiry_unix_ms())
        {
            Ok(metadata) => metadata,
            Err(error) => {
                if !self.adopt_committed_refresh(&key, request.idempotency_key(), grant)? {
                    self.record_refresh_failure(&key);
                }
                return Err(error);
            }
        };
        self.leases
            .lock()
            .map_err(|_| invariant())?
            .insert(
                key,
                LeaseRecord {
                    idempotency_key: request.idempotency_key().to_owned(),
                    pending_acquire_idempotency: record.pending_acquire_idempotency,
                    metadata: metadata.clone(),
                    refresh_attempts: 0,
                    health: crate::EntraResourceHealth::Ready,
                },
            );
        Ok(CredentialResponse::RefreshToken(DeliveryResponse {
            metadata,
            delivery_session_params: delivery,
        }))
    }

    async fn revoke_async(
        &self,
        request: &CredentialRequest,
    ) -> Result<CredentialResponse, CredentialServiceError> {
        let deadline = Self::operation_deadline(request.deadline_unix_ms())?;
        let key = request.credential_ref().to_canonical_string();
        self.ensure_client_ready_async(deadline).await?;
        let primary = self
            .leases
            .lock()
            .map_err(|_| invariant())?
            .get(&key)
            .cloned();
        let cleanup_records = self
            .cleanup_leases
            .lock()
            .map_err(|_| invariant())?
            .get(&key)
            .cloned()
            .unwrap_or_default();
        if primary.is_none() && cleanup_records.is_empty() {
            return Err(expired());
        }
        let mut outcome = primary
            .as_ref()
            .filter(|record| record.metadata.state == CredentialLeaseState::Revoked)
            .map(|_| CredentialOutcomeCode::AlreadyRevoked);
        if let Some(record) = primary.as_ref()
            && record.metadata.state != CredentialLeaseState::Revoked
        {
            let lease = EntraLeaseRef {
                credential_ref: request.credential_ref().clone(),
                metadata: record.metadata.clone(),
                endpoint_generation: self.placement.endpoint_generation(),
            };
            outcome = Some(
                match await_client(self.client.revoke_lease(&lease), deadline).await {
                    Ok(crate::EntraLeaseRevocation::Revoked) => CredentialOutcomeCode::Revoked,
                    Ok(crate::EntraLeaseRevocation::AlreadyRevoked) => {
                        CredentialOutcomeCode::AlreadyRevoked
                    }
                    Err(error)
                        if matches!(
                            error.code(),
                            CredentialServiceErrorCode::LeaseExpired
                                | CredentialServiceErrorCode::LeaseRevoked
                        ) =>
                    {
                        CredentialOutcomeCode::AlreadyRevoked
                    }
                    Err(error) => return Err(error),
                },
            );
        }
        for record in &cleanup_records {
            let lease = EntraLeaseRef {
                credential_ref: request.credential_ref().clone(),
                metadata: record.metadata.clone(),
                endpoint_generation: self.placement.endpoint_generation(),
            };
            match await_client(self.client.revoke_lease(&lease), deadline).await {
                Ok(crate::EntraLeaseRevocation::Revoked)
                | Ok(crate::EntraLeaseRevocation::AlreadyRevoked) => {}
                Err(error)
                    if matches!(
                        error.code(),
                        CredentialServiceErrorCode::LeaseExpired
                            | CredentialServiceErrorCode::LeaseRevoked
                    ) => {}
                Err(error) => return Err(error),
            }
        }
        let metadata = if primary.is_some() {
            let mut leases = self.leases.lock().map_err(|_| invariant())?;
            let record = leases.get_mut(&key).ok_or_else(expired)?;
            record.metadata.state = CredentialLeaseState::Revoked;
            record.metadata.outcome = outcome.unwrap_or(CredentialOutcomeCode::Revoked);
            record.pending_acquire_idempotency = None;
            record.health = crate::EntraResourceHealth::Revoked;
            record.metadata.clone()
        } else {
            let mut metadata = cleanup_records
                .first()
                .map(|record| record.metadata.clone())
                .ok_or_else(expired)?;
            metadata.state = CredentialLeaseState::Revoked;
            metadata.outcome = CredentialOutcomeCode::AlreadyRevoked;
            metadata
        };
        self.cleanup_leases
            .lock()
            .map_err(|_| invariant())?
            .remove(&key);
        Ok(CredentialResponse::RevokeToken(MetadataResponse { metadata }))
    }

    async fn inspect_async(
        &self,
        request: &CredentialRequest,
    ) -> Result<CredentialResponse, CredentialServiceError> {
        let deadline = Self::operation_deadline(request.deadline_unix_ms())?;
        let key = request.credential_ref().to_canonical_string();
        self.ensure_client_ready_async(deadline).await?;
        let record = self
            .leases
            .lock()
            .map_err(|_| invariant())?
            .get(&key)
            .cloned()
            .ok_or_else(expired)?;
        if record.metadata.state == CredentialLeaseState::Revoked {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::LeaseRevoked,
            ));
        }
        let lease = EntraLeaseRef {
            credential_ref: request.credential_ref().clone(),
            metadata: record.metadata,
            endpoint_generation: self.placement.endpoint_generation(),
        };
        let inspection = await_client(self.client.inspect_lease(&lease), deadline).await?;
        let metadata = self.adopt_inspection(&key, inspection, false)?;
        match metadata.state {
            CredentialLeaseState::Active => {
                Ok(CredentialResponse::InspectMetadata(MetadataResponse { metadata }))
            }
            state => Err(error_for_state(state)),
        }
    }

    fn is_controller_session(
        &self,
        subject: &d2b_contracts_resource::v3::identity::AuthenticatedSubjectContext,
    ) -> bool {
        subject.transport_binding().locality() == Locality::Local
            && subject.subject_ref().to_canonical_string() == crate::PROVIDER_REF
            && subject
                .provider_ref()
                .is_some_and(|provider| provider.to_canonical_string() == crate::PROVIDER_REF)
            && subject.service().as_str() == CREDENTIAL_SERVICE_NAME
            && subject.session_purpose().as_str() == "provider-control"
            && subject
                .provider_generation()
                .is_some_and(|generation| generation.get() == self.placement.endpoint_generation())
            && subject
                .process_ref()
                .is_some_and(|process| process.resource_type().as_str() == "Process")
            && self.placement.validate_zone(subject.zone_ref()).is_ok()
    }

    fn acquire(
        &self,
        request: &CredentialRequest,
        authorization: &CredentialAuthorization,
    ) -> Result<CredentialResponse, CredentialServiceError> {
        let delivery = authorization
            .delivery_session_params()
            .cloned()
            .ok_or_else(invariant)?;
        let deadline = Self::operation_deadline(request.deadline_unix_ms())?;
        let _mutation = self.mutation_guard()?;
        let key = request.credential_ref().to_canonical_string();
        self.ensure_lifecycle_active(&key)?;
        self.ensure_client_ready(deadline)?;
        if self
            .cleanup_leases
            .lock()
            .map_err(|_| invariant())?
            .get(&key)
            .is_some_and(|records| !records.is_empty())
        {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::ProviderUnavailable,
            ));
        }
        let existing = {
            let leases = self.leases.lock().map_err(|_| invariant())?;
            leases.get(&key).cloned()
        };
        let active_leases = self
            .leases
            .lock()
            .map_err(|_| invariant())?
            .values()
            .filter(|record| record.metadata.state == CredentialLeaseState::Active)
            .count();
        if let Some(ref existing) = existing {
            if existing.pending_acquire_idempotency.as_deref() == Some(request.idempotency_key()) {
                // An explicit retry of an ambiguous replacement may ask the
                // identity Guest to resolve its idempotency key.
            } else if existing.pending_acquire_idempotency.is_some() {
                return Err(CredentialServiceError::new(
                    CredentialServiceErrorCode::ProviderUnavailable,
                ));
            } else if existing.metadata.state == CredentialLeaseState::Active
                && existing.idempotency_key == request.idempotency_key()
            {
                return Ok(CredentialResponse::AcquireToken(DeliveryResponse {
                    metadata: existing.metadata.clone(),
                    delivery_session_params: delivery,
                }));
            }
            let active_after_replacement = active_leases.saturating_sub(usize::from(
                existing.metadata.state == CredentialLeaseState::Active,
            ));
            if active_after_replacement >= self.config.max_leases() as usize {
                return Err(CredentialServiceError::new(
                    CredentialServiceErrorCode::ProviderUnavailable,
                ));
            }
        } else if active_leases >= self.config.max_leases() as usize {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::ProviderUnavailable,
            ));
        }
        let client_request = EntraLeaseRequest {
            credential_ref: request.credential_ref().clone(),
            operation_id: request.operation_id().to_owned(),
            idempotency_key: request.idempotency_key().to_owned(),
            requested_expiry_unix_ms: request.requested_expiry_unix_ms(),
            endpoint_generation: self.placement.endpoint_generation(),
        };
        let grant = match Self::poll_client_sync(self.client.issue_lease(&client_request), deadline) {
            Ok(grant) => grant,
            Err(error) => {
                if existing.as_ref().is_some_and(|record| {
                    record.metadata.state == CredentialLeaseState::Active
                        && matches!(
                            error.code(),
                            CredentialServiceErrorCode::DeadlineExceeded
                                | CredentialServiceErrorCode::InvariantFailure
                        )
                }) {
                    self.mark_pending_acquire(&key, request.idempotency_key());
                }
                return Err(error);
            }
        };
        let metadata = match Self::grant_metadata(grant.clone(), request.requested_expiry_unix_ms())
        {
            Ok(metadata) => metadata,
            Err(error) => {
                self.cleanup_uncommitted_grant(
                    request.credential_ref(),
                    request.idempotency_key(),
                    grant,
                    request.requested_expiry_unix_ms(),
                    deadline,
                );
                return Err(error);
            }
        };
        if let Some(existing) = existing.as_ref()
            && existing.metadata.state != CredentialLeaseState::Revoked
        {
            let lease = EntraLeaseRef {
                credential_ref: request.credential_ref().clone(),
                metadata: existing.metadata.clone(),
                endpoint_generation: self.placement.endpoint_generation(),
            };
            if let Err(error) = Self::poll_client_sync(self.client.revoke_lease(&lease), deadline)
                && !matches!(
                    error.code(),
                    CredentialServiceErrorCode::LeaseExpired
                        | CredentialServiceErrorCode::LeaseRevoked
                )
            {
                self.cleanup_uncommitted_grant(
                    request.credential_ref(),
                    request.idempotency_key(),
                    grant,
                    request.requested_expiry_unix_ms(),
                    deadline,
                );
                return Err(error);
            }
        }
        let record = LeaseRecord {
            idempotency_key: request.idempotency_key().to_owned(),
            pending_acquire_idempotency: None,
            metadata: metadata.clone(),
            refresh_attempts: 0,
            health: crate::EntraResourceHealth::Ready,
        };
        if let Err(error) = self
            .leases
            .lock()
            .map_err(|_| invariant())
            .map(|mut leases| {
                leases.insert(key.clone(), record);
            })
        {
            self.cleanup_uncommitted_grant(
                request.credential_ref(),
                request.idempotency_key(),
                grant,
                request.requested_expiry_unix_ms(),
                deadline,
            );
            return Err(error);
        }
        Ok(CredentialResponse::AcquireToken(DeliveryResponse {
            metadata,
            delivery_session_params: delivery,
        }))
    }

    fn refresh(
        &self,
        request: &CredentialRequest,
        authorization: &CredentialAuthorization,
    ) -> Result<CredentialResponse, CredentialServiceError> {
        let delivery = authorization
            .delivery_session_params()
            .cloned()
            .ok_or_else(invariant)?;
        let deadline = Self::operation_deadline(request.deadline_unix_ms())?;
        let _mutation = self.mutation_guard()?;
        let key = request.credential_ref().to_canonical_string();
        self.ensure_lifecycle_active(&key)?;
        self.ensure_client_ready(deadline)?;
        let record = self
            .leases
            .lock()
            .map_err(|_| invariant())?
            .get(&key)
            .cloned()
            .ok_or_else(expired)?;
        if record.metadata.state != CredentialLeaseState::Active {
            return Err(error_for_state(record.metadata.state));
        }
        if record.refresh_attempts >= crate::MAX_REFRESH_ATTEMPTS {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::ProviderUnavailable,
            ));
        }
        let lease = EntraLeaseRef {
            credential_ref: request.credential_ref().clone(),
            metadata: record.metadata.clone(),
            endpoint_generation: self.placement.endpoint_generation(),
        };
        let inspection = match Self::poll_client_sync(self.client.inspect_lease(&lease), deadline) {
            Ok(inspection) => inspection,
            Err(error) => {
                self.record_refresh_failure(&key);
                return Err(error);
            }
        };
        let inspected_metadata = self.adopt_inspection(&key, inspection, true)?;
        if inspected_metadata.state != CredentialLeaseState::Active {
            return Err(error_for_state(inspected_metadata.state));
        }
        let lease = EntraLeaseRef {
            credential_ref: request.credential_ref().clone(),
            metadata: inspected_metadata,
            endpoint_generation: self.placement.endpoint_generation(),
        };
        let grant = match Self::poll_client_sync(self.client.refresh_lease(&lease), deadline) {
            Ok(grant) => grant,
            Err(error) => {
                self.record_refresh_failure(&key);
                return Err(error);
            }
        };
        if grant.rotation_generation < lease.metadata.rotation_generation {
            self.record_refresh_failure(&key);
            return Err(invariant());
        }
        let metadata = match Self::grant_metadata(grant.clone(), request.requested_expiry_unix_ms())
        {
            Ok(metadata) => metadata,
            Err(error) => {
                if !self.adopt_committed_refresh(&key, request.idempotency_key(), grant)? {
                    self.record_refresh_failure(&key);
                }
                return Err(error);
            }
        };
        let pending_acquire_idempotency = record.pending_acquire_idempotency.clone();
        self.leases.lock().map_err(|_| invariant())?.insert(
            key.clone(),
            LeaseRecord {
                idempotency_key: request.idempotency_key().to_owned(),
                pending_acquire_idempotency,
                metadata: metadata.clone(),
                refresh_attempts: 0,
                health: crate::EntraResourceHealth::Ready,
            },
        );
        Ok(CredentialResponse::RefreshToken(DeliveryResponse {
            metadata,
            delivery_session_params: delivery,
        }))
    }

    fn revoke(
        &self,
        request: &CredentialRequest,
    ) -> Result<CredentialResponse, CredentialServiceError> {
        let deadline = Self::operation_deadline(request.deadline_unix_ms())?;
        let _mutation = self.mutation_guard()?;
        let key = request.credential_ref().to_canonical_string();
        self.ensure_client_ready(deadline)?;
        let primary = self
            .leases
            .lock()
            .map_err(|_| invariant())?
            .get(&key)
            .cloned();
        let cleanup_records = self
            .cleanup_leases
            .lock()
            .map_err(|_| invariant())?
            .get(&key)
            .cloned()
            .unwrap_or_default();
        if primary.is_none() && cleanup_records.is_empty() {
            return Err(expired());
        }
        let mut outcome = primary
            .as_ref()
            .filter(|record| record.metadata.state == CredentialLeaseState::Revoked)
            .map(|_| CredentialOutcomeCode::AlreadyRevoked);
        if let Some(record) = primary.as_ref()
            && record.metadata.state != CredentialLeaseState::Revoked
        {
            let lease = EntraLeaseRef {
                credential_ref: request.credential_ref().clone(),
                metadata: record.metadata.clone(),
                endpoint_generation: self.placement.endpoint_generation(),
            };
            outcome = Some(
                match Self::poll_client_sync(self.client.revoke_lease(&lease), deadline) {
                    Ok(crate::EntraLeaseRevocation::Revoked) => CredentialOutcomeCode::Revoked,
                    Ok(crate::EntraLeaseRevocation::AlreadyRevoked) => {
                        CredentialOutcomeCode::AlreadyRevoked
                    }
                    Err(error)
                        if matches!(
                            error.code(),
                            CredentialServiceErrorCode::LeaseExpired
                                | CredentialServiceErrorCode::LeaseRevoked
                        ) =>
                    {
                        CredentialOutcomeCode::AlreadyRevoked
                    }
                    Err(error) => return Err(error),
                },
            );
        }
        for record in &cleanup_records {
            let lease = EntraLeaseRef {
                credential_ref: request.credential_ref().clone(),
                metadata: record.metadata.clone(),
                endpoint_generation: self.placement.endpoint_generation(),
            };
            match Self::poll_client_sync(self.client.revoke_lease(&lease), deadline) {
                Ok(crate::EntraLeaseRevocation::Revoked)
                | Ok(crate::EntraLeaseRevocation::AlreadyRevoked) => {}
                Err(error)
                    if matches!(
                        error.code(),
                        CredentialServiceErrorCode::LeaseExpired
                            | CredentialServiceErrorCode::LeaseRevoked
                    ) => {}
                Err(error) => return Err(error),
            }
        }
        let metadata = if primary.is_some() {
            let mut leases = self.leases.lock().map_err(|_| invariant())?;
            let record = leases.get_mut(&key).ok_or_else(expired)?;
            record.metadata.state = CredentialLeaseState::Revoked;
            record.metadata.outcome = outcome.unwrap_or(CredentialOutcomeCode::Revoked);
            record.pending_acquire_idempotency = None;
            record.health = crate::EntraResourceHealth::Revoked;
            record.metadata.clone()
        } else {
            let mut metadata = cleanup_records
                .first()
                .map(|record| record.metadata.clone())
                .ok_or_else(expired)?;
            metadata.state = CredentialLeaseState::Revoked;
            metadata.outcome = CredentialOutcomeCode::AlreadyRevoked;
            metadata
        };
        self.cleanup_leases
            .lock()
            .map_err(|_| invariant())?
            .remove(&key);
        Ok(CredentialResponse::RevokeToken(MetadataResponse {
            metadata,
        }))
    }

    fn inspect(
        &self,
        request: &CredentialRequest,
    ) -> Result<CredentialResponse, CredentialServiceError> {
        let deadline = Self::operation_deadline(request.deadline_unix_ms())?;
        let _mutation = self.mutation_guard()?;
        self.ensure_client_ready(deadline)?;
        let key = request.credential_ref().to_canonical_string();
        let record = self
            .leases
            .lock()
            .map_err(|_| invariant())?
            .get(&key)
            .cloned()
            .ok_or_else(expired)?;
        if record.metadata.state == CredentialLeaseState::Revoked {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::LeaseRevoked,
            ));
        }
        let lease = EntraLeaseRef {
            credential_ref: request.credential_ref().clone(),
            metadata: record.metadata,
            endpoint_generation: self.placement.endpoint_generation(),
        };
        let inspection = Self::poll_client_sync(self.client.inspect_lease(&lease), deadline)?;
        let metadata = self.adopt_inspection(&key, inspection, false)?;
        match metadata.state {
            CredentialLeaseState::Active => {
                Ok(CredentialResponse::InspectMetadata(MetadataResponse {
                    metadata,
                }))
            }
            state => Err(error_for_state(state)),
        }
    }

    fn adopt_inspection(
        &self,
        key: &str,
        inspection: EntraLeaseInspection,
        count_refresh_failure: bool,
    ) -> Result<d2b_contracts_provider::v3::credential::CredentialMetadata, CredentialServiceError>
    {
        if inspection.rotation_generation == 0 || inspection.expires_at_unix_ms == 0 {
            if count_refresh_failure {
                self.record_refresh_failure(key);
            }
            return Err(invariant());
        }
        let mut leases = self.leases.lock().map_err(|_| invariant())?;
        let record = leases.get_mut(key).ok_or_else(expired)?;
        if record.metadata.state == CredentialLeaseState::Revoked {
            return Err(CredentialServiceError::new(
                CredentialServiceErrorCode::LeaseRevoked,
            ));
        }
        if inspection.rotation_generation < record.metadata.rotation_generation {
            if count_refresh_failure {
                record.refresh_attempts = record
                    .refresh_attempts
                    .saturating_add(1)
                    .min(crate::MAX_REFRESH_ATTEMPTS);
                record.health = crate::EntraResourceHealth::Degraded;
            }
            return Err(invariant());
        }
        if inspection.state == CredentialLeaseState::Unknown {
            if count_refresh_failure {
                record.refresh_attempts = record
                    .refresh_attempts
                    .saturating_add(1)
                    .min(crate::MAX_REFRESH_ATTEMPTS);
                record.health = crate::EntraResourceHealth::Degraded;
            }
            return Err(invariant());
        }
        let state = if inspection.state == CredentialLeaseState::Active
            && crate::EntraCredentialProvider::is_expired_unix_ms(inspection.expires_at_unix_ms)
        {
            CredentialLeaseState::Expired
        } else {
            inspection.state
        };
        record.metadata.state = state;
        record.metadata.source_version = inspection.source_version;
        record.metadata.rotation_generation = inspection.rotation_generation;
        record.metadata.expires_at_unix_ms = inspection.expires_at_unix_ms;
        match state {
            CredentialLeaseState::Active => {}
            CredentialLeaseState::Expired => {
                record.health = crate::EntraResourceHealth::Degraded;
            }
            CredentialLeaseState::Revoked => {
                record.health = crate::EntraResourceHealth::Revoked;
                record.refresh_attempts = 0;
            }
            CredentialLeaseState::Unknown => {
                record.health = crate::EntraResourceHealth::Degraded;
            }
        }
        Ok(record.metadata.clone())
    }

    fn ensure_client_ready(
        &self,
        deadline: std::time::Instant,
    ) -> Result<(), CredentialServiceError> {
        match Self::poll_client_sync(self.client.state(), deadline)? {
            EntraClientState::Ready => Ok(()),
            EntraClientState::InteractionRequired => Err(CredentialServiceError::new(
                CredentialServiceErrorCode::ProviderUnavailable,
            )),
        }
    }

    async fn ensure_client_ready_async(
        &self,
        deadline: std::time::Instant,
    ) -> Result<(), CredentialServiceError> {
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .ok_or_else(|| {
                CredentialServiceError::new(CredentialServiceErrorCode::DeadlineExceeded)
            })?;
        match tokio::time::timeout(remaining, self.client.state())
            .await
            .map_err(|_| {
                CredentialServiceError::new(CredentialServiceErrorCode::DeadlineExceeded)
            })?
            .map_err(Self::map_client_error)?
        {
            EntraClientState::Ready => Ok(()),
            EntraClientState::InteractionRequired => Err(CredentialServiceError::new(
                CredentialServiceErrorCode::ProviderUnavailable,
            )),
        }
    }

    fn mark_pending_acquire(&self, key: &str, idempotency_key: &str) {
        if let Ok(mut leases) = self.leases.lock()
            && let Some(record) = leases.get_mut(key)
        {
            record.pending_acquire_idempotency = Some(idempotency_key.to_owned());
            record.health = crate::EntraResourceHealth::Degraded;
        }
    }

    fn cleanup_uncommitted_grant(
        &self,
        credential_ref: &ResourceRef,
        idempotency_key: &str,
        grant: crate::EntraLeaseGrant,
        requested_expiry_unix_ms: u64,
        deadline: std::time::Instant,
    ) {
        let metadata = CredentialMetadata {
            lease_handle: grant.lease_handle,
            rotation_generation: grant.rotation_generation.max(1),
            source_version: grant.source_version,
            expires_at_unix_ms: if grant.expires_at_unix_ms == 0 {
                requested_expiry_unix_ms
            } else {
                grant.expires_at_unix_ms
            },
            state: CredentialLeaseState::Active,
            outcome: CredentialOutcomeCode::Success,
        };
        let lease = EntraLeaseRef {
            credential_ref: credential_ref.clone(),
            metadata: metadata.clone(),
            endpoint_generation: self.placement.endpoint_generation(),
        };
        let cleanup = Self::poll_client_sync(self.client.revoke_lease(&lease), deadline);
        if cleanup.is_ok()
            || cleanup.as_ref().is_err_and(|error| {
                matches!(
                    error.code(),
                    CredentialServiceErrorCode::LeaseExpired
                        | CredentialServiceErrorCode::LeaseRevoked
                )
            })
        {
            return;
        }
        if let Ok(mut cleanup_leases) = self.cleanup_leases.lock() {
            cleanup_leases
                .entry(credential_ref.to_canonical_string())
                .or_default()
                .push(LeaseRecord {
                    idempotency_key: idempotency_key.to_owned(),
                    pending_acquire_idempotency: None,
                    metadata,
                    refresh_attempts: crate::MAX_REFRESH_ATTEMPTS,
                    health: crate::EntraResourceHealth::Degraded,
                });
        }
    }

    async fn cleanup_uncommitted_grant_async(
        &self,
        credential_ref: &ResourceRef,
        idempotency_key: &str,
        grant: crate::EntraLeaseGrant,
        requested_expiry_unix_ms: u64,
        deadline: std::time::Instant,
    ) {
        let metadata = CredentialMetadata {
            lease_handle: grant.lease_handle,
            rotation_generation: grant.rotation_generation.max(1),
            source_version: grant.source_version,
            expires_at_unix_ms: if grant.expires_at_unix_ms == 0 {
                requested_expiry_unix_ms
            } else {
                grant.expires_at_unix_ms
            },
            state: CredentialLeaseState::Active,
            outcome: CredentialOutcomeCode::Success,
        };
        let lease = EntraLeaseRef {
            credential_ref: credential_ref.clone(),
            metadata: metadata.clone(),
            endpoint_generation: self.placement.endpoint_generation(),
        };
        let cleanup = await_client(self.client.revoke_lease(&lease), deadline).await;
        if cleanup.is_ok()
            || cleanup.as_ref().is_err_and(|error| {
                matches!(
                    error.code(),
                    CredentialServiceErrorCode::LeaseExpired
                        | CredentialServiceErrorCode::LeaseRevoked
                )
            })
        {
            return;
        }
        if let Ok(mut cleanup_leases) = self.cleanup_leases.lock() {
            cleanup_leases
                .entry(credential_ref.to_canonical_string())
                .or_default()
                .push(LeaseRecord {
                    idempotency_key: idempotency_key.to_owned(),
                    pending_acquire_idempotency: None,
                    metadata,
                    refresh_attempts: crate::MAX_REFRESH_ATTEMPTS,
                    health: crate::EntraResourceHealth::Degraded,
                });
        }
    }
}

async fn await_client<T: Send>(
    future: crate::EntraFuture<'_, T>,
    deadline: std::time::Instant,
) -> Result<T, CredentialServiceError> {
    let remaining = deadline
        .checked_duration_since(std::time::Instant::now())
        .ok_or_else(|| {
            CredentialServiceError::new(CredentialServiceErrorCode::DeadlineExceeded)
        })?;
    tokio::time::timeout(remaining, future)
        .await
        .map_err(|_| CredentialServiceError::new(CredentialServiceErrorCode::DeadlineExceeded))?
        .map_err(EntraCredentialProvider::map_client_error)
}

fn invariant() -> CredentialServiceError {
    CredentialServiceError::new(CredentialServiceErrorCode::InvariantFailure)
}

fn denied() -> CredentialServiceError {
    CredentialServiceError::new(CredentialServiceErrorCode::OperationDenied)
}

fn expired() -> CredentialServiceError {
    CredentialServiceError::new(CredentialServiceErrorCode::LeaseExpired)
}

fn error_for_state(state: CredentialLeaseState) -> CredentialServiceError {
    match state {
        CredentialLeaseState::Expired => expired(),
        CredentialLeaseState::Revoked => {
            CredentialServiceError::new(CredentialServiceErrorCode::LeaseRevoked)
        }
        CredentialLeaseState::Active => invariant(),
        CredentialLeaseState::Unknown => invariant(),
    }
}
