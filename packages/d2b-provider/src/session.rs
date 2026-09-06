//! The v3 Provider session identity.
//!
//! The ADR45 identity keyed a Provider call by `RealmId` plus an
//! `EndpointRole` peer role. The v3 identity keys it by the Zone's
//! [`ZonePath`] plus the authenticated Zone principal, and the principal is
//! never taken from the request payload.

use d2b_contracts_resource::v3::identity::{AuthenticatedSubjectContext, ServiceName};
use d2b_contracts_resource::v3::{ResourceGeneration, ResourceRef, identity::ReconnectGeneration};
use d2b_contracts_zone_session::v3::zone_routing::ZonePath;

use crate::{descriptor::ProviderDescriptor, error::ProviderRuntimeError};

/// The authenticated identity one admitted Provider call runs under.
///
/// A value of this type exists only when it was derived from an
/// [`AuthenticatedSubjectContext`], which peers cannot deserialize and cannot
/// mutate. There is no constructor that accepts a caller-asserted principal,
/// so a Provider cannot name itself a subject it is not.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionIdentity {
    zone: ZonePath,
    subject_ref: ResourceRef,
    provider_ref: ResourceRef,
    provider_generation: ResourceGeneration,
    session_generation: ReconnectGeneration,
    service: ServiceName,
}

impl SessionIdentity {
    /// Derive the identity from trusted authenticated evidence.
    ///
    /// `zone` is supplied by the local Zone runtime that owns the registry,
    /// not by the peer. The subject must already carry the Provider binding
    /// and Provider/session generations its evidence established.
    pub fn from_authenticated(
        zone: ZonePath,
        subject: &AuthenticatedSubjectContext,
    ) -> Result<Self, ProviderRuntimeError> {
        let provider_ref = subject
            .provider_ref()
            .ok_or(ProviderRuntimeError::MissingProviderBinding)?
            .clone();
        if provider_ref.resource_type().as_str() != "Provider" {
            return Err(ProviderRuntimeError::MissingProviderBinding);
        }
        let provider_generation = subject
            .provider_generation()
            .ok_or(ProviderRuntimeError::MissingProviderBinding)?;
        Ok(Self {
            zone,
            subject_ref: subject.subject_ref().clone(),
            provider_ref,
            provider_generation,
            session_generation: subject.reconnect_generation(),
            service: subject.service().clone(),
        })
    }

    /// The Zone this session is admitted in.
    pub const fn zone(&self) -> &ZonePath {
        &self.zone
    }

    /// The authenticated subject reference.
    pub const fn subject_ref(&self) -> &ResourceRef {
        &self.subject_ref
    }

    /// The bound `Provider/<name>` reference.
    pub const fn provider_ref(&self) -> &ResourceRef {
        &self.provider_ref
    }

    /// The bound Provider resource generation.
    pub const fn provider_generation(&self) -> ResourceGeneration {
        self.provider_generation
    }

    /// Return the authenticated reconnect generation.
    pub const fn session_generation(&self) -> ReconnectGeneration {
        self.session_generation
    }

    /// The selected service.
    pub const fn service(&self) -> &ServiceName {
        &self.service
    }

    /// Require exact agreement with the descriptor being dispatched to.
    ///
    /// Zone, Provider reference, Provider generation, and service must all
    /// match exactly; a near miss is a refusal, never a coercion.
    pub fn matches_descriptor(
        &self,
        descriptor: &ProviderDescriptor,
    ) -> Result<(), ProviderRuntimeError> {
        if self.zone != *descriptor.zone()
            || self.provider_ref != *descriptor.provider_ref()
            || self.provider_generation != descriptor.provider_generation()
            || descriptor
                .session_generation()
                .is_some_and(|generation| generation != self.session_generation)
            || self.service != *descriptor.service()
        {
            return Err(ProviderRuntimeError::SessionIdentityMismatch);
        }
        Ok(())
    }
}

impl std::fmt::Debug for SessionIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SessionIdentity(<redacted>)")
    }
}
