//! Gateway Guest-only Relay credential delivery.

use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use async_trait::async_trait;
use d2b_contracts_resource::v3::{ResourceRef, ZoneId};
use zeroize::{Zeroize, Zeroizing};

/// Maximum size of one non-secret binding component.
pub const MAX_RELAY_BINDING_COMPONENT_BYTES: usize = 256;

/// Maximum lifetime a Relay credential lease may cover.
pub const MAX_RELAY_LEASE_TTL_MS: u64 = 15 * 60 * 1_000;

/// Maximum number of live Guest-local Relay leases.
pub const MAX_ACTIVE_RELAY_LEASES: usize = 256;

/// Relay credential role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayCredentialRole {
    /// Listener credential.
    Listen,
    /// Sender credential.
    Send,
}

/// Exact ZoneLink/session fence for one credential lease.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RelayCredentialBinding {
    zone_link_uid: String,
    session_id: String,
    reconnect_generation: u64,
    zone: Option<ZoneId>,
}

impl RelayCredentialBinding {
    /// Construct a binding for one authenticated connection.
    pub fn new(
        zone_link_uid: impl Into<String>,
        session_id: impl Into<String>,
        reconnect_generation: u64,
    ) -> Result<Self, RelayCredentialError> {
        let binding = Self {
            zone_link_uid: zone_link_uid.into(),
            session_id: session_id.into(),
            reconnect_generation,
            zone: None,
        };
        if reconnect_generation == 0
            || !valid_binding_component(&binding.zone_link_uid)
            || !valid_binding_component(&binding.session_id)
        {
            return Err(RelayCredentialError::InvalidBinding);
        }
        Ok(binding)
    }

    /// Construct a binding carrying the exact Zone scope for a ResourceClient
    /// credential read.
    pub fn new_scoped(
        zone: ZoneId,
        zone_link_uid: impl Into<String>,
        session_id: impl Into<String>,
        reconnect_generation: u64,
    ) -> Result<Self, RelayCredentialError> {
        let mut binding = Self::new(zone_link_uid, session_id, reconnect_generation)?;
        binding.zone = Some(zone);
        Ok(binding)
    }

    /// Return the exact ZoneLink UID.
    pub fn zone_link_uid(&self) -> &str {
        &self.zone_link_uid
    }

    /// Return the exact session identifier.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Return the reconnect generation.
    pub const fn reconnect_generation(&self) -> u64 {
        self.reconnect_generation
    }

    /// Return the optional same-Zone scope.
    pub const fn zone(&self) -> Option<&ZoneId> {
        self.zone.as_ref()
    }
}

impl fmt::Debug for RelayCredentialBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayCredentialBinding")
            .field("zone_link_uid", &"<redacted>")
            .field("session_id", &"<redacted>")
            .field("reconnect_generation", &self.reconnect_generation)
            .field("has_zone_scope", &self.zone.is_some())
            .finish()
    }
}

/// The narrow Credential read boundary supplied by U10's ResourceClient.
///
/// This request contains only non-secret, same-Zone admission data. The
/// transport Provider does not resolve resources, own Credential rows, or
/// retain a credential registry; U10 supplies the scoped ResourceClient/session
/// gate through this boundary.
#[derive(Clone, PartialEq, Eq)]
pub struct ScopedCredentialRequest {
    zone: ZoneId,
    credential_ref: ResourceRef,
    execution_ref: ResourceRef,
    role: RelayCredentialRole,
    binding: RelayCredentialBinding,
    deadline_ms: u32,
}

impl ScopedCredentialRequest {
    /// Construct a same-Zone, Gateway-Guest-scoped Credential read.
    pub fn new(
        zone: ZoneId,
        credential_ref: ResourceRef,
        execution_ref: ResourceRef,
        role: RelayCredentialRole,
        binding: RelayCredentialBinding,
        deadline_ms: u32,
    ) -> Result<Self, RelayCredentialError> {
        let request = Self {
            zone,
            credential_ref,
            execution_ref,
            role,
            binding,
            deadline_ms,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), RelayCredentialError> {
        if self.credential_ref.resource_type().as_str() != "Credential"
            || self.execution_ref.resource_type().as_str() != "Guest"
            || self.binding.zone() != Some(&self.zone)
            || self.deadline_ms == 0
        {
            return Err(RelayCredentialError::InvalidScope);
        }
        Ok(())
    }

    /// Return the caller's Zone scope.
    pub const fn zone(&self) -> &ZoneId {
        &self.zone
    }

    /// Return the same-Zone Credential resource reference.
    pub const fn credential_ref(&self) -> &ResourceRef {
        &self.credential_ref
    }

    /// Return the Gateway Guest execution reference.
    pub const fn execution_ref(&self) -> &ResourceRef {
        &self.execution_ref
    }

    /// Return the relay role requested by the caller.
    pub const fn role(&self) -> RelayCredentialRole {
        self.role
    }

    /// Return the exact ZoneLink/session/generation binding.
    pub const fn binding(&self) -> &RelayCredentialBinding {
        &self.binding
    }

    /// Return the current bounded acquisition deadline.
    pub const fn deadline_ms(&self) -> u32 {
        self.deadline_ms
    }

    /// Rebind only the attempt deadline without widening scope.
    pub fn with_deadline(&self, deadline_ms: u32) -> Result<Self, RelayCredentialError> {
        Self::new(
            self.zone.clone(),
            self.credential_ref.clone(),
            self.execution_ref.clone(),
            self.role,
            self.binding.clone(),
            deadline_ms,
        )
    }
}

impl fmt::Debug for ScopedCredentialRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScopedCredentialRequest")
            .field("zone", &"<redacted>")
            .field("credential_ref", &"<redacted>")
            .field("execution_ref", &"<redacted>")
            .field("role", &self.role)
            .field("binding", &self.binding)
            .field("deadline_ms", &self.deadline_ms)
            .finish()
    }
}

/// Bounded request context for a binding-aware credential acquisition.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayCredentialRequest {
    role: RelayCredentialRole,
    binding: RelayCredentialBinding,
    deadline_ms: u32,
}

impl RelayCredentialRequest {
    /// Construct a credential request.
    pub const fn new(
        role: RelayCredentialRole,
        binding: RelayCredentialBinding,
        deadline_ms: u32,
    ) -> Self {
        Self {
            role,
            binding,
            deadline_ms,
        }
    }

    /// Return the requested role.
    pub const fn role(&self) -> RelayCredentialRole {
        self.role
    }

    /// Return the exact connection binding.
    pub const fn binding(&self) -> &RelayCredentialBinding {
        &self.binding
    }

    /// Return the bounded acquisition deadline.
    pub const fn deadline_ms(&self) -> u32 {
        self.deadline_ms
    }
}

impl fmt::Debug for RelayCredentialRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayCredentialRequest")
            .field("role", &self.role)
            .field("binding", &self.binding)
            .field("deadline_ms", &self.deadline_ms)
            .finish()
    }
}

/// Bounded zeroizing secret.
pub struct RelaySecret(Zeroizing<Vec<u8>>);

impl RelaySecret {
    /// Construct a non-empty bounded secret.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, RelayCredentialError> {
        let mut bytes = bytes.into();
        if bytes.is_empty() || bytes.len() > 16 * 1024 {
            bytes.zeroize();
            return Err(RelayCredentialError::InvalidSecret);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Borrow bytes only inside the gateway effect adapter.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Clone for RelaySecret {
    fn clone(&self) -> Self {
        Self(Zeroizing::new(self.0.to_vec()))
    }
}

impl fmt::Debug for RelaySecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RelaySecret(<redacted>)")
    }
}

/// Secret material available only inside the gateway Guest.
#[derive(Clone)]
pub enum RelayCredentialMaterial {
    /// SAS rule key material.
    SasRule {
        /// Rule name.
        key_name: RelaySecret,
        /// Rule key.
        key: RelaySecret,
    },
    /// A pre-minted SAS token.
    SasToken(RelaySecret),
    /// An Entra bearer.
    EntraBearer(RelaySecret),
}

impl fmt::Debug for RelayCredentialMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SasRule { .. } => "RelayCredentialMaterial::SasRule(<redacted>)",
            Self::SasToken(_) => "RelayCredentialMaterial::SasToken(<redacted>)",
            Self::EntraBearer(_) => "RelayCredentialMaterial::EntraBearer(<redacted>)",
        })
    }
}

static NEXT_LEASE_ID: AtomicU64 = AtomicU64::new(1);

fn next_lease_id() -> u64 {
    let id = NEXT_LEASE_ID.fetch_add(1, Ordering::Relaxed);
    if id == 0 {
        NEXT_LEASE_ID.fetch_add(1, Ordering::Relaxed)
    } else {
        id
    }
}

/// One short-lived credential lease.
pub struct RelayCredentialLease {
    lease_id: u64,
    material: RelayCredentialMaterial,
    role: RelayCredentialRole,
    expires_at_unix_ms: u64,
    binding: Option<RelayCredentialBinding>,
    drop_hook: Option<Arc<dyn Fn(u64) + Send + Sync>>,
}

impl RelayCredentialLease {
    /// Construct an unbound lease inside a credential Provider.
    ///
    /// The transport binds this lease before it can authenticate a socket.
    pub fn new(
        material: RelayCredentialMaterial,
        role: RelayCredentialRole,
        expires_at_unix_ms: u64,
    ) -> Self {
        Self {
            lease_id: next_lease_id(),
            material,
            role,
            expires_at_unix_ms,
            binding: None,
            drop_hook: None,
        }
    }

    /// Construct a lease already bound to one exact connection.
    pub fn new_bound(
        material: RelayCredentialMaterial,
        role: RelayCredentialRole,
        expires_at_unix_ms: u64,
        binding: RelayCredentialBinding,
    ) -> Result<Self, RelayCredentialError> {
        let mut lease = Self::new(material, role, expires_at_unix_ms);
        lease.binding = Some(binding);
        Ok(lease)
    }

    /// Bind an unbound lease to one exact connection.
    pub fn bind(mut self, binding: RelayCredentialBinding) -> Result<Self, RelayCredentialError> {
        if self.binding.is_some() {
            return Err(RelayCredentialError::AlreadyBound);
        }
        self.binding = Some(binding);
        Ok(self)
    }

    /// Return the opaque lease identifier used for exact revocation.
    pub const fn lease_id(&self) -> u64 {
        self.lease_id
    }

    /// Install a bounded synchronous cleanup hook for this exact lease.
    ///
    /// The hook is invoked when the lease is dropped without an explicit
    /// revoke. It must not block or perform asynchronous work.
    pub fn set_drop_hook(&mut self, hook: Arc<dyn Fn(u64) + Send + Sync>) {
        if self.drop_hook.is_none() {
            self.drop_hook = Some(hook);
        }
    }

    /// Return the lease role.
    pub const fn role(&self) -> RelayCredentialRole {
        self.role
    }

    /// Return the expiry.
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    /// Return the exact binding, if this lease has been admitted.
    pub fn binding(&self) -> Option<&RelayCredentialBinding> {
        self.binding.as_ref()
    }

    /// Return the reconnect generation, or zero for an unbound lease.
    pub fn reconnect_generation(&self) -> u64 {
        self.binding
            .as_ref()
            .map_or(0, RelayCredentialBinding::reconnect_generation)
    }

    /// Borrow material only inside the transport's Guest-local connector.
    pub(crate) fn material(&self) -> &RelayCredentialMaterial {
        &self.material
    }

    /// Clone the lease material into the relay authentication adapter.
    pub(crate) fn auth_credential(
        &self,
    ) -> Result<crate::auth::RelayCredential, crate::auth::RelayError> {
        match self.material() {
            RelayCredentialMaterial::SasRule { key_name, key } => {
                Ok(crate::auth::RelayCredential::Sas {
                    key_name: String::from_utf8(key_name.as_bytes().to_vec())
                        .map_err(|_| crate::auth::RelayError::InvalidCredential)?,
                    key: String::from_utf8(key.as_bytes().to_vec())
                        .map_err(|_| crate::auth::RelayError::InvalidCredential)?,
                })
            }
            RelayCredentialMaterial::SasToken(token) => Ok(crate::auth::RelayCredential::SasToken(
                String::from_utf8(token.as_bytes().to_vec())
                    .map_err(|_| crate::auth::RelayError::InvalidCredential)?,
            )),
            RelayCredentialMaterial::EntraBearer(token) => {
                Ok(crate::auth::RelayCredential::EntraBearer(
                    String::from_utf8(token.as_bytes().to_vec())
                        .map_err(|_| crate::auth::RelayError::InvalidCredential)?,
                ))
            }
        }
    }
}

impl Drop for RelayCredentialLease {
    fn drop(&mut self) {
        if let Some(hook) = self.drop_hook.take() {
            hook(self.lease_id);
        }
    }
}

impl fmt::Debug for RelayCredentialLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayCredentialLease")
            .field("lease_id", &"<opaque>")
            .field("material", &self.material)
            .field("role", &self.role)
            .field("expires_at_unix_ms", &"<redacted>")
            .field("binding", &self.binding)
            .finish()
    }
}

/// Credential Provider failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayCredentialError {
    /// Secret or lease data was invalid.
    InvalidSecret,
    /// Binding data was invalid or incomplete.
    InvalidBinding,
    /// A credential request omitted its exact connection binding.
    BindingRequired,
    /// A lease was already bound to another exact connection.
    AlreadyBound,
    /// A lease did not match the requested exact binding.
    BindingMismatch,
    /// The request did not carry a valid same-Zone Guest scope.
    InvalidScope,
    /// No lease is available.
    Unavailable,
    /// Lease is expired.
    Expired,
    /// Lease has the wrong role.
    RoleMismatch,
    /// The exact lease was not active in the credential Provider.
    UnknownLease,
}

impl fmt::Display for RelayCredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSecret => "relay-credential-invalid",
            Self::InvalidBinding => "relay-credential-binding-invalid",
            Self::BindingRequired => "relay-credential-binding-required",
            Self::AlreadyBound => "relay-credential-already-bound",
            Self::BindingMismatch => "relay-credential-binding-mismatch",
            Self::InvalidScope => "relay-credential-scope-invalid",
            Self::Unavailable => "relay-credential-unavailable",
            Self::Expired => "relay-credential-expired",
            Self::RoleMismatch => "relay-credential-role-mismatch",
            Self::UnknownLease => "relay-credential-unknown-lease",
        })
    }
}

impl std::error::Error for RelayCredentialError {}

fn valid_binding_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_RELAY_BINDING_COMPONENT_BYTES
        && !value.bytes().any(|byte| byte.is_ascii_control())
        && !contains_secret_shape(value)
}

fn contains_secret_shape(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    [
        "sharedaccesssignature",
        "bearer ",
        "begin private key",
        "token=",
        "password=",
    ]
    .iter()
    .any(|marker| value.contains(marker))
}

/// Typed credential effect boundary.
#[async_trait]
pub trait RelayCredentialPort: Send + Sync {
    /// Acquire a short-lived lease for one role.
    async fn acquire(
        &self,
        role: RelayCredentialRole,
        deadline_ms: u32,
    ) -> Result<RelayCredentialLease, RelayCredentialError>;

    /// Acquire and bind a lease to one exact ZoneLink/session/generation.
    async fn acquire_bound(
        &self,
        _role: RelayCredentialRole,
        _binding: &RelayCredentialBinding,
        _deadline_ms: u32,
    ) -> Result<RelayCredentialLease, RelayCredentialError> {
        Err(RelayCredentialError::BindingRequired)
    }

    /// Alias for callers that model acquisition as a request.
    async fn acquire_for(
        &self,
        request: &RelayCredentialRequest,
    ) -> Result<RelayCredentialLease, RelayCredentialError> {
        self.acquire_bound(request.role(), request.binding(), request.deadline_ms())
            .await
    }

    /// Revoke one exact lease.
    async fn revoke(&self, lease: RelayCredentialLease) -> Result<(), RelayCredentialError>;
}

/// Narrow scoped credential-client boundary consumed by the Relay carriage.
///
/// U10 implements this boundary with its authenticated same-Zone
/// `ResourceClient`/ComponentSession path. It deliberately exposes no list,
/// watch, mutation, Host, or ZoneLink scheduling operations.
#[async_trait]
pub trait ScopedCredentialClient: Send + Sync {
    /// Read one role credential under the already validated scope.
    async fn read_credential(
        &self,
        request: &ScopedCredentialRequest,
    ) -> Result<RelayCredentialLease, RelayCredentialError>;

    /// Revoke one exact lease.
    async fn revoke_credential(
        &self,
        lease: RelayCredentialLease,
    ) -> Result<(), RelayCredentialError>;
}
