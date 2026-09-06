//! Gateway Guest-local ZoneLink transport composition.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    sync::Arc,
};

use crate::{
    AzureRelaySocketConnector, AzureRelayTransportProvider, RelayComponentSessionTransport,
    RelayCredentialBinding, RelayCredentialError, RelayCredentialLease, RelayCredentialRole,
    RelayEnrollmentProof, RelayEnrollmentVerifier, RelayRole, RelayTransportConfig,
    RelayTransportError, RelayTransportSettings, ScopedCredentialClient, ScopedCredentialRequest,
};
use d2b_contracts_resource::v3::ResourceRef;
use d2b_contracts_resource::v3::ZoneId;

use crate::guest_credential::{
    CredentialError, CredentialFilePolicy, GatewayGuestCredentialPort, SealingKey,
};

use std::time::{SystemTime, UNIX_EPOCH};

fn system_now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Closed failures while composing the Gateway Guest ZoneLink transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayGuestZoneLinkError {
    /// The execution or egress Network reference has the wrong ResourceType.
    InvalidPlacement,
    /// The Guest-local sealed credential or sealing key could not be opened.
    CredentialUnavailable,
    /// The selected Relay Provider rejected its non-secret configuration.
    TransportConfiguration,
    /// The Relay carriage or its enrollment proof was refused.
    TransportUnavailable,
    /// The non-secret Guest-local open observation could not be persisted.
    ObservationUnavailable,
}

impl GatewayGuestZoneLinkError {
    /// Return the stable path-free error code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidPlacement => "gateway-guest-zonelink-placement-invalid",
            Self::CredentialUnavailable => "gateway-guest-zonelink-credential-unavailable",
            Self::TransportConfiguration => "gateway-guest-zonelink-transport-invalid",
            Self::TransportUnavailable => "gateway-guest-zonelink-transport-unavailable",
            Self::ObservationUnavailable => "gateway-guest-zonelink-observation-unavailable",
        }
    }
}

impl std::fmt::Display for GatewayGuestZoneLinkError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for GatewayGuestZoneLinkError {}

impl From<CredentialError> for GatewayGuestZoneLinkError {
    fn from(_: CredentialError) -> Self {
        Self::CredentialUnavailable
    }
}

impl From<RelayTransportError> for GatewayGuestZoneLinkError {
    fn from(_: RelayTransportError) -> Self {
        Self::TransportUnavailable
    }
}

enum GatewayGuestCredentialSource {
    Sealed(GatewayGuestCredentialPort),
    Scoped(Arc<dyn ScopedCredentialClient>),
}

#[async_trait::async_trait]
impl ScopedCredentialClient for GatewayGuestCredentialSource {
    async fn read_credential(
        &self,
        request: &ScopedCredentialRequest,
    ) -> Result<RelayCredentialLease, RelayCredentialError> {
        match self {
            Self::Sealed(port) => port.read_credential(request).await,
            Self::Scoped(client) => client.read_credential(request).await,
        }
    }

    async fn revoke_credential(
        &self,
        lease: RelayCredentialLease,
    ) -> Result<(), RelayCredentialError> {
        match self {
            Self::Sealed(port) => port.revoke_credential(lease).await,
            Self::Scoped(client) => client.revoke_credential(lease).await,
        }
    }
}

/// Gateway Guest-local Azure Relay Provider and credential boundary.
///
/// Credential custody is supplied either by the Guest-local sealed bootstrap
/// or an authenticated scoped client. The resulting Provider never exposes
/// credential bytes and returns only an authenticated `OwnedTransport`
/// carrying protected ComponentSession data.
pub struct GatewayGuestZoneLinkRuntime {
    provider: AzureRelayTransportProvider<GatewayGuestCredentialSource, AzureRelaySocketConnector>,
    credential_generation: Option<u64>,
    credential_send_key_digest: Option<[u8; 32]>,
}

impl std::fmt::Debug for GatewayGuestZoneLinkRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("GatewayGuestZoneLinkRuntime(<redacted>)")
    }
}

impl GatewayGuestZoneLinkRuntime {
    /// Open the Guest-local sealed credential and compose the Relay Provider.
    pub fn from_sealed(
        credential_path: impl AsRef<Path>,
        seal_key_path: impl AsRef<Path>,
        execution_ref: ResourceRef,
        network_ref: ResourceRef,
        settings: RelayTransportSettings,
        max_concurrent_sessions: u32,
        connect_timeout_seconds: u32,
        policy: &CredentialFilePolicy,
    ) -> Result<Self, GatewayGuestZoneLinkError> {
        if execution_ref.resource_type().as_str() != "Guest"
            || network_ref.resource_type().as_str() != "Network"
        {
            return Err(GatewayGuestZoneLinkError::InvalidPlacement);
        }
        let sealing_key = SealingKey::load(seal_key_path, policy)?;
        let credentials = GatewayGuestCredentialPort::from_sealed(
            credential_path,
            &sealing_key,
            policy,
            system_now_unix(),
        )?;
        let credential_generation = credentials.credential_generation();
        let credential_send_key_digest = credentials.safe_observation_digest();
        let provider = AzureRelayTransportProvider::new(
            RelayTransportConfig {
                execution_ref,
                network_ref,
                max_concurrent_sessions,
                connect_timeout_seconds,
            },
            crate::RelayEndpoint { settings },
            Arc::new(GatewayGuestCredentialSource::Sealed(credentials)),
            Arc::new(AzureRelaySocketConnector::new()),
        )
        .map_err(|_| GatewayGuestZoneLinkError::TransportConfiguration)?;
        Ok(Self {
            provider,
            credential_generation: Some(credential_generation),
            credential_send_key_digest: Some(credential_send_key_digest),
        })
    }

    /// Compose the Guest-local Relay Provider over a same-Zone typed
    /// Credential session.
    ///
    /// The supplied client owns credential custody and delivery. This
    /// constructor retains only the typed capability; it never opens or
    /// serializes credential material.
    pub fn from_scoped_client(
        credentials: Arc<dyn ScopedCredentialClient>,
        execution_ref: ResourceRef,
        network_ref: ResourceRef,
        settings: RelayTransportSettings,
        max_concurrent_sessions: u32,
        connect_timeout_seconds: u32,
    ) -> Result<Self, GatewayGuestZoneLinkError> {
        if execution_ref.resource_type().as_str() != "Guest"
            || network_ref.resource_type().as_str() != "Network"
        {
            return Err(GatewayGuestZoneLinkError::InvalidPlacement);
        }
        let provider = AzureRelayTransportProvider::new(
            RelayTransportConfig {
                execution_ref,
                network_ref,
                max_concurrent_sessions,
                connect_timeout_seconds,
            },
            crate::RelayEndpoint { settings },
            Arc::new(GatewayGuestCredentialSource::Scoped(credentials)),
            Arc::new(AzureRelaySocketConnector::new()),
        )
        .map_err(|_| GatewayGuestZoneLinkError::TransportConfiguration)?;
        Ok(Self {
            provider,
            credential_generation: None,
            credential_send_key_digest: None,
        })
    }

    /// Persist a non-secret marker after the sealed credential and Guest
    /// runtime have been successfully composed.
    pub fn write_open_observation(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<(), GatewayGuestZoneLinkError> {
        let (Some(credential_generation), Some(credential_send_key_digest)) = (
            self.credential_generation,
            self.credential_send_key_digest,
        ) else {
            return Err(GatewayGuestZoneLinkError::ObservationUnavailable);
        };
        let path = path.as_ref();
        let parent = path
            .parent()
            .ok_or(GatewayGuestZoneLinkError::ObservationUnavailable)?;
        fs::create_dir_all(parent)
            .map_err(|_| GatewayGuestZoneLinkError::ObservationUnavailable)?;
        let file_name = path
            .file_name()
            .ok_or(GatewayGuestZoneLinkError::ObservationUnavailable)?
            .to_string_lossy();
        let temporary = parent.join(format!(".{file_name}.{}", std::process::id()));
        let marker = format!(
            "schemaVersion=1\ngeneration={}\ndigest=sha256:{}\n",
            credential_generation,
            digest_hex(&credential_send_key_digest),
        );
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&temporary)
                .map_err(|_| GatewayGuestZoneLinkError::ObservationUnavailable)?;
            file.write_all(marker.as_bytes())
                .map_err(|_| GatewayGuestZoneLinkError::ObservationUnavailable)?;
            file.sync_all()
                .map_err(|_| GatewayGuestZoneLinkError::ObservationUnavailable)?;
            fs::rename(&temporary, path)
                .map_err(|_| GatewayGuestZoneLinkError::ObservationUnavailable)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    /// Open and enroll one exact Relay carriage for a ZoneLink session.
    pub async fn open_authenticated_transport<V: RelayEnrollmentVerifier>(
        &self,
        role: RelayRole,
        zone: ZoneId,
        credential_ref: ResourceRef,
        execution_ref: ResourceRef,
        binding: RelayCredentialBinding,
        deadline_ms: u32,
        verifier: &V,
        transcript: &[u8],
    ) -> Result<RelayComponentSessionTransport, GatewayGuestZoneLinkError> {
        let credential_role = Self::credential_role(role);
        let request = crate::ScopedCredentialRequest::new(
            zone,
            credential_ref,
            execution_ref,
            credential_role,
            binding,
            deadline_ms,
        )
        .map_err(|_| GatewayGuestZoneLinkError::CredentialUnavailable)?;
        let connection = self
            .provider
            .open_scoped(request)
            .await
            .map_err(GatewayGuestZoneLinkError::from)?;
        let proof = RelayEnrollmentProof::authenticate(
            verifier,
            transcript,
            &connection.enrollment_challenge(),
        )
        .map_err(|_| GatewayGuestZoneLinkError::TransportUnavailable)?;
        connection
            .enroll(proof)
            .await
            .map_err(GatewayGuestZoneLinkError::from)?;
        Ok(RelayComponentSessionTransport::from_connection(connection))
    }

    /// Return the Guest-local Relay Provider's exact credential role mapping.
    pub const fn credential_role(role: RelayRole) -> RelayCredentialRole {
        match role {
            RelayRole::Listener => RelayCredentialRole::Listen,
            RelayRole::Sender => RelayCredentialRole::Send,
        }
    }
}

fn digest_hex(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RelayCredentialMaterial, RelaySecret};
    use crate::guest_credential::GatewayCredential;
    use async_trait::async_trait;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::Path;

    struct ScopedOnlyCredentials;

    #[async_trait]
    impl ScopedCredentialClient for ScopedOnlyCredentials {
        async fn read_credential(
            &self,
            request: &ScopedCredentialRequest,
        ) -> Result<RelayCredentialLease, RelayCredentialError> {
            RelayCredentialLease::new_bound(
                RelayCredentialMaterial::SasToken(RelaySecret::new(b"scoped-token".to_vec())?),
                request.role(),
                2_000,
                request.binding().clone(),
            )
        }

        async fn revoke_credential(
            &self,
            _lease: RelayCredentialLease,
        ) -> Result<(), RelayCredentialError> {
            Ok(())
        }
    }

    fn sealed_runtime(dir: &Path) -> GatewayGuestZoneLinkRuntime {
        let credential_path = dir.join("credential.sealed.json");
        let seal_key =
            SealingKey::from_bytes([7_u8; crate::guest_credential::GATEWAY_SEAL_KEY_LEN]);
        GatewayCredential::enroll_sealed(
            &credential_path,
            &seal_key,
            crate::guest_credential::GatewayCredentialMaterial {
                listen_key_name: "gateway-listen".to_owned(),
                listen_key: "listen-secret".to_owned(),
                send_key_name: "gateway-send".to_owned(),
                send_key: "send-secret".to_owned(),
            },
            crate::guest_credential::CredentialEnvelopeMeta::first(None),
            1,
        )
        .expect("sealed credential");
        let seal_key_path = dir.join("seal.key");
        fs::write(
            &seal_key_path,
            [7_u8; crate::guest_credential::GATEWAY_SEAL_KEY_LEN],
        )
        .expect("seal key");
        fs::set_permissions(&seal_key_path, fs::Permissions::from_mode(0o600))
            .expect("seal key mode");
        GatewayGuestZoneLinkRuntime::from_sealed(
            credential_path,
            seal_key_path,
            ResourceRef::parse("Guest/gateway").expect("Guest ref"),
            ResourceRef::parse("Network/relay-egress").expect("Network ref"),
            RelayTransportSettings::new("relns-d2b-prod", "hc-d2b").expect("Relay settings"),
            32,
            30,
            &CredentialFilePolicy::default(),
        )
        .expect("Guest runtime")
    }

    #[test]
    fn relay_roles_are_selected_without_exposing_credential_material() {
        assert_eq!(
            GatewayGuestZoneLinkRuntime::credential_role(RelayRole::Listener),
            RelayCredentialRole::Listen
        );
        assert_eq!(
            GatewayGuestZoneLinkRuntime::credential_role(RelayRole::Sender),
            RelayCredentialRole::Send
        );
    }

    #[test]
    fn host_execution_is_refused_before_guest_credential_open() {
        let result = GatewayGuestZoneLinkRuntime::from_sealed(
            "credential.sealed.json",
            "seal.key",
            ResourceRef::parse("Host/host").unwrap(),
            ResourceRef::parse("Network/relay").unwrap(),
            RelayTransportSettings::new("relns-d2b-prod", "hc-d2b").unwrap(),
            32,
            30,
            &CredentialFilePolicy::default(),
        );
        assert!(matches!(
            result,
            Err(GatewayGuestZoneLinkError::InvalidPlacement)
        ));
    }

    #[test]
    fn scoped_client_composition_never_requires_a_sealed_credential() {
        let runtime = GatewayGuestZoneLinkRuntime::from_scoped_client(
            Arc::new(ScopedOnlyCredentials),
            ResourceRef::parse("Guest/gateway").unwrap(),
            ResourceRef::parse("Network/relay-egress").unwrap(),
            RelayTransportSettings::new("relns-d2b-prod", "hc-d2b").unwrap(),
            32,
            30,
        )
        .expect("scoped client runtime");
        assert_eq!(
            format!("{runtime:?}"),
            "GatewayGuestZoneLinkRuntime(<redacted>)"
        );
        assert_eq!(
            runtime.write_open_observation("opened").unwrap_err(),
            GatewayGuestZoneLinkError::ObservationUnavailable
        );
    }

    #[test]
    fn open_observation_is_emitted_only_after_successful_sealed_open() {
        let dir = tempfile::tempdir().expect("temporary Guest state");
        let runtime = sealed_runtime(dir.path());
        let marker = dir.path().join("opened");

        runtime
            .write_open_observation(&marker)
            .expect("open observation");

        let marker_text = fs::read_to_string(marker).expect("marker");
        assert_eq!(
            fs::metadata(dir.path().join("opened"))
                .expect("marker metadata")
                .mode()
                & 0o777,
            0o600
        );
        assert!(marker_text.contains("schemaVersion=1\n"));
        assert!(marker_text.contains("generation=1\n"));
        assert!(marker_text.contains("digest=sha256:"));
        assert!(!marker_text.contains("listen-secret"));
        assert!(!marker_text.contains("send-secret"));
    }

    #[test]
    fn missing_or_invalid_sealed_open_emits_no_observation() {
        let dir = tempfile::tempdir().expect("temporary Guest state");
        let missing_marker = dir.path().join("missing-opened");
        let missing = GatewayGuestZoneLinkRuntime::from_sealed(
            dir.path().join("missing.sealed.json"),
            dir.path().join("missing.key"),
            ResourceRef::parse("Guest/gateway").expect("Guest ref"),
            ResourceRef::parse("Network/relay-egress").expect("Network ref"),
            RelayTransportSettings::new("relns-d2b-prod", "hc-d2b").expect("Relay settings"),
            32,
            30,
            &CredentialFilePolicy::default(),
        );
        assert!(missing.is_err());
        assert!(!missing_marker.exists());

        let invalid_credential = dir.path().join("invalid.sealed.json");
        let invalid_key = dir.path().join("invalid.key");
        fs::write(&invalid_credential, b"not-a-sealed-envelope").expect("invalid credential");
        fs::write(
            &invalid_key,
            [7_u8; crate::guest_credential::GATEWAY_SEAL_KEY_LEN],
        )
        .expect("invalid key");
        fs::set_permissions(&invalid_credential, fs::Permissions::from_mode(0o600))
            .expect("invalid credential mode");
        fs::set_permissions(&invalid_key, fs::Permissions::from_mode(0o600))
            .expect("invalid key mode");
        let invalid_marker = dir.path().join("invalid-opened");
        let invalid = GatewayGuestZoneLinkRuntime::from_sealed(
            invalid_credential,
            invalid_key,
            ResourceRef::parse("Guest/gateway").expect("Guest ref"),
            ResourceRef::parse("Network/relay-egress").expect("Network ref"),
            RelayTransportSettings::new("relns-d2b-prod", "hc-d2b").expect("Relay settings"),
            32,
            30,
            &CredentialFilePolicy::default(),
        );
        assert!(invalid.is_err());
        assert!(!invalid_marker.exists());
    }
}
