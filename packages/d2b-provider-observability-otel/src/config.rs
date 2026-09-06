//! Installation-wide observability Provider configuration.

use serde::{Deserialize, Serialize};

/// Provider configuration error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    /// An unknown field or unsupported value was supplied.
    Invalid,
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("observability-provider-config-invalid")
    }
}

impl std::error::Error for ConfigError {}

/// Rejectable ambient credential-chain environment variables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmbientCredentialError {
    /// A process environment variable would let the exporter acquire an
    /// unbound credential outside the Resource/ComponentSession contract.
    ChainDetected,
}

impl core::fmt::Display for AmbientCredentialError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("observability-ambient-credential-chain")
    }
}

impl std::error::Error for AmbientCredentialError {}

const FORBIDDEN_AMBIENT_KEYS: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_CONFIG_FILE",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_EC2_METADATA_SERVICE_ENDPOINT",
    "AWS_PROFILE",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN",
    "AZURE_CLIENT_CERTIFICATE_PATH",
    "AZURE_CLIENT_ID",
    "AZURE_CLIENT_SECRET",
    "AZURE_FEDERATED_TOKEN_FILE",
    "AZURE_TENANT_ID",
    "AZURE_USERNAME",
    "AZURE_PASSWORD",
    "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE",
    "CLOUDSDK_CONFIG",
    "GCE_METADATA_HOST",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_GHA_CREDS_PATH",
    "GOOGLE_OAUTH_ACCESS_TOKEN",
    "IDENTITY_ENDPOINT",
    "MSI_ENDPOINT",
    "OTEL_EXPORTER_OTLP_AUTH",
    "OTEL_EXPORTER_OTLP_CERTIFICATE",
    "OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE",
    "OTEL_EXPORTER_OTLP_CLIENT_KEY",
    "OTEL_EXPORTER_OTLP_HEADERS",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_LOGS_CERTIFICATE",
    "OTEL_EXPORTER_OTLP_LOGS_CLIENT_CERTIFICATE",
    "OTEL_EXPORTER_OTLP_LOGS_CLIENT_KEY",
    "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
    "OTEL_EXPORTER_OTLP_LOGS_HEADERS",
    "OTEL_EXPORTER_OTLP_METRICS_CERTIFICATE",
    "OTEL_EXPORTER_OTLP_METRICS_CLIENT_CERTIFICATE",
    "OTEL_EXPORTER_OTLP_METRICS_CLIENT_KEY",
    "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
    "OTEL_EXPORTER_OTLP_METRICS_HEADERS",
    "OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE",
    "OTEL_EXPORTER_OTLP_TRACES_CLIENT_CERTIFICATE",
    "OTEL_EXPORTER_OTLP_TRACES_CLIENT_KEY",
    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    "OTEL_EXPORTER_OTLP_TRACES_HEADERS",
];

/// Refuse exporter credential discovery from the ambient process environment.
///
/// Values are never inspected or copied, so this check cannot retain a
/// credential byte in diagnostics or status.
pub fn reject_ambient_credential_chain(
    keys: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<(), AmbientCredentialError> {
    if keys
        .into_iter()
        .any(|key| FORBIDDEN_AMBIENT_KEYS.contains(&key.as_ref()))
    {
        return Err(AmbientCredentialError::ChainDetected);
    }
    Ok(())
}

/// Reject credential-bearing OTEL and cloud SDK variables in the production
/// process environment while inspecting names only.
pub fn reject_process_environment_credential_chain(
) -> Result<(), AmbientCredentialError> {
    reject_ambient_credential_chain(
        std::env::vars_os().filter_map(|(key, _value)| key.into_string().ok()),
    )
}

/// The only installation-wide setting accepted by the Provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderConfig {
    /// Whether bounded self-metrics are exposed.
    pub self_metrics_enable: bool,
}

impl Serialize for ProviderConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_json().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ProviderConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        Self::from_json(&value).map_err(|_| serde::de::Error::custom(ConfigError::Invalid))
    }
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            self_metrics_enable: true,
        }
    }
}

impl ProviderConfig {
    /// Parse the strict root config shape.
    pub fn from_json(value: &serde_json::Value) -> Result<Self, ConfigError> {
        let object = value.as_object().ok_or(ConfigError::Invalid)?;
        let allowed = ["selfMetrics"];
        if object.keys().any(|key| !allowed.contains(&key.as_str())) {
            return Err(ConfigError::Invalid);
        }
        let self_metrics_enable = match object.get("selfMetrics") {
            None => true,
            Some(value) => {
                let object = value.as_object().ok_or(ConfigError::Invalid)?;
                if object.keys().any(|key| key != "enable") {
                    return Err(ConfigError::Invalid);
                }
                object
                    .get("enable")
                    .and_then(serde_json::Value::as_bool)
                    .ok_or(ConfigError::Invalid)?
            }
        };
        Ok(Self {
            self_metrics_enable,
        })
    }

    /// Return the canonical provider-neutral JSON shape.
    pub fn to_json(self) -> serde_json::Value {
        serde_json::json!({
            "selfMetrics": {
                "enable": self.self_metrics_enable
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_self_metrics_is_accepted() {
        let config = ProviderConfig::from_json(&serde_json::json!({})).unwrap();
        assert!(config.self_metrics_enable);
        assert!(
            ProviderConfig::from_json(&serde_json::json!({
                "serviceRef": "TelemetryService/one"
            }))
            .is_err()
        );
        assert!(
            ProviderConfig::from_json(&serde_json::json!({
                "selfMetrics": {"enable": "yes"}
            }))
            .is_err()
        );
    }

    #[test]
    fn ambient_exporter_credential_chains_are_rejected_without_reading_values() {
        assert_eq!(
            reject_ambient_credential_chain([
                "OTEL_EXPORTER_OTLP_HEADERS",
                "OTEL_EXPORTER_OTLP_METRICS_HEADERS",
                "AWS_WEB_IDENTITY_TOKEN_FILE",
                "GOOGLE_GHA_CREDS_PATH",
            ]),
            Err(AmbientCredentialError::ChainDetected)
        );
        assert_eq!(
            reject_ambient_credential_chain(["RUST_LOG", "PATH"]),
            Ok(())
        );
    }
}
