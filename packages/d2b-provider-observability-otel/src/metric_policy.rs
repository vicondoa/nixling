//! Closed metric-label and OTEL resource-attribute policy for the Provider.
//!
//! Metric descriptor policy is shared through the neutral contract crate. The
//! Provider keeps only its resource-attribute admission policy local.

use std::collections::{BTreeMap, BTreeSet};

pub use d2b_contracts_provider::v3::telemetry_policy::label;
pub use d2b_contracts_provider::v3::telemetry_policy::{
    FORBIDDEN_LABEL_KEYS, FORBIDDEN_LABEL_SUFFIXES, IdentityCanaries, LabelDescriptor,
    METRIC_LABEL_POLICY, MetricDescriptor, MetricPolicyError, OTEL_RESOURCE_ATTRIBUTES,
    allowed_values, canonical_descriptor,
    validate_data_point_without_label_key_validation as validate_data_point, validate_descriptor,
    validate_label_key,
};

/// Maximum bytes in one OTEL resource attribute value.
pub const MAX_RESOURCE_ATTRIBUTE_BYTES: usize = 256;

/// Validate one set of attributes before it can enter a telemetry frame.
pub fn validate_resource_attributes(
    attributes: &BTreeMap<String, String>,
) -> Result<(), ResourceAttributeError> {
    let mut seen = BTreeSet::new();
    for (key, value) in attributes {
        if !OTEL_RESOURCE_ATTRIBUTES.contains(&key.as_str()) {
            return Err(ResourceAttributeError::NotAllowlisted);
        }
        if value.is_empty()
            || value.len() > MAX_RESOURCE_ATTRIBUTE_BYTES
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_graphic() || byte == b'/')
            || !seen.insert(key)
            || !valid_resource_attribute_value(key, value)
        {
            return Err(ResourceAttributeError::Invalid);
        }
    }
    Ok(())
}

fn valid_resource_attribute_value(key: &str, value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    if lowered.contains("secret")
        || lowered.contains("credential")
        || lowered.contains("token")
        || lowered.contains("password")
        || lowered.contains("privatekey")
        || lowered.contains("bearer ")
    {
        return false;
    }
    let identity_key = matches!(
        key,
        "d2b.zone"
            | "d2b.provider"
            | "d2b.component"
            | "host.name"
            | "vm.name"
            | "vm.env"
            | "vm.role"
    );
    if identity_key {
        return d2b_contracts_resource::v3::is_canonical_digest(value);
    }
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
}

/// Closed resource-attribute validation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceAttributeError {
    /// The attribute key is outside the OTEL allowlist.
    NotAllowlisted,
    /// The value or set shape is invalid.
    Invalid,
}

impl core::fmt::Display for ResourceAttributeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::NotAllowlisted => "otel-resource-attribute-not-allowlisted",
            Self::Invalid => "otel-resource-attribute-invalid",
        })
    }
}

impl std::error::Error for ResourceAttributeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forbidden_identity_keys_fail_structurally() {
        for key in FORBIDDEN_LABEL_KEYS {
            assert_eq!(
                validate_label_key(key),
                Err(MetricPolicyError::KeyForbidden)
            );
        }
        for key in ["resource_name", "zone_uid", "link_name_hash"] {
            assert!(validate_label_key(key).is_err());
        }
    }

    #[test]
    fn descriptor_validation_rejects_identity_canaries() {
        let descriptor =
            canonical_descriptor("d2b_store_write_duration_seconds").expect("store descriptor");
        let canaries = IdentityCanaries::new(["resource-name"], ["uid-value"], ["Process/name"]);
        let labels = BTreeMap::from([
            ("kind".to_owned(), "single".to_owned()),
            ("outcome".to_owned(), "resource-name".to_owned()),
        ]);
        assert_eq!(
            validate_data_point(&descriptor, &labels, &canaries),
            Err(MetricPolicyError::ValueNotAllowlisted)
        );
    }

    #[test]
    fn data_point_label_set_mismatch_precedes_actual_label_policy() {
        let descriptor = canonical_descriptor("d2b_api_watch_active").expect("watch descriptor");
        let labels = BTreeMap::from([("vm".to_owned(), "work".to_owned())]);

        assert_eq!(
            validate_data_point(&descriptor, &labels, &IdentityCanaries::default()),
            Err(MetricPolicyError::LabelSetMismatch)
        );
    }

    #[test]
    fn resource_attributes_have_a_separate_allowlist() {
        let attributes = BTreeMap::from([
            (
                "d2b.zone".to_owned(),
                "sha256:0000000000000000000000000000000000000000000000000000000000000001"
                    .to_owned(),
            ),
            ("service.version".to_owned(), "0.0.0".to_owned()),
        ]);
        assert!(validate_resource_attributes(&attributes).is_ok());
        assert!(
            validate_resource_attributes(&BTreeMap::from([("zone".to_owned(), "work".to_owned())]))
                .is_err()
        );
        assert!(
            validate_resource_attributes(&BTreeMap::from([(
                "source".to_owned(),
                "credential-canary".to_owned()
            )]))
            .is_err()
        );
    }
}
