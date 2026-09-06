//! Total one-way store-to-resource error mapping.

use d2b_contracts_resource::resource_proto as wire;
use d2b_contracts_resource::v3::{
    ResourceError, ResourceErrorKind, ResourceErrorReason, RetryClass,
};
use d2b_resource_store::{StoreError, StoreErrorKind};
use protobuf::EnumOrUnknown;

/// Map every store error kind onto the closed API set.
pub const fn map_store_error_kind(kind: StoreErrorKind) -> ResourceErrorKind {
    match kind {
        StoreErrorKind::ResourceNotFound => ResourceErrorKind::ResourceNotFound,
        StoreErrorKind::ResourceAlreadyExists => ResourceErrorKind::ResourceAlreadyExists,
        StoreErrorKind::ResourceConflict => ResourceErrorKind::ResourceConflict,
        StoreErrorKind::ResourceSchemaInvalid => ResourceErrorKind::ResourceSchemaInvalid,
        StoreErrorKind::ResourceRefInvalid => ResourceErrorKind::ResourceRefInvalid,
        StoreErrorKind::ResourceOwnerCycle => ResourceErrorKind::ResourceOwnerCycle,
        StoreErrorKind::ResourceOwnerDepth => ResourceErrorKind::ResourceOwnerDepth,
        StoreErrorKind::ResourceFinalizerDenied => ResourceErrorKind::ResourceFinalizerDenied,
        StoreErrorKind::ResourceProviderUnavailable => {
            ResourceErrorKind::ResourceProviderUnavailable
        }
        StoreErrorKind::ResourceControllerMismatch => ResourceErrorKind::ResourceControllerMismatch,
        StoreErrorKind::ResourceStatusOwnerMismatch => {
            ResourceErrorKind::ResourceStatusOwnerMismatch
        }
        StoreErrorKind::StatusOversize => ResourceErrorKind::StatusOversize,
        StoreErrorKind::StatusProviderSchemaInvalid => {
            ResourceErrorKind::StatusProviderSchemaInvalid
        }
        StoreErrorKind::StatusProviderOverlap => ResourceErrorKind::StatusProviderOverlap,
        StoreErrorKind::SpecProviderSchemaInvalid => ResourceErrorKind::SpecProviderSchemaInvalid,
        StoreErrorKind::SpecProviderShadow => ResourceErrorKind::SpecProviderShadow,
        StoreErrorKind::UnsupportedCapability => ResourceErrorKind::UnsupportedCapability,
        StoreErrorKind::ExpeditedNotAuthorized => ResourceErrorKind::ExpeditedNotAuthorized,
        StoreErrorKind::ExpeditedQuotaExceeded => ResourceErrorKind::ExpeditedQuotaExceeded,
        StoreErrorKind::ExpeditedReconcilePending => ResourceErrorKind::ExpeditedReconcilePending,
        StoreErrorKind::UpgradeRequired => ResourceErrorKind::UpgradeRequired,
        StoreErrorKind::EndpointResolveDenied => ResourceErrorKind::EndpointResolveDenied,
        StoreErrorKind::RelayDenied => ResourceErrorKind::RelayDenied,
        StoreErrorKind::RoleRelayGrantRestricted => ResourceErrorKind::RoleRelayGrantRestricted,
        StoreErrorKind::AuthorizationDenied => ResourceErrorKind::AuthorizationDenied,
        StoreErrorKind::RevisionExpired => ResourceErrorKind::RevisionExpired,
        StoreErrorKind::Backpressure | StoreErrorKind::StoreBackpressure => {
            ResourceErrorKind::Backpressure
        }
        StoreErrorKind::Timeout => ResourceErrorKind::Timeout,
        StoreErrorKind::Cancelled => ResourceErrorKind::Cancelled,
        StoreErrorKind::ResourcePlaneUnavailable | StoreErrorKind::StoreQuarantined => {
            ResourceErrorKind::ResourcePlaneUnavailable
        }
        StoreErrorKind::InternalIntegrityFailure | StoreErrorKind::StoreIntegrityFailure => {
            ResourceErrorKind::InternalIntegrityFailure
        }
    }
}

/// Preserve only API-safe fields from a store error.
pub fn map_store_error(error: StoreError) -> ResourceError {
    map_store_error_with_revision_visibility(error, true)
}

/// Preserve revision metadata only after a separate read authorization succeeds.
pub fn map_store_error_with_revision_visibility(
    error: StoreError,
    revision_visible: bool,
) -> ResourceError {
    let mapped = ResourceError::new(
        map_store_error_kind(error.kind()),
        revision_visible.then(|| error.current_revision()).flatten(),
        error.retry_after_ms(),
        error.retry_class(),
        ResourceErrorReason::parse(error.reason_code()).unwrap_or_else(|_| {
            ResourceErrorReason::parse("store-error-contract-invalid").unwrap()
        }),
    );
    mapped.unwrap_or_else(|_| {
        ResourceError::terminal(
            ResourceErrorKind::InternalIntegrityFailure,
            "store-error-contract-invalid",
        )
    })
}

/// Encode a codec-neutral error into its typed protobuf value.
pub fn to_wire_error(error: &ResourceError) -> wire::ResourceError {
    wire::ResourceError {
        kind: EnumOrUnknown::new(to_wire_kind(error.kind())),
        current_revision: error.current_revision().map(|revision| revision.get()),
        retry_after_ms: error.retry_after_ms(),
        retry_class: EnumOrUnknown::new(to_wire_retry(error.retry_class())),
        reason: error.reason().as_str().to_owned(),
        special_fields: protobuf::SpecialFields::new(),
    }
}

fn to_wire_retry(retry: RetryClass) -> wire::RetryClass {
    match retry {
        RetryClass::Never => wire::RetryClass::RETRY_CLASS_NEVER,
        RetryClass::Immediate => wire::RetryClass::RETRY_CLASS_IMMEDIATE,
        RetryClass::AfterDelay => wire::RetryClass::RETRY_CLASS_AFTER_DELAY,
        RetryClass::Reauthorize => wire::RetryClass::RETRY_CLASS_REAUTHORIZE,
    }
}

fn to_wire_kind(kind: ResourceErrorKind) -> wire::ResourceErrorKind {
    match kind {
        ResourceErrorKind::ResourceNotFound => {
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_NOT_FOUND
        }
        ResourceErrorKind::ResourceAlreadyExists => {
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_ALREADY_EXISTS
        }
        ResourceErrorKind::ResourceConflict => {
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_CONFLICT
        }
        ResourceErrorKind::ResourceSchemaInvalid => {
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_SCHEMA_INVALID
        }
        ResourceErrorKind::ResourceRefInvalid => {
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_REF_INVALID
        }
        ResourceErrorKind::ResourceOwnerCycle => {
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_OWNER_CYCLE
        }
        ResourceErrorKind::ResourceOwnerDepth => {
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_OWNER_DEPTH
        }
        ResourceErrorKind::ResourceFinalizerDenied => {
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_FINALIZER_DENIED
        }
        ResourceErrorKind::ResourceProviderUnavailable => {
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_PROVIDER_UNAVAILABLE
        }
        ResourceErrorKind::ResourceControllerMismatch => {
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_CONTROLLER_MISMATCH
        }
        ResourceErrorKind::ResourceStatusOwnerMismatch => {
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_STATUS_OWNER_MISMATCH
        }
        ResourceErrorKind::StatusOversize => {
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_STATUS_OVERSIZE
        }
        ResourceErrorKind::StatusProviderSchemaInvalid => {
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_STATUS_PROVIDER_SCHEMA_INVALID
        }
        ResourceErrorKind::StatusProviderOverlap => {
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_STATUS_PROVIDER_OVERLAP
        }
        ResourceErrorKind::SpecProviderSchemaInvalid => {
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_SPEC_PROVIDER_SCHEMA_INVALID
        }
        ResourceErrorKind::SpecProviderShadow => {
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_SPEC_PROVIDER_SHADOW
        }
        ResourceErrorKind::UnsupportedCapability => {
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_UNSUPPORTED_CAPABILITY
        }
        ResourceErrorKind::ExpeditedNotAuthorized => {
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_EXPEDITED_NOT_AUTHORIZED
        }
        ResourceErrorKind::ExpeditedQuotaExceeded => {
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_EXPEDITED_QUOTA_EXCEEDED
        }
        ResourceErrorKind::ExpeditedReconcilePending => {
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_EXPEDITED_RECONCILE_PENDING
        }
        ResourceErrorKind::UpgradeRequired => {
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_UPGRADE_REQUIRED
        }
        ResourceErrorKind::EndpointResolveDenied => {
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_ENDPOINT_RESOLVE_DENIED
        }
        ResourceErrorKind::RelayDenied => wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RELAY_DENIED,
        ResourceErrorKind::RoleRelayGrantRestricted => {
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_ROLE_RELAY_GRANT_RESTRICTED
        }
        ResourceErrorKind::AuthorizationDenied => {
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_AUTHORIZATION_DENIED
        }
        ResourceErrorKind::RevisionExpired => {
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_REVISION_EXPIRED
        }
        ResourceErrorKind::Backpressure => {
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_BACKPRESSURE
        }
        ResourceErrorKind::Timeout => wire::ResourceErrorKind::RESOURCE_ERROR_KIND_TIMEOUT,
        ResourceErrorKind::Cancelled => wire::ResourceErrorKind::RESOURCE_ERROR_KIND_CANCELLED,
        ResourceErrorKind::ResourcePlaneUnavailable => {
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_PLANE_UNAVAILABLE
        }
        ResourceErrorKind::InternalIntegrityFailure => {
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_INTERNAL_INTEGRITY_FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use d2b_contracts_resource::v3::ZoneRevision;

    #[test]
    fn store_mapping_is_total_and_one_way() {
        assert_eq!(StoreErrorKind::all().len(), 34);
        let mapped = StoreErrorKind::all()
            .iter()
            .copied()
            .map(map_store_error_kind)
            .collect::<Vec<_>>();
        assert_eq!(mapped.len(), 34);
        assert_eq!(
            map_store_error_kind(StoreErrorKind::StoreIntegrityFailure),
            ResourceErrorKind::InternalIntegrityFailure
        );
        assert_eq!(
            map_store_error_kind(StoreErrorKind::StoreBackpressure),
            ResourceErrorKind::Backpressure
        );
        assert_eq!(
            map_store_error_kind(StoreErrorKind::StoreQuarantined),
            ResourceErrorKind::ResourcePlaneUnavailable
        );
    }

    #[test]
    fn conflict_revision_survives_typed_wire_mapping() {
        let error = map_store_error(StoreError::new(
            StoreErrorKind::ResourceConflict,
            Some(ZoneRevision::new(8)),
            None,
            RetryClass::Immediate,
            "resource revision changed",
        ));
        let wire = to_wire_error(&error);
        assert_eq!(wire.current_revision, Some(8));
        assert_eq!(
            wire.kind.enum_value().unwrap(),
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_CONFLICT
        );
    }

    #[test]
    fn assignment_required_conflict_is_wire_valid_and_retryable() {
        let error = map_store_error(StoreError::new(
            StoreErrorKind::ResourceConflict,
            Some(ZoneRevision::new(8)),
            None,
            RetryClass::Reauthorize,
            "assignment-required",
        ));
        assert_eq!(error.kind(), ResourceErrorKind::ResourceConflict);
        assert_eq!(error.current_revision(), Some(ZoneRevision::new(8)));
        assert_eq!(error.retry_class(), RetryClass::Reauthorize);
        let wire = to_wire_error(&error);
        assert_eq!(
            wire.kind.enum_value().unwrap(),
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_RESOURCE_CONFLICT
        );
        assert_eq!(wire.current_revision, Some(8));
        assert_eq!(
            wire.retry_class.enum_value().unwrap(),
            wire::RetryClass::RETRY_CLASS_REAUTHORIZE
        );
        assert_eq!(wire.reason, "assignment-required");
    }

    #[test]
    fn invalid_store_error_metadata_fails_closed_without_panicking() {
        let error = map_store_error(StoreError::new(
            StoreErrorKind::ResourceNotFound,
            Some(ZoneRevision::new(8)),
            None,
            RetryClass::Never,
            "invalid-store-error",
        ));
        assert_eq!(error.kind(), ResourceErrorKind::InternalIntegrityFailure);
    }

    #[test]
    fn conflict_revision_can_be_hidden_without_changing_the_kind() {
        let error = map_store_error_with_revision_visibility(
            StoreError::new(
                StoreErrorKind::ResourceConflict,
                Some(ZoneRevision::new(8)),
                None,
                RetryClass::Reauthorize,
                "revision-changed",
            ),
            false,
        );
        assert_eq!(error.kind(), ResourceErrorKind::ResourceConflict);
        assert_eq!(error.current_revision(), None);
    }

    #[test]
    fn authorization_denied_visible_revision_and_retry_survive_mapping() {
        let error = map_store_error_with_revision_visibility(
            StoreError::new(
                StoreErrorKind::AuthorizationDenied,
                Some(ZoneRevision::new(8)),
                None,
                RetryClass::Reauthorize,
                "store-generation-recheck-failed",
            ),
            true,
        );
        assert_eq!(error.kind(), ResourceErrorKind::AuthorizationDenied);
        assert_eq!(error.current_revision(), Some(ZoneRevision::new(8)));
        assert_eq!(error.retry_class(), RetryClass::Reauthorize);

        let wire = to_wire_error(&error);
        assert_eq!(
            wire.kind.enum_value().unwrap(),
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_AUTHORIZATION_DENIED
        );
        assert_eq!(wire.current_revision, Some(8));
        assert_eq!(
            wire.retry_class.enum_value().unwrap(),
            wire::RetryClass::RETRY_CLASS_REAUTHORIZE
        );
    }

    #[test]
    fn authorization_denied_revision_can_be_hidden_without_changing_kind_or_retry() {
        let error = map_store_error_with_revision_visibility(
            StoreError::new(
                StoreErrorKind::AuthorizationDenied,
                Some(ZoneRevision::new(8)),
                None,
                RetryClass::Reauthorize,
                "store-generation-recheck-failed",
            ),
            false,
        );
        assert_eq!(error.kind(), ResourceErrorKind::AuthorizationDenied);
        assert_eq!(error.current_revision(), None);
        assert_eq!(error.retry_class(), RetryClass::Reauthorize);

        let wire = to_wire_error(&error);
        assert_eq!(
            wire.kind.enum_value().unwrap(),
            wire::ResourceErrorKind::RESOURCE_ERROR_KIND_AUTHORIZATION_DENIED
        );
        assert_eq!(wire.current_revision, None);
        assert_eq!(
            wire.retry_class.enum_value().unwrap(),
            wire::RetryClass::RETRY_CLASS_REAUTHORIZE
        );
    }
}
