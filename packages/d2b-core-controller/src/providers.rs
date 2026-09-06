//! Provider lifecycle validation and child-resource planning.

use d2b_contracts_provider::v3::{ComponentType, ProviderManifest};
use d2b_contracts_resource::v3::{ResourceRef, SchemaFingerprint};

/// Provider lifecycle phase derived from exact child observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderPhase {
    Pending,
    Ready,
    Draining,
    Degraded,
    Failed,
    Unknown,
}

/// Requested Provider lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderIntent {
    Enable,
    Update,
    Disable,
    Delete,
}

/// One child-resource action. The plan never spawns a process directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderChildAction {
    EnsureComponent(ComponentType),
    EnsureDeclaredStateVolume,
    WithdrawExports,
    RevokeComponents,
    RequestComponentDeletion,
}

/// Effect-free Provider lifecycle plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderPlan {
    phase: ProviderPhase,
    actions: Vec<ProviderChildAction>,
    publish_exports: bool,
}

impl ProviderPlan {
    /// Return the projected aggregate phase.
    pub const fn phase(&self) -> ProviderPhase {
        self.phase
    }

    /// Borrow the child-resource actions.
    pub fn actions(&self) -> &[ProviderChildAction] {
        &self.actions
    }

    /// Whether exported ResourceTypes and services may be published.
    pub const fn publish_exports(&self) -> bool {
        self.publish_exports
    }
}

/// Trusted observations needed to plan one Provider pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderObservation {
    pub package_present: bool,
    pub config_valid: bool,
    pub graph_valid: bool,
    pub conformance_valid: bool,
    pub required_dependencies_ready: bool,
    pub required_components_ready: bool,
    pub optional_components_degraded: bool,
    pub components_drained: bool,
}

/// Closed Provider handler failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderError {
    WrongResourceType,
    TrustOrCompatibilityDenied,
    PackageUnavailable,
    ConfigInvalid,
    GraphInvalid,
    ConformanceInvalid,
}

impl ProviderError {
    /// Return a stable, identity-free reason code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::WrongResourceType => "provider-resource-type-invalid",
            Self::TrustOrCompatibilityDenied => "provider-admission-denied",
            Self::PackageUnavailable => "provider-package-unavailable",
            Self::ConfigInvalid => "provider-config-invalid",
            Self::GraphInvalid => "provider-graph-invalid",
            Self::ConformanceInvalid => "provider-conformance-invalid",
        }
    }
}

impl core::fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ProviderError {}

/// Pure Provider lifecycle planner.
pub struct ProviderHandler;

impl ProviderHandler {
    /// Validate and plan an external Provider from its signed manifest.
    #[allow(clippy::too_many_arguments)]
    pub fn plan_external(
        provider_ref: &ResourceRef,
        manifest: &ProviderManifest,
        required_api_major: u32,
        required_api_minor: u32,
        required_descriptor_fingerprint: &SchemaFingerprint,
        intent: ProviderIntent,
        observation: ProviderObservation,
    ) -> Result<ProviderPlan, ProviderError> {
        if provider_ref.resource_type().as_str() != "Provider" {
            return Err(ProviderError::WrongResourceType);
        }
        manifest
            .admit(
                required_api_major,
                required_api_minor,
                required_descriptor_fingerprint,
            )
            .map_err(|_| ProviderError::TrustOrCompatibilityDenied)?;
        manifest
            .validate_installation_contract()
            .map_err(|_| ProviderError::GraphInvalid)?;
        if !observation.package_present {
            return Err(ProviderError::PackageUnavailable);
        }
        if !observation.config_valid {
            return Err(ProviderError::ConfigInvalid);
        }
        if !observation.graph_valid {
            return Err(ProviderError::GraphInvalid);
        }
        if !observation.conformance_valid {
            return Err(ProviderError::ConformanceInvalid);
        }

        let mut plan = Self::plan_observed(provider_ref, intent, observation)?;
        if matches!(intent, ProviderIntent::Enable | ProviderIntent::Update) {
            plan.actions = manifest
                .components()
                .iter()
                .map(|component| {
                    ProviderChildAction::EnsureComponent(component.component_type())
                })
                .collect();
            if manifest.declares_state_volume() {
                plan.actions
                    .push(ProviderChildAction::EnsureDeclaredStateVolume);
            }
        }
        Ok(plan)
    }

    /// Project an already admitted Provider from its trusted runtime evidence.
    ///
    /// Manifest admission remains the authority for artifact, descriptor, and
    /// registration identity. This entry point is used by the active Core
    /// handler after those facts have been established by the runtime and
    /// represented in the owned Process/session observations.
    pub fn plan_observed(
        provider_ref: &ResourceRef,
        intent: ProviderIntent,
        observation: ProviderObservation,
    ) -> Result<ProviderPlan, ProviderError> {
        if provider_ref.resource_type().as_str() != "Provider" {
            return Err(ProviderError::WrongResourceType);
        }
        if !observation.package_present {
            return Err(ProviderError::PackageUnavailable);
        }
        if !observation.config_valid {
            return Err(ProviderError::ConfigInvalid);
        }
        if !observation.graph_valid {
            return Err(ProviderError::GraphInvalid);
        }
        if !observation.conformance_valid {
            return Err(ProviderError::ConformanceInvalid);
        }

        match intent {
            ProviderIntent::Enable | ProviderIntent::Update => {
                let ready = observation.required_dependencies_ready
                    && observation.required_components_ready;
                Ok(ProviderPlan {
                    phase: if ready {
                        if observation.optional_components_degraded {
                            ProviderPhase::Degraded
                        } else {
                            ProviderPhase::Ready
                        }
                    } else {
                        ProviderPhase::Pending
                    },
                    actions: Vec::new(),
                    publish_exports: ready,
                })
            }
            ProviderIntent::Disable | ProviderIntent::Delete => Ok(ProviderPlan {
                phase: if observation.components_drained {
                    ProviderPhase::Pending
                } else {
                    ProviderPhase::Draining
                },
                actions: vec![
                    ProviderChildAction::WithdrawExports,
                    ProviderChildAction::RevokeComponents,
                    ProviderChildAction::RequestComponentDeletion,
                ],
                publish_exports: false,
            }),
        }
    }

    /// Plan the fixed system-core bootstrap exception.
    ///
    /// It is hosted internally and therefore never receives a Process child.
    pub fn plan_system_core(required_handlers_ready: bool) -> ProviderPlan {
        ProviderPlan {
            phase: if required_handlers_ready {
                ProviderPhase::Ready
            } else {
                ProviderPhase::Pending
            },
            actions: Vec::new(),
            publish_exports: required_handlers_ready,
        }
    }
}

#[cfg(test)]
mod tests {
    use d2b_contracts_provider::v3::UpgradePolicy as ProviderUpgradePolicy;
    use d2b_contracts_provider::v3::{
        ArtifactDigest, ArtifactDigestSet, BinaryRef, CompatibilityRange, ComponentDescriptor,
        ComponentExecution, ComponentTargetCapability, ControllerTargetKind, EffectPortClass,
        PolicyEvaluation, RevocationState, SignatureState, TargetRuntimeArtifacts, TrustEvidence,
        UpgradeDisposition,
    };
    use d2b_contracts_resource::v3::{
        ArtifactId,
        execution_policy::{BoundedToken, ExecutionDomain},
    };

    use super::*;

    const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000001";

    fn fingerprint() -> SchemaFingerprint {
        SchemaFingerprint::parse(DIGEST).unwrap()
    }

    fn manifest(trusted: bool) -> ProviderManifest {
        let digest = || ArtifactDigest::parse(DIGEST).unwrap();
        ProviderManifest::new(
            ArtifactId::parse("provider").unwrap(),
            ArtifactDigestSet {
                executable: digest(),
                config: digest(),
                schema: digest(),
                service: digest(),
            },
            TrustEvidence {
                publisher: BoundedToken::parse("trusted").unwrap(),
                root_epoch: 1,
                publisher_trusted: trusted,
                signature: SignatureState::Valid,
                revocation: RevocationState::Clear,
                emergency_deny: false,
                provenance: PolicyEvaluation::Accepted,
                sbom: PolicyEvaluation::Accepted,
                license: PolicyEvaluation::Accepted,
                vulnerability: PolicyEvaluation::Accepted,
                conformance: PolicyEvaluation::Accepted,
                support_channel: BoundedToken::parse("stable").unwrap(),
            },
            CompatibilityRange {
                api_major: 3,
                api_minor: 0,
                descriptor_fingerprint: fingerprint(),
                state_schema_version: d2b_contracts_resource::v3::SchemaVersion::new(1, 0).unwrap(),
            },
            [ComponentDescriptor::new(
                BoundedToken::parse("service").unwrap(),
                ComponentType::Service,
                [],
                [BoundedToken::parse("observe").unwrap()],
                [ExecutionDomain::System],
                1,
                digest(),
                [],
                false,
            )
            .unwrap()
            .with_execution(ComponentExecution::Launchable {
                binary_ref: BinaryRef::parse("service").unwrap(),
            })
            .with_target_capabilities([
                ComponentTargetCapability::new(
                    ControllerTargetKind::Host,
                    digest(),
                    [EffectPortClass::Runtime],
                )
                .unwrap(),
                ComponentTargetCapability::new(
                    ControllerTargetKind::Guest,
                    digest(),
                    [EffectPortClass::Runtime],
                )
                .unwrap(),
            ])
            .unwrap()],
            [],
            [],
            ProviderUpgradePolicy {
                drain_before_upgrade: true,
                max_automatic_disposition: UpgradeDisposition::InPlace,
                preserves_durable_state: true,
            },
        )
        .unwrap()
        .with_target_runtime_artifacts([
            TargetRuntimeArtifacts::new(ControllerTargetKind::Host, digest(), digest()).unwrap(),
            TargetRuntimeArtifacts::new(ControllerTargetKind::Guest, digest(), digest()).unwrap(),
        ])
        .unwrap()
    }

    fn observation() -> ProviderObservation {
        ProviderObservation {
            package_present: true,
            config_valid: true,
            graph_valid: true,
            conformance_valid: true,
            required_dependencies_ready: true,
            required_components_ready: true,
            optional_components_degraded: false,
            components_drained: false,
        }
    }

    #[test]
    fn ready_external_provider_publishes_only_after_children_are_ready() {
        let plan = ProviderHandler::plan_external(
            &ResourceRef::parse("Provider/example").unwrap(),
            &manifest(true),
            3,
            0,
            &fingerprint(),
            ProviderIntent::Enable,
            observation(),
        )
        .unwrap();
        assert_eq!(plan.phase(), ProviderPhase::Ready);
        assert!(plan.publish_exports());
        assert_eq!(
            plan.actions(),
            &[ProviderChildAction::EnsureComponent(ComponentType::Service)]
        );
    }

    #[test]
    fn missing_dependency_keeps_exports_withdrawn() {
        let mut observed = observation();
        observed.required_dependencies_ready = false;
        let plan = ProviderHandler::plan_external(
            &ResourceRef::parse("Provider/example").unwrap(),
            &manifest(true),
            3,
            0,
            &fingerprint(),
            ProviderIntent::Enable,
            observed,
        )
        .unwrap();
        assert_eq!(plan.phase(), ProviderPhase::Pending);
        assert!(!plan.publish_exports());
    }

    #[test]
    fn untrusted_provider_is_rejected_before_child_planning() {
        let manifest = manifest(false);
        assert_eq!(
            ProviderHandler::plan_external(
                &ResourceRef::parse("Provider/example").unwrap(),
                &manifest,
                3,
                0,
                &fingerprint(),
                ProviderIntent::Enable,
                observation(),
            )
            .unwrap_err(),
            ProviderError::TrustOrCompatibilityDenied
        );
    }

    #[test]
    fn fixed_system_core_never_plans_a_process_child() {
        let plan = ProviderHandler::plan_system_core(true);
        assert_eq!(plan.phase(), ProviderPhase::Ready);
        assert!(plan.actions().is_empty());
    }
}
