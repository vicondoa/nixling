//! The volume-local controller.
//!
//! It is the sole Volume writer. It validates the Volume base spec,
//! resolves the source through the injected source port, reconciles every
//! declared layout entry in parent-before-child order through the
//! injected layout port, admits attachments, and writes the aggregated
//! status. It performs no privileged mutation itself.

use std::collections::BTreeSet;

use d2b_contracts_resource::v3::execution_policy::BoundedToken;
use d2b_contracts_resource::v3::volume::{SourceKind, VolumeSpec};
use d2b_contracts_resource::v3::{ResourceRef, ResourceUid};

use crate::content::{
    ContentMaterializationEvidence, ContentProjection, NetworkConfigContentProjection,
    NetworkConfigMaterializationEvidence,
};
use crate::error::VolumeLocalError;
use crate::finalization::{
    FinalizationAction, FinalizationObservation, FinalizationResult, finalization_plan,
};
use crate::identity::{MarkerState, VolumeRootHandle};
use crate::layout::{ConditionSeverity, EntryCondition, EntryRequest, plan_cleanup, plan_entry};
use crate::port::{QuotaCapability, VolumeLayoutEffectPort, VolumeSourceEffectPort};
use crate::source::{SourcePolicyCatalog, validate_source_spec};
use crate::status::{AttachmentState, AttachmentStatus, LayoutPhase, VolumeStatusReport};
use crate::views::admit_attachments;

/// The exact shared-Runner contract for `volume-local`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeRunnerContract {
    /// The sole ResourceType owned by this Provider.
    pub resource_type: &'static str,
    /// The finalizer installed on Volume resources.
    pub finalizer: &'static str,
    /// Bounded repair interval in seconds.
    pub repair_interval_secs: u64,
    /// Whether configuration is dependency-only.
    pub watched_configuration_is_dependency: bool,
}

/// The fixed finalizer owned by volume-local.
pub const VOLUME_FINALIZER: &str = "volume-local.d2bus.org/layout";

/// Return the production volume-local Runner contract.
pub const fn volume_runner_contract() -> VolumeRunnerContract {
    VolumeRunnerContract {
        resource_type: "Volume",
        finalizer: VOLUME_FINALIZER,
        repair_interval_secs: 30,
        watched_configuration_is_dependency: true,
    }
}

/// The declared conformance profile of one volume-local instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeLocalProfile {
    provider: BoundedToken,
    supported_source_kinds: BTreeSet<SourceKind>,
    supports_shared_write: bool,
    source_policies: Option<SourcePolicyCatalog>,
}

impl VolumeLocalProfile {
    /// Declare a profile. A Provider that supports no source kind is
    /// rejected.
    pub fn new(
        provider: BoundedToken,
        supported_source_kinds: BTreeSet<SourceKind>,
        supports_shared_write: bool,
    ) -> Result<Self, VolumeLocalError> {
        if supported_source_kinds.is_empty() {
            return Err(VolumeLocalError::InvalidSpec);
        }
        Ok(Self {
            provider,
            supported_source_kinds,
            supports_shared_write,
            source_policies: None,
        })
    }

    /// The default shipped profile: every source kind, no shared write.
    pub fn shipped() -> Self {
        Self {
            provider: BoundedToken::parse("volume-local").expect("frozen provider name"),
            supported_source_kinds: [
                SourceKind::LocalPath,
                SourceKind::BlockImage,
                SourceKind::Tmpfs,
                SourceKind::NixClosure,
            ]
            .into_iter()
            .collect(),
            supports_shared_write: false,
            source_policies: None,
        }
    }

    /// Borrow the Provider name.
    pub const fn provider(&self) -> &BoundedToken {
        &self.provider
    }

    /// Borrow the supported source kinds.
    pub const fn supported_source_kinds(&self) -> &BTreeSet<SourceKind> {
        &self.supported_source_kinds
    }

    /// Whether this Provider admits `shared-write` attachments.
    pub const fn supports_shared_write(&self) -> bool {
        self.supports_shared_write
    }

    /// Attach the private source-policy catalog used for strict admission.
    pub fn with_source_policy_catalog(mut self, catalog: SourcePolicyCatalog) -> Self {
        self.source_policies = Some(catalog);
        self
    }
}

/// The volume-local controller over its two injected effect ports.
#[derive(Debug)]
pub struct VolumeLocalController<S, L> {
    profile: VolumeLocalProfile,
    source: S,
    layout: L,
}

impl<S: VolumeSourceEffectPort, L: VolumeLayoutEffectPort> VolumeLocalController<S, L> {
    /// Build a controller over the injected ports.
    pub const fn new(profile: VolumeLocalProfile, source: S, layout: L) -> Self {
        Self {
            profile,
            source,
            layout,
        }
    }

    /// Borrow the declared profile.
    pub const fn profile(&self) -> &VolumeLocalProfile {
        &self.profile
    }

    /// Reconcile one Volume and return its public status projection.
    pub async fn reconcile(
        &self,
        volume_uid: &ResourceUid,
        spec: &VolumeSpec,
        provider: Option<&serde_json::Value>,
        owner_ref: Option<&d2b_contracts_resource::v3::ResourceRef>,
    ) -> Result<VolumeStatusReport, VolumeLocalError> {
        let mut status = self.reconcile_layout(volume_uid, spec).await?;
        if status.layout_phase != LayoutPhase::Ready {
            return Ok(status);
        }
        if let Some(provider) = provider {
            if provider.get("schemaId").and_then(serde_json::Value::as_str)
                != Some(crate::VOLUME_CONTENT_SCHEMA_ID)
                || provider.get("schemaVersion").and_then(serde_json::Value::as_str)
                    != Some(crate::VOLUME_CONTENT_SCHEMA_VERSION)
            {
                return Err(VolumeLocalError::InvalidSpec);
            }
            let settings = provider
                .get("settings")
                .ok_or(VolumeLocalError::InvalidSpec)?;
            if settings.get("kind").and_then(serde_json::Value::as_str)
                != Some(crate::NETWORK_CONFIG_CONTENT_KIND)
            {
                return Err(VolumeLocalError::InvalidSpec);
            }
            let owner_ref = owner_ref.ok_or(VolumeLocalError::InvalidSpec)?;
            let projection = NetworkConfigContentProjection::from_settings(
                settings
                    .get("content")
                    .ok_or(VolumeLocalError::InvalidSpec)?,
            )?;
            status.content = Some(
                self.reconcile_owned_network_config_content(
                    volume_uid,
                    spec,
                    &projection,
                    owner_ref,
                )
                .await?,
            );
        }
        Ok(status)
    }

    async fn reconcile_layout(
        &self,
        volume_uid: &ResourceUid,
        spec: &VolumeSpec,
    ) -> Result<VolumeStatusReport, VolumeLocalError> {
        let kind = self.validate_spec(spec)?;
        let attachments = admit_attachments(spec, self.profile.supports_shared_write())?;

        let root = self
            .source
            .resolve_root_for(
                volume_uid,
                spec.source().settings().source_policy_id(),
                spec.source().settings().system_artifact_id(),
                kind,
            )
            .await?;
        self.assert_quota(spec, &root).await?;

        let marker = self.layout.marker_state(&root).await?;
        let mut phase = LayoutPhase::Pending;
        let mut conditions = Vec::new();

        let mut ordered_entries: Vec<_> = spec.layout().iter().collect();
        ordered_entries.sort_by_key(|entry| {
            (
                !entry.path().is_empty(),
                entry.path().split('/').count(),
                entry.path(),
            )
        });

        for declared in ordered_entries {
            let entry = EntryRequest::resolve(volume_uid, declared)?;
            let observed = self.layout.observe(&root, &entry).await?;
            let plan = plan_entry(&entry, &observed, marker);
            if let Some(condition) = plan.condition {
                conditions.push(condition);
                phase = phase.worse(severity_phase(condition));
            }
            if plan.recreate {
                self.layout.cleanup(&root, &entry).await?;
            }
            if plan.provision {
                self.layout.provision(&root, &entry).await?;
            }
            if !plan.repair.is_empty() {
                self.layout.repair(&root, &entry, &plan.repair).await?;
            }
            if plan.apply_acl {
                self.layout.apply_acl(&root, &entry).await?;
            }
            if plan.condition.is_none() {
                phase = phase.worse(LayoutPhase::Ready);
            }
        }
        if marker == MarkerState::NeverProvisioned && conditions.is_empty() {
            self.layout.publish_marker(&root).await?;
        }

        Ok(VolumeStatusReport {
            provider: self.profile.provider().clone(),
            kind: spec.kind(),
            layout_phase: if spec.layout().is_empty() {
                LayoutPhase::Ready
            } else {
                phase
            },
            layout_conditions: conditions,
            attachment_statuses: attachments
                .into_iter()
                .map(|plan| AttachmentStatus {
                    execution_ref: plan.execution_ref,
                    view: plan.view,
                    access: plan.access,
                    state: AttachmentState::Pending,
                    export_ready: false,
                    guest_mount_ready: false,
                })
                .collect(),
            content: None,
        })
    }

    /// Materialize a typed Network configuration projection through the
    /// Volume-owned content effect port.
    async fn reconcile_owned_network_config_content(
        &self,
        volume_uid: &ResourceUid,
        spec: &VolumeSpec,
        projection: &NetworkConfigContentProjection,
        owner_ref: &d2b_contracts_resource::v3::ResourceRef,
    ) -> Result<NetworkConfigMaterializationEvidence, VolumeLocalError> {
        let kind = self.validate_spec(spec)?;
        if projection.volume_uid() != volume_uid || projection.network_ref() != owner_ref {
            return Err(VolumeLocalError::InvalidSpec);
        }
        validate_network_config_layout(spec, projection)?;
        let root = self
            .source
            .resolve_root_for(
                volume_uid,
                spec.source().settings().source_policy_id(),
                spec.source().settings().system_artifact_id(),
                kind,
            )
            .await?;
        if self.layout.marker_state(&root).await? != MarkerState::Provisioned {
            return Err(VolumeLocalError::InvariantViolated);
        }
        let evidence = self
            .layout
            .materialize_network_config(&root, projection)
            .await?;
        if !evidence.matches(projection) {
            return Err(VolumeLocalError::EffectFailed);
        }
        Ok(evidence)
    }

    /// Reconcile the Volume layout and materialize a typed Network
    /// configuration projection, returning the evidence for status.
    /// Remove every declared entry whose cleanup policy admits removal.
    ///
    /// Returns the digests of the entries that were removed. An entry
    /// with `cleanup-policy: never` is always preserved, and a
    /// process-scoped entry is removed only with proof its owner is gone.
    pub async fn cleanup(
        &self,
        volume_uid: &ResourceUid,
        spec: &VolumeSpec,
    ) -> Result<Vec<crate::identity::EntryDigest>, VolumeLocalError> {
        let kind = self.validate_spec(spec)?;
        let root = self
            .source
            .resolve_root_for(
                volume_uid,
                spec.source().settings().source_policy_id(),
                spec.source().settings().system_artifact_id(),
                kind,
            )
            .await?;
        let mut removed = Vec::new();
        let mut ordered_entries: Vec<_> = spec.layout().iter().collect();
        ordered_entries.sort_by_key(|entry| {
            (
                entry.path().is_empty(),
                core::cmp::Reverse(entry.path().split('/').count()),
                core::cmp::Reverse(entry.path()),
            )
        });
        for declared in ordered_entries {
            let entry = EntryRequest::resolve(volume_uid, declared)?;
            let observed = self.layout.observe(&root, &entry).await?;
            if plan_cleanup(&entry, &observed) {
                self.layout.cleanup(&root, &entry).await?;
                removed.push(entry.digest());
            }
        }
        Ok(removed)
    }

    /// Materialize a validated content projection after layout convergence.
    ///
    /// The returned evidence is suitable for a status projection only after
    /// the effect adapter has atomically replaced each declared file and read
    /// every file back under its anchored Volume lock.
    pub async fn reconcile_content(
        &self,
        volume_uid: &ResourceUid,
        spec: &VolumeSpec,
        projection: &ContentProjection,
    ) -> Result<ContentMaterializationEvidence, VolumeLocalError> {
        if projection.volume_uid() != volume_uid {
            return Err(VolumeLocalError::InvariantViolated);
        }
        let status = self.reconcile(volume_uid, spec, None, None).await?;
        if status.layout_phase != LayoutPhase::Ready {
            return Err(VolumeLocalError::InvariantViolated);
        }
        let kind = self.validate_spec(spec)?;
        let root = self
            .source
            .resolve_root_for(
                volume_uid,
                spec.source().settings().source_policy_id(),
                spec.source().settings().system_artifact_id(),
                kind,
            )
            .await?;
        if self.layout.marker_state(&root).await? != MarkerState::Provisioned {
            return Err(VolumeLocalError::InvariantViolated);
        }
        let evidence = self.layout.materialize_content(&root, projection).await?;
        if !evidence.matches(projection) {
            return Err(VolumeLocalError::EffectFailed);
        }
        Ok(evidence)
    }

    /// Materialize the qualified Network configuration projection.
    pub async fn reconcile_network_config_content(
        &self,
        volume_uid: &ResourceUid,
        spec: &VolumeSpec,
        projection: &NetworkConfigContentProjection,
    ) -> Result<NetworkConfigMaterializationEvidence, VolumeLocalError> {
        if projection.volume_uid() != volume_uid {
            return Err(VolumeLocalError::InvariantViolated);
        }
        let status = self.reconcile(volume_uid, spec, None, None).await?;
        if status.layout_phase != LayoutPhase::Ready {
            return Err(VolumeLocalError::InvariantViolated);
        }
        validate_network_config_layout(spec, projection)?;
        let kind = self.validate_spec(spec)?;
        let root = self
            .source
            .resolve_root_for(
                volume_uid,
                spec.source().settings().source_policy_id(),
                spec.source().settings().system_artifact_id(),
                kind,
            )
            .await?;
        if self.layout.marker_state(&root).await? != MarkerState::Provisioned {
            return Err(VolumeLocalError::InvariantViolated);
        }
        let evidence = self
            .layout
            .materialize_network_config(&root, projection)
            .await?;
        if !evidence.matches(projection) {
            return Err(VolumeLocalError::EffectFailed);
        }
        Ok(evidence)
    }

    /// Reconcile a Volume and its provider-owned content projection.
    ///
    /// This keeps provider-extension parsing at the Volume owner while
    /// leaving the generic file materialization boundary reusable by later
    /// Providers.
    pub async fn reconcile_with_provider(
        &self,
        volume_uid: &ResourceUid,
        spec: &VolumeSpec,
        provider: &serde_json::Value,
        owner_ref: &ResourceRef,
    ) -> Result<VolumeStatusReport, VolumeLocalError> {
        self.reconcile(volume_uid, spec, Some(provider), Some(owner_ref))
            .await
    }

    /// Finalize only after dependents and the store-view writer have closed.
    pub async fn finalize(
        &self,
        volume_uid: &ResourceUid,
        spec: &VolumeSpec,
        observation: FinalizationObservation,
    ) -> Result<FinalizationResult, VolumeLocalError> {
        match finalization_plan(observation) {
            FinalizationAction::Cleanup => self
                .cleanup(volume_uid, spec)
                .await
                .map(FinalizationResult::Cleaned),
            action => Ok(FinalizationResult::Waiting(action)),
        }
    }

    async fn assert_quota(
        &self,
        spec: &VolumeSpec,
        root: &VolumeRootHandle,
    ) -> Result<(), VolumeLocalError> {
        use d2b_contracts_resource::v3::volume::QuotaEnforcement;
        let Some(quota) = spec.quota() else {
            return Ok(());
        };
        if quota.enforcement() != QuotaEnforcement::Hard {
            return Ok(());
        }
        match self.source.quota_capability(root).await? {
            QuotaCapability::Enforceable => Ok(()),
            QuotaCapability::Unenforceable => Err(VolumeLocalError::QuotaUnenforceable),
        }
    }

    fn validate_spec(&self, spec: &VolumeSpec) -> Result<SourceKind, VolumeLocalError> {
        validate_source_spec(spec)?;
        if let Some(catalog) = &self.profile.source_policies {
            catalog.validate(spec)?;
        }
        let kind = spec.source().settings().kind();
        if !self.profile.supported_source_kinds().contains(&kind) {
            return Err(VolumeLocalError::SourceKindUnsupported);
        }
        Ok(kind)
    }
}

const fn severity_phase(condition: EntryCondition) -> LayoutPhase {
    match condition.severity {
        ConditionSeverity::Degraded => LayoutPhase::Degraded,
        ConditionSeverity::Failed => LayoutPhase::Failed,
    }
}

fn validate_network_config_layout(
    spec: &VolumeSpec,
    projection: &NetworkConfigContentProjection,
) -> Result<(), VolumeLocalError> {
    let expected = [
        ("dnsmasq.conf", projection.file_owner(), projection.file_group()),
        ("nftables.rules", projection.file_owner(), projection.file_group()),
        ("routing.conf", projection.file_owner(), projection.file_group()),
        (
            "attachments.json",
            projection.file_owner(),
            projection.file_group(),
        ),
    ];
    if expected.iter().all(|(path, owner, group)| {
        spec.layout().iter().any(|entry| {
            entry.path() == *path
                && entry.entry_type() == d2b_contracts_resource::v3::volume::EntryType::File
                && entry.owner_ref() == *owner
                && entry.group_ref() == *group
                && entry.mode() == projection.file_mode()
        })
    }) {
        Ok(())
    } else {
        Err(VolumeLocalError::InvariantViolated)
    }
}
