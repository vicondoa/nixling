//! Pure activation-nixos reconciliation policy.

use std::collections::BTreeSet;

use d2b_contracts_resource::v3::{
    ActivationMode, ActivationOutcomeCode, ActivationRunnerInput, ArtifactId, EnvironmentClass,
    ExecutionDomain, NixosGenerationSpec, ResourceName, ResourcePhase, ResourceRef,
    process::{EphemeralProcessSpec, ExecutionSpec, NamespaceClass, ProcessClass, SandboxSpec},
};
use ring::signature;
use sha2::{Digest, Sha256};

/// The target-local Process template used for activation effects.
pub const ACTIVATION_RUNNER_TEMPLATE: &str = "activation-nixos-runner";
/// The generic one-shot process resource type used for activation effects.
pub const ACTIVATION_RUNNER_RESOURCE_TYPE: &str = "EphemeralProcess";

/// Caller role derived from the authenticated daemon request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerRole {
    /// Lifecycle-authorized operator.
    Lifecycle,
    /// Administrator with lifecycle authority.
    Admin,
    /// Ordinary user without activation authority.
    User,
    /// Provider-internal caller; never accepted from a public request.
    Provider,
}

/// Authenticated activation caller context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationCaller {
    role: CallerRole,
    target: ResourceRef,
}

impl ActivationCaller {
    /// Bind a caller role to an authenticated execution target.
    pub const fn new(role: CallerRole, target: ResourceRef) -> Self {
        Self { role, target }
    }

    /// Borrow the caller target.
    pub const fn target(&self) -> &ResourceRef {
        &self.target
    }

    fn authorize(&self, spec: &NixosGenerationSpec) -> Result<(), ActivationError> {
        if !matches!(self.role, CallerRole::Lifecycle | CallerRole::Admin) {
            return Err(ActivationError::Unauthorized);
        }
        if self.target != *spec.execution_ref() {
            return Err(ActivationError::TargetMismatch);
        }
        Ok(())
    }
}

/// Simplified observed generation phase used by the controller seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GenerationPhase {
    /// Reconciliation has not completed.
    Pending,
    /// Generation is the active known-good generation.
    Ready,
    /// One-shot test completed.
    Succeeded,
    /// Generation failed.
    Failed,
    /// Generation is degraded.
    Degraded,
    /// The resource was deleted.
    Deleted,
}

impl GenerationPhase {
    fn resource_phase(self) -> ResourcePhase {
        match self {
            Self::Pending => ResourcePhase::Pending,
            Self::Ready => ResourcePhase::Ready,
            Self::Succeeded => ResourcePhase::Succeeded,
            Self::Failed => ResourcePhase::Failed,
            Self::Degraded => ResourcePhase::Degraded,
            Self::Deleted => ResourcePhase::Deleted,
        }
    }

    fn terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed)
    }
}

/// One observed generation row without private store information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationObservation {
    name: String,
    phase: GenerationPhase,
    ordinal: u64,
}

impl GenerationObservation {
    /// Construct a bounded observation.
    pub fn new(name: impl Into<String>, phase: GenerationPhase) -> Self {
        let name = name.into();
        let ordinal = name
            .rsplit('-')
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        Self::terminal(name, phase, ordinal)
    }

    /// Construct a bounded terminal observation.
    pub fn terminal(name: impl Into<String>, phase: GenerationPhase, ordinal: u64) -> Self {
        let name = name.into();
        assert!(!name.is_empty() && !name.contains('/') && name.len() <= 128);
        Self {
            name,
            phase,
            ordinal,
        }
    }

    /// Borrow the bounded row name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the observed phase.
    pub const fn phase(&self) -> GenerationPhase {
        self.phase
    }

    /// Return the monotonic generation ordinal.
    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }
}

/// A typed runner launch request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerRequest {
    /// Deterministic child resource name, derived from the generation.
    pub runner_name: ResourceName,
    /// Target execution context.
    pub execution_ref: ResourceRef,
    /// Private-catalog artifact identifier.
    pub system_artifact_id: ArtifactId,
    /// Requested activation mode.
    pub activation_mode: ActivationMode,
    /// Target generation ordinal bound to the runner stdin envelope.
    pub target_generation: u64,
    /// Activation runners start without an in-namespace root UID.
    pub start_root: bool,
}

/// Production activation/application verification hook.
pub trait ActivationApplicationVerifier: Send + Sync {
    /// Verify trust, signature, artifact, and catalog identity before an
    /// activation effect or runner resource is created.
    fn verify_application(
        &self,
        controller: &ActivationController,
        request: &RunnerRequest,
    ) -> Result<(), ActivationVerificationError>;
}

/// Default fail-closed verifier used until trusted material is supplied by
/// the artifact/application adapter.
#[derive(Debug, Default, Clone, Copy)]
pub struct FailClosedActivationVerifier;

impl ActivationApplicationVerifier for FailClosedActivationVerifier {
    fn verify_application(
        &self,
        controller: &ActivationController,
        _request: &RunnerRequest,
    ) -> Result<(), ActivationVerificationError> {
        let trust = ActivationTrust::new(
            0,
            None,
            TrustStatus::Unknown,
            TrustStatus::Unknown,
            "",
            "",
            Vec::new(),
            Vec::new(),
        );
        let expected = ActivationTrustExpectation::new(
            0,
            None,
            "",
            "",
            "",
            "",
            Vec::new(),
        );
        controller.verify_application(&trust, &expected, &[], "")
    }
}

/// Verification material supplied by the trusted artifact/application
/// adapter. The bytes are retained only in memory for one verification call.
pub struct SignedActivationApplicationVerifier {
    request: RunnerRequest,
    trust: ActivationTrust,
    expected: ActivationTrustExpectation,
    artifact_bytes: Vec<u8>,
    activation_catalog_digest: String,
}

impl core::fmt::Debug for SignedActivationApplicationVerifier {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SignedActivationApplicationVerifier")
            .field("request", &self.request)
            .field("trust", &self.trust)
            .field("expected", &self.expected)
            .field("artifact_bytes", &self.artifact_bytes.len())
            .field(
                "activation_catalog_digest_bytes",
                &self.activation_catalog_digest.len(),
            )
            .finish()
    }
}

impl SignedActivationApplicationVerifier {
    /// Bind verification material to one exact runner request.
    pub fn new(
        request: RunnerRequest,
        trust: ActivationTrust,
        expected: ActivationTrustExpectation,
        artifact_bytes: impl Into<Vec<u8>>,
        activation_catalog_digest: impl Into<String>,
    ) -> Self {
        Self {
            request,
            trust,
            expected,
            artifact_bytes: artifact_bytes.into(),
            activation_catalog_digest: activation_catalog_digest.into(),
        }
    }
}

impl ActivationApplicationVerifier for SignedActivationApplicationVerifier {
    fn verify_application(
        &self,
        controller: &ActivationController,
        request: &RunnerRequest,
    ) -> Result<(), ActivationVerificationError> {
        if request != &self.request {
            return Err(ActivationVerificationError::InvalidEvidence);
        }
        controller.verify_application(
            &self.trust,
            &self.expected,
            &self.artifact_bytes,
            &self.activation_catalog_digest,
        )
    }
}

/// Return the deterministic target-local child name for one generation.
///
/// The name is derived from the qualified generation reference rather than
/// an operator-provided value, so retries and daemon restarts converge on the
/// same EphemeralProcess.
pub fn activation_runner_name(generation: &ResourceRef) -> ResourceName {
    let readable = format!("activation-nixos--runner--{}", generation.name().as_str());
    if let Ok(name) = ResourceName::parse(readable) {
        return name;
    }
    let mut digest = Sha256::new();
    digest.update(b"d2b-activation-runner-v1");
    digest.update([0]);
    digest.update(generation.to_canonical_string().as_bytes());
    let digest = digest.finalize();
    let suffix = digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    ResourceName::parse(format!("activation-runner-{suffix}"))
        .expect("activation runner name is bounded and lowercase")
}

/// Return the deterministic child reference owned by one generation.
pub fn activation_runner_ref(generation: &ResourceRef) -> ResourceRef {
    let canonical = format!(
        "{ACTIVATION_RUNNER_RESOURCE_TYPE}/{}",
        activation_runner_name(generation).as_str()
    );
    ResourceRef::parse(&canonical).expect("activation runner reference is valid")
}

/// Build the closed EphemeralProcess contract for one activation request.
///
pub fn activation_runner_spec(request: &RunnerRequest) -> EphemeralProcessSpec {
    let template = d2b_contracts_resource::v3::BoundedToken::parse(ACTIVATION_RUNNER_TEMPLATE)
        .expect("static activation runner template");
    let sandbox = SandboxSpec::new(
        vec![
            NamespaceClass::Pid,
            NamespaceClass::Mount,
            NamespaceClass::Ipc,
        ],
        Vec::new(),
        d2b_contracts_resource::v3::BoundedToken::parse("activation-nixos-runner")
            .expect("static activation runner seccomp class"),
        true,
        request.start_root,
        EnvironmentClass::Minimal,
        true,
        Some("0022".to_owned()),
        0,
        None,
    )
    .expect("static activation runner sandbox");
    let budget = d2b_contracts_resource::v3::BudgetSpec::new(
        Some(d2b_contracts_resource::v3::CpuBudget {
            request: Some(
                d2b_contracts_resource::v3::MilliCpu::parse("100m")
                    .expect("static activation runner cpu request"),
            ),
            limit: Some(
                d2b_contracts_resource::v3::MilliCpu::parse("2000m")
                    .expect("static activation runner cpu limit"),
            ),
        }),
        Some(d2b_contracts_resource::v3::MemoryBudget {
            request: Some(
                d2b_contracts_resource::v3::ByteQuantity::parse("32Mi")
                    .expect("static activation runner memory request"),
            ),
            limit: Some(
                d2b_contracts_resource::v3::ByteQuantity::parse("128Mi")
                    .expect("static activation runner memory limit"),
            ),
        }),
        Some(d2b_contracts_resource::v3::CountBudget { limit: Some(128) }),
        Some(d2b_contracts_resource::v3::CountBudget { limit: Some(512) }),
        None,
        None,
        None,
    )
    .expect("static activation runner budget");
    let execution = ExecutionSpec::new(
        request.execution_ref.clone(),
        Some(ExecutionDomain::System),
        None,
        ProcessClass::Worker,
        template,
        None,
        Vec::new(),
        Vec::new(),
        sandbox,
        budget,
        None,
        Vec::new(),
        Default::default(),
    )
    .expect("static activation runner execution");
    let spec = EphemeralProcessSpec::new(
        execution,
        d2b_contracts_resource::v3::DurationMs::parse("120s", 1_000, 3_600_000)
            .expect("static activation runner start deadline"),
        d2b_contracts_resource::v3::DurationMs::parse("600s", 1_000, 86_400_000)
            .expect("static activation runner runtime deadline"),
        d2b_contracts_resource::v3::DurationMs::parse("1h", 0, 7 * 86_400_000)
            .expect("static activation runner success ttl"),
        d2b_contracts_resource::v3::DurationMs::parse("24h", 0, 30 * 86_400_000)
            .expect("static activation runner failure ttl"),
        false,
    )
    .expect("static activation runner process");
    spec.with_activation_input(
        ActivationRunnerInput::new(
            request.system_artifact_id.clone(),
            request.target_generation,
            request.activation_mode,
        )
        .expect("activation runner generation is nonzero"),
    )
    .expect("activation runner accepts its typed input")
}

/// Stable controller failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationError {
    /// Caller lacks lifecycle authority.
    Unauthorized,
    /// Caller or runner target differs from the authenticated target.
    TargetMismatch,
    /// Generation resource is malformed.
    InvalidSpec,
    /// A deleted row cannot be started.
    AlreadyDeleted,
    /// Result code does not match the selected activation mode.
    OutcomeMismatch,
}

impl core::fmt::Display for ActivationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Unauthorized => "activation-unauthorized",
            Self::TargetMismatch => "activation-target-mismatch",
            Self::InvalidSpec => "activation-spec-invalid",
            Self::AlreadyDeleted => "activation-already-deleted",
            Self::OutcomeMismatch => "activation-outcome-mismatch",
        })
    }
}

impl std::error::Error for ActivationError {}

/// Closed trust state used by activation/application verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustStatus {
    /// The trust state was explicitly cleared.
    Clear,
    /// The artifact or key was denied or revoked.
    Denied,
    /// The trust state could not be established.
    Unknown,
}

/// Redacted trust evidence bound to one activation request.
///
/// Signature and key bytes are retained only for the verification call and
/// are never rendered by `Debug` or copied into a resource projection.
#[derive(Clone, PartialEq, Eq)]
pub struct ActivationTrust {
    trust_epoch: u64,
    revocation_ref: Option<String>,
    revocation_status: TrustStatus,
    deny_status: TrustStatus,
    publisher_root: String,
    signature_id: String,
    public_key: Vec<u8>,
    signature: Vec<u8>,
}

impl core::fmt::Debug for ActivationTrust {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ActivationTrust")
            .field("trust_epoch", &self.trust_epoch)
            .field("has_revocation_ref", &self.revocation_ref.is_some())
            .field("revocation_status", &self.revocation_status)
            .field("deny_status", &self.deny_status)
            .field("has_publisher_root", &!self.publisher_root.is_empty())
            .field("has_signature_id", &!self.signature_id.is_empty())
            .field("public_key_bytes", &self.public_key.len())
            .field("signature_bytes", &self.signature.len())
            .finish()
    }
}

/// Expected trust and integrity facts for one activation/application.
#[derive(Clone, PartialEq, Eq)]
pub struct ActivationTrustExpectation {
    trust_epoch: u64,
    revocation_ref: Option<String>,
    publisher_root: String,
    signature_id: String,
    artifact_digest: String,
    artifact_catalog_digest: String,
    signed_payload: Vec<u8>,
}

impl core::fmt::Debug for ActivationTrustExpectation {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ActivationTrustExpectation")
            .field("trust_epoch", &self.trust_epoch)
            .field("has_revocation_ref", &self.revocation_ref.is_some())
            .field("has_publisher_root", &!self.publisher_root.is_empty())
            .field("has_signature_id", &!self.signature_id.is_empty())
            .field("has_artifact_digest", &!self.artifact_digest.is_empty())
            .field(
                "has_artifact_catalog_digest",
                &!self.artifact_catalog_digest.is_empty(),
            )
            .field("signed_payload_bytes", &self.signed_payload.len())
            .finish()
    }
}

/// Fail-closed activation/application verification failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationVerificationError {
    /// The trust epoch was absent or mismatched.
    TrustEpochMismatch,
    /// The revocation reference was absent or mismatched.
    RevocationRefMismatch,
    /// Revocation or deny status was not explicitly clear.
    TrustDenied,
    /// The publisher root was absent or mismatched.
    PublisherRootMismatch,
    /// The signature identifier was absent or mismatched.
    SignatureIdMismatch,
    /// The Ed25519 signature did not verify.
    SignatureInvalid,
    /// The artifact bytes did not match the expected digest.
    ArtifactDigestMismatch,
    /// The activation-time catalog digest did not match.
    ArtifactCatalogDigestMismatch,
    /// A required verification token was malformed.
    InvalidEvidence,
}

impl core::fmt::Display for ActivationVerificationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::TrustEpochMismatch => "activation-trust-epoch-mismatch",
            Self::RevocationRefMismatch => "activation-revocation-ref-mismatch",
            Self::TrustDenied => "activation-trust-denied",
            Self::PublisherRootMismatch => "activation-publisher-root-mismatch",
            Self::SignatureIdMismatch => "activation-signature-id-mismatch",
            Self::SignatureInvalid => "activation-signature-invalid",
            Self::ArtifactDigestMismatch => "activation-artifact-digest-mismatch",
            Self::ArtifactCatalogDigestMismatch => "activation-artifact-catalog-digest-mismatch",
            Self::InvalidEvidence => "activation-trust-evidence-invalid",
        })
    }
}

impl std::error::Error for ActivationVerificationError {}

impl ActivationTrust {
    /// Construct trust evidence for one activation request.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        trust_epoch: u64,
        revocation_ref: Option<String>,
        revocation_status: TrustStatus,
        deny_status: TrustStatus,
        publisher_root: impl Into<String>,
        signature_id: impl Into<String>,
        public_key: impl Into<Vec<u8>>,
        signature: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            trust_epoch,
            revocation_ref,
            revocation_status,
            deny_status,
            publisher_root: publisher_root.into(),
            signature_id: signature_id.into(),
            public_key: public_key.into(),
            signature: signature.into(),
        }
    }

    /// Verify all trust, Ed25519, artifact, and activation-catalog fences.
    pub fn verify(
        &self,
        expected: &ActivationTrustExpectation,
        artifact_bytes: &[u8],
        activation_catalog_digest: &str,
    ) -> Result<(), ActivationVerificationError> {
        if self.trust_epoch == 0 || self.trust_epoch != expected.trust_epoch {
            return Err(ActivationVerificationError::TrustEpochMismatch);
        }
        if self.revocation_ref != expected.revocation_ref {
            return Err(ActivationVerificationError::RevocationRefMismatch);
        }
        if self.revocation_status != TrustStatus::Clear || self.deny_status != TrustStatus::Clear {
            return Err(ActivationVerificationError::TrustDenied);
        }
        if self.publisher_root.is_empty() || self.publisher_root != expected.publisher_root {
            return Err(ActivationVerificationError::PublisherRootMismatch);
        }
        if self.signature_id.is_empty() || self.signature_id != expected.signature_id {
            return Err(ActivationVerificationError::SignatureIdMismatch);
        }
        if !is_sha256_digest(&expected.artifact_digest)
            || !is_sha256_digest(&expected.artifact_catalog_digest)
            || activation_catalog_digest != expected.artifact_catalog_digest
        {
            return Err(ActivationVerificationError::ArtifactCatalogDigestMismatch);
        }
        let actual_artifact_digest = sha256_digest(artifact_bytes);
        if actual_artifact_digest != expected.artifact_digest {
            return Err(ActivationVerificationError::ArtifactDigestMismatch);
        }
        if self.public_key.len() != 32 || self.signature.len() != 64 {
            return Err(ActivationVerificationError::InvalidEvidence);
        }
        signature::UnparsedPublicKey::new(&signature::ED25519, &self.public_key)
            .verify(&expected.signed_payload, &self.signature)
            .map_err(|_| ActivationVerificationError::SignatureInvalid)
    }
}

impl ActivationTrustExpectation {
    /// Construct expected trust and integrity facts.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        trust_epoch: u64,
        revocation_ref: Option<String>,
        publisher_root: impl Into<String>,
        signature_id: impl Into<String>,
        artifact_digest: impl Into<String>,
        artifact_catalog_digest: impl Into<String>,
        signed_payload: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            trust_epoch,
            revocation_ref,
            publisher_root: publisher_root.into(),
            signature_id: signature_id.into(),
            artifact_digest: artifact_digest.into(),
            artifact_catalog_digest: artifact_catalog_digest.into(),
            signed_payload: signed_payload.into(),
        }
    }
}

fn is_sha256_digest(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// Result of one activation reconcile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerResult {
    phase: ResourcePhase,
    source_generation_preserved: bool,
    audit_codes: Vec<ActivationOutcomeCode>,
    runner_requests: Vec<RunnerRequest>,
}

impl RunnerResult {
    /// Return the projected universal phase.
    pub const fn phase(&self) -> ResourcePhase {
        self.phase
    }

    /// Whether a failed effect left the source generation usable.
    pub const fn source_generation_preserved(&self) -> bool {
        self.source_generation_preserved
    }

    /// Borrow the bounded audit outcomes.
    pub fn audit_codes(&self) -> &[ActivationOutcomeCode] {
        &self.audit_codes
    }

    /// Borrow the typed runner requests.
    pub fn runner_requests(&self) -> &[RunnerRequest] {
        &self.runner_requests
    }
}

/// Retention result for terminal generation rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionPlan {
    delete_names: Vec<String>,
}

impl RetentionPlan {
    /// Return rows eligible for finalizer-driven deletion.
    pub fn delete_names(&self) -> &[String] {
        &self.delete_names
    }

    /// Retention never uses a time-to-live.
    pub const fn uses_ttl(&self) -> bool {
        false
    }
}

/// Activation-nixos controller policy.
#[derive(Debug, Clone, Copy)]
pub struct ActivationController {
    retained_generations: usize,
}

impl ActivationController {
    /// Construct a controller with the bounded retention window.
    pub fn new(retained_generations: usize) -> Self {
        assert!((1..=16).contains(&retained_generations));
        Self {
            retained_generations,
        }
    }

    /// Gate activation/application on the complete signed artifact envelope.
    pub fn verify_application(
        &self,
        trust: &ActivationTrust,
        expected: &ActivationTrustExpectation,
        artifact_bytes: &[u8],
        activation_catalog_digest: &str,
    ) -> Result<(), ActivationVerificationError> {
        trust.verify(expected, artifact_bytes, activation_catalog_digest)
    }

    /// Reconcile one desired generation.
    pub fn reconcile(
        &self,
        spec: &NixosGenerationSpec,
        caller: &ActivationCaller,
        prior: &[GenerationObservation],
        observed: GenerationObservation,
    ) -> Result<RunnerResult, ActivationError> {
        caller.authorize(spec)?;
        if let Some(prior_ref) = spec.prior_generation_ref()
            && !prior
                .iter()
                .any(|generation| generation.name() == prior_ref.name().as_str())
        {
            return Err(ActivationError::InvalidSpec);
        }
        if observed.phase == GenerationPhase::Deleted {
            return Err(ActivationError::AlreadyDeleted);
        }
        let runner_requests = if matches!(
            observed.phase,
            GenerationPhase::Pending | GenerationPhase::Degraded
        ) && spec.activation_mode() != ActivationMode::Adopt
        {
            let generation_ref = format!(
                "activation-nixos.d2bus.org.NixosGeneration/{}",
                observed.name()
            );
            vec![RunnerRequest {
                runner_name: activation_runner_name(
                    &ResourceRef::parse(&generation_ref).expect("generation reference is valid"),
                ),
                execution_ref: spec.execution_ref().clone(),
                system_artifact_id: spec.system_artifact_id().clone(),
                activation_mode: spec.activation_mode(),
                target_generation: observed.ordinal(),
                start_root: true,
            }]
        } else {
            Vec::new()
        };
        Ok(RunnerResult {
            phase: observed.phase.resource_phase(),
            source_generation_preserved: true,
            audit_codes: Vec::new(),
            runner_requests,
        })
    }

    /// Apply a typed runner result while preserving the prior generation on
    /// every refusal or failure.
    pub fn apply_runner_result(
        &self,
        spec: &NixosGenerationSpec,
        outcome: ActivationOutcomeCode,
        source: GenerationObservation,
    ) -> Result<RunnerResult, ActivationError> {
        let outcome_matches_mode = match spec.activation_mode() {
            ActivationMode::Adopt => matches!(outcome, ActivationOutcomeCode::Adopted),
            _ => !matches!(outcome, ActivationOutcomeCode::Adopted),
        };
        if !outcome_matches_mode {
            return Err(ActivationError::OutcomeMismatch);
        }
        let phase = if outcome.is_success() {
            match spec.activation_mode() {
                ActivationMode::Test => ResourcePhase::Succeeded,
                _ => ResourcePhase::Ready,
            }
        } else {
            match source.phase {
                GenerationPhase::Ready => ResourcePhase::Degraded,
                _ => ResourcePhase::Failed,
            }
        };
        Ok(RunnerResult {
            phase,
            source_generation_preserved: !outcome.is_success(),
            audit_codes: vec![outcome],
            runner_requests: Vec::new(),
        })
    }

    /// Compute finalizer-driven retention deletions.
    pub fn retention_plan(&self, observations: &[GenerationObservation]) -> RetentionPlan {
        let mut ordered = observations
            .iter()
            .map(|row| (row.ordinal, row.name.clone()))
            .collect::<Vec<_>>();
        ordered.sort_by_key(|(ordinal, _)| *ordinal);
        let keep = ordered
            .iter()
            .rev()
            .take(self.retained_generations)
            .map(|(_, name)| name.as_str())
            .collect::<BTreeSet<_>>();
        RetentionPlan {
            delete_names: observations
                .iter()
                .filter(|row| row.phase.terminal() && !keep.contains(row.name.as_str()))
                .map(|row| row.name.clone())
                .collect(),
        }
    }
}
