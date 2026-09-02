use d2b_contracts_resource::v3::ActivationOutcomeCode;
use d2b_contracts_resource::v3::{ActivationMode, NixosGenerationSpec, ResourcePhase, ResourceRef};
use d2b_provider_activation_nixos::{
    ActivationCaller, ActivationController, ActivationTrust, ActivationTrustExpectation,
    CallerRole, GenerationObservation, GenerationPhase, TrustStatus, activation_runner_name,
    activation_runner_ref,
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use sha2::{Digest, Sha256};

fn spec() -> NixosGenerationSpec {
    NixosGenerationSpec::new(
        ResourceRef::parse("Provider/activation-nixos").unwrap(),
        ResourceRef::parse("Guest/dev-vm").unwrap(),
        "dev-vm-system",
        ActivationMode::Switch,
        None,
    )
    .unwrap()
}

fn spec_with_mode(mode: ActivationMode) -> NixosGenerationSpec {
    NixosGenerationSpec::new(
        ResourceRef::parse("Provider/activation-nixos").unwrap(),
        ResourceRef::parse("Guest/dev-vm").unwrap(),
        "dev-vm-system",
        mode,
        None,
    )
    .unwrap()
}

fn caller() -> ActivationCaller {
    ActivationCaller::new(
        CallerRole::Lifecycle,
        ResourceRef::parse("Guest/dev-vm").unwrap(),
    )
}

#[test]
fn compatible_generation_starts_one_typed_runner() {
    let controller = ActivationController::new(3);
    let result = controller
        .reconcile(
            &spec(),
            &caller(),
            &[],
            GenerationObservation::new("gen-7", GenerationPhase::Pending),
        )
        .unwrap();
    assert_eq!(result.runner_requests().len(), 1);
    assert!(result.runner_requests()[0].start_root);
    assert_eq!(
        result.runner_requests()[0].runner_name,
        activation_runner_name(
            &ResourceRef::parse("activation-nixos.d2bus.org.NixosGeneration/gen-7").unwrap()
        )
    );
    assert_eq!(result.phase(), ResourcePhase::Pending);
}

#[test]
fn activation_runner_reference_is_stable_and_target_local() {
    let generation =
        ResourceRef::parse("activation-nixos.d2bus.org.NixosGeneration/gen-7").unwrap();
    assert_eq!(
        activation_runner_ref(&generation),
        activation_runner_ref(&generation)
    );
    assert_eq!(
        activation_runner_ref(&generation).resource_type().as_str(),
        "EphemeralProcess"
    );
    assert_ne!(
        activation_runner_ref(&generation),
        activation_runner_ref(
            &ResourceRef::parse("activation-nixos.d2bus.org.NixosGeneration/gen-8").unwrap()
        )
    );
}

#[test]
fn activation_runner_spec_is_closed_and_bounded() {
    let generation =
        ResourceRef::parse("activation-nixos.d2bus.org.NixosGeneration/gen-7").unwrap();
    let controller = ActivationController::new(3);
    let planned = controller
        .reconcile(
            &spec(),
            &caller(),
            &[],
            GenerationObservation::new("gen-7", GenerationPhase::Pending),
        )
        .unwrap();
    let runner =
        d2b_provider_activation_nixos::activation_runner_spec(&planned.runner_requests()[0]);
    let rendered = serde_json::to_value(&runner).expect("runner spec is serializable");
    assert_eq!(
        rendered["activationInput"]["systemArtifactId"],
        "dev-vm-system"
    );
    assert_eq!(rendered["activationInput"]["targetGeneration"], 7);
    assert_eq!(rendered["activationInput"]["activationMode"], "switch");
    assert_eq!(
        runner.execution().execution_ref(),
        &ResourceRef::parse("Guest/dev-vm").unwrap()
    );
    assert_eq!(
        runner.execution().template().as_str(),
        "activation-nixos-runner"
    );
    assert_eq!(
        runner.execution().process_class(),
        d2b_contracts_resource::v3::ProcessClass::Worker
    );
    assert!(runner.execution().sandbox().start_root());
    assert!(runner.execution().sandbox().no_new_privileges());
    assert_eq!(runner.start_deadline().as_str(), "120s");
    assert_eq!(runner.runtime_deadline().as_str(), "600s");
    assert_eq!(
        activation_runner_name(&generation).as_str(),
        "activation-nixos--runner--gen-7"
    );
}

#[test]
fn unauthorized_or_foreign_callers_refuse_before_runner_creation() {
    let controller = ActivationController::new(3);
    let foreign = ActivationCaller::new(
        CallerRole::User,
        ResourceRef::parse("Guest/dev-vm").unwrap(),
    );
    let result = controller.reconcile(
        &spec(),
        &foreign,
        &[],
        GenerationObservation::new("gen-7", GenerationPhase::Pending),
    );
    assert!(result.is_err());
}

#[test]
fn runner_failure_preserves_the_source_generation_and_audits_one_code() {
    let controller = ActivationController::new(3);
    let failed = controller
        .apply_runner_result(
            &spec(),
            ActivationOutcomeCode::HelperFailed,
            GenerationObservation::new("gen-6", GenerationPhase::Ready),
        )
        .unwrap();
    assert!(failed.source_generation_preserved());
    assert_eq!(failed.audit_codes(), &[ActivationOutcomeCode::HelperFailed]);
}

#[test]
fn adopted_outcome_is_rejected_for_switch_mode() {
    let controller = ActivationController::new(3);
    let result = controller.apply_runner_result(
        &spec(),
        ActivationOutcomeCode::Adopted,
        GenerationObservation::new("gen-6", GenerationPhase::Ready),
    );
    assert_eq!(
        result.unwrap_err(),
        d2b_provider_activation_nixos::ActivationError::OutcomeMismatch
    );
}

#[test]
fn adopt_mode_accepts_adoption_without_starting_a_runner() {
    let controller = ActivationController::new(3);
    let adopt = spec_with_mode(ActivationMode::Adopt);
    let pending = controller
        .reconcile(
            &adopt,
            &caller(),
            &[],
            GenerationObservation::new("gen-7", GenerationPhase::Pending),
        )
        .unwrap();
    assert!(pending.runner_requests().is_empty());

    let result = controller
        .apply_runner_result(
            &adopt,
            ActivationOutcomeCode::Adopted,
            GenerationObservation::new("gen-6", GenerationPhase::Ready),
        )
        .unwrap();
    assert_eq!(result.phase(), ResourcePhase::Ready);
    assert!(!result.source_generation_preserved());
}

#[test]
fn test_mode_succeeds_without_preserving_the_source_generation() {
    let controller = ActivationController::new(3);
    let result = controller
        .apply_runner_result(
            &spec_with_mode(ActivationMode::Test),
            ActivationOutcomeCode::Succeeded,
            GenerationObservation::new("gen-6", GenerationPhase::Ready),
        )
        .unwrap();
    assert_eq!(result.phase(), ResourcePhase::Succeeded);
    assert!(!result.source_generation_preserved());
}

#[test]
fn successful_switch_reports_ready_and_replaces_the_source_generation() {
    let controller = ActivationController::new(3);
    let result = controller
        .apply_runner_result(
            &spec(),
            ActivationOutcomeCode::Succeeded,
            GenerationObservation::new("gen-6", GenerationPhase::Ready),
        )
        .unwrap();
    assert_eq!(result.phase(), ResourcePhase::Ready);
    assert!(!result.source_generation_preserved());
}

#[test]
fn deleted_generation_is_not_restarted() {
    let controller = ActivationController::new(3);
    let result = controller.reconcile(
        &spec(),
        &caller(),
        &[],
        GenerationObservation::new("gen-7", GenerationPhase::Deleted),
    );
    assert_eq!(
        result.unwrap_err(),
        d2b_provider_activation_nixos::ActivationError::AlreadyDeleted
    );
}

#[test]
fn prior_generation_reference_must_be_present_in_observations() {
    let spec = NixosGenerationSpec::new(
        ResourceRef::parse("Provider/activation-nixos").unwrap(),
        ResourceRef::parse("Guest/dev-vm").unwrap(),
        "dev-vm-system",
        ActivationMode::Switch,
        Some(ResourceRef::parse("activation-nixos.d2bus.org.NixosGeneration/gen-6").unwrap()),
    )
    .unwrap();
    let controller = ActivationController::new(3);
    let result = controller.reconcile(
        &spec,
        &caller(),
        &[],
        GenerationObservation::new("gen-7", GenerationPhase::Pending),
    );
    assert_eq!(
        result.unwrap_err(),
        d2b_provider_activation_nixos::ActivationError::InvalidSpec
    );
    let result = controller
        .reconcile(
            &spec,
            &caller(),
            &[GenerationObservation::new("gen-6", GenerationPhase::Ready)],
            GenerationObservation::new("gen-7", GenerationPhase::Pending),
        )
        .unwrap();
    assert_eq!(result.runner_requests().len(), 1);
}

#[test]
fn retention_prunes_only_old_terminal_generations_without_ttl() {
    let controller = ActivationController::new(2);
    let observations = vec![
        GenerationObservation::terminal("gen-1", GenerationPhase::Succeeded, 1),
        GenerationObservation::terminal("gen-2", GenerationPhase::Failed, 2),
        GenerationObservation::terminal("gen-3", GenerationPhase::Ready, 3),
    ];
    let plan = controller.retention_plan(&observations);
    assert_eq!(plan.delete_names(), &["gen-1".to_owned()]);
    assert!(!plan.uses_ttl());
}

fn trust_fixture() -> (ActivationTrust, ActivationTrustExpectation, Vec<u8>, String) {
    let rng = ring::rand::SystemRandom::new();
    let key_pair = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(key_pair.as_ref()).unwrap();
    let payload = b"activation-envelope".to_vec();
    let artifact = b"verified-system".to_vec();
    let signature = key_pair.sign(&payload);
    let artifact_digest = format!("sha256:{:x}", Sha256::digest(&artifact));
    let catalog_digest = format!("sha256:{}", "1".repeat(64));
    let trust = ActivationTrust::new(
        7,
        Some("revocation/7".to_owned()),
        TrustStatus::Clear,
        TrustStatus::Clear,
        "publisher-root",
        "signing-key-7",
        key_pair.public_key().as_ref().to_vec(),
        signature.as_ref().to_vec(),
    );
    let expected = ActivationTrustExpectation::new(
        7,
        Some("revocation/7".to_owned()),
        "publisher-root",
        "signing-key-7",
        artifact_digest,
        catalog_digest.clone(),
        payload,
    );
    (trust, expected, artifact, catalog_digest)
}

#[test]
fn activation_verification_requires_all_trust_and_digest_fences() {
    let (trust, expected, artifact, catalog_digest) = trust_fixture();
    ActivationController::new(3)
        .verify_application(&trust, &expected, &artifact, &catalog_digest)
        .expect("trusted activation verifies");

    let mut cases = Vec::new();
    cases.push(ActivationTrust::new(
        8,
        Some("revocation/7".to_owned()),
        TrustStatus::Clear,
        TrustStatus::Clear,
        "publisher-root",
        "signing-key-7",
        vec![0; 32],
        vec![0; 64],
    ));
    cases.push(ActivationTrust::new(
        7,
        Some("revocation/8".to_owned()),
        TrustStatus::Clear,
        TrustStatus::Clear,
        "publisher-root",
        "signing-key-7",
        vec![0; 32],
        vec![0; 64],
    ));
    cases.push(ActivationTrust::new(
        7,
        Some("revocation/7".to_owned()),
        TrustStatus::Denied,
        TrustStatus::Clear,
        "publisher-root",
        "signing-key-7",
        vec![0; 32],
        vec![0; 64],
    ));
    cases.push(ActivationTrust::new(
        7,
        Some("revocation/7".to_owned()),
        TrustStatus::Unknown,
        TrustStatus::Clear,
        "publisher-root",
        "signing-key-7",
        vec![0; 32],
        vec![0; 64],
    ));
    cases.push(ActivationTrust::new(
        7,
        Some("revocation/7".to_owned()),
        TrustStatus::Clear,
        TrustStatus::Clear,
        "other-root",
        "signing-key-7",
        vec![0; 32],
        vec![0; 64],
    ));
    cases.push(ActivationTrust::new(
        7,
        Some("revocation/7".to_owned()),
        TrustStatus::Clear,
        TrustStatus::Clear,
        "publisher-root",
        "other-key",
        vec![0; 32],
        vec![0; 64],
    ));

    for (trust, expected_error) in cases.into_iter().zip([
        d2b_provider_activation_nixos::ActivationVerificationError::TrustEpochMismatch,
        d2b_provider_activation_nixos::ActivationVerificationError::RevocationRefMismatch,
        d2b_provider_activation_nixos::ActivationVerificationError::TrustDenied,
        d2b_provider_activation_nixos::ActivationVerificationError::TrustDenied,
        d2b_provider_activation_nixos::ActivationVerificationError::PublisherRootMismatch,
        d2b_provider_activation_nixos::ActivationVerificationError::SignatureIdMismatch,
    ]) {
        assert_eq!(
            trust.verify(&expected, &artifact, &catalog_digest),
            Err(expected_error)
        );
    }
}

#[test]
fn activation_verification_rejects_digest_catalog_and_signature_changes() {
    let (trust, expected, artifact, catalog_digest) = trust_fixture();
    assert_eq!(
        trust.verify(&expected, b"changed", &catalog_digest),
        Err(d2b_provider_activation_nixos::ActivationVerificationError::ArtifactDigestMismatch)
    );
    assert_eq!(
        trust.verify(
            &expected,
            &artifact,
            &("sha256:".to_owned() + &"2".repeat(64))
        ),
        Err(d2b_provider_activation_nixos::ActivationVerificationError::ArtifactCatalogDigestMismatch)
    );
    let payload = b"changed-envelope".to_vec();
    let changed = ActivationTrustExpectation::new(
        7,
        Some("revocation/7".to_owned()),
        "publisher-root",
        "signing-key-7",
        format!("sha256:{:x}", Sha256::digest(&artifact)),
        catalog_digest.clone(),
        payload,
    );
    assert_eq!(
        trust.verify(&changed, &artifact, &catalog_digest),
        Err(d2b_provider_activation_nixos::ActivationVerificationError::SignatureInvalid)
    );
}
