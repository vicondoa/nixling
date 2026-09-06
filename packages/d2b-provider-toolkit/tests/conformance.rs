//! Focused Provider toolkit conformance over the v3 registry and service seam.

use std::{
    fmt::Write as FmtWrite,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use d2b_contracts_provider::v3::provider::{
    ArtifactDigest, ArtifactDigestSet, BinaryRef, CompatibilityRange, ComponentDescriptor,
    ComponentExecution, ComponentTargetCapability, ComponentType, ControllerInstanceScope,
    ControllerTargetKind, EffectPortClass, PolicyEvaluation, ProviderManifest, ResourceApiBinding,
    RevocationState, SignatureState, StandardCapabilityMatrix, TargetRuntimeArtifacts,
    TrustEvidence, UpgradeDisposition, UpgradePolicy,
};
use d2b_contracts_resource::v3::execution_policy::{BoundedToken, ExecutionDomain};
use d2b_contracts_resource::v3::{
    ArtifactId,
    identity::{ResourceTypeName, SchemaFingerprint},
    resource_schema::{PlacementAnchor, SchemaVersion},
};
use d2b_provider::{
    AdmissionOptions, CancellationToken, ProviderClass, ProviderMethodName,
    ProviderRegistryBuilder, ProviderRuntimeError,
};
use d2b_provider_toolkit::{
    FakeProvider, Fixture, GeneratedProviderServiceServer, ProviderValues, ServerError,
    manifest::{self, VerificationError},
};
use sha2::{Digest, Sha256};

const MANIFEST_DIGEST_VECTOR: &str =
    "sha256:9990d27a7e6aa2b2a946ac8966c3470a6d664641f3de3a55ed5a3d6a59696697";
const MANIFEST_DIGEST: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000001";
static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[tokio::test]
async fn fake_provider_round_trip_uses_the_exact_placement_binding() {
    let first = Fixture::new(ProviderClass::Runtime, 0).expect("first fixture");
    let second = Fixture::new(ProviderClass::Runtime, 1).expect("second fixture");
    let mut builder =
        ProviderRegistryBuilder::new(first.zone().clone(), first.descriptor.registry_generation());
    builder
        .register_instance(first.descriptor.clone(), ())
        .expect("first descriptor");
    builder
        .register_instance(second.descriptor.clone(), ())
        .expect("second descriptor");
    let registry = builder.finish().expect("registry");
    let method = ProviderMethodName::parse("health").expect("health method");
    let first_admitted = registry
        .admit(AdmissionOptions {
            identity: first.session_identity().expect("first identity"),
            expected_method: method.clone(),
            deadline_after: Duration::from_secs(1),
            caller_cancellation: CancellationToken::new(),
        })
        .expect("first admission");
    let second_admitted = registry
        .admit(AdmissionOptions {
            identity: second.session_identity().expect("second identity"),
            expected_method: method.clone(),
            deadline_after: Duration::from_secs(1),
            caller_cancellation: CancellationToken::new(),
        })
        .expect("second admission");

    let provider = FakeProvider::new(first.clone());
    let response = provider.call(method.clone()).expect("round trip");
    assert!(response.get("state").is_some());
    first_admitted
        .context
        .identity()
        .matches_descriptor(&first.descriptor)
        .expect("matching placement");
    assert_eq!(
        second_admitted
            .context
            .identity()
            .matches_descriptor(&first.descriptor)
            .expect_err("foreign placement must fail"),
        ProviderRuntimeError::SessionIdentityMismatch
    );
    assert_eq!(provider.call_count(), 1);
}

#[test]
fn fake_provider_conformance_keeps_health_inspection_and_observability_closed() {
    let fixture = Fixture::new(ProviderClass::Observability, 0).expect("fixture");
    let values = ProviderValues::new(&fixture.descriptor, fixture.now_unix_ms).expect("values");
    assert_eq!(
        values.observability().sequence(),
        &["health", "inspect", "observability"]
    );
    FakeProvider::new(fixture)
        .conformance_sequence()
        .expect("closed sequence");
}

#[tokio::test]
async fn generated_server_shutdown_refuses_new_work_after_drain() {
    let fixture = Fixture::new(ProviderClass::Runtime, 0).expect("fixture");
    let server = GeneratedProviderServiceServer::new(FakeProvider::new(fixture));
    let permit = server.admit_request().expect("request permit");
    let drain = server.shutdown(Duration::from_millis(1)).await;
    assert!(!drain);
    drop(permit);
    assert!(server.shutdown(Duration::from_millis(100)).await);
    assert_eq!(
        server.admit_request().expect_err("server is retired"),
        ServerError::NotAccepting
    );
}

#[test]
fn canonical_manifest_round_trip_is_byte_identical() {
    let emitted = manifest::emit_canonical(&test_manifest());
    let parsed: ProviderManifest = serde_json::from_slice(&emitted).expect("canonical bytes parse");

    assert_eq!(emitted, manifest::emit_canonical(&parsed));
}

#[test]
fn canonical_manifest_cli_output_has_no_newline_or_bom() {
    let input = manifest::emit_canonical(&test_manifest());
    let path = unique_temp_path("emit");
    let output = run_emit(&input, &path);

    assert!(output.status.success(), "emit failed: {output:?}");
    let written = fs::read(&path).expect("read emitted manifest");
    assert_eq!(written, input);
    assert_ne!(
        written.first(),
        Some(&0xef),
        "the output must not start with a BOM"
    );
    assert_ne!(
        written.last(),
        Some(&b'\n'),
        "the output must not end in a newline"
    );
    assert_eq!(written.len(), input.len());
    let verification = run_verify(&path);
    assert!(
        verification.status.success(),
        "verify failed: {verification:?}"
    );
    assert_eq!(verification.stdout, b"canonical\n");
    remove_temp_path(&path);
}

#[test]
fn canonical_manifest_digest_matches_the_committed_vector() {
    let emitted = manifest::emit_canonical(&test_manifest());
    let digest = Sha256::digest(emitted);
    let mut rendered = String::from("sha256:");
    for byte in digest {
        write!(&mut rendered, "{byte:02x}").expect("format digest");
    }

    assert_eq!(rendered, MANIFEST_DIGEST_VECTOR);
}

#[test]
fn canonical_manifest_is_independent_of_input_key_order() {
    let canonical = manifest::emit_canonical(&test_manifest());
    let reordered = reorder_top_level_keys(&canonical);
    assert_ne!(canonical, reordered);

    let first: ProviderManifest = serde_json::from_slice(&canonical).expect("canonical manifest");
    let second: ProviderManifest = serde_json::from_slice(&reordered).expect("reordered manifest");
    assert_eq!(
        manifest::emit_canonical(&first),
        manifest::emit_canonical(&second)
    );
}

#[test]
fn verify_reports_the_same_offset_as_compiler_canonicality_check() {
    let canonical = manifest::emit_canonical(&test_manifest());
    let parsed: ProviderManifest = serde_json::from_slice(&canonical).expect("canonical manifest");
    let expected = manifest::emit_canonical(&parsed);
    let mangled = [
        {
            let mut bytes = canonical.clone();
            bytes.push(b'\n');
            bytes
        },
        reorder_top_level_keys(&canonical),
        serde_json::to_vec_pretty(
            &serde_json::from_slice::<serde_json::Value>(&canonical).expect("canonical JSON value"),
        )
        .expect("pretty JSON"),
    ];

    for (index, observed) in mangled.into_iter().enumerate() {
        let mismatch = match manifest::verify_canonical(&observed) {
            Err(VerificationError::NotCanonical(mismatch)) => mismatch,
            other => panic!("mangle {index} unexpectedly verified: {other:?}"),
        };
        let compiler_offset = first_difference(&expected, &observed);
        assert_eq!(mismatch.offset(), compiler_offset as u64);

        let path = unique_temp_path(&format!("verify-{index}"));
        fs::write(&path, &observed).expect("write mangled manifest");
        let output = run_verify(&path);
        assert!(!output.status.success(), "mangle {index} verified");
        assert_eq!(
            reported_offset(&output),
            compiler_offset as u64,
            "mangle {index} reported a different offset"
        );
        remove_temp_path(&path);
    }
}

fn test_manifest() -> ProviderManifest {
    let digest = ArtifactDigest::parse(MANIFEST_DIGEST).expect("valid digest");
    let component = ComponentDescriptor::new(
        BoundedToken::parse("volume-controller").expect("valid component"),
        ComponentType::Controller,
        [ResourceTypeName::parse("Volume").expect("valid resource type")],
        [BoundedToken::parse("assess-update").expect("valid method")],
        [ExecutionDomain::System],
        1,
        digest.clone(),
        [],
        false,
    )
    .expect("valid component")
    .with_execution(ComponentExecution::Launchable {
        binary_ref: BinaryRef::parse("volume-controller").expect("valid binary ref"),
    })
    .with_controller_placement(
        ControllerInstanceScope::PerResourceTarget,
        [ControllerTargetKind::Host, ControllerTargetKind::Guest],
    )
    .expect("valid controller placement")
    .with_target_capabilities([
        ComponentTargetCapability::new(
            ControllerTargetKind::Host,
            digest.clone(),
            [EffectPortClass::Storage],
        )
        .expect("valid host capability"),
        ComponentTargetCapability::new(
            ControllerTargetKind::Guest,
            digest.clone(),
            [EffectPortClass::Storage],
        )
        .expect("valid guest capability"),
    ])
    .expect("valid target capabilities");
    let binding = ResourceApiBinding::new_with_placement(
        ResourceTypeName::parse("Volume").expect("valid resource type"),
        SchemaVersion::new(1, 0).expect("valid schema version"),
        fingerprint("2"),
        SchemaVersion::new(1, 0).expect("valid schema version"),
        fingerprint("3"),
        StandardCapabilityMatrix::default(),
        None,
        None,
        PlacementAnchor::ExecutionRef,
    )
    .expect("valid binding");
    ProviderManifest::new(
        ArtifactId::parse("provider-volume-local").expect("valid artifact"),
        ArtifactDigestSet {
            executable: digest.clone(),
            config: digest.clone(),
            schema: digest.clone(),
            service: digest.clone(),
        },
        TrustEvidence {
            publisher: BoundedToken::parse("first-party").expect("valid publisher"),
            root_epoch: 1,
            publisher_trusted: true,
            signature: SignatureState::Valid,
            revocation: RevocationState::Clear,
            emergency_deny: false,
            provenance: PolicyEvaluation::Accepted,
            sbom: PolicyEvaluation::Accepted,
            license: PolicyEvaluation::Accepted,
            vulnerability: PolicyEvaluation::Accepted,
            conformance: PolicyEvaluation::Accepted,
            support_channel: BoundedToken::parse("stable").expect("valid channel"),
        },
        CompatibilityRange {
            api_major: 3,
            api_minor: 4,
            descriptor_fingerprint: fingerprint("1"),
            state_schema_version: SchemaVersion::new(1, 0).expect("valid schema version"),
        },
        [component],
        [binding],
        [],
        UpgradePolicy {
            drain_before_upgrade: true,
            max_automatic_disposition: UpgradeDisposition::InPlace,
            preserves_durable_state: true,
        },
    )
    .expect("valid manifest")
    .with_target_runtime_artifacts([
        TargetRuntimeArtifacts::new(ControllerTargetKind::Host, digest.clone(), digest.clone())
            .expect("valid host runtime artifacts"),
        TargetRuntimeArtifacts::new(ControllerTargetKind::Guest, digest.clone(), digest.clone())
            .expect("valid guest runtime artifacts"),
    ])
    .expect("valid shared runtime artifacts")
}

fn fingerprint(tail: &str) -> SchemaFingerprint {
    SchemaFingerprint::parse(format!("sha256:{}{tail}", "0".repeat(63))).expect("valid fingerprint")
}

fn reorder_top_level_keys(bytes: &[u8]) -> Vec<u8> {
    let value: serde_json::Value = serde_json::from_slice(bytes).expect("JSON object");
    let object = value.as_object().expect("manifest object");
    let mut keys = object.keys().cloned().collect::<Vec<_>>();
    keys.reverse();
    let mut output = b"{".to_vec();
    for (index, key) in keys.iter().enumerate() {
        if index != 0 {
            output.push(b',');
        }
        output.extend(serde_json::to_vec(key).expect("JSON key"));
        output.push(b':');
        output.extend(serde_json::to_vec(&object[key]).expect("JSON member"));
    }
    output.push(b'}');
    output
}

fn first_difference(expected: &[u8], observed: &[u8]) -> usize {
    expected
        .iter()
        .zip(observed)
        .position(|(expected, observed)| expected != observed)
        .unwrap_or_else(|| expected.len().min(observed.len()))
}

fn unique_temp_path(label: &str) -> PathBuf {
    let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "d2b-provider-toolkit-{}-{sequence}-{label}.json",
        std::process::id()
    ))
}

fn run_emit(input: &[u8], path: &Path) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_d2b-provider-toolkit"))
        .args(["manifest", "emit", "--out"])
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn toolkit CLI");
    child
        .stdin
        .take()
        .expect("stdin pipe")
        .write_all(input)
        .expect("write manifest input");
    child.wait_with_output().expect("wait for toolkit CLI")
}

fn run_verify(path: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_d2b-provider-toolkit"))
        .args(["manifest", "verify"])
        .arg(path)
        .output()
        .expect("run toolkit CLI")
}

fn reported_offset(output: &Output) -> u64 {
    let stderr = String::from_utf8_lossy(&output.stderr);
    stderr
        .split_whitespace()
        .find_map(|token| token.strip_prefix("offset="))
        .expect("offset in verification diagnostic")
        .parse()
        .expect("numeric offset")
}

fn remove_temp_path(path: &Path) {
    fs::remove_file(path).expect("remove temporary manifest");
}
