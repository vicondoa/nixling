use std::process::Command;

#[test]
fn no_bootstrap_descriptor_fails_closed() {
    let binary = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("CARGO_BIN_EXE_d2b-provider-test-controller").ok())
        .or_else(|| std::env::var("CARGO_BIN_EXE_d2b_provider_test_controller").ok())
        .expect("controller fixture binary path");
    let output = Command::new(binary)
        .output()
        .expect("spawn controller fixture");
    assert!(
        !output.status.success(),
        "controller without inherited fd10 must fail closed"
    );
}
