use std::process::Command;

fn scrub_ambient_environment(command: &mut Command) -> &mut Command {
    for key in [
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
        "AZURE_TENANT_ID",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "IDENTITY_ENDPOINT",
        "MSI_ENDPOINT",
    ] {
        command.env_remove(key);
    }
    command
}

#[test]
fn controller_entrypoint_refuses_without_authenticated_registration() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_d2b-managed-identity-controller"));
    let output = scrub_ambient_environment(&mut command)
        .output()
        .expect("run managed identity controller");
    assert!(!output.status.success());
}

#[test]
fn agent_entrypoint_refuses_without_authenticated_registration() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_d2b-managed-identity-agent"));
    let output = scrub_ambient_environment(&mut command)
        .output()
        .expect("run managed identity agent");
    assert!(!output.status.success());
}
