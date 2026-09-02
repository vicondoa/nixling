use std::process::Command;

#[test]
fn standalone_entrypoint_refuses_without_authenticated_registration() {
    let output = Command::new(env!("CARGO_BIN_EXE_d2b-provider-credential-entra"))
        .env_remove("AZURE_CLIENT_ID")
        .env_remove("AZURE_CLIENT_SECRET")
        .env_remove("AZURE_TENANT_ID")
        .env_remove("AWS_ACCESS_KEY_ID")
        .env_remove("AWS_SECRET_ACCESS_KEY")
        .output()
        .expect("run Entra entrypoint");
    assert!(!output.status.success());
}
