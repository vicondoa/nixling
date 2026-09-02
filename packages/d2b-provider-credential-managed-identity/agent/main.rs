//! Co-located managed identity agent entry point.

fn main() {
    std::process::exit(d2b_provider_credential_managed_identity::run_from_fd10(
        d2b_provider_credential_managed_identity::AGENT_BINARY,
    ));
}
