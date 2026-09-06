//! Secret Service Provider binary entry point.

fn main() {
    std::process::exit(d2b_provider_credential_secret_service::run_from_fd10());
}
