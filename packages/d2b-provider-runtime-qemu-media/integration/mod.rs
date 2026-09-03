//! integration-target: container
//! Fake-host integration fixtures for the qemu-media Provider.

mod fixture;

#[cfg(test)]
mod tests {
    use super::fixture;

    #[test]
    fn fixture_contains_guest_runtime_volume_and_process() {
        let (guest, volume, process) = fixture::fixture();
        assert_eq!(
            guest.provider_ref().unwrap().to_canonical_string(),
            "Provider/runtime-qemu-media"
        );
        assert_eq!(volume.cleanup_policy(), "vm-stop-with-proof");
        assert_eq!(process.execution().template().as_str(), "qemu-media-runner");
    }
}
