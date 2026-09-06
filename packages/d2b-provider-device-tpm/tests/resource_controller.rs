use d2b_contracts_resource::v3::{ResourceRef, ResourceUid};
use d2b_provider_device_tpm::{
    TpmResourceController, TpmResourceEffectError, TpmResourceEffectPort, TpmResourceOutcome,
    build_tpm_state_volume_spec,
};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[test]
fn controller_uses_opaque_resource_effects_and_preserves_volume_on_finalize() {
    let device = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
    let device_ref = ResourceRef::parse("Device/work-tpm").unwrap();
    let execution = ResourceRef::parse("Host/host-system").unwrap();
    let spec = build_tpm_state_volume_spec(&device, &execution).unwrap();
    assert_eq!(spec["source"]["settings"]["kind"], "local-path");
    assert!(spec.get("hostPath").is_none());

    fn assert_port<P: TpmResourceEffectPort>() {}
    assert_port::<NoopEffects>();
    assert_eq!(TpmResourceOutcome::VolumeRetained.code(), "volume-retained");

    let mut controller = TpmResourceController::new(device, device_ref, execution).unwrap();
    let effects = NoopEffects;
    assert_eq!(
        block_on(controller.reconcile(&effects)).unwrap(),
        TpmResourceOutcome::Ready
    );
    assert_eq!(
        block_on(controller.finalize(&effects)).unwrap(),
        TpmResourceOutcome::VolumeRetained
    );
    assert!(!controller.finalizer_installed());
}

#[test]
fn repeated_reconcile_reuses_children_and_keeps_persistent_evidence() {
    let device = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
    let device_ref = ResourceRef::parse("Device/work-tpm").unwrap();
    let execution = ResourceRef::parse("Host/host-system").unwrap();
    let effects = ScriptedEffects::default();
    let mut controller = TpmResourceController::new(device, device_ref, execution).unwrap();

    block_on(controller.reconcile(&effects)).unwrap();
    let first_status = controller.status();
    block_on(controller.reconcile(&effects)).unwrap();
    let second_status = controller.status();

    assert_eq!(first_status, second_status);
    assert_eq!(
        effects.events.lock().unwrap().as_slice(),
        ["volume", "flush", "process", "endpoint", "endpoint"]
    );
    assert_eq!(
        first_status.marker_status,
        d2b_provider_device_tpm::TpmMarkerStatus::Verified
    );
    assert!(first_status.state_volume_ref.is_some());
    assert!(first_status.swtpm_process_ref.is_some());
    assert!(first_status.last_flush_ref.is_some());
    assert!(first_status.tpm_endpoint_ref.is_some());
}

#[test]
fn persisted_evidence_rehydrates_without_recreating_children() {
    let device = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
    let device_ref = ResourceRef::parse("Device/work-tpm").unwrap();
    let execution = ResourceRef::parse("Host/host-system").unwrap();
    let effects = ScriptedEffects::default();
    let mut controller =
        TpmResourceController::new(device.clone(), device_ref.clone(), execution.clone()).unwrap();
    block_on(controller.reconcile(&effects)).unwrap();
    let status = controller.status();

    let mut restored =
        TpmResourceController::from_status(device, device_ref, execution, &status).unwrap();
    let restored_effects = ScriptedEffects::default();
    block_on(restored.reconcile(&restored_effects)).unwrap();
    assert_eq!(restored.status(), status);
    assert_eq!(
        restored_effects.events.lock().unwrap().as_slice(),
        ["volume", "endpoint"]
    );
}

#[test]
fn tampered_persisted_status_fails_before_child_reuse() {
    let device = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
    let device_ref = ResourceRef::parse("Device/work-tpm").unwrap();
    let execution = ResourceRef::parse("Host/host-system").unwrap();
    let effects = ScriptedEffects::default();
    let mut controller =
        TpmResourceController::new(device.clone(), device_ref.clone(), execution.clone()).unwrap();
    block_on(controller.reconcile(&effects)).unwrap();
    let mut status = controller.status();
    status.marker_status = d2b_provider_device_tpm::TpmMarkerStatus::Tampered;

    assert!(matches!(
        TpmResourceController::from_status(device, device_ref, execution, &status),
        Err(d2b_provider_device_tpm::TpmResourceControllerError::Effect(
            TpmResourceEffectError::StateIntegrity
        ))
    ));
}

#[test]
fn tpm_runner_contract_disables_legacy_scheduling() {
    let contract = d2b_provider_device_tpm::tpm_runner_contract();
    assert_eq!(contract.resource_type(), "Device");
    assert_eq!(contract.finalizer(), d2b_provider_device_tpm::DEVICE_TPM_FINALIZER);
    assert!(contract.watched_configuration_is_dependency());
    assert!((30..=60).contains(&contract.repair_interval_secs()));
}

#[test]
fn controller_rejects_non_host_execution_refs() {
    let device = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
    let device_ref = ResourceRef::parse("Device/work-tpm").unwrap();
    let execution = ResourceRef::parse("Zone/zone-a").unwrap();

    assert!(matches!(
        TpmResourceController::new(device, device_ref, execution),
        Err(d2b_provider_device_tpm::TpmResourceControllerError::Effect(
            TpmResourceEffectError::InvalidExecutionRef
        ))
    ));
}

#[test]
fn controller_finalize_before_reconcile_is_invalid() {
    let device = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
    let device_ref = ResourceRef::parse("Device/work-tpm").unwrap();
    let execution = ResourceRef::parse("Host/host-system").unwrap();
    let mut controller = TpmResourceController::new(device, device_ref, execution).unwrap();

    assert_eq!(
        block_on(controller.finalize(&NoopEffects)),
        Err(d2b_provider_device_tpm::TpmResourceControllerError::InvalidState)
    );
}

#[test]
fn controller_finalizes_the_swtpm_process_after_endpoint_watch_failure() {
    let device = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
    let device_ref = ResourceRef::parse("Device/work-tpm").unwrap();
    let execution = ResourceRef::parse("Host/host-system").unwrap();
    let mut controller = TpmResourceController::new(device, device_ref, execution).unwrap();
    let effects = ScriptedEffects {
        endpoint_fails: true,
        ..ScriptedEffects::default()
    };

    assert_eq!(
        block_on(controller.reconcile(&effects)),
        Err(d2b_provider_device_tpm::TpmResourceControllerError::Effect(
            TpmResourceEffectError::Transient
        ))
    );
    assert_eq!(
        block_on(controller.finalize(&effects)).unwrap(),
        TpmResourceOutcome::VolumeRetained
    );
    assert_eq!(effects.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(effects.delete_calls.load(Ordering::SeqCst), 1);
    assert!(!controller.finalizer_installed());
}

#[test]
fn controller_retains_process_when_stop_fails_during_finalize() {
    let device = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
    let device_ref = ResourceRef::parse("Device/work-tpm").unwrap();
    let execution = ResourceRef::parse("Host/host-system").unwrap();
    let mut controller = TpmResourceController::new(device, device_ref, execution).unwrap();
    let effects = ScriptedEffects {
        stop_fails: AtomicBool::new(true),
        ..ScriptedEffects::default()
    };

    assert_eq!(
        block_on(controller.reconcile(&effects)).unwrap(),
        TpmResourceOutcome::Ready
    );
    assert_eq!(
        block_on(controller.finalize(&effects)),
        Err(d2b_provider_device_tpm::TpmResourceControllerError::Effect(
            TpmResourceEffectError::Transient
        ))
    );
    assert!(controller.finalizer_installed());
    assert_eq!(
        controller.phase(),
        d2b_provider_device_tpm::TpmResourcePhase::Degraded
    );
    assert_eq!(effects.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(effects.delete_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn controller_does_not_repeat_stop_after_flush_delete_retry() {
    let device = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
    let device_ref = ResourceRef::parse("Device/work-tpm").unwrap();
    let execution = ResourceRef::parse("Host/host-system").unwrap();
    let mut controller = TpmResourceController::new(device, device_ref, execution).unwrap();
    let effects = ScriptedEffects {
        delete_failures: AtomicUsize::new(1),
        ..ScriptedEffects::default()
    };

    assert_eq!(
        block_on(controller.reconcile(&effects)).unwrap(),
        TpmResourceOutcome::Ready
    );
    assert_eq!(
        block_on(controller.finalize(&effects)),
        Err(d2b_provider_device_tpm::TpmResourceControllerError::Effect(
            TpmResourceEffectError::Transient
        ))
    );
    assert_eq!(
        block_on(controller.finalize(&effects)).unwrap(),
        TpmResourceOutcome::VolumeRetained
    );
    assert_eq!(effects.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(effects.delete_calls.load(Ordering::SeqCst), 2);
    assert!(!controller.finalizer_installed());
}

#[test]
fn flush_failure_stops_the_long_lived_process_and_retains_state() {
    let device = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
    let device_ref = ResourceRef::parse("Device/work-tpm").unwrap();
    let execution = ResourceRef::parse("Host/host-system").unwrap();
    let mut controller = TpmResourceController::new(device, device_ref, execution).unwrap();
    let effects = ScriptedEffects {
        flush_fails: true,
        ..ScriptedEffects::default()
    };

    assert_eq!(
        block_on(controller.reconcile(&effects)),
        Err(d2b_provider_device_tpm::TpmResourceControllerError::Effect(
            TpmResourceEffectError::Transient
        ))
    );
    assert_eq!(
        effects.events.lock().unwrap().as_slice(),
        ["volume", "flush"]
    );
    assert_eq!(effects.stop_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn controller_flushes_before_starting_swtpm_and_waits_for_endpoint() {
    let device = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
    let device_ref = ResourceRef::parse("Device/work-tpm").unwrap();
    let execution = ResourceRef::parse("Host/host-system").unwrap();
    let mut controller = TpmResourceController::new(device, device_ref, execution).unwrap();
    let effects = ScriptedEffects::default();

    assert_eq!(
        block_on(controller.reconcile(&effects)).unwrap(),
        TpmResourceOutcome::Ready
    );
    assert_eq!(
        effects.events.lock().unwrap().as_slice(),
        ["volume", "flush", "process", "endpoint"]
    );
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};
    let mut future = pin!(future);
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::hint::spin_loop(),
        }
    }
}

struct NoopEffects;

#[derive(Default)]
struct ScriptedEffects {
    endpoint_fails: bool,
    flush_fails: bool,
    delete_failures: AtomicUsize,
    stop_calls: AtomicUsize,
    delete_calls: AtomicUsize,
    stop_fails: AtomicBool,
    events: Mutex<Vec<&'static str>>,
}

impl TpmResourceEffectPort for ScriptedEffects {
    async fn ensure_state_volume(
        &self,
        _: &ResourceUid,
        device_ref: &ResourceRef,
        _: &ResourceRef,
    ) -> Result<ResourceRef, TpmResourceEffectError> {
        assert_eq!(device_ref.to_canonical_string(), "Device/work-tpm");
        self.events.lock().unwrap().push("volume");
        Ok(ResourceRef::parse("Volume/device-state").unwrap())
    }

    async fn request_swtpm_process(
        &self,
        _: &ResourceUid,
        _: &ResourceRef,
        _: &ResourceRef,
    ) -> Result<ResourceRef, TpmResourceEffectError> {
        self.events.lock().unwrap().push("process");
        Ok(ResourceRef::parse("Process/device-swtpm").unwrap())
    }

    async fn request_flush_process(
        &self,
        _: &ResourceUid,
        _: &ResourceRef,
    ) -> Result<ResourceRef, TpmResourceEffectError> {
        self.events.lock().unwrap().push("flush");
        if self.flush_fails {
            Err(TpmResourceEffectError::Transient)
        } else {
            Ok(ResourceRef::parse("EphemeralProcess/device-flush").unwrap())
        }
    }

    fn stop_swtpm_process(
        &self,
        _: &ResourceRef,
    ) -> impl std::future::Future<Output = Result<(), TpmResourceEffectError>> + Send {
        self.stop_calls.fetch_add(1, Ordering::SeqCst);
        let fails = self.stop_fails.load(Ordering::SeqCst);
        async move {
            if fails {
                Err(TpmResourceEffectError::Transient)
            } else {
                Ok(())
            }
        }
    }

    fn delete_flush_process(
        &self,
        _: &ResourceRef,
    ) -> impl std::future::Future<Output = Result<(), TpmResourceEffectError>> + Send {
        self.delete_calls.fetch_add(1, Ordering::SeqCst);
        let should_fail = self
            .delete_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                if remaining > 0 {
                    Some(remaining - 1)
                } else {
                    None
                }
            })
            .is_ok();
        async move {
            if should_fail {
                Err(TpmResourceEffectError::Transient)
            } else {
                Ok(())
            }
        }
    }

    fn watch_tpm_endpoint(
        &self,
        _: &ResourceRef,
    ) -> impl std::future::Future<Output = Result<ResourceRef, TpmResourceEffectError>> + Send {
        let fails = self.endpoint_fails;
        self.events.lock().unwrap().push("endpoint");
        async move {
            if fails {
                Err(TpmResourceEffectError::Transient)
            } else {
                Ok(ResourceRef::parse("Endpoint/device-tpm").unwrap())
            }
        }
    }
}

#[allow(clippy::manual_async_fn)]
impl TpmResourceEffectPort for NoopEffects {
    fn ensure_state_volume(
        &self,
        _: &ResourceUid,
        _: &ResourceRef,
        _: &ResourceRef,
    ) -> impl std::future::Future<Output = Result<ResourceRef, TpmResourceEffectError>> + Send {
        async { Ok(ResourceRef::parse("Volume/device-state").unwrap()) }
    }

    fn request_swtpm_process(
        &self,
        _: &ResourceUid,
        _: &ResourceRef,
        _: &ResourceRef,
    ) -> impl std::future::Future<Output = Result<ResourceRef, TpmResourceEffectError>> + Send {
        async { Ok(ResourceRef::parse("Process/device-swtpm").unwrap()) }
    }

    fn request_flush_process(
        &self,
        _: &ResourceUid,
        _: &ResourceRef,
    ) -> impl std::future::Future<Output = Result<ResourceRef, TpmResourceEffectError>> + Send {
        async { Ok(ResourceRef::parse("EphemeralProcess/device-flush").unwrap()) }
    }

    fn stop_swtpm_process(
        &self,
        _: &ResourceRef,
    ) -> impl std::future::Future<Output = Result<(), TpmResourceEffectError>> + Send {
        async { Ok(()) }
    }

    fn delete_flush_process(
        &self,
        _: &ResourceRef,
    ) -> impl std::future::Future<Output = Result<(), TpmResourceEffectError>> + Send {
        async { Ok(()) }
    }

    fn watch_tpm_endpoint(
        &self,
        _: &ResourceRef,
    ) -> impl std::future::Future<Output = Result<ResourceRef, TpmResourceEffectError>> + Send {
        async { Ok(ResourceRef::parse("Endpoint/device-tpm").unwrap()) }
    }
}
