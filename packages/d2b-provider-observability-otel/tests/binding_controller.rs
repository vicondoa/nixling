use std::collections::BTreeMap;

use d2b_contracts_resource::v3::ResourceRef;
use d2b_provider_observability_otel::{
    IdentityCanaries, Ingress, IngressOutcome, MetricFrame, MetricPoint,
    TelemetryBindingController, TelemetryBindingPhase, TelemetryComponentSession,
    TelemetryControllerError, TelemetryServiceController, TelemetryServicePhase,
    TelemetryServiceRole, TelemetryStreamRequest, TelemetryStreamSignal,
};

fn refs() -> (ResourceRef, ResourceRef, ResourceRef) {
    (
        ResourceRef::parse("telemetry.d2bus.org.TelemetryBinding/metrics").unwrap(),
        ResourceRef::parse("telemetry.d2bus.org.TelemetryService/zone").unwrap(),
        ResourceRef::parse("Guest/workload").unwrap(),
    )
}

fn frame() -> MetricFrame {
    MetricFrame::new(
        64,
        [MetricPoint {
            descriptor: d2b_provider_observability_otel::canonical_descriptor(
                "d2b_otel_ingress_policy_total",
            )
            .unwrap(),
            labels: BTreeMap::from([
                ("ingress".to_owned(), "otlp_vsock".to_owned()),
                ("outcome".to_owned(), "accepted".to_owned()),
                ("error_class".to_owned(), "none".to_owned()),
            ]),
            value: 1.0,
        }],
        BTreeMap::from([(
            "d2b.zone".to_owned(),
            "sha256:0000000000000000000000000000000000000000000000000000000000000001".to_owned(),
        )]),
    )
}

#[test]
fn explicit_binding_reconciles_collector_children_and_route_status() {
    let (binding, service, target) = refs();
    let mut controller = TelemetryBindingController::new();
    let result = controller
        .reconcile(
            &binding,
            &service,
            &target,
            Ingress::OtlpVsock,
            7,
            &frame(),
            &IdentityCanaries::default(),
            true,
        )
        .unwrap();
    assert_eq!(controller.phase(), TelemetryBindingPhase::Ready);
    assert_eq!(result.status.outcome, Some(IngressOutcome::Accepted));
    assert_eq!(result.children.iter().count(), 4);
    assert_eq!(
        result
            .children
            .child("ingest-endpoint")
            .unwrap()
            .producer_ref(),
        Some(result.children.child("collector").unwrap().resource_ref())
    );
    assert_eq!(
        result
            .children
            .child("forwarder-endpoint")
            .unwrap()
            .producer_ref(),
        Some(result.children.child("forwarder").unwrap().resource_ref())
    );
}

#[test]
fn finalization_blocks_reconcile_and_service_alone_cannot_create_children() {
    let (binding, service, target) = refs();
    let mut controller = TelemetryBindingController::new();
    controller.finalize().unwrap();
    assert!(
        controller
            .reconcile(
                &binding,
                &service,
                &target,
                Ingress::OtlpVsock,
                7,
                &frame(),
                &IdentityCanaries::default(),
                true,
            )
            .is_err()
    );
    assert!(TelemetryBindingController::child_resources(&service, &service, &target).is_err());
}

#[test]
fn service_resource_reconciliation_is_separate_from_stream_admission() {
    let (binding, service, _target) = refs();
    let provider = ResourceRef::parse("Provider/observability-otel").unwrap();
    let endpoint = ResourceRef::parse("Endpoint/ingest").unwrap();
    let mut service_controller = TelemetryServiceController::new();
    let status = service_controller
        .reconcile(
            &service,
            &provider,
            TelemetryServiceRole::Authority,
            &[endpoint],
            true,
            true,
        )
        .unwrap();
    assert_eq!(status.phase, TelemetryServicePhase::Ready);
    assert_eq!(service_controller.phase(), TelemetryServicePhase::Ready);

    let session = TelemetryComponentSession;
    let stream = session
        .open_stream(TelemetryStreamRequest {
            service_ref: service,
            binding_ref: binding,
            signal: TelemetryStreamSignal::Metrics,
        })
        .unwrap();
    assert_eq!(stream.request().signal, TelemetryStreamSignal::Metrics);
    assert_eq!(
        TelemetryComponentSession::resource_mutation_forbidden(),
        TelemetryControllerError::StreamOnly
    );
}

#[test]
fn service_authority_and_stream_target_mismatches_fail_closed() {
    let mut controller = TelemetryServiceController::new();
    let result = controller.reconcile(
        &ResourceRef::parse("telemetry.d2bus.org.TelemetryBinding/incorrect").unwrap(),
        &ResourceRef::parse("Provider/observability-otel").unwrap(),
        TelemetryServiceRole::Authority,
        &[ResourceRef::parse("Endpoint/ingest").unwrap()],
        true,
        true,
    );
    assert!(result.is_err());

    let session = TelemetryComponentSession;
    let result = session.open_stream(TelemetryStreamRequest {
        service_ref: ResourceRef::parse("telemetry.d2bus.org.TelemetryService/ingest").unwrap(),
        binding_ref: ResourceRef::parse("Process/not-a-binding").unwrap(),
        signal: TelemetryStreamSignal::Logs,
    });
    assert_eq!(result, Err(TelemetryControllerError::Admission));
}

#[test]
fn projection_readiness_requires_ingest_evidence() {
    let (_binding, service, _target) = refs();
    let provider = ResourceRef::parse("Provider/observability-otel").unwrap();
    let mut controller = TelemetryServiceController::new();

    let status = controller
        .reconcile(
            &service,
            &provider,
            TelemetryServiceRole::Projection,
            &[],
            true,
            false,
        )
        .unwrap();

    assert_eq!(status.phase, TelemetryServicePhase::Pending);
}

#[test]
fn telemetry_children_reject_unsupported_target_types() {
    let (binding, service, _target) = refs();
    let user = ResourceRef::parse("User/alice").unwrap();

    assert_eq!(
        TelemetryBindingController::child_resources(&binding, &service, &user),
        Err(TelemetryControllerError::Admission)
    );
}

#[test]
fn telemetry_authority_rejects_non_endpoint_ingest_rows() {
    let (_binding, service, _target) = refs();
    let provider = ResourceRef::parse("Provider/observability-otel").unwrap();
    let process = ResourceRef::parse("Process/not-an-endpoint").unwrap();
    let mut controller = TelemetryServiceController::new();

    assert_eq!(
        controller.reconcile(
            &service,
            &provider,
            TelemetryServiceRole::Authority,
            &[process],
            true,
            true,
        ),
        Err(d2b_provider_observability_otel::TelemetryServiceError::InvalidAuthority)
    );
}

#[test]
fn telemetry_binding_requires_an_identity_scoped_connection() {
    let (binding, service, target) = refs();
    let mut controller = TelemetryBindingController::new();

    assert_eq!(
        controller.reconcile(
            &binding,
            &service,
            &target,
            Ingress::OtlpVsock,
            0,
            &frame(),
            &IdentityCanaries::default(),
            true,
        ),
        Err(TelemetryControllerError::Admission)
    );
}
