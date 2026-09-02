use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use d2b_contracts_provider::v3::credential::OpaqueAzureRef;
use d2b_contracts_resource::v3::{
    DesiredLifecycle, ResourceGeneration, ResourcePhase, ResourceRef, ResourceUid, ZoneId,
    ZoneRevision,
};
use d2b_provider_runtime_cloud_hypervisor::{
    BootstrapGraph, BootstrapHandoff, ChildRole, ChildSpecUpdate, CloudHypervisorConfig,
    CloudHypervisorController, CloudHypervisorError, CloudHypervisorResourceApi,
    CloudHypervisorResourceApiError, CommittedChild, DescriptorSignature, GuestChildCommitResponse,
    GuestChildCreateBatch, GuestDependencySnapshot, GuestFinalizationInput, GuestGenerationSet,
    GuestSeedContract, GuestSetupDescriptor, GuestSetupDescriptorVerifier, GuestSnapshot,
    GuestStatusProjection, OwnedChildSnapshot, ProcessAdoptionStatus, ProcessState, SessionState,
    SignatureAlgorithm, UpgradeReason,
};

#[test]
fn cloud_hypervisor_publishes_the_shared_runner_contract() {
    let contract = d2b_provider_runtime_cloud_hypervisor::cloud_hypervisor_runner_contract();
    assert_eq!(contract.resource_type(), "Guest");
    assert_eq!(
        contract.finalizer(),
        d2b_provider_runtime_cloud_hypervisor::GUEST_CONTROLLER_FINALIZER
    );
    assert_eq!(contract.repair_interval_secs(), 30);
    assert!(contract.legacy_scheduler_disabled());
    assert!(contract.watched_configuration_is_dependency());
}

const ARTIFACT_DIGEST: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SCHEMA_FINGERPRINT: &str =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ZONE_UID: &str = "223e4567-e89b-42d3-a456-426614174001";
const GUEST_UID: &str = "123e4567-e89b-42d3-a456-426614174000";

struct AcceptingVerifier;

impl GuestSetupDescriptorVerifier for AcceptingVerifier {
    fn verify(
        &self,
        _key_fingerprint: &d2b_contracts_resource::v3::SchemaFingerprint,
        _descriptor_digest: &d2b_contracts_resource::v3::SchemaFingerprint,
        signature: &str,
    ) -> bool {
        signature == "signature-sentinel"
    }
}

fn descriptor() -> d2b_provider_runtime_cloud_hypervisor::VerifiedGuestSetupDescriptor {
    GuestSetupDescriptor::new(
        ResourceRef::parse("Provider/runtime-cloud-hypervisor").unwrap(),
        ResourceGeneration::new(3).unwrap(),
        d2b_contracts_resource::v3::ArtifactId::parse("guest-system").unwrap(),
        d2b_contracts_provider::v3::ArtifactDigest::parse(ARTIFACT_DIGEST).unwrap(),
        GuestSeedContract::new(
            "guest-resource-seed",
            d2b_contracts_resource::v3::SchemaVersion::new(1, 0).unwrap(),
            d2b_contracts_resource::v3::SchemaFingerprint::parse(SCHEMA_FINGERPRINT).unwrap(),
        )
        .unwrap(),
        BootstrapHandoff::new("opaque-bootstrap", 30_000).unwrap(),
        DescriptorSignature::new(
            SignatureAlgorithm::Ed25519Blake3,
            d2b_contracts_resource::v3::SchemaFingerprint::parse(SCHEMA_FINGERPRINT).unwrap(),
            "signature-sentinel",
        )
        .unwrap(),
    )
    .unwrap()
    .verify_with(&AcceptingVerifier)
    .unwrap()
}

fn config() -> CloudHypervisorConfig {
    CloudHypervisorConfig {
        controller_execution_ref: ResourceRef::parse("Host/host-system").unwrap(),
        default_vcpus: 2,
        default_memory_mb: 512,
        default_machine_type: OpaqueAzureRef::parse("q35").unwrap(),
        watchdog: true,
        adoption_window_ms: 30_000,
        health_check_interval_ms: 30_000,
        health_check_timeout_ms: 5_000,
        health_check_failure_threshold: 3,
        startup_deadline_ms: 120_000,
    }
}

fn graph() -> BootstrapGraph {
    BootstrapGraph::new(
        vec![ResourceRef::parse("Device/kvm").unwrap()],
        vec![ResourceRef::parse("Network/work").unwrap()],
        vec![ResourceRef::parse("Volume/store").unwrap()],
        vec![],
    )
    .unwrap()
}

fn guest(name: &str, zone: &str, uid: &str, zone_uid: &str) -> GuestSnapshot {
    let resource_ref = format!("Guest/{name}");
    GuestSnapshot::new(
        ZoneId::parse(zone).unwrap(),
        ResourceUid::parse(zone_uid).unwrap(),
        ResourceRef::parse(&resource_ref).unwrap(),
        ResourceUid::parse(uid).unwrap(),
        ResourceGeneration::new(1).unwrap(),
        ZoneRevision::new(7),
        ResourceRef::parse("Host/host-system").unwrap(),
        ResourceRef::parse("Provider/runtime-cloud-hypervisor").unwrap(),
        Some("guest-system".to_owned()),
        GuestGenerationSet::all(1),
        false,
    )
    .unwrap()
}

fn deleting_guest(name: &str, zone: &str, uid: &str, zone_uid: &str) -> GuestSnapshot {
    let resource_ref = format!("Guest/{name}");
    GuestSnapshot::new(
        ZoneId::parse(zone).unwrap(),
        ResourceUid::parse(zone_uid).unwrap(),
        ResourceRef::parse(&resource_ref).unwrap(),
        ResourceUid::parse(uid).unwrap(),
        ResourceGeneration::new(1).unwrap(),
        ZoneRevision::new(7),
        ResourceRef::parse("Host/host-system").unwrap(),
        ResourceRef::parse("Provider/runtime-cloud-hypervisor").unwrap(),
        Some("guest-system".to_owned()),
        GuestGenerationSet::all(1),
        true,
    )
    .unwrap()
}

fn finalization_input(
    guest: &GuestSnapshot,
    children: &[OwnedChildSnapshot],
    session: SessionState,
    guest_local_drained: bool,
    process: ProcessState,
) -> GuestFinalizationInput {
    let fences = children
        .iter()
        .map(|child| {
            let role =
                d2b_provider_runtime_cloud_hypervisor::child_role_for_ref(child.resource_ref())
                    .unwrap();
            d2b_provider_runtime_cloud_hypervisor::FencedChild::new(
                role,
                child.resource_ref().clone(),
                child.uid().clone(),
                child.revision(),
            )
            .unwrap()
        })
        .collect();
    GuestFinalizationInput::new(
        guest.uid().clone(),
        session,
        guest_local_drained,
        process,
        fences,
        false,
        false,
        false,
    )
    .unwrap()
}

fn dependencies(
    devices_ready: bool,
    networks_ready: bool,
    volumes_ready: bool,
    exports_ready: bool,
    setup_ready: bool,
) -> GuestDependencySnapshot {
    GuestDependencySnapshot::new(
        vec![(
            ResourceRef::parse("Device/kvm").unwrap(),
            if devices_ready {
                ResourcePhase::Ready
            } else {
                ResourcePhase::Pending
            },
        )],
        vec![(
            ResourceRef::parse("Network/work").unwrap(),
            if networks_ready {
                ResourcePhase::Ready
            } else {
                ResourcePhase::Pending
            },
        )],
        vec![(
            ResourceRef::parse("Volume/store").unwrap(),
            if volumes_ready {
                ResourcePhase::Ready
            } else {
                ResourcePhase::Pending
            },
        )],
        exports_ready,
        setup_ready,
    )
    .unwrap()
}

fn committed_children(batch: &GuestChildCreateBatch) -> Vec<CommittedChild> {
    batch
        .mutations()
        .iter()
        .enumerate()
        .map(|(index, mutation)| {
            CommittedChild::new(
                mutation.target().clone(),
                mutation.owner_ref().clone(),
                mutation.zone().clone(),
                ResourceUid::parse(format!("323e4567-e89b-42d3-a456-42661417{index:04}")).unwrap(),
                ZoneRevision::new(2),
            )
            .unwrap()
        })
        .collect()
}

fn matching_children(
    guest: &GuestSnapshot,
    batch: &GuestChildCreateBatch,
) -> Vec<OwnedChildSnapshot> {
    batch
        .mutations()
        .iter()
        .enumerate()
        .map(|(index, mutation)| {
            OwnedChildSnapshot::new(
                mutation.target().clone(),
                guest.zone().clone(),
                guest.resource_ref().clone(),
                ResourceUid::parse(format!("323e4567-e89b-42d3-a456-42661417{index:04}")).unwrap(),
                ResourceGeneration::new(1).unwrap(),
                ZoneRevision::new(2),
                batch.desired_digest(mutation.target()).unwrap(),
                ResourcePhase::Ready,
                if mutation.target().resource_type().as_str() == "Process" {
                    Some(DesiredLifecycle::Running)
                } else {
                    None
                },
                true,
            )
            .unwrap()
            .with_owner_uid(guest.uid().clone())
        })
        .collect()
}

#[derive(Default)]
struct ApiState {
    guest: Option<GuestSnapshot>,
    children: Vec<OwnedChildSnapshot>,
    dependencies: Option<GuestDependencySnapshot>,
    commits: Vec<GuestChildCreateBatch>,
    commit_responses: VecDeque<GuestChildCommitResponse>,
    updates: Vec<ChildSpecUpdate>,
    update_results: VecDeque<Result<CommittedChild, CloudHypervisorResourceApiError>>,
    statuses: Vec<GuestStatusProjection>,
    process_observation: Option<ProcessAdoptionStatus>,
    finalization: Option<GuestFinalizationInput>,
    upgrade_reason: Option<UpgradeReason>,
    lifecycle_events: Vec<String>,
    get_calls: usize,
    relist_calls: usize,
}

#[derive(Clone)]
struct FakeApi {
    state: Arc<Mutex<ApiState>>,
}

impl FakeApi {
    fn new(guest: GuestSnapshot, dependencies: GuestDependencySnapshot) -> Self {
        Self {
            state: Arc::new(Mutex::new(ApiState {
                guest: Some(guest),
                dependencies: Some(dependencies),
                ..ApiState::default()
            })),
        }
    }
}

#[async_trait]
impl CloudHypervisorResourceApi for FakeApi {
    async fn register(
        &self,
        _: &d2b_provider_runtime_cloud_hypervisor::CloudHypervisorControllerRegistration,
    ) -> Result<(), CloudHypervisorResourceApiError> {
        Ok(())
    }

    async fn get_guest(
        &self,
        _: &ResourceRef,
    ) -> Result<GuestSnapshot, CloudHypervisorResourceApiError> {
        let mut state = self.state.lock().unwrap();
        state.get_calls += 1;
        state
            .guest
            .clone()
            .ok_or(CloudHypervisorResourceApiError::NotFound)
    }

    async fn relist_owned_children(
        &self,
        _: &GuestSnapshot,
        _: &[ResourceRef],
    ) -> Result<Vec<OwnedChildSnapshot>, CloudHypervisorResourceApiError> {
        let mut state = self.state.lock().unwrap();
        state.relist_calls += 1;
        Ok(state.children.clone())
    }

    async fn observe_dependencies(
        &self,
        _: &GuestSnapshot,
        _: &BootstrapGraph,
    ) -> Result<GuestDependencySnapshot, CloudHypervisorResourceApiError> {
        self.state
            .lock()
            .unwrap()
            .dependencies
            .clone()
            .ok_or(CloudHypervisorResourceApiError::NotFound)
    }

    async fn commit_batch(
        &self,
        batch: GuestChildCreateBatch,
    ) -> Result<GuestChildCommitResponse, CloudHypervisorResourceApiError> {
        let mut state = self.state.lock().unwrap();
        let response = state
            .commit_responses
            .pop_front()
            .unwrap_or_else(|| GuestChildCommitResponse::Committed(committed_children(&batch)));
        state.commits.push(batch);
        Ok(response)
    }

    async fn update_spec(
        &self,
        update: ChildSpecUpdate,
    ) -> Result<CommittedChild, CloudHypervisorResourceApiError> {
        let mut state = self.state.lock().unwrap();
        let result = state.update_results.pop_front();
        state.updates.push(update.clone());
        result.unwrap_or_else(|| {
            Ok(CommittedChild::new(
                update.target().clone(),
                ResourceRef::parse("Guest/gateway").unwrap(),
                ZoneId::parse("work").unwrap(),
                update.expected_uid().clone(),
                ZoneRevision::new(update.expected_revision().get().saturating_add(1)),
            )
            .unwrap())
        })
    }

    async fn update_status(
        &self,
        _: &GuestSnapshot,
        status: GuestStatusProjection,
    ) -> Result<(), CloudHypervisorResourceApiError> {
        self.state.lock().unwrap().statuses.push(status);
        Ok(())
    }

    async fn observe_process_adoption(
        &self,
        _: &GuestSnapshot,
        _: &OwnedChildSnapshot,
    ) -> Result<ProcessAdoptionStatus, CloudHypervisorResourceApiError> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .process_observation
            .clone()
            .unwrap_or(ProcessAdoptionStatus::Current))
    }

    async fn assess_update(
        &self,
        _: &GuestSnapshot,
        _: &[OwnedChildSnapshot],
    ) -> Result<Option<UpgradeReason>, CloudHypervisorResourceApiError> {
        Ok(self.state.lock().unwrap().upgrade_reason)
    }

    async fn observe_finalization(
        &self,
        _: &GuestSnapshot,
        _: &[OwnedChildSnapshot],
    ) -> Result<GuestFinalizationInput, CloudHypervisorResourceApiError> {
        self.state
            .lock()
            .unwrap()
            .finalization
            .clone()
            .ok_or(CloudHypervisorResourceApiError::InvalidResponse)
    }

    async fn drain_guest_local(
        &self,
        _: &GuestSnapshot,
    ) -> Result<(), CloudHypervisorResourceApiError> {
        self.state
            .lock()
            .unwrap()
            .lifecycle_events
            .push("drain-guest-local".to_owned());
        Ok(())
    }

    async fn close_guest_session(
        &self,
        _: &GuestSnapshot,
    ) -> Result<(), CloudHypervisorResourceApiError> {
        self.state
            .lock()
            .unwrap()
            .lifecycle_events
            .push("close-session".to_owned());
        Ok(())
    }

    async fn delete_child(
        &self,
        _: &GuestSnapshot,
        child: d2b_provider_runtime_cloud_hypervisor::FencedChild,
    ) -> Result<(), CloudHypervisorResourceApiError> {
        self.state
            .lock()
            .unwrap()
            .lifecycle_events
            .push(format!("delete-{}", child.role().suffix()));
        Ok(())
    }

    async fn clear_guest_finalizer(
        &self,
        _: &GuestSnapshot,
    ) -> Result<(), CloudHypervisorResourceApiError> {
        self.state
            .lock()
            .unwrap()
            .lifecycle_events
            .push("clear-finalizer".to_owned());
        Ok(())
    }

    async fn invalidate_guest_session(
        &self,
        _: &GuestSnapshot,
        minimum_generation: u64,
    ) -> Result<(), CloudHypervisorResourceApiError> {
        self.state
            .lock()
            .unwrap()
            .lifecycle_events
            .push(format!("invalidate-session-{minimum_generation}"));
        Ok(())
    }
}

fn make_controller(api: FakeApi) -> CloudHypervisorController<FakeApi> {
    CloudHypervisorController::from_verified_descriptor(
        config(),
        graph(),
        descriptor(),
        Arc::new(api),
    )
    .unwrap()
}

#[tokio::test]
async fn dependency_gate_keeps_process_stopped_until_every_dependency_is_ready() {
    let guest = guest("gateway", "work", GUEST_UID, ZONE_UID);
    let api = FakeApi::new(guest.clone(), dependencies(true, true, true, false, false));
    let state = Arc::clone(&api.state);
    let mut controller = make_controller(api);
    controller.register().await.unwrap();

    let outcome = controller.reconcile(guest.resource_ref()).await.unwrap();
    assert!(outcome.is_pending());

    let state = state.lock().unwrap();
    assert_eq!(state.commits.len(), 1);
    assert!(state.updates.is_empty());
    let process = state.commits[0]
        .mutations()
        .iter()
        .find(|mutation| mutation.target().resource_type().as_str() == "Process")
        .unwrap();
    let process_payload = state.commits[0]
        .canonical_payload(process.target())
        .unwrap();
    let process_payload: serde_json::Value = serde_json::from_slice(&process_payload).unwrap();
    assert_eq!(process_payload["spec"]["desiredLifecycle"], "stopped");
    assert!(state.statuses.is_empty());
}

#[tokio::test]
async fn uncertain_batch_relist_does_not_create_a_duplicate_incarnation() {
    let guest = guest("gateway", "work", GUEST_UID, ZONE_UID);
    let api = FakeApi::new(guest.clone(), dependencies(true, true, true, true, true));
    {
        api.state
            .lock()
            .unwrap()
            .commit_responses
            .push_back(GuestChildCommitResponse::Uncertain);
    }
    let state = Arc::clone(&api.state);
    let mut controller = make_controller(api.clone());
    controller.register().await.unwrap();
    assert!(
        controller
            .reconcile(guest.resource_ref())
            .await
            .unwrap()
            .is_pending()
    );

    let batch = state.lock().unwrap().commits[0].clone();
    state.lock().unwrap().children = matching_children(&guest, &batch);
    let mut restarted = make_controller(api);
    restarted.register().await.unwrap();
    restarted.reconcile(guest.resource_ref()).await.unwrap();

    let state = state.lock().unwrap();
    assert_eq!(state.commits.len(), 1);
    assert!(state.relist_calls >= 2);
}

#[tokio::test]
async fn truncated_batch_response_stays_pending_without_update_spec() {
    let guest = guest("gateway", "work", GUEST_UID, ZONE_UID);
    let api = FakeApi::new(guest.clone(), dependencies(true, true, true, true, true));
    api.state
        .lock()
        .unwrap()
        .commit_responses
        .push_back(GuestChildCommitResponse::Truncated);
    let state = Arc::clone(&api.state);
    let mut controller = make_controller(api.clone());
    controller.register().await.unwrap();

    assert!(
        controller
            .reconcile(guest.resource_ref())
            .await
            .unwrap()
            .is_pending()
    );
    let batch = state.lock().unwrap().commits[0].clone();
    state.lock().unwrap().children = matching_children(&guest, &batch);
    let mut restarted = make_controller(api);
    restarted.register().await.unwrap();
    restarted.reconcile(guest.resource_ref()).await.unwrap();

    let state = state.lock().unwrap();
    assert_eq!(state.commits.len(), 1);
    assert!(state.updates.is_empty());
    assert!(state.relist_calls >= 2);
}

#[tokio::test]
async fn child_uid_or_revision_conflict_is_retryable_and_relists_before_replacement_update() {
    let guest = guest("gateway", "work", GUEST_UID, ZONE_UID);
    let api = FakeApi::new(guest.clone(), dependencies(true, true, true, true, true));
    let batch = {
        let verified = descriptor();
        BootstrapGraph::plan_children(
            guest.zone().clone(),
            guest.resource_ref().clone(),
            guest.execution_ref().clone(),
            &verified,
        )
        .unwrap()
        .child_batch()
        .clone()
    };
    let process = batch
        .mutations()
        .iter()
        .find(|mutation| mutation.target().resource_type().as_str() == "Process")
        .unwrap();
    let process_child = OwnedChildSnapshot::new(
        process.target().clone(),
        guest.zone().clone(),
        guest.resource_ref().clone(),
        ResourceUid::parse("323e4567-e89b-42d3-a456-426614170099").unwrap(),
        ResourceGeneration::new(1).unwrap(),
        ZoneRevision::new(3),
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned(),
        ResourcePhase::Ready,
        Some(DesiredLifecycle::Stopped),
        true,
    )
    .unwrap()
    .with_owner_uid(guest.uid().clone());
    {
        let mut children = matching_children(
            &guest,
            &GuestChildCreateBatch::new(
                &guest,
                &batch,
                batch
                    .mutations()
                    .iter()
                    .map(|mutation| mutation.target().clone()),
            )
            .unwrap(),
        );
        let process_index = children
            .iter()
            .position(|child| child.resource_ref() == process.target())
            .unwrap();
        children[process_index] = process_child;
        let mut state = api.state.lock().unwrap();
        state.children = children;
        state
            .update_results
            .push_back(Err(CloudHypervisorResourceApiError::Conflict));
    }
    let state = Arc::clone(&api.state);
    let mut controller = make_controller(api.clone());
    controller.register().await.unwrap();
    assert!(
        controller
            .reconcile(guest.resource_ref())
            .await
            .unwrap()
            .is_pending()
    );

    let create_batch = GuestChildCreateBatch::new(
        &guest,
        &batch,
        batch
            .mutations()
            .iter()
            .map(|mutation| mutation.target().clone()),
    )
    .unwrap();
    state.lock().unwrap().children = matching_children(&guest, &create_batch);
    let mut replacement = make_controller(api);
    replacement.register().await.unwrap();
    replacement.reconcile(guest.resource_ref()).await.unwrap();

    let state = state.lock().unwrap();
    assert_eq!(state.relist_calls, 2);
    assert_eq!(state.updates.len(), 1);
}

#[tokio::test]
async fn restart_converges_from_resource_state_without_direct_effects() {
    let guest = guest("gateway", "work", GUEST_UID, ZONE_UID);
    let api = FakeApi::new(guest.clone(), dependencies(true, true, true, true, true));
    let state = Arc::clone(&api.state);
    let mut first = make_controller(api.clone());
    first.register().await.unwrap();
    first.reconcile(guest.resource_ref()).await.unwrap();
    let batch = state.lock().unwrap().commits[0].clone();
    state.lock().unwrap().children = matching_children(&guest, &batch);

    let mut restarted = make_controller(api);
    restarted.register().await.unwrap();
    let outcome = restarted.reconcile(guest.resource_ref()).await.unwrap();

    let state = state.lock().unwrap();
    assert_eq!(state.commits.len(), 1);
    assert!(state.updates.is_empty());
    assert!(outcome.is_pending(), "unexpected restart outcome: {outcome:?}");
    assert!(outcome.status().has_condition(
        d2b_provider_runtime_cloud_hypervisor::GuestCondition::SessionNotReady
    ));
    assert!(state.get_calls >= 2);
    assert!(state.relist_calls >= 2);
}

#[tokio::test]
async fn foreign_child_owner_fails_closed_before_any_mutation() {
    let guest = guest("gateway", "work", GUEST_UID, ZONE_UID);
    let api = FakeApi::new(guest.clone(), dependencies(true, true, true, true, true));
    api.state.lock().unwrap().children = vec![
        OwnedChildSnapshot::new(
            ResourceRef::parse("Process/gateway-vmm").unwrap(),
            guest.zone().clone(),
            ResourceRef::parse("Guest/other").unwrap(),
            ResourceUid::parse("323e4567-e89b-42d3-a456-426614170099").unwrap(),
            ResourceGeneration::new(1).unwrap(),
            ZoneRevision::new(2),
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned(),
            ResourcePhase::Ready,
            Some(DesiredLifecycle::Stopped),
            true,
        )
        .unwrap()
        .with_owner_uid(guest.uid().clone()),
    ];
    let state = Arc::clone(&api.state);
    let mut controller = make_controller(api);
    controller.register().await.unwrap();
    assert_eq!(
        controller
            .reconcile(guest.resource_ref())
            .await
            .unwrap_err(),
        CloudHypervisorError::ChildConflict
    );
    let state = state.lock().unwrap();
    assert!(state.commits.is_empty());
    assert!(state.updates.is_empty());
    assert!(state.statuses.is_empty());
}

#[tokio::test]
async fn restart_adopts_only_the_exact_process_identity() {
    let guest = guest("gateway", "work", GUEST_UID, ZONE_UID);
    let api = FakeApi::new(guest.clone(), dependencies(true, true, true, true, true));
    let batch = {
        let plan = BootstrapGraph::plan_children(
            guest.zone().clone(),
            guest.resource_ref().clone(),
            guest.execution_ref().clone(),
            &descriptor(),
        )
        .unwrap();
        GuestChildCreateBatch::new(
            &guest,
            plan.child_batch(),
            plan.child_batch()
                .mutations()
                .iter()
                .map(|mutation| mutation.target().clone()),
        )
        .unwrap()
    };
    {
        let mut state = api.state.lock().unwrap();
        state.children = matching_children(&guest, &batch)
            .into_iter()
            .map(|child| {
                if child.resource_ref().resource_type().as_str() != "Process" {
                    return child;
                }
                OwnedChildSnapshot::new(
                    child.resource_ref().clone(),
                    child.zone().clone(),
                    child.owner_ref().clone(),
                    child.uid().clone(),
                    child.generation(),
                    child.revision(),
                    child.spec_digest(),
                    ResourcePhase::Pending,
                    child.desired_lifecycle(),
                    child.healthy(),
                )
                .unwrap()
                .with_owner_uid(guest.uid().clone())
            })
            .collect();
        state.process_observation = Some(ProcessAdoptionStatus::Adopted);
    }
    let state = Arc::clone(&api.state);
    let mut controller = make_controller(api);
    controller.register().await.unwrap();
    let outcome = controller.reconcile(guest.resource_ref()).await.unwrap();

    assert!(
        !outcome.status().has_condition(
            d2b_provider_runtime_cloud_hypervisor::GuestCondition::AdoptionAmbiguous
        )
    );
    let state = state.lock().unwrap();
    assert!(state.commits.is_empty());
    assert!(state.updates.is_empty());
}

#[tokio::test]
async fn matching_process_resource_avoids_direct_adoption_effects() {
    for observation in [
        ProcessAdoptionStatus::Quarantined,
        ProcessAdoptionStatus::Unavailable,
    ] {
        let guest = guest("gateway", "work", GUEST_UID, ZONE_UID);
        let api = FakeApi::new(guest.clone(), dependencies(true, true, true, true, true));
        let batch = {
            let plan = BootstrapGraph::plan_children(
                guest.zone().clone(),
                guest.resource_ref().clone(),
                guest.execution_ref().clone(),
                &descriptor(),
            )
            .unwrap();
            GuestChildCreateBatch::new(
                &guest,
                plan.child_batch(),
                plan.child_batch()
                    .mutations()
                    .iter()
                    .map(|mutation| mutation.target().clone()),
            )
            .unwrap()
        };
        let state = Arc::clone(&api.state);
        {
            let mut state = state.lock().unwrap();
            state.children = matching_children(&guest, &batch);
            state.process_observation = Some(observation);
        }
        let mut controller = make_controller(api);
        controller.register().await.unwrap();
        let outcome = controller.reconcile(guest.resource_ref()).await.unwrap();
        assert!(outcome.is_pending(), "unexpected adoption outcome: {outcome:?}");
        assert!(outcome.status().has_condition(
            d2b_provider_runtime_cloud_hypervisor::GuestCondition::SessionNotReady
        ));
        assert!(!outcome.status().has_condition(
            d2b_provider_runtime_cloud_hypervisor::GuestCondition::AdoptionAmbiguous
        ));
        assert!(state.lock().unwrap().updates.is_empty());
    }
}

#[tokio::test]
async fn vmm_exit_is_bounded_degraded_and_retries_through_process_resource() {
    let guest = guest("gateway", "work", GUEST_UID, ZONE_UID);
    let api = FakeApi::new(guest.clone(), dependencies(true, true, true, true, true));
    let plan = BootstrapGraph::plan_children(
        guest.zone().clone(),
        guest.resource_ref().clone(),
        guest.execution_ref().clone(),
        &descriptor(),
    )
    .unwrap();
    let batch = GuestChildCreateBatch::new(
        &guest,
        plan.child_batch(),
        plan.child_batch()
            .mutations()
            .iter()
            .map(|mutation| mutation.target().clone()),
    )
    .unwrap();
    let mut children = matching_children(&guest, &batch);
    let process_index = children
        .iter()
        .position(|child| child.resource_ref().resource_type().as_str() == "Process")
        .unwrap();
    let process_mutation = batch
        .mutations()
        .iter()
        .find(|mutation| mutation.target().resource_type().as_str() == "Process")
        .unwrap();
    children[process_index] = OwnedChildSnapshot::new(
        process_mutation.target().clone(),
        guest.zone().clone(),
        guest.resource_ref().clone(),
        children[process_index].uid().clone(),
        ResourceGeneration::new(1).unwrap(),
        ZoneRevision::new(2),
        batch.desired_digest(process_mutation.target()).unwrap(),
        ResourcePhase::Degraded,
        Some(DesiredLifecycle::Running),
        false,
    )
    .unwrap()
    .with_owner_uid(guest.uid().clone());
    {
        let mut state = api.state.lock().unwrap();
        state.children = children;
        state.process_observation = Some(ProcessAdoptionStatus::Absent);
    }
    let state = Arc::clone(&api.state);
    let mut controller = make_controller(api);
    controller.register().await.unwrap();
    let outcome = controller.reconcile(guest.resource_ref()).await.unwrap();

    assert!(matches!(
        outcome,
        d2b_provider_runtime_cloud_hypervisor::CloudHypervisorReconcileOutcome::Degraded(_)
    ));
    assert!(
        outcome
            .status()
            .has_condition(d2b_provider_runtime_cloud_hypervisor::GuestCondition::VmmProcessExited)
    );
    let state = state.lock().unwrap();
    assert_eq!(state.updates.len(), 1);
    assert_eq!(
        state.updates[0].desired_lifecycle(),
        Some(DesiredLifecycle::Running)
    );
}

#[tokio::test]
async fn deletion_executes_reverse_order_and_clears_finalizer_only_after_absence() {
    let guest = deleting_guest("gateway", "work", GUEST_UID, ZONE_UID);
    let api = FakeApi::new(guest.clone(), dependencies(true, true, true, true, true));
    let plan = BootstrapGraph::plan_children(
        guest.zone().clone(),
        guest.resource_ref().clone(),
        guest.execution_ref().clone(),
        &descriptor(),
    )
    .unwrap();
    let batch = GuestChildCreateBatch::new(
        &guest,
        plan.child_batch(),
        plan.child_batch()
            .mutations()
            .iter()
            .map(|mutation| mutation.target().clone()),
    )
    .unwrap();
    {
        let mut state = api.state.lock().unwrap();
        state.children = matching_children(&guest, &batch);
        state.finalization = Some(finalization_input(
            &guest,
            &state.children,
            SessionState::Active,
            false,
            ProcessState::Running {
                identity_verified: true,
            },
        ));
    }
    let state = Arc::clone(&api.state);
    let mut controller = make_controller(api.clone());
    controller.register().await.unwrap();
    controller.reconcile(guest.resource_ref()).await.unwrap();
    {
        let state = state.lock().unwrap();
        assert_eq!(state.lifecycle_events, vec!["drain-guest-local"]);
    }

    {
        let mut state = state.lock().unwrap();
        state.finalization = Some(finalization_input(
            &guest,
            &state.children,
            SessionState::Active,
            true,
            ProcessState::Running {
                identity_verified: true,
            },
        ));
    }
    controller.reconcile(guest.resource_ref()).await.unwrap();
    {
        let state = state.lock().unwrap();
        assert_eq!(
            state.lifecycle_events,
            vec!["drain-guest-local", "close-session"]
        );
    }

    {
        let mut state = state.lock().unwrap();
        state.finalization = Some(finalization_input(
            &guest,
            &state.children,
            SessionState::Closed,
            true,
            ProcessState::Running {
                identity_verified: true,
            },
        ));
    }
    controller.reconcile(guest.resource_ref()).await.unwrap();
    {
        let state = state.lock().unwrap();
        assert_eq!(
            state.updates[0].desired_lifecycle(),
            Some(DesiredLifecycle::Stopped)
        );
        assert_eq!(state.lifecycle_events.len(), 2);
    }

    for expected_role in [
        ChildRole::ChApiEndpoint,
        ChildRole::GuestControlEndpoint,
        ChildRole::VmmProcess,
        ChildRole::SystemVolume,
    ] {
        {
            let mut state = state.lock().unwrap();
            state.finalization = Some(finalization_input(
                &guest,
                &state.children,
                SessionState::Closed,
                true,
                ProcessState::Stopped,
            ));
        }
        controller.reconcile(guest.resource_ref()).await.unwrap();
        {
            let mut state = state.lock().unwrap();
            let event = format!("delete-{}", expected_role.suffix());
            assert_eq!(
                state.lifecycle_events.last().map(String::as_str),
                Some(event.as_str())
            );
            state.children.retain(|child| {
                d2b_provider_runtime_cloud_hypervisor::child_role_for_ref(child.resource_ref())
                    != Some(expected_role)
            });
        }
    }

    state.lock().unwrap().finalization = Some(finalization_input(
        &guest,
        &[],
        SessionState::Closed,
        true,
        ProcessState::Absent,
    ));
    controller.reconcile(guest.resource_ref()).await.unwrap();
    assert_eq!(
        state
            .lock()
            .unwrap()
            .lifecycle_events
            .last()
            .map(String::as_str),
        Some("clear-finalizer")
    );
}

#[tokio::test]
async fn interrupted_upgrade_preserves_volume_and_fences_old_transient_uids() {
    let guest = guest("gateway", "work", GUEST_UID, ZONE_UID);
    let api = FakeApi::new(guest.clone(), dependencies(true, true, true, true, true));
    let plan = BootstrapGraph::plan_children(
        guest.zone().clone(),
        guest.resource_ref().clone(),
        guest.execution_ref().clone(),
        &descriptor(),
    )
    .unwrap();
    let batch = GuestChildCreateBatch::new(
        &guest,
        plan.child_batch(),
        plan.child_batch()
            .mutations()
            .iter()
            .map(|mutation| mutation.target().clone()),
    )
    .unwrap();
    let observed = matching_children(&guest, &batch);
    let observed_map = observed
        .iter()
        .cloned()
        .map(|child| (child.resource_ref().clone(), child))
        .collect::<std::collections::BTreeMap<_, _>>();
    let state = Arc::clone(&api.state);
    state.lock().unwrap().children = observed.clone();
    let mut controller = make_controller(api.clone());
    controller.register().await.unwrap();
    let upgrade = controller
        .plan_upgrade(
            &guest,
            &observed_map,
            d2b_provider_runtime_cloud_hypervisor::UpgradeReason::ProviderGenerationChanged,
        )
        .unwrap();
    let durable_uid = upgrade.durable_volumes()[0].uid().clone();
    assert_eq!(upgrade.next_session_generation(), 1);
    {
        let mut state = state.lock().unwrap();
        state.finalization = Some(finalization_input(
            &guest,
            &state.children,
            SessionState::Closed,
            true,
            ProcessState::Running {
                identity_verified: true,
            },
        ));
    }
    controller
        .execute_upgrade(&guest, &plan, &upgrade)
        .await
        .unwrap();

    {
        let state = state.lock().unwrap();
        assert_eq!(upgrade.durable_volumes()[0].uid(), &durable_uid);
        assert!(
            state
                .lifecycle_events
                .contains(&"invalidate-session-1".to_owned())
        );
        assert!(
            !state
                .lifecycle_events
                .iter()
                .any(|event| event == "delete-system")
        );
        assert_eq!(
            state
                .updates
                .last()
                .and_then(ChildSpecUpdate::desired_lifecycle),
            Some(DesiredLifecycle::Stopped)
        );
    }

    {
        let mut state = state.lock().unwrap();
        state.finalization = Some(finalization_input(
            &guest,
            &state.children,
            SessionState::Closed,
            true,
            ProcessState::Stopped,
        ));
    }
    for expected_role in [
        ChildRole::ChApiEndpoint,
        ChildRole::GuestControlEndpoint,
        ChildRole::VmmProcess,
    ] {
        {
            let mut state = state.lock().unwrap();
            state.finalization = Some(finalization_input(
                &guest,
                &state.children,
                SessionState::Closed,
                true,
                ProcessState::Stopped,
            ));
        }
        controller
            .execute_upgrade(&guest, &plan, &upgrade)
            .await
            .unwrap();
        {
            let mut state = state.lock().unwrap();
            let event = format!("delete-{}", expected_role.suffix());
            assert_eq!(
                state.lifecycle_events.last().map(String::as_str),
                Some(event.as_str())
            );
            state.children.retain(|child| {
                d2b_provider_runtime_cloud_hypervisor::child_role_for_ref(child.resource_ref())
                    != Some(expected_role)
            });
            state.finalization = Some(finalization_input(
                &guest,
                &state.children,
                SessionState::Closed,
                true,
                ProcessState::Stopped,
            ));
        }
        controller
            .execute_upgrade(&guest, &plan, &upgrade)
            .await
            .unwrap();
    }
    state.lock().unwrap().finalization = Some(finalization_input(
        &guest,
        &[],
        SessionState::Closed,
        true,
        ProcessState::Absent,
    ));
    controller
        .execute_upgrade(&guest, &plan, &upgrade)
        .await
        .unwrap();

    state.lock().unwrap().children = observed.clone();
    let old_result = controller.reconcile(guest.resource_ref()).await;
    assert_eq!(old_result, Err(CloudHypervisorError::ChildConflict));

    let replacement_children = observed
        .into_iter()
        .enumerate()
        .map(|(index, child)| {
            let child_uid =
                if d2b_provider_runtime_cloud_hypervisor::child_role_for_ref(child.resource_ref())
                    == Some(ChildRole::SystemVolume)
                {
                    child.uid().clone()
                } else {
                    ResourceUid::parse(format!("423e4567-e89b-42d3-a456-42661417{index:04}"))
                        .unwrap()
                };
            OwnedChildSnapshot::new(
                child.resource_ref().clone(),
                child.zone().clone(),
                child.owner_ref().clone(),
                child_uid,
                child.generation(),
                child.revision(),
                child.spec_digest().to_owned(),
                ResourcePhase::Ready,
                child.desired_lifecycle(),
                true,
            )
            .unwrap()
            .with_owner_uid(guest.uid().clone())
        })
        .collect::<Vec<_>>();
    state.lock().unwrap().children = replacement_children;
    assert!(controller.reconcile(guest.resource_ref()).await.is_ok());
}

#[tokio::test]
async fn disruptive_update_reports_upgrade_required_without_in_place_repair() {
    let guest = guest("gateway", "work", GUEST_UID, ZONE_UID);
    let api = FakeApi::new(guest.clone(), dependencies(true, true, true, true, true));
    let plan = BootstrapGraph::plan_children(
        guest.zone().clone(),
        guest.resource_ref().clone(),
        guest.execution_ref().clone(),
        &descriptor(),
    )
    .unwrap();
    let batch = GuestChildCreateBatch::new(
        &guest,
        plan.child_batch(),
        plan.child_batch()
            .mutations()
            .iter()
            .map(|mutation| mutation.target().clone()),
    )
    .unwrap();
    let state = Arc::clone(&api.state);
    {
        let mut state = state.lock().unwrap();
        state.children = matching_children(&guest, &batch);
        state.upgrade_reason = Some(UpgradeReason::ImageOrSystemGenerationChanged);
    }
    let mut controller = make_controller(api);
    controller.register().await.unwrap();
    let outcome = controller.reconcile(guest.resource_ref()).await.unwrap();
    assert!(matches!(
        outcome,
        d2b_provider_runtime_cloud_hypervisor::CloudHypervisorReconcileOutcome::Degraded(_)
    ));
    assert!(
        outcome
            .status()
            .has_condition(d2b_provider_runtime_cloud_hypervisor::GuestCondition::UpgradeRequired)
    );
    assert!(state.lock().unwrap().updates.is_empty());
}
