use std::{
    future::Future,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use d2b_contracts_resource::v3::{
    ResourceBundleGenerationId, ResourceGeneration, ResourceUid,
    execution_policy::BoundedToken,
    network::{
        AttachmentGenerationFence, AttachmentHandle, DhcpSpec, DnsSpec, Ipv4Cidr, IsolationSpec,
        MdnsSpec, NetworkSpec, RoutingSpec,
    },
};
use d2b_provider_network_local::{
    artifact::{ArtifactCatalogEntry, ArtifactKind},
    controller::{
        AttachmentRealization, FinalizerStage, FirewallDigest, FirewallIntent,
        NetworkAdmissionIntent, NetworkAdmissionKey, NetworkConfigContent, NetworkEffectError,
        NetworkEffectPort, NetworkReconciler, NetworkResourcePort, ReconcileInput,
        ReconcileProgress,
    },
    plan::{PlanStep, compute_plan, ActualState},
};

#[derive(Clone, Default)]
struct FakePorts {
    inner: Arc<FakePortState>,
}

#[derive(Default)]
struct FakePortState {
    events: Mutex<Vec<&'static str>>,
    effect_error: Mutex<Option<NetworkEffectError>>,
    mdns_values: Mutex<Vec<bool>>,
    firewall_generations: Mutex<Vec<String>>,
}

impl FakePorts {
    fn push(&self, event: &'static str) -> Result<(), NetworkEffectError> {
        self.inner.events.lock().unwrap().push(event);
        let mut configured = self.inner.effect_error.lock().unwrap();
        if configured.is_some_and(|error| {
            matches!(
                (event, error),
                (
                    "firewall-apply",
                    NetworkEffectError::StaleConfigurationGeneration
                ) | ("tap-delete", NetworkEffectError::StaleAttachmentGeneration)
                    | ("tap-delete", NetworkEffectError::Transient)
            )
        }) {
            return Err(configured.take().expect("configured error exists"));
        }
        Ok(())
    }

    fn events(&self) -> Vec<&'static str> {
        self.inner.events.lock().unwrap().clone()
    }
}

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = Box::pin(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

impl NetworkEffectPort for FakePorts {
    async fn validate_policy(&self, spec: &NetworkSpec) -> Result<(), NetworkEffectError> {
        if spec.isolation().allow_east_west {
            Err(NetworkEffectError::EastWestHostOptInRequired)
        } else {
            Ok(())
        }
    }

    async fn create_bridges(&self, _: &ResourceUid) -> Result<(), NetworkEffectError> {
        self.push("bridges")
    }

    async fn apply_sysctls(&self, _: &ResourceUid) -> Result<(), NetworkEffectError> {
        self.push("sysctls")
    }

    async fn apply_host_firewall(
        &self,
        intent: &FirewallIntent,
    ) -> Result<FirewallDigest, NetworkEffectError> {
        self.inner
            .firewall_generations
            .lock()
            .unwrap()
            .push(intent.expected_generation_id().as_str().to_owned());
        self.push("firewall-apply")?;
        Ok(FirewallDigest::new([1; 32]))
    }

    async fn remove_host_firewall(&self, _: &FirewallIntent) -> Result<(), NetworkEffectError> {
        self.push("firewall-remove")
    }

    async fn apply_nm_unmanaged(&self) -> Result<(), NetworkEffectError> {
        self.push("nm")
    }

    async fn apply_routes(&self, _: &ResourceUid) -> Result<(), NetworkEffectError> {
        self.push("routes")
    }

    async fn remove_routes(&self, _: &ResourceUid) -> Result<(), NetworkEffectError> {
        self.push("routes-remove")
    }

    async fn update_hosts(&self, _: &ResourceUid) -> Result<(), NetworkEffectError> {
        self.push("hosts")
    }

    async fn seed_dhcp(&self, _: &ResourceUid) -> Result<(), NetworkEffectError> {
        self.push("dhcp")
    }

    async fn delete_persistent_tap(
        &self,
        _: &AttachmentHandle,
        _: &AttachmentGenerationFence,
    ) -> Result<(), NetworkEffectError> {
        self.push("tap-delete")
    }

    async fn delete_bridges(&self, _: &ResourceUid) -> Result<(), NetworkEffectError> {
        self.push("bridge-delete")
    }
}

impl NetworkResourcePort for FakePorts {
    async fn upsert_volume_backing(
        &self,
        _: &d2b_contracts_resource::v3::volume::VolumeSpec,
    ) -> Result<(), NetworkEffectError> {
        self.push("volume-upsert")
    }

    async fn write_volume_content(
        &self,
        _: &NetworkConfigContent,
    ) -> Result<(), NetworkEffectError> {
        self.push("volume-write")
    }

    async fn upsert_guest(
        &self,
        _: &d2b_contracts_resource::v3::guest::GuestSpec,
    ) -> Result<(), NetworkEffectError> {
        self.push("guest-upsert")
    }

    async fn attach_volume(
        &self,
        _: &d2b_contracts_resource::v3::volume::VolumeAttachment,
    ) -> Result<(), NetworkEffectError> {
        self.push("volume-attach")
    }

    async fn upsert_agent(
        &self,
        _: &d2b_contracts_resource::v3::process::ProcessSpec,
    ) -> Result<(), NetworkEffectError> {
        self.push("agent-upsert")
    }

    async fn reconcile_mdns(&self, enabled: bool) -> Result<(), NetworkEffectError> {
        self.inner.mdns_values.lock().unwrap().push(enabled);
        self.push("mdns")
    }

    async fn delete_processes(&self) -> Result<(), NetworkEffectError> {
        self.push("process-delete")
    }

    async fn detach_volume(&self) -> Result<(), NetworkEffectError> {
        self.push("volume-detach")
    }

    async fn delete_guest(&self) -> Result<(), NetworkEffectError> {
        self.push("guest-delete")
    }

    async fn delete_volume(&self) -> Result<(), NetworkEffectError> {
        self.push("volume-delete")
    }
}

fn spec(lan: &str, uplink: &str) -> NetworkSpec {
    NetworkSpec::minimal(
        Ipv4Cidr::parse(lan).unwrap(),
        Ipv4Cidr::parse(uplink).unwrap(),
        BoundedToken::parse("net-vm-base").unwrap(),
    )
    .unwrap()
}

fn east_west_spec(lan: &str, uplink: &str) -> NetworkSpec {
    NetworkSpec::new(
        Ipv4Cidr::parse(lan).unwrap(),
        Ipv4Cidr::parse(uplink).unwrap(),
        None,
        false,
        IsolationSpec {
            allow_east_west: true,
        },
        RoutingSpec::default(),
        DhcpSpec::default(),
        DnsSpec::default(),
        None,
        MdnsSpec::default(),
        None,
        BoundedToken::parse("net-vm-base").unwrap(),
        Vec::new(),
    )
    .unwrap()
}

fn generation() -> ResourceBundleGenerationId {
    ResourceBundleGenerationId::parse(
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )
    .unwrap()
}

fn input() -> ReconcileInput {
    let network_uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
    let attachment_uid = ResourceUid::parse("223e4567-e89b-42d3-a456-426614174001").unwrap();
    let spec = spec("10.20.0.0/24", "192.0.2.0/30");
    let admission = NetworkAdmissionIntent::new(
        NetworkAdmissionKey::new(
            ResourceUid::parse("323e4567-e89b-42d3-a456-426614174002").unwrap(),
            network_uid.clone(),
            ResourceGeneration::new(4).unwrap(),
            ResourceGeneration::new(7).unwrap(),
            generation(),
        ),
        spec.clone(),
        Vec::new(),
    )
    .unwrap()
    .proof();
    ReconcileInput {
        spec,
        mdns_enabled: false,
        network_uid: network_uid.clone(),
        network_generation: ResourceGeneration::new(4).unwrap(),
        attachment_generation: ResourceGeneration::new(7).unwrap(),
        installed_generation: generation(),
        admission,
        artifact_catalog: vec![ArtifactCatalogEntry::new(
            BoundedToken::parse("net-vm-base").unwrap(),
            ArtifactKind::NixosSystem,
        )],
        user_ready: true,
        host_memory_budget_available: 8 * 1024 * 1024,
        volume_ready: true,
        guest_ready: true,
        volume_attachment_ready: true,
        workload_fds_closed: true,
        agent_deleted: true,
        mdns_deleted: true,
        volume_attachment_removed: true,
        guest_deleted: true,
        volume_deleted: true,
        attachments: vec![AttachmentRealization {
            handle: AttachmentHandle::new(
                attachment_uid.clone(),
                AttachmentGenerationFence::new(
                    network_uid,
                    ResourceGeneration::new(4).unwrap(),
                    attachment_uid,
                    ResourceGeneration::new(7).unwrap(),
                ),
            ),
            vmm_fd_closed: true,
        }],
    }
}

#[test]
fn reconcile_enforces_effect_and_child_readiness_order() {
    let effects = FakePorts::default();
    let resources = FakePorts::default();
    let controller = NetworkReconciler::new(effects.clone(), resources.clone());
    assert_eq!(
        block_on(controller.reconcile(&input())).unwrap(),
        ReconcileProgress::Ready
    );
    assert_eq!(
        effects.events(),
        [
            "bridges",
            "sysctls",
            "firewall-apply",
            "nm",
            "routes",
            "hosts",
            "dhcp",
            "tap-delete",
        ]
    );
    assert_eq!(
        *effects.inner.firewall_generations.lock().unwrap(),
        [generation().as_str()]
    );
    assert_eq!(
        resources.events(),
        [
            "volume-upsert",
            "volume-write",
            "guest-upsert",
            "volume-attach",
            "agent-upsert",
            "mdns",
        ]
    );
}

#[test]
fn guest_and_agent_are_barriered_by_volume_and_attachment_readiness() {
    let effects = FakePorts::default();
    let resources = FakePorts::default();
    let controller = NetworkReconciler::new(effects.clone(), resources.clone());
    let mut state = input();
    state.volume_ready = false;
    assert!(matches!(
        block_on(controller.reconcile(&state)).unwrap(),
        ReconcileProgress::Pending(_)
    ));
    assert!(!resources.events().contains(&"guest-upsert"));

    let effects = FakePorts::default();
    let resources = FakePorts::default();
    let controller = NetworkReconciler::new(effects.clone(), resources.clone());
    let mut state = input();
    state.guest_ready = false;
    assert!(matches!(
        block_on(controller.reconcile(&state)).unwrap(),
        ReconcileProgress::Pending(_)
    ));
    assert!(!resources.events().contains(&"volume-attach"));

    let effects = FakePorts::default();
    let resources = FakePorts::default();
    let controller = NetworkReconciler::new(effects.clone(), resources.clone());
    let mut state = input();
    state.volume_attachment_ready = false;
    assert!(matches!(
        block_on(controller.reconcile(&state)).unwrap(),
        ReconcileProgress::Pending(_)
    ));
    assert!(!resources.events().contains(&"agent-upsert"));
}

#[test]
fn stale_configuration_generation_requeues_without_following_effects() {
    let effects = FakePorts::default();
    *effects.inner.effect_error.lock().unwrap() =
        Some(NetworkEffectError::StaleConfigurationGeneration);
    let resources = FakePorts::default();
    let controller = NetworkReconciler::new(effects.clone(), resources.clone());
    assert!(matches!(
        block_on(controller.reconcile(&input())).unwrap(),
        ReconcileProgress::Requeue(_)
    ));
    assert_eq!(effects.events(), ["bridges", "sysctls", "firewall-apply"]);
    assert!(resources.events().is_empty());
}

#[test]
fn finalizer_never_deletes_bridge_before_tap_and_children() {
    let effects = FakePorts::default();
    let resources = FakePorts::default();
    let controller = NetworkReconciler::new(effects.clone(), resources.clone());
    assert_eq!(
        block_on(controller.finalize(&input())).unwrap(),
        FinalizerStage::Complete
    );
    assert_eq!(
        effects.events(),
        [
            "tap-delete",
            "firewall-remove",
            "routes-remove",
            "bridge-delete"
        ]
    );

    let effects = FakePorts::default();
    let resources = FakePorts::default();
    let controller = NetworkReconciler::new(effects.clone(), resources.clone());
    let mut waiting = input();
    waiting.attachments[0].vmm_fd_closed = false;
    assert_eq!(
        block_on(controller.finalize(&waiting)).unwrap(),
        FinalizerStage::WorkloadFdClosure
    );
    assert!(effects.events().is_empty());
}

#[test]
fn admission_mismatch_and_host_budget_block_before_effects() {
    let effects = FakePorts::default();
    let resources = FakePorts::default();
    let controller = NetworkReconciler::new(effects.clone(), resources.clone());
    let mut conflicting = input();
    conflicting.spec = spec("10.30.0.0/24", "198.51.100.0/30");
    assert_eq!(
        block_on(controller.reconcile(&conflicting)),
        Err(NetworkEffectError::NetworkAdmissionMismatch)
    );
    assert!(effects.events().is_empty());

    let effects = FakePorts::default();
    let resources = FakePorts::default();
    let controller = NetworkReconciler::new(effects.clone(), resources.clone());
    let mut exhausted = input();
    exhausted.host_memory_budget_available = 1024;
    assert_eq!(
        block_on(controller.reconcile(&exhausted)),
        Err(NetworkEffectError::HostMemoryBudgetExceeded)
    );
    assert!(effects.events().is_empty());
}

#[test]
fn stale_attachment_admission_refuses_before_effects() {
    let effects = FakePorts::default();
    let resources = FakePorts::default();
    let controller = NetworkReconciler::new(effects.clone(), resources);
    let mut stale = input();
    let network_uid = stale.network_uid.clone();
    let attachment_uid = stale.attachments[0].handle.opaque_id().clone();
    stale.attachments[0].handle = AttachmentHandle::new(
        attachment_uid.clone(),
        AttachmentGenerationFence::new(
            network_uid,
            stale.network_generation,
            attachment_uid,
            ResourceGeneration::new(6).unwrap(),
        ),
    );
    assert_eq!(
        block_on(controller.reconcile(&stale)),
        Err(NetworkEffectError::NetworkAdmissionMismatch)
    );
    assert!(effects.events().is_empty());
}

#[test]
fn user_readiness_and_mdns_toggle_are_explicit() {
    let effects = FakePorts::default();
    let resources = FakePorts::default();
    let controller = NetworkReconciler::new(effects.clone(), resources.clone());
    let mut waiting = input();
    waiting.user_ready = false;
    assert!(matches!(
        block_on(controller.reconcile(&waiting)).unwrap(),
        ReconcileProgress::Pending(_)
    ));
    assert!(effects.events().is_empty());

    let mut enabled = input();
    enabled.mdns_enabled = true;
    assert_eq!(
        block_on(controller.reconcile(&enabled)).unwrap(),
        ReconcileProgress::Ready
    );
    assert_eq!(*resources.inner.mdns_values.lock().unwrap(), [true]);
}

#[test]
fn east_west_requires_the_site_opt_in_before_any_effect() {
    let effects = FakePorts::default();
    let resources = FakePorts::default();
    let controller = NetworkReconciler::new(effects.clone(), resources);
    let mut state = input();
    state.spec = east_west_spec("10.20.0.0/24", "192.0.2.0/30");
    assert_eq!(
        block_on(controller.reconcile(&state)),
        Err(NetworkEffectError::EastWestHostOptInRequired)
    );
    assert!(effects.events().is_empty());
}

#[test]
fn transient_tap_delete_retains_finalizer_stage_for_retry() {
    let effects = FakePorts::default();
    *effects.inner.effect_error.lock().unwrap() = Some(NetworkEffectError::Transient);
    let resources = FakePorts::default();
    let controller = NetworkReconciler::new(effects.clone(), resources);
    assert_eq!(
        block_on(controller.finalize(&input())).unwrap(),
        FinalizerStage::PersistentTaps
    );
    assert!(!effects.events().contains(&"bridge-delete"));
}

#[test]
fn finalizer_removes_volume_attachment_before_guest_and_volume() {
    let effects = FakePorts::default();
    let resources = FakePorts::default();
    let controller = NetworkReconciler::new(effects, resources.clone());
    let mut state = input();
    state.volume_attachment_removed = false;
    state.guest_deleted = false;
    state.volume_deleted = false;
    assert_eq!(
        block_on(controller.finalize(&state)).unwrap(),
        FinalizerStage::VolumeAttachment
    );
    assert_eq!(resources.events(), ["volume-detach"]);

    state.volume_attachment_removed = true;
    assert_eq!(
        block_on(controller.finalize(&state)).unwrap(),
        FinalizerStage::Guest
    );
    assert_eq!(resources.events(), ["volume-detach", "guest-delete"]);

    state.guest_deleted = true;
    assert_eq!(
        block_on(controller.finalize(&state)).unwrap(),
        FinalizerStage::Volume
    );
    assert_eq!(
        resources.events(),
        ["volume-detach", "guest-delete", "volume-delete"]
    );
}

#[test]
fn matching_mdns_state_does_not_schedule_a_second_effect() {
    let plan = compute_plan(
        &spec("10.20.0.0/24", "192.0.2.0/30"),
        true,
        ActualState {
            bridges_ready: true,
            sysctls_ready: true,
            firewall_ready: true,
            volume_ready: true,
            guest_ready: true,
            attachment_ready: true,
            agent_ready: true,
            mdns_matches: true,
        },
    );

    assert!(!plan.steps().contains(&PlanStep::ReconcileMdns));
}

#[test]
fn network_runner_is_the_only_scheduler_and_watches_config_as_dependency() {
    let contract = d2b_provider_network_local::controller::network_runner_contract();
    assert_eq!(contract.resource_type(), "Network");
    assert_eq!(contract.finalizer(), "network.d2bus.org/fabric-cleanup");
    assert!(contract.legacy_scheduler_disabled());
    assert!(contract.watched_configuration_is_dependency());
    assert!((30..=60).contains(&contract.repair_interval_secs()));
}
