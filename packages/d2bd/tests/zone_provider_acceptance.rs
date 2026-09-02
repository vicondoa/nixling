//! Hermetic Zone acceptance for the four Wave 6 resource boundaries.
//!
//! The ports in this file are small real adapters: they persist their
//! effects below a temporary directory or own a real child process. They do
//! not record expected calls or bypass the Provider controllers.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::FileTypeExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use d2b_contracts_provider::v3::{
    ArtifactDigest, BinaryRef, ComponentDescriptor, ComponentExecution, ComponentTargetCapability,
    ComponentType, ControllerInstanceScope, ControllerTargetKind, EffectPortClass,
};
use d2b_contracts_resource::v3::{
    ArtifactId, ControllerGeneration, DesiredLifecycle, ResourceBundleGenerationId,
    ResourceGeneration, ResourcePhase, ResourceRef, ResourceTypeName, ResourceUid,
    SchemaFingerprint, SchemaVersion, ZoneId, ZoneRevision,
    execution_policy::BoundedToken,
    guest::GuestSpec,
    identity::ReconnectGeneration,
    network::{
        AttachmentGenerationFence, AttachmentHandle, DhcpSpec, DnsSpec, Ipv4Cidr, IsolationSpec,
        MdnsSpec, NetworkSpec, RoutingSpec,
    },
    process::{ProcessClass, ProcessSpec},
    volume::{EntryType, VolumeSpec},
};
use d2b_provider_device_tpm::{
    TpmResourceController, TpmResourceEffectError, TpmResourceEffectPort, TpmResourceOutcome,
};
use d2b_provider_network_local::{
    artifact::{ArtifactCatalogEntry, ArtifactKind},
    controller::{
        AttachmentRealization, FinalizerStage, FirewallDigest, FirewallIntent,
        NetworkAdmissionIntent, NetworkAdmissionKey, NetworkConfigContent, NetworkEffectError,
        NetworkEffectPort, NetworkReconciler, NetworkResourcePort, ReconcileInput,
        ReconcileProgress,
    },
};
use d2b_provider_runtime_cloud_hypervisor::{
    AuthenticatedResourceApiAdapter, AuthenticatedResourceSession, BootstrapGraph,
    BootstrapHandoff, CloudHypervisorConfig, CloudHypervisorController,
    CloudHypervisorReconcileOutcome, CloudHypervisorResourceApiError,
    CloudHypervisorResourceRequest, CloudHypervisorResourceResponse, CommittedChild,
    DescriptorSignature, GuestChildCommitResponse, GuestGenerationSet, GuestSeedContract,
    GuestSessionEvidence, GuestSetupDescriptor, GuestSetupDescriptorVerifier, GuestSnapshot,
    GuestStatusPhase, OwnedChildSnapshot, SignatureAlgorithm, health::GuestSessionEvidenceBinding,
};
use d2b_provider_volume_local::{
    DriftClass, MarkerState, OwnerProof, QuotaCapability, VolumeLayoutEffectPort,
    VolumeLocalController, VolumeLocalProfile, VolumeRootHandle, VolumeSourceEffectPort,
};
use d2bd_runtime::resource_operator_activation::{
    Wave6BoundaryError, Wave6Dependencies, Wave6ProviderBoundary, Wave6ReconcileResult,
    Wave6Resource, Wave6ResourceSet,
};
use d2bd_runtime::target_runtime::{
    AdmissionLimits, ControllerAssignmentRequest, ControllerChildObservation,
    ControllerProcessPhase, ControllerResourceVerb, ControllerSessionBinding, DaemonMode,
    ProviderDeployment,
};
use serde_json::json;

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    let waker = std::task::Waker::noop();
    let mut context = std::task::Context::from_waker(waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(value) => return value,
            std::task::Poll::Pending => std::thread::yield_now(),
        }
    }
}

struct FilesystemVolume {
    root: PathBuf,
    marker: PathBuf,
}

impl FilesystemVolume {
    fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            marker: root.join(".d2b-provisioned"),
            root,
        }
    }

    fn entry_path(&self, path: &str) -> PathBuf {
        if path.is_empty() {
            self.root.clone()
        } else {
            self.root.join(path)
        }
    }

    fn ensure_parent(path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(())
    }

    fn provision(&self, entry: &d2b_provider_volume_local::EntryRequest) -> io::Result<()> {
        let path = self.entry_path(entry.declared().path());
        Self::ensure_parent(&path)?;
        match entry.entry_type() {
            EntryType::Directory => fs::create_dir_all(path),
            EntryType::File => File::create(path).map(|_| ()),
            EntryType::Symlink => {
                let target = entry.declared().target().unwrap_or("target");
                std::os::unix::fs::symlink(target, path)
            }
            EntryType::UnixSocket => Ok(()),
        }
    }

    fn remove(&self, entry: &d2b_provider_volume_local::EntryRequest) -> io::Result<()> {
        let path = self.entry_path(entry.declared().path());
        if !path.exists() {
            return Ok(());
        }
        match entry.entry_type() {
            EntryType::Directory => fs::remove_dir(path),
            EntryType::File | EntryType::Symlink | EntryType::UnixSocket => fs::remove_file(path),
        }
    }

    fn matches_type(path: &Path, entry_type: EntryType) -> io::Result<bool> {
        let metadata = fs::symlink_metadata(path)?;
        Ok(match entry_type {
            EntryType::Directory => metadata.is_dir(),
            EntryType::File => metadata.is_file(),
            EntryType::Symlink => metadata.file_type().is_symlink(),
            EntryType::UnixSocket => metadata.file_type().is_socket(),
        })
    }
}

impl VolumeSourceEffectPort for &FilesystemVolume {
    async fn resolve_root(
        &self,
        _source_policy_id: Option<&BoundedToken>,
        _system_artifact_id: Option<&BoundedToken>,
        _kind: d2b_contracts_resource::v3::volume::SourceKind,
    ) -> Result<VolumeRootHandle, d2b_provider_volume_local::VolumeLocalError> {
        fs::create_dir_all(&self.root)
            .map_err(|_| d2b_provider_volume_local::VolumeLocalError::EffectFailed)?;
        Ok(VolumeRootHandle::held())
    }

    async fn quota_capability(
        &self,
        _root: &VolumeRootHandle,
    ) -> Result<QuotaCapability, d2b_provider_volume_local::VolumeLocalError> {
        Ok(QuotaCapability::Enforceable)
    }
}

impl VolumeLayoutEffectPort for &FilesystemVolume {
    async fn observe(
        &self,
        _root: &VolumeRootHandle,
        entry: &d2b_provider_volume_local::EntryRequest,
    ) -> Result<d2b_provider_volume_local::ObservedEntry, d2b_provider_volume_local::VolumeLocalError>
    {
        let path = self.entry_path(entry.declared().path());
        match FilesystemVolume::matches_type(&path, entry.entry_type()) {
            Ok(true) => Ok(d2b_provider_volume_local::ObservedEntry::conformant(
                OwnerProof::NotApplicable,
            )),
            Ok(false) => Ok(d2b_provider_volume_local::ObservedEntry {
                present: true,
                drift: [DriftClass::EntryType].into_iter().collect(),
                symlink_encountered: false,
                foreign_children: false,
                owner_proof: OwnerProof::NotApplicable,
            }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                Ok(d2b_provider_volume_local::ObservedEntry::absent())
            }
            Err(_) => Err(d2b_provider_volume_local::VolumeLocalError::EffectFailed),
        }
    }

    async fn provision(
        &self,
        _root: &VolumeRootHandle,
        entry: &d2b_provider_volume_local::EntryRequest,
    ) -> Result<(), d2b_provider_volume_local::VolumeLocalError> {
        FilesystemVolume::provision(self, entry)
            .map_err(|_| d2b_provider_volume_local::VolumeLocalError::EffectFailed)
    }

    async fn repair(
        &self,
        _root: &VolumeRootHandle,
        entry: &d2b_provider_volume_local::EntryRequest,
        _drift: &std::collections::BTreeSet<DriftClass>,
    ) -> Result<(), d2b_provider_volume_local::VolumeLocalError> {
        FilesystemVolume::remove(self, entry)
            .and_then(|_| FilesystemVolume::provision(self, entry))
            .map_err(|_| d2b_provider_volume_local::VolumeLocalError::EffectFailed)
    }

    async fn apply_acl(
        &self,
        _root: &VolumeRootHandle,
        _entry: &d2b_provider_volume_local::EntryRequest,
    ) -> Result<(), d2b_provider_volume_local::VolumeLocalError> {
        Ok(())
    }

    async fn cleanup(
        &self,
        _root: &VolumeRootHandle,
        entry: &d2b_provider_volume_local::EntryRequest,
    ) -> Result<(), d2b_provider_volume_local::VolumeLocalError> {
        FilesystemVolume::remove(self, entry)
            .map_err(|_| d2b_provider_volume_local::VolumeLocalError::EffectFailed)
    }

    async fn marker_state(
        &self,
        _root: &VolumeRootHandle,
    ) -> Result<MarkerState, d2b_provider_volume_local::VolumeLocalError> {
        if self.marker.exists() {
            Ok(MarkerState::Provisioned)
        } else {
            File::create(&self.marker)
                .and_then(|file| file.sync_all())
                .map_err(|_| d2b_provider_volume_local::VolumeLocalError::EffectFailed)?;
            Ok(MarkerState::NeverProvisioned)
        }
    }

    async fn materialize_network_config(
        &self,
        _root: &VolumeRootHandle,
        _projection: &d2b_provider_volume_local::NetworkConfigContentProjection,
    ) -> Result<
        d2b_provider_volume_local::NetworkConfigMaterializationEvidence,
        d2b_provider_volume_local::VolumeLocalError,
    > {
        Err(d2b_provider_volume_local::VolumeLocalError::EffectFailed)
    }
}

pub fn volume_spec() -> VolumeSpec {
    serde_json::from_value(json!({
        "source": {
            "executionRef": "Host/host-system",
            "settings": {
                "kind": "local-path",
                "sourcePolicyId": "zone-state"
            }
        },
        "kind": "state",
        "layout": [
            {
                "path": "",
                "type": "directory",
                "ownerRef": "User/d2bd",
                "groupRef": "User/d2bd",
                "mode": "0700",
                "cleanupPolicy": "never"
            },
            {
                "path": "state.db",
                "type": "file",
                "ownerRef": "User/d2bd",
                "groupRef": "User/d2bd",
                "mode": "0600",
                "cleanupPolicy": "boot"
            }
        ],
        "views": {
            "controller": {
                "path": "",
                "rights": ["read", "write", "create", "delete", "traverse"]
            }
        }
    }))
    .expect("valid Volume acceptance fixture")
}

#[test]
fn volume_zone_activation_ready_restart_and_cleanup_use_real_files() {
    let directory = tempfile::tempdir().expect("Volume backing directory");
    let volume = FilesystemVolume::new(directory.path());
    let uid = ResourceUid::parse("6f9619ff-8b86-4d01-b42d-00cf4fc964ff").unwrap();
    let spec = volume_spec();
    let controller = VolumeLocalController::new(VolumeLocalProfile::shipped(), &volume, &volume);

    let first = block_on(controller.reconcile(&uid, &spec, None, None))
        .expect("initial Volume reconcile");
    assert_eq!(
        first.layout_phase,
        d2b_provider_volume_local::LayoutPhase::Ready
    );
    assert!(directory.path().join("state.db").is_file());

    let restarted = VolumeLocalController::new(VolumeLocalProfile::shipped(), &volume, &volume);
    let adopted = block_on(restarted.reconcile(&uid, &spec, None, None))
        .expect("restart Volume reconcile");
    assert_eq!(
        adopted.layout_phase,
        d2b_provider_volume_local::LayoutPhase::Ready
    );
    assert!(directory.path().join("state.db").is_file());

    let removed = block_on(restarted.cleanup(&uid, &spec)).expect("Volume finalization");
    assert_eq!(removed.len(), 1);
    assert!(!directory.path().join("state.db").exists());
    assert!(directory.path().is_dir(), "never-cleanup root is retained");
}

struct FilesystemNetworkBoundary {
    root: PathBuf,
}

impl FilesystemNetworkBoundary {
    fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn event(&self, name: &str) -> Result<(), NetworkEffectError> {
        fs::create_dir_all(&self.root).map_err(|_| NetworkEffectError::Transient)?;
        let path = self.root.join("events.log");
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|_| NetworkEffectError::Transient)?;
        writeln!(file, "{name}").map_err(|_| NetworkEffectError::Transient)?;
        file.sync_all().map_err(|_| NetworkEffectError::Transient)
    }

    fn events(&self) -> Vec<String> {
        fs::read_to_string(self.root.join("events.log"))
            .unwrap_or_default()
            .lines()
            .map(ToOwned::to_owned)
            .collect()
    }
}

impl NetworkEffectPort for &FilesystemNetworkBoundary {
    async fn validate_policy(&self, spec: &NetworkSpec) -> Result<(), NetworkEffectError> {
        if spec.isolation().allow_east_west {
            Err(NetworkEffectError::EastWestHostOptInRequired)
        } else {
            Ok(())
        }
    }

    async fn create_bridges(&self, _: &ResourceUid) -> Result<(), NetworkEffectError> {
        fs::create_dir_all(self.root.join("bridges"))
            .map_err(|_| NetworkEffectError::BridgeCreate)?;
        self.event("bridges")
    }

    async fn apply_sysctls(&self, _: &ResourceUid) -> Result<(), NetworkEffectError> {
        self.event("sysctls")
    }

    async fn apply_host_firewall(
        &self,
        intent: &FirewallIntent,
    ) -> Result<FirewallDigest, NetworkEffectError> {
        fs::write(
            self.root.join("firewall-generation"),
            intent.expected_generation_id().as_str(),
        )
        .map_err(|_| NetworkEffectError::Transient)?;
        self.event("firewall-apply")?;
        Ok(FirewallDigest::new([1; 32]))
    }

    async fn remove_host_firewall(&self, _: &FirewallIntent) -> Result<(), NetworkEffectError> {
        let _ = fs::remove_file(self.root.join("firewall-generation"));
        self.event("firewall-remove")
    }

    async fn apply_nm_unmanaged(&self) -> Result<(), NetworkEffectError> {
        self.event("nm")
    }

    async fn apply_routes(&self, _: &ResourceUid) -> Result<(), NetworkEffectError> {
        self.event("routes")
    }

    async fn remove_routes(&self, _: &ResourceUid) -> Result<(), NetworkEffectError> {
        self.event("routes-remove")
    }

    async fn update_hosts(&self, _: &ResourceUid) -> Result<(), NetworkEffectError> {
        self.event("hosts")
    }

    async fn seed_dhcp(&self, _: &ResourceUid) -> Result<(), NetworkEffectError> {
        self.event("dhcp")
    }

    async fn delete_persistent_tap(
        &self,
        _: &AttachmentHandle,
        _: &AttachmentGenerationFence,
    ) -> Result<(), NetworkEffectError> {
        self.event("tap-delete")
    }

    async fn delete_bridges(&self, _: &ResourceUid) -> Result<(), NetworkEffectError> {
        let _ = fs::remove_dir(self.root.join("bridges"));
        self.event("bridge-delete")
    }
}

impl NetworkResourcePort for &FilesystemNetworkBoundary {
    async fn upsert_volume_backing(
        &self,
        _: &d2b_contracts_resource::v3::volume::VolumeSpec,
    ) -> Result<(), NetworkEffectError> {
        self.event("volume-upsert")
    }

    async fn write_volume_content(
        &self,
        content: &NetworkConfigContent,
    ) -> Result<(), NetworkEffectError> {
        fs::write(self.root.join("dnsmasq.conf"), &content.dnsmasq)
            .and_then(|_| fs::write(self.root.join("nftables.conf"), &content.nftables))
            .and_then(|_| fs::write(self.root.join("routing.conf"), &content.routing))
            .and_then(|_| fs::write(self.root.join("attachments.conf"), &content.attachments))
            .map_err(|_| NetworkEffectError::Transient)?;
        self.event("volume-write")
    }

    async fn upsert_guest(&self, _: &GuestSpec) -> Result<(), NetworkEffectError> {
        self.event("guest-upsert")
    }

    async fn attach_volume(
        &self,
        _: &d2b_contracts_resource::v3::volume::VolumeAttachment,
    ) -> Result<(), NetworkEffectError> {
        self.event("volume-attach")
    }

    async fn upsert_agent(&self, _: &ProcessSpec) -> Result<(), NetworkEffectError> {
        self.event("agent-upsert")
    }

    async fn reconcile_mdns(&self, _: bool) -> Result<(), NetworkEffectError> {
        self.event("mdns")
    }

    async fn delete_processes(&self) -> Result<(), NetworkEffectError> {
        self.event("process-delete")
    }

    async fn detach_volume(&self) -> Result<(), NetworkEffectError> {
        self.event("volume-detach")
    }

    async fn delete_guest(&self) -> Result<(), NetworkEffectError> {
        self.event("guest-delete")
    }

    async fn delete_volume(&self) -> Result<(), NetworkEffectError> {
        self.event("volume-delete")
    }
}

pub fn network_spec() -> NetworkSpec {
    NetworkSpec::minimal(
        Ipv4Cidr::parse("10.20.0.0/24").unwrap(),
        Ipv4Cidr::parse("192.0.2.0/30").unwrap(),
        BoundedToken::parse("net-vm-base").unwrap(),
    )
    .unwrap()
}

fn network_input(
    spec: NetworkSpec,
    volume_ready: bool,
    guest_ready: bool,
    attachment_ready: bool,
) -> ReconcileInput {
    let network_uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
    let attachment_uid = ResourceUid::parse("223e4567-e89b-42d3-a456-426614174001").unwrap();
    let installed_generation = ResourceBundleGenerationId::parse(
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )
    .unwrap();
    let admission = NetworkAdmissionIntent::new(
        NetworkAdmissionKey::new(
            ResourceUid::parse("323e4567-e89b-42d3-a456-426614174002").unwrap(),
            network_uid.clone(),
            ResourceGeneration::new(4).unwrap(),
            ResourceGeneration::new(7).unwrap(),
            installed_generation.clone(),
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
        installed_generation,
        admission,
        artifact_catalog: vec![ArtifactCatalogEntry::new(
            BoundedToken::parse("net-vm-base").unwrap(),
            ArtifactKind::NixosSystem,
        )],
        user_ready: true,
        host_memory_budget_available: 8 * 1024 * 1024,
        volume_ready,
        guest_ready,
        volume_attachment_ready: attachment_ready,
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
fn network_zone_waits_for_children_refuses_unauthorized_policy_and_finalizes_ordered() {
    let directory = tempfile::tempdir().expect("Network state directory");
    let boundary = FilesystemNetworkBoundary::new(directory.path());
    let reconciler = NetworkReconciler::new(&boundary, &boundary);

    let waiting = network_input(network_spec(), false, true, true);
    assert_eq!(
        block_on(reconciler.reconcile(&waiting)).unwrap(),
        ReconcileProgress::Pending(
            d2b_provider_network_local::controller::NetworkConditionReason::VolumeNotReady
        )
    );
    assert!(
        !boundary
            .events()
            .iter()
            .any(|event| event == "guest-upsert"),
        "dependency wait must not reach Guest effects"
    );

    let ready = network_input(network_spec(), true, true, true);
    assert_eq!(
        block_on(reconciler.reconcile(&ready)).unwrap(),
        ReconcileProgress::Ready
    );

    let mut unauthorized = network_input(network_spec(), true, true, true);
    unauthorized.spec = NetworkSpec::new(
        Ipv4Cidr::parse("10.21.0.0/24").unwrap(),
        Ipv4Cidr::parse("192.0.2.4/30").unwrap(),
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
    .unwrap();
    let event_count = boundary.events().len();
    assert_eq!(
        block_on(reconciler.reconcile(&unauthorized)),
        Err(NetworkEffectError::EastWestHostOptInRequired)
    );
    assert_eq!(boundary.events().len(), event_count);

    let mut finalizing = ready;
    finalizing.agent_deleted = false;
    finalizing.mdns_deleted = false;
    finalizing.volume_attachment_removed = false;
    finalizing.guest_deleted = false;
    finalizing.volume_deleted = false;
    assert_eq!(
        block_on(reconciler.finalize(&finalizing)).unwrap(),
        FinalizerStage::Processes
    );
    finalizing.agent_deleted = true;
    finalizing.mdns_deleted = true;
    assert_eq!(
        block_on(reconciler.finalize(&finalizing)).unwrap(),
        FinalizerStage::VolumeAttachment
    );
    finalizing.volume_attachment_removed = true;
    assert_eq!(
        block_on(reconciler.finalize(&finalizing)).unwrap(),
        FinalizerStage::Guest
    );
    finalizing.guest_deleted = true;
    assert_eq!(
        block_on(reconciler.finalize(&finalizing)).unwrap(),
        FinalizerStage::Volume
    );
    finalizing.volume_deleted = true;
    assert_eq!(
        block_on(reconciler.finalize(&finalizing)).unwrap(),
        FinalizerStage::Complete
    );
    let events = boundary.events();
    let detach = events
        .iter()
        .position(|event| event == "volume-detach")
        .unwrap();
    let guest = events
        .iter()
        .position(|event| event == "guest-delete")
        .unwrap();
    let volume = events
        .iter()
        .position(|event| event == "volume-delete")
        .unwrap();
    let bridge = events
        .iter()
        .position(|event| event == "bridge-delete")
        .unwrap();
    assert!(detach < guest && guest < volume && volume < bridge);
}

struct FilesystemTpm {
    root: PathBuf,
    process: Mutex<Option<Child>>,
}

impl FilesystemTpm {
    fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            process: Mutex::new(None),
        }
    }
}

impl TpmResourceEffectPort for FilesystemTpm {
    async fn ensure_state_volume(
        &self,
        _: &ResourceUid,
        _: &ResourceRef,
        _: &ResourceRef,
    ) -> Result<ResourceRef, TpmResourceEffectError> {
        fs::create_dir_all(self.root.join("tpm-state"))
            .map_err(|_| TpmResourceEffectError::Transient)?;
        Ok(ResourceRef::parse("Volume/device-tpm-state").unwrap())
    }

    async fn request_swtpm_process(
        &self,
        _: &ResourceUid,
        _: &ResourceRef,
        _: &ResourceRef,
    ) -> Result<ResourceRef, TpmResourceEffectError> {
        if let Some(process) = self
            .process
            .lock()
            .map_err(|_| TpmResourceEffectError::Transient)?
            .as_mut()
            && process
                .try_wait()
                .map_err(|_| TpmResourceEffectError::Transient)?
                .is_none()
        {
            return Ok(ResourceRef::parse("Process/device-swtpm").unwrap());
        }
        let child = Command::new("sleep")
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| TpmResourceEffectError::Transient)?;
        fs::write(self.root.join("swtpm.pid"), child.id().to_string())
            .map_err(|_| TpmResourceEffectError::Transient)?;
        *self
            .process
            .lock()
            .map_err(|_| TpmResourceEffectError::Transient)? = Some(child);
        Ok(ResourceRef::parse("Process/device-swtpm").unwrap())
    }

    async fn request_flush_process(
        &self,
        _: &ResourceUid,
        _: &ResourceRef,
    ) -> Result<ResourceRef, TpmResourceEffectError> {
        Command::new("true")
            .status()
            .map_err(|_| TpmResourceEffectError::Transient)?;
        fs::write(self.root.join("flush.complete"), b"ok")
            .map_err(|_| TpmResourceEffectError::Transient)?;
        Ok(ResourceRef::parse("EphemeralProcess/device-tpm-flush").unwrap())
    }

    async fn stop_swtpm_process(&self, _: &ResourceRef) -> Result<(), TpmResourceEffectError> {
        let Some(mut child) = self
            .process
            .lock()
            .map_err(|_| TpmResourceEffectError::Transient)?
            .take()
        else {
            return Ok(());
        };
        child
            .kill()
            .and_then(|_| child.wait())
            .map_err(|_| TpmResourceEffectError::Transient)?;
        fs::write(self.root.join("swtpm.stopped"), b"ok")
            .map_err(|_| TpmResourceEffectError::Transient)
    }

    async fn delete_flush_process(&self, _: &ResourceRef) -> Result<(), TpmResourceEffectError> {
        let _ = fs::remove_file(self.root.join("flush.complete"));
        Ok(())
    }

    async fn watch_tpm_endpoint(
        &self,
        _: &ResourceRef,
    ) -> Result<ResourceRef, TpmResourceEffectError> {
        let mut process = self
            .process
            .lock()
            .map_err(|_| TpmResourceEffectError::Transient)?;
        if process
            .as_mut()
            .and_then(|child| child.try_wait().ok())
            .flatten()
            .is_some()
        {
            return Err(TpmResourceEffectError::Transient);
        }
        Ok(ResourceRef::parse("Endpoint/device-tpm").unwrap())
    }
}

impl Drop for FilesystemTpm {
    fn drop(&mut self) {
        if let Ok(mut process) = self.process.lock()
            && let Some(mut child) = process.take()
        {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[tokio::test]
async fn device_tpm_zone_activation_ready_and_state_preserving_removal() {
    let directory = tempfile::tempdir().expect("TPM state directory");
    let effects = FilesystemTpm::new(directory.path());
    let device = ResourceUid::parse("323e4567-e89b-42d3-a456-426614174002").unwrap();
    let device_ref = ResourceRef::parse("Device/work-tpm").unwrap();
    let execution = ResourceRef::parse("Host/host-system").unwrap();
    let mut controller = TpmResourceController::new(device, device_ref, execution).unwrap();

    assert_eq!(
        controller.reconcile(&effects).await.unwrap(),
        TpmResourceOutcome::Ready
    );
    assert!(directory.path().join("tpm-state").is_dir());
    assert!(controller.endpoint_ref().is_some());
    assert!(directory.path().join("flush.complete").is_file());

    assert_eq!(
        controller.finalize(&effects).await.unwrap(),
        TpmResourceOutcome::VolumeRetained
    );
    assert!(!directory.path().join("flush.complete").exists());
    assert!(directory.path().join("tpm-state").is_dir());
    assert!(directory.path().join("swtpm.stopped").is_file());
}

const CLOUD_ARTIFACT_DIGEST: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CLOUD_SCHEMA_FINGERPRINT: &str =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const CLOUD_GUEST_UID: &str = "123e4567-e89b-42d3-a456-426614174000";
const CLOUD_ZONE_UID: &str = "223e4567-e89b-42d3-a456-426614174001";

struct AcceptingCloudDescriptorVerifier;

impl GuestSetupDescriptorVerifier for AcceptingCloudDescriptorVerifier {
    fn verify(
        &self,
        _key_fingerprint: &SchemaFingerprint,
        _descriptor_digest: &SchemaFingerprint,
        signature: &str,
    ) -> bool {
        signature == "signature-sentinel"
    }
}

fn cloud_descriptor() -> d2b_provider_runtime_cloud_hypervisor::VerifiedGuestSetupDescriptor {
    GuestSetupDescriptor::new(
        ResourceRef::parse("Provider/runtime-cloud-hypervisor").unwrap(),
        ResourceGeneration::new(3).unwrap(),
        ArtifactId::parse("guest-system").unwrap(),
        ArtifactDigest::parse(CLOUD_ARTIFACT_DIGEST).unwrap(),
        GuestSeedContract::new(
            "guest-resource-seed",
            SchemaVersion::new(1, 0).unwrap(),
            SchemaFingerprint::parse(CLOUD_SCHEMA_FINGERPRINT).unwrap(),
        )
        .unwrap(),
        BootstrapHandoff::new("opaque-bootstrap", 30_000).unwrap(),
        DescriptorSignature::new(
            SignatureAlgorithm::Ed25519Blake3,
            SchemaFingerprint::parse(CLOUD_SCHEMA_FINGERPRINT).unwrap(),
            "signature-sentinel",
        )
        .unwrap(),
    )
    .unwrap()
    .verify_with(&AcceptingCloudDescriptorVerifier)
    .unwrap()
}

fn cloud_guest(
    guest_ref: ResourceRef,
    guest_uid: ResourceUid,
    generation: ResourceGeneration,
) -> GuestSnapshot {
    let evidence = GuestSessionEvidence::current_bound(
        guest_ref.clone(),
        format!("sha256:{}", "0".repeat(64)),
        Vec::<String>::new(),
        true,
        true,
        true,
        GuestSessionEvidenceBinding::new(
            guest_uid.to_canonical_string(),
            CLOUD_SCHEMA_FINGERPRINT,
            CLOUD_SCHEMA_FINGERPRINT,
            1,
            1,
            1,
            1,
            1,
            1,
        )
        .unwrap(),
    )
    .unwrap();
    GuestSnapshot::new(
        ZoneId::parse("work").unwrap(),
        ResourceUid::parse(CLOUD_ZONE_UID).unwrap(),
        guest_ref,
        guest_uid,
        generation,
        ZoneRevision::new(1),
        ResourceRef::parse("Host/host-system").unwrap(),
        ResourceRef::parse("Provider/runtime-cloud-hypervisor").unwrap(),
        Some("guest-system".to_owned()),
        GuestGenerationSet::all(generation.get()),
        false,
    )
    .unwrap()
    .with_session_evidence(evidence)
}

fn cloud_graph() -> BootstrapGraph {
    BootstrapGraph::new(
        vec![ResourceRef::parse("Device/kvm").unwrap()],
        vec![ResourceRef::parse("Network/work").unwrap()],
        vec![ResourceRef::parse("Volume/store").unwrap()],
        vec![],
    )
    .unwrap()
}

struct RealCloudHypervisorResourceSession {
    root: PathBuf,
    guest: Mutex<GuestSnapshot>,
    dependencies_ready: Mutex<bool>,
    children: Mutex<BTreeMap<ResourceRef, OwnedChildSnapshot>>,
    process: Mutex<Option<Child>>,
    lifecycle_updates: Mutex<Vec<DesiredLifecycle>>,
}

impl RealCloudHypervisorResourceSession {
    fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        fs::create_dir_all(&root).expect("create Cloud Hypervisor Resource API root");
        let guest_ref = ResourceRef::parse("Guest/workstation").unwrap();
        let guest_uid = ResourceUid::parse(CLOUD_GUEST_UID).unwrap();
        Self {
            root,
            guest: Mutex::new(cloud_guest(
                guest_ref,
                guest_uid,
                ResourceGeneration::new(1).unwrap(),
            )),
            dependencies_ready: Mutex::new(false),
            children: Mutex::new(BTreeMap::new()),
            process: Mutex::new(None),
            lifecycle_updates: Mutex::new(Vec::new()),
        }
    }

    fn set_guest(&self, resource: &Wave6Resource) -> Result<(), CloudHypervisorResourceApiError> {
        let guest = cloud_guest(
            resource.resource_ref.clone(),
            resource.uid.clone(),
            resource.generation,
        );
        *self
            .guest
            .lock()
            .map_err(|_| CloudHypervisorResourceApiError::Transport)? = guest;
        Ok(())
    }

    fn set_dependencies_ready(&self, ready: bool) -> Result<(), CloudHypervisorResourceApiError> {
        *self
            .dependencies_ready
            .lock()
            .map_err(|_| CloudHypervisorResourceApiError::Transport)? = ready;
        Ok(())
    }

    fn start_process(&self) -> Result<(), CloudHypervisorResourceApiError> {
        let mut process = self
            .process
            .lock()
            .map_err(|_| CloudHypervisorResourceApiError::Transport)?;
        if let Some(child) = process.as_mut() {
            match child
                .try_wait()
                .map_err(|_| CloudHypervisorResourceApiError::Transport)?
            {
                Some(_) => *process = None,
                None => return Ok(()),
            }
        }
        let child = Command::new("sleep")
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| CloudHypervisorResourceApiError::Transport)?;
        *process = Some(child);
        fs::write(self.root.join("process.started"), b"running")
            .map_err(|_| CloudHypervisorResourceApiError::Transport)
    }

    fn stop_process(&self) -> Result<(), CloudHypervisorResourceApiError> {
        let mut process = self
            .process
            .lock()
            .map_err(|_| CloudHypervisorResourceApiError::Transport)?;
        if let Some(mut child) = process.take() {
            if child
                .try_wait()
                .map_err(|_| CloudHypervisorResourceApiError::Transport)?
                .is_none()
            {
                child
                    .kill()
                    .and_then(|_| child.wait())
                    .map_err(|_| CloudHypervisorResourceApiError::Transport)?;
            }
        }
        fs::write(self.root.join("process.stopped"), b"stopped")
            .map_err(|_| CloudHypervisorResourceApiError::Transport)
    }

    fn process_running(&self) -> Result<bool, CloudHypervisorResourceApiError> {
        let mut process = self
            .process
            .lock()
            .map_err(|_| CloudHypervisorResourceApiError::Transport)?;
        let Some(child) = process.as_mut() else {
            return Ok(false);
        };
        if child
            .try_wait()
            .map_err(|_| CloudHypervisorResourceApiError::Transport)?
            .is_some()
        {
            *process = None;
            return Ok(false);
        }
        Ok(true)
    }

    fn remove_guest(&self) -> Result<(), CloudHypervisorResourceApiError> {
        self.stop_process()?;
        self.children
            .lock()
            .map_err(|_| CloudHypervisorResourceApiError::Transport)?
            .clear();
        fs::write(self.root.join("guest.removed"), b"removed")
            .map_err(|_| CloudHypervisorResourceApiError::Transport)
    }

    fn lifecycle_updates(&self) -> Result<Vec<DesiredLifecycle>, CloudHypervisorResourceApiError> {
        Ok(self
            .lifecycle_updates
            .lock()
            .map_err(|_| CloudHypervisorResourceApiError::Transport)?
            .clone())
    }
}

#[async_trait]
impl AuthenticatedResourceSession for RealCloudHypervisorResourceSession {
    async fn call(
        &self,
        request: CloudHypervisorResourceRequest,
    ) -> Result<CloudHypervisorResourceResponse, CloudHypervisorResourceApiError> {
        match request {
            CloudHypervisorResourceRequest::Register { .. } => {
                fs::write(self.root.join("registered"), b"registered")
                    .map_err(|_| CloudHypervisorResourceApiError::Transport)?;
                Ok(CloudHypervisorResourceResponse::Registered)
            }
            CloudHypervisorResourceRequest::GetGuest { .. } => {
                Ok(CloudHypervisorResourceResponse::Guest(
                    self.guest
                        .lock()
                        .map_err(|_| CloudHypervisorResourceApiError::Transport)?
                        .clone(),
                ))
            }
            CloudHypervisorResourceRequest::RelistOwnedChildren { expected_refs, .. } => {
                let ready = *self
                    .dependencies_ready
                    .lock()
                    .map_err(|_| CloudHypervisorResourceApiError::Transport)?;
                let has_process = {
                    let mut children = self
                        .children
                        .lock()
                        .map_err(|_| CloudHypervisorResourceApiError::Transport)?;
                    if ready {
                        for child in children.values_mut() {
                            if child.resource_ref().resource_type().as_str() == "Process" {
                                *child = child
                                    .clone()
                                    .with_desired_lifecycle(DesiredLifecycle::Running);
                            }
                        }
                    }
                    children
                        .values()
                        .any(|child| child.resource_ref().resource_type().as_str() == "Process")
                };
                if ready && has_process {
                    self.start_process()?;
                }
                let children = self
                    .children
                    .lock()
                    .map_err(|_| CloudHypervisorResourceApiError::Transport)?;
                Ok(CloudHypervisorResourceResponse::OwnedChildren(
                    expected_refs
                        .iter()
                        .filter_map(|resource_ref| children.get(resource_ref).cloned())
                        .collect(),
                ))
            }
            CloudHypervisorResourceRequest::ObserveDependencies { graph, .. } => {
                let ready = *self
                    .dependencies_ready
                    .lock()
                    .map_err(|_| CloudHypervisorResourceApiError::Transport)?;
                let snapshot = if ready {
                    d2b_provider_runtime_cloud_hypervisor::GuestDependencySnapshot::ready(graph)
                } else {
                    d2b_provider_runtime_cloud_hypervisor::GuestDependencySnapshot::new(
                        graph
                            .devices
                            .iter()
                            .cloned()
                            .map(|resource_ref| (resource_ref, ResourcePhase::Pending))
                            .collect(),
                        graph
                            .networks
                            .iter()
                            .cloned()
                            .map(|resource_ref| (resource_ref, ResourcePhase::Pending))
                            .collect(),
                        graph
                            .volumes
                            .iter()
                            .cloned()
                            .map(|resource_ref| (resource_ref, ResourcePhase::Pending))
                            .collect(),
                        false,
                        false,
                    )
                    .map_err(|_| CloudHypervisorResourceApiError::InvalidResponse)?
                };
                Ok(CloudHypervisorResourceResponse::Dependencies(snapshot))
            }
            CloudHypervisorResourceRequest::CommitBatch { batch } => {
                let ready = *self
                    .dependencies_ready
                    .lock()
                    .map_err(|_| CloudHypervisorResourceApiError::Transport)?;
                let mut committed = Vec::with_capacity(batch.mutations().len());
                let mut children = self
                    .children
                    .lock()
                    .map_err(|_| CloudHypervisorResourceApiError::Transport)?;
                for (index, mutation) in batch.mutations().iter().enumerate() {
                    let uid =
                        ResourceUid::parse(format!("323e4567-e89b-42d3-a456-42661417{index:04}"))
                            .map_err(|_| CloudHypervisorResourceApiError::InvalidResponse)?;
                    let desired_lifecycle = (mutation.target().resource_type().as_str()
                        == "Process")
                        .then_some(if ready {
                            DesiredLifecycle::Running
                        } else {
                            DesiredLifecycle::Stopped
                        });
                    let child = OwnedChildSnapshot::new(
                        mutation.target().clone(),
                        batch.zone().clone(),
                        batch.owner_ref().clone(),
                        uid.clone(),
                        ResourceGeneration::new(1)
                            .map_err(|_| CloudHypervisorResourceApiError::InvalidResponse)?,
                        batch.owner_revision(),
                        batch
                            .desired_digest(mutation.target())
                            .map_err(|_| CloudHypervisorResourceApiError::InvalidResponse)?,
                        ResourcePhase::Ready,
                        desired_lifecycle,
                        true,
                    )
                    .map_err(|_| CloudHypervisorResourceApiError::InvalidResponse)?
                    .with_owner_uid(batch.owner_uid().clone());
                    children.insert(mutation.target().clone(), child);
                    committed.push(
                        CommittedChild::new(
                            mutation.target().clone(),
                            batch.owner_ref().clone(),
                            batch.zone().clone(),
                            uid,
                            batch.owner_revision(),
                        )
                        .map_err(|_| CloudHypervisorResourceApiError::InvalidResponse)?,
                    );
                }
                drop(children);
                if ready {
                    self.start_process()?;
                }
                Ok(CloudHypervisorResourceResponse::Committed(
                    GuestChildCommitResponse::Committed(committed),
                ))
            }
            CloudHypervisorResourceRequest::UpdateSpec { update } => {
                let target = update.target().clone();
                let current = self
                    .children
                    .lock()
                    .map_err(|_| CloudHypervisorResourceApiError::Transport)?
                    .get(&target)
                    .cloned()
                    .ok_or(CloudHypervisorResourceApiError::NotFound)?;
                if current.uid() != update.expected_uid()
                    || current.revision() != update.expected_revision()
                {
                    return Err(CloudHypervisorResourceApiError::Conflict);
                }
                let desired_lifecycle = if target.resource_type().as_str() == "Process" {
                    update.desired_lifecycle()
                } else {
                    None
                };
                if let Some(desired_lifecycle) = desired_lifecycle {
                    self.lifecycle_updates
                        .lock()
                        .map_err(|_| CloudHypervisorResourceApiError::Transport)?
                        .push(desired_lifecycle);
                }
                match desired_lifecycle {
                    Some(DesiredLifecycle::Running) => self.start_process()?,
                    Some(DesiredLifecycle::Stopped) => self.stop_process()?,
                    None => {}
                }
                let revision =
                    ZoneRevision::new(update.expected_revision().get().saturating_add(1));
                let updated = OwnedChildSnapshot::new(
                    current.resource_ref().clone(),
                    current.zone().clone(),
                    current.owner_ref().clone(),
                    current.uid().clone(),
                    current.generation(),
                    revision,
                    current.spec_digest().to_owned(),
                    current.phase(),
                    desired_lifecycle.or(current.desired_lifecycle()),
                    current.healthy(),
                )
                .map_err(|_| CloudHypervisorResourceApiError::InvalidResponse)?
                .with_owner_uid(
                    current
                        .owner_uid()
                        .cloned()
                        .ok_or(CloudHypervisorResourceApiError::InvalidResponse)?,
                );
                self.children
                    .lock()
                    .map_err(|_| CloudHypervisorResourceApiError::Transport)?
                    .insert(target.clone(), updated);
                Ok(CloudHypervisorResourceResponse::Updated(
                    CommittedChild::new(
                        target,
                        current.owner_ref().clone(),
                        current.zone().clone(),
                        current.uid().clone(),
                        revision,
                    )
                    .map_err(|_| CloudHypervisorResourceApiError::InvalidResponse)?,
                ))
            }
            CloudHypervisorResourceRequest::UpdateStatus { status, .. } => {
                fs::write(
                    self.root.join("status.json"),
                    serde_json::to_vec(status.status())
                        .map_err(|_| CloudHypervisorResourceApiError::InvalidResponse)?,
                )
                .map_err(|_| CloudHypervisorResourceApiError::Transport)?;
                Ok(CloudHypervisorResourceResponse::StatusUpdated)
            }
            CloudHypervisorResourceRequest::ObserveProcessAdoption { .. } => {
                Ok(CloudHypervisorResourceResponse::ProcessAdoption(
                    d2b_provider_runtime_cloud_hypervisor::ProcessAdoptionStatus::Current,
                ))
            }
            CloudHypervisorResourceRequest::AssessUpdate { .. } => {
                Ok(CloudHypervisorResourceResponse::UpdateAssessment(None))
            }
            CloudHypervisorResourceRequest::ObserveFinalization { .. } => {
                Err(CloudHypervisorResourceApiError::InvalidResponse)
            }
            CloudHypervisorResourceRequest::DrainGuestLocal { .. }
            | CloudHypervisorResourceRequest::CloseGuestSession { .. }
            | CloudHypervisorResourceRequest::DeleteChild { .. }
            | CloudHypervisorResourceRequest::InvalidateGuestSession { .. }
            | CloudHypervisorResourceRequest::EnsureGuestFinalizer { .. }
            | CloudHypervisorResourceRequest::ClearGuestFinalizer { .. } => {
                Ok(CloudHypervisorResourceResponse::LifecycleApplied)
            }
        }
    }
}

impl Drop for RealCloudHypervisorResourceSession {
    fn drop(&mut self) {
        if let Ok(mut process) = self.process.lock()
            && let Some(mut child) = process.take()
        {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

type CloudController =
    CloudHypervisorController<AuthenticatedResourceApiAdapter<RealCloudHypervisorResourceSession>>;

fn cloud_controller(session: Arc<RealCloudHypervisorResourceSession>) -> CloudController {
    let config = CloudHypervisorConfig {
        controller_execution_ref: ResourceRef::parse("Host/host-system").unwrap(),
        default_vcpus: 2,
        default_memory_mb: 512,
        default_machine_type: d2b_contracts_provider::v3::credential::OpaqueAzureRef::parse("q35")
            .unwrap(),
        watchdog: true,
        adoption_window_ms: 30_000,
        health_check_interval_ms: 30_000,
        health_check_timeout_ms: 5_000,
        health_check_failure_threshold: 3,
        startup_deadline_ms: 30_000,
    };
    let api = AuthenticatedResourceApiAdapter::new(session);
    CloudHypervisorController::from_verified_descriptor(
        config,
        cloud_graph(),
        cloud_descriptor(),
        Arc::new(api),
    )
    .unwrap()
}

#[tokio::test]
async fn cloud_hypervisor_zone_waits_dependencies_reaches_ready_and_adopts_process() {
    let directory = tempfile::tempdir().expect("Cloud Hypervisor Resource API state directory");
    let session = Arc::new(RealCloudHypervisorResourceSession::new(directory.path()));
    let mut controller = cloud_controller(Arc::clone(&session));
    controller.register().await.unwrap();

    session.set_dependencies_ready(false).unwrap();
    let pending = controller
        .reconcile(&ResourceRef::parse("Guest/workstation").unwrap())
        .await
        .unwrap();
    assert_eq!(pending.status().status().phase, GuestStatusPhase::Pending);
    assert!(
        pending.is_pending(),
        "unexpected dependency-gated outcome: {pending:?}"
    );
    assert!(
        session.lifecycle_updates().unwrap().is_empty(),
        "dependency-pending reconcile must not force the VMM Process Running"
    );

    session.set_dependencies_ready(true).unwrap();
    let ready = controller
        .reconcile(&ResourceRef::parse("Guest/workstation").unwrap())
        .await
        .unwrap();
    assert_eq!(ready.status().status().phase, GuestStatusPhase::Ready);
    assert!(matches!(ready, CloudHypervisorReconcileOutcome::Ready(_)));
    assert!(session.process_running().unwrap());
    drop(controller);

    let mut restarted = cloud_controller(Arc::clone(&session));
    restarted.register().await.unwrap();
    let adopted = restarted
        .reconcile(&ResourceRef::parse("Guest/workstation").unwrap())
        .await
        .unwrap();
    assert_eq!(adopted.status().status().phase, GuestStatusPhase::Ready);
    assert!(matches!(adopted, CloudHypervisorReconcileOutcome::Ready(_)));
    assert!(session.process_running().unwrap());
    session.remove_guest().unwrap();
    assert!(!session.process_running().unwrap());
}

/// Shared Resource API boundary used by the daemon-level operator acceptance.
///
/// The boundary deliberately owns filesystem and child-process effects behind
/// the authenticated Resource API and reconstructs controller state during
/// `adopt_after_restart`; it is not a call-recording test double.
pub struct Wave6RealBoundary {
    root: PathBuf,
    volume: FilesystemVolume,
    network: FilesystemNetworkBoundary,
    tpm: FilesystemTpm,
    tpm_controller: Mutex<Option<TpmResourceController>>,
    cloud_session: Arc<RealCloudHypervisorResourceSession>,
    guest_sessionler: Mutex<Option<CloudController>>,
}

impl Wave6RealBoundary {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        fs::create_dir_all(&root).expect("create Wave 6 provider effect root");
        Self {
            volume: FilesystemVolume::new(root.join("volume")),
            network: FilesystemNetworkBoundary::new(root.join("network")),
            tpm: FilesystemTpm::new(root.join("tpm")),
            tpm_controller: Mutex::new(None),
            cloud_session: Arc::new(RealCloudHypervisorResourceSession::new(
                root.join("cloud-hypervisor"),
            )),
            guest_sessionler: Mutex::new(None),
            root,
        }
    }

    fn tpm_controller() -> Result<TpmResourceController, Wave6BoundaryError> {
        TpmResourceController::new(
            ResourceUid::parse("323e4567-e89b-42d3-a456-426614174002")
                .map_err(|_| Wave6BoundaryError::Effect)?,
            ResourceRef::parse("Device/work-tpm").map_err(|_| Wave6BoundaryError::Effect)?,
            ResourceRef::parse("Host/host-system").map_err(|_| Wave6BoundaryError::Effect)?,
        )
        .map_err(|_| Wave6BoundaryError::Effect)
    }

    fn guest_sessionler(&self) -> CloudController {
        cloud_controller(Arc::clone(&self.cloud_session))
    }

    fn ready_network_input(&self, dependencies: Wave6Dependencies) -> ReconcileInput {
        network_input(
            network_spec(),
            dependencies.volume_ready,
            dependencies.guest_ready,
            dependencies.attachment_ready,
        )
    }
}

#[async_trait]
impl Wave6ProviderBoundary for Wave6RealBoundary {
    async fn reconcile_volume(
        &self,
        resource: &Wave6Resource,
    ) -> Result<Wave6ReconcileResult, Wave6BoundaryError> {
        let controller =
            VolumeLocalController::new(VolumeLocalProfile::shipped(), &self.volume, &self.volume);
        controller
            .reconcile(&resource.uid, &volume_spec(), None, None)
            .await
            .map_err(|_| Wave6BoundaryError::Effect)?;
        Ok(Wave6ReconcileResult::Ready)
    }

    async fn reconcile_network(
        &self,
        _resource: &Wave6Resource,
        dependencies: Wave6Dependencies,
    ) -> Result<Wave6ReconcileResult, Wave6BoundaryError> {
        let reconciler = NetworkReconciler::new(&self.network, &self.network);
        match reconciler
            .reconcile(&self.ready_network_input(dependencies))
            .await
            .map_err(|_| Wave6BoundaryError::Effect)?
        {
            ReconcileProgress::Pending(_) => Ok(Wave6ReconcileResult::Waiting),
            ReconcileProgress::Requeue(_) => Ok(Wave6ReconcileResult::Waiting),
            ReconcileProgress::Ready => Ok(Wave6ReconcileResult::Ready),
            ReconcileProgress::Blocked(_) => Err(Wave6BoundaryError::Lifecycle),
        }
    }

    async fn reconcile_device_tpm(
        &self,
        _resource: &Wave6Resource,
    ) -> Result<Wave6ReconcileResult, Wave6BoundaryError> {
        let mut controller = self
            .tpm_controller
            .lock()
            .map_err(|_| Wave6BoundaryError::Effect)?
            .take()
            .unwrap_or(Self::tpm_controller()?);
        let result = controller
            .reconcile(&self.tpm)
            .await
            .map_err(|_| Wave6BoundaryError::Effect);
        self.tpm_controller
            .lock()
            .map_err(|_| Wave6BoundaryError::Effect)?
            .replace(controller);
        result?;
        Ok(Wave6ReconcileResult::Ready)
    }

    async fn reconcile_cloud_hypervisor_guest(
        &self,
        resource: &Wave6Resource,
        dependencies: Wave6Dependencies,
    ) -> Result<Wave6ReconcileResult, Wave6BoundaryError> {
        self.cloud_session
            .set_guest(resource)
            .map_err(|_| Wave6BoundaryError::Effect)?;
        self.cloud_session
            .set_dependencies_ready(dependencies.network_ready)
            .map_err(|_| Wave6BoundaryError::Effect)?;
        let mut controller = self
            .guest_sessionler
            .lock()
            .map_err(|_| Wave6BoundaryError::Effect)?
            .take()
            .unwrap_or_else(|| self.guest_sessionler());
        controller
            .register()
            .await
            .map_err(|_| Wave6BoundaryError::Effect)?;
        let outcome = controller
            .reconcile(&resource.resource_ref)
            .await
            .map_err(|_| Wave6BoundaryError::Effect)?;
        self.guest_sessionler
            .lock()
            .map_err(|_| Wave6BoundaryError::Effect)?
            .replace(controller);
        match outcome {
            CloudHypervisorReconcileOutcome::Pending(_)
            | CloudHypervisorReconcileOutcome::RelistRequired(_) => {
                Ok(Wave6ReconcileResult::Waiting)
            }
            CloudHypervisorReconcileOutcome::Ready(status)
                if status.status().phase == GuestStatusPhase::Ready =>
            {
                Ok(Wave6ReconcileResult::Ready)
            }
            CloudHypervisorReconcileOutcome::Ready(_)
            | CloudHypervisorReconcileOutcome::Degraded(_) => Err(Wave6BoundaryError::Lifecycle),
        }
    }

    async fn adopt_after_restart(
        &self,
        resources: &Wave6ResourceSet,
    ) -> Result<(), Wave6BoundaryError> {
        let volume =
            VolumeLocalController::new(VolumeLocalProfile::shipped(), &self.volume, &self.volume);
        volume
            .reconcile(&resources.volume.uid, &volume_spec(), None, None)
            .await
            .map_err(|_| Wave6BoundaryError::Effect)?;

        let network = NetworkReconciler::new(&self.network, &self.network);
        let network_result = network
            .reconcile(&self.ready_network_input(Wave6Dependencies::guest_ready_for_adoption()))
            .await
            .map_err(|_| Wave6BoundaryError::Effect)?;
        if !matches!(network_result, ReconcileProgress::Ready) {
            return Err(Wave6BoundaryError::Lifecycle);
        }

        let mut tpm_controller = Self::tpm_controller()?;
        tpm_controller
            .reconcile(&self.tpm)
            .await
            .map_err(|_| Wave6BoundaryError::Effect)?;
        self.tpm_controller
            .lock()
            .map_err(|_| Wave6BoundaryError::Effect)?
            .replace(tpm_controller);

        self.cloud_session
            .set_guest(&resources.cloud_hypervisor_guest)
            .map_err(|_| Wave6BoundaryError::Effect)?;
        self.cloud_session
            .set_dependencies_ready(true)
            .map_err(|_| Wave6BoundaryError::Effect)?;
        self.guest_sessionler
            .lock()
            .map_err(|_| Wave6BoundaryError::Effect)?
            .take()
            .ok_or(Wave6BoundaryError::Lifecycle)?;
        let mut restarted = self.guest_sessionler();
        restarted
            .register()
            .await
            .map_err(|_| Wave6BoundaryError::Effect)?;
        let outcome = restarted
            .reconcile(&resources.cloud_hypervisor_guest.resource_ref)
            .await
            .map_err(|_| Wave6BoundaryError::Effect)?;
        if !matches!(
            outcome,
            CloudHypervisorReconcileOutcome::Ready(status)
                if status.status().phase == GuestStatusPhase::Ready
        ) || !self
            .cloud_session
            .process_running()
            .map_err(|_| Wave6BoundaryError::Effect)?
        {
            return Err(Wave6BoundaryError::Lifecycle);
        }
        *self
            .guest_sessionler
            .lock()
            .map_err(|_| Wave6BoundaryError::Effect)? = Some(restarted);
        Ok(())
    }

    async fn remove_cloud_hypervisor_guest(
        &self,
        _resource: &Wave6Resource,
    ) -> Result<(), Wave6BoundaryError> {
        self.guest_sessionler
            .lock()
            .map_err(|_| Wave6BoundaryError::Effect)?
            .take()
            .ok_or(Wave6BoundaryError::Lifecycle)?;
        self.cloud_session
            .remove_guest()
            .map_err(|_| Wave6BoundaryError::Effect)?;
        if self
            .cloud_session
            .process_running()
            .map_err(|_| Wave6BoundaryError::Effect)?
            || !self
                .cloud_session
                .children
                .lock()
                .map_err(|_| Wave6BoundaryError::Effect)?
                .is_empty()
        {
            return Err(Wave6BoundaryError::Lifecycle);
        }
        Ok(())
    }

    async fn remove_network(&self, _resource: &Wave6Resource) -> Result<(), Wave6BoundaryError> {
        let reconciler = NetworkReconciler::new(&self.network, &self.network);
        let mut input = self.ready_network_input(Wave6Dependencies::guest_ready_for_adoption());
        input.agent_deleted = false;
        input.mdns_deleted = false;
        input.volume_attachment_removed = false;
        input.guest_deleted = false;
        input.volume_deleted = false;
        if !matches!(
            reconciler
                .finalize(&input)
                .await
                .map_err(|_| Wave6BoundaryError::Effect)?,
            FinalizerStage::Processes
        ) {
            return Err(Wave6BoundaryError::Lifecycle);
        }
        input.agent_deleted = true;
        input.mdns_deleted = true;
        if !matches!(
            reconciler
                .finalize(&input)
                .await
                .map_err(|_| Wave6BoundaryError::Effect)?,
            FinalizerStage::VolumeAttachment
        ) {
            return Err(Wave6BoundaryError::Lifecycle);
        }
        input.volume_attachment_removed = true;
        if !matches!(
            reconciler
                .finalize(&input)
                .await
                .map_err(|_| Wave6BoundaryError::Effect)?,
            FinalizerStage::Guest
        ) {
            return Err(Wave6BoundaryError::Lifecycle);
        }
        input.guest_deleted = true;
        if !matches!(
            reconciler
                .finalize(&input)
                .await
                .map_err(|_| Wave6BoundaryError::Effect)?,
            FinalizerStage::Volume
        ) {
            return Err(Wave6BoundaryError::Lifecycle);
        }
        input.volume_deleted = true;
        if !matches!(
            reconciler
                .finalize(&input)
                .await
                .map_err(|_| Wave6BoundaryError::Effect)?,
            FinalizerStage::Complete
        ) {
            return Err(Wave6BoundaryError::Lifecycle);
        }
        Ok(())
    }

    async fn remove_device_tpm(
        &self,
        _resource: &Wave6Resource,
    ) -> Result<bool, Wave6BoundaryError> {
        let mut controller = self
            .tpm_controller
            .lock()
            .map_err(|_| Wave6BoundaryError::Effect)?
            .take()
            .ok_or(Wave6BoundaryError::Lifecycle)?;
        let outcome = controller
            .finalize(&self.tpm)
            .await
            .map_err(|_| Wave6BoundaryError::Effect)?;
        if !matches!(outcome, TpmResourceOutcome::VolumeRetained)
            || !self.root.join("tpm/tpm-state").is_dir()
        {
            return Err(Wave6BoundaryError::DeviceStateNotRetained);
        }
        Ok(true)
    }

    async fn remove_volume(&self, resource: &Wave6Resource) -> Result<(), Wave6BoundaryError> {
        let controller =
            VolumeLocalController::new(VolumeLocalProfile::shipped(), &self.volume, &self.volume);
        controller
            .cleanup(&resource.uid, &volume_spec())
            .await
            .map_err(|_| Wave6BoundaryError::Effect)?;
        if self.root.join("volume/state.db").exists() {
            return Err(Wave6BoundaryError::Lifecycle);
        }
        Ok(())
    }
}

fn u4_controller_descriptor() -> ComponentDescriptor {
    let digest = ArtifactDigest::parse(format!("sha256:{}", "a".repeat(64))).unwrap();
    ComponentDescriptor::new(
        BoundedToken::parse("process-controller").unwrap(),
        ComponentType::Controller,
        [ResourceTypeName::parse("Process").unwrap()],
        [BoundedToken::parse("reconcile").unwrap()],
        [d2b_contracts_resource::v3::execution_policy::ExecutionDomain::System],
        8,
        digest.clone(),
        [],
        false,
    )
    .unwrap()
    .with_execution(ComponentExecution::Launchable {
        binary_ref: BinaryRef::parse("process-controller").unwrap(),
    })
    .with_controller_placement(
        ControllerInstanceScope::PerResourceTarget,
        [ControllerTargetKind::Host, ControllerTargetKind::Guest],
    )
    .unwrap()
    .with_target_capabilities([
        ComponentTargetCapability::new(
            ControllerTargetKind::Host,
            digest.clone(),
            [EffectPortClass::Process],
        )
        .unwrap(),
        ComponentTargetCapability::new(
            ControllerTargetKind::Guest,
            digest,
            [EffectPortClass::Process],
        )
        .unwrap(),
    ])
    .unwrap()
}

#[test]
fn controller_process_acceptance_fences_assignment_and_cleanup() {
    let deployment =
        ProviderDeployment::new(DaemonMode::Guest, AdmissionLimits::guest_default()).unwrap();
    let provider = ResourceRef::parse("Provider/runtime").unwrap();
    let target = ResourceRef::parse("Guest/workload").unwrap();
    let process = deployment
        .create_controller_process(
            ZoneId::parse("work").unwrap(),
            provider.clone(),
            &u4_controller_descriptor(),
            ResourceGeneration::new(1).unwrap(),
            ResourceGeneration::new(2).unwrap(),
            ControllerGeneration::new(3).unwrap(),
            ReconnectGeneration::new(4).unwrap(),
            ZoneRevision::new(5),
            target.clone(),
            ResourceRef::parse("Provider/system-systemd").unwrap(),
            true,
        )
        .unwrap();
    assert_eq!(
        process.process_spec().execution().process_class(),
        ProcessClass::Controller
    );
    assert_eq!(
        process.finalizer(),
        "provider-controller.d2bus.org/children"
    );
    assert!(
        process
            .owned_resource_types()
            .contains(&ResourceTypeName::parse("Process").expect("Process type"))
    );

    let readiness = SchemaFingerprint::parse(format!("sha256:{}", "b".repeat(64))).unwrap();
    deployment
        .begin_controller_launch(process.process_ref(), readiness.clone())
        .unwrap();
    assert!(matches!(
        deployment.admit_controller_assignment(ControllerAssignmentRequest::new(
            process.process_ref().clone(),
            ResourceRef::parse("Process/child").unwrap(),
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap(),
            ResourceGeneration::new(1).unwrap(),
            ZoneRevision::new(6),
            provider.clone(),
            target.clone(),
            ReconnectGeneration::new(7).unwrap(),
        )),
        Err(d2bd_runtime::target_runtime::DeploymentError::ControllerNotReady)
    ));
    deployment
        .controller_launch_succeeded(process.process_ref(), [1; 32])
        .unwrap();
    let session = deployment
        .admit_controller_session(ControllerSessionBinding::new(
            process.process_ref().clone(),
            process.zone().clone(),
            provider.clone(),
            target.clone(),
            process.provider_generation(),
            process.controller_generation(),
            process.target_session_generation(),
            ReconnectGeneration::new(7).unwrap(),
            readiness,
        ))
        .unwrap();
    let assignment = deployment
        .admit_controller_assignment(ControllerAssignmentRequest::new(
            process.process_ref().clone(),
            ResourceRef::parse("Process/child").unwrap(),
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap(),
            ResourceGeneration::new(1).unwrap(),
            ZoneRevision::new(6),
            provider,
            target,
            session.generation(),
        ))
        .unwrap();
    assert!(assignment.is_active());
    assert!(
        assignment
            .resource_types()
            .contains(&ResourceTypeName::parse("Process").expect("Process type"))
    );
    assert!(assignment.allows(ControllerResourceVerb::UpdateStatus));
    assert!(assignment.allows(ControllerResourceVerb::Watch));
    drop(session);
    assert!(!assignment.is_active());
    assert_eq!(
        deployment.controller_phase(process.process_ref()),
        Some(ControllerProcessPhase::Revoked)
    );

    deployment
        .record_controller_child(
            process.process_ref(),
            ResourceRef::parse("Process/child").unwrap(),
            ResourceUid::parse("223e4567-e89b-42d3-a456-426614174001").unwrap(),
        )
        .unwrap();
    let child_uid = ResourceUid::parse("223e4567-e89b-42d3-a456-426614174001").unwrap();
    deployment
        .adopt_controller_children(
            process.process_ref(),
            [ControllerChildObservation::verified(
                ResourceRef::parse("Process/child").unwrap(),
                child_uid.clone(),
            )],
        )
        .unwrap();
    deployment
        .remove_controller_child(
            process.process_ref(),
            ResourceRef::parse("Process/child").unwrap(),
            &child_uid,
        )
        .unwrap();
    deployment
        .prepare_controller_cleanup(process.process_ref(), process.process_ref())
        .unwrap();
    assert!(
        deployment
            .controller_finalizer_held(process.process_ref())
            .unwrap()
    );
    deployment
        .complete_controller_cleanup(process.process_ref(), process.process_ref())
        .unwrap();
    assert!(
        !deployment
            .controller_finalizer_held(process.process_ref())
            .unwrap()
    );
}

#[test]
fn host_and_guest_sessionler_process_resources_keep_one_process_shape() {
    let descriptor = u4_controller_descriptor();
    let host_deployment =
        ProviderDeployment::new(DaemonMode::Host, AdmissionLimits::host_default()).unwrap();
    let guest_deployment =
        ProviderDeployment::new(DaemonMode::Guest, AdmissionLimits::guest_default()).unwrap();
    let provider = ResourceRef::parse("Provider/runtime").unwrap();
    let process_provider = ResourceRef::parse("Provider/system-systemd").unwrap();
    let host = host_deployment
        .create_controller_process(
            ZoneId::parse("work").unwrap(),
            provider.clone(),
            &descriptor,
            ResourceGeneration::new(1).unwrap(),
            ResourceGeneration::new(2).unwrap(),
            ControllerGeneration::new(3).unwrap(),
            ReconnectGeneration::new(4).unwrap(),
            ZoneRevision::new(5),
            ResourceRef::parse("Host/host-system").unwrap(),
            process_provider.clone(),
            true,
        )
        .unwrap();
    let guest = guest_deployment
        .create_controller_process(
            ZoneId::parse("work").unwrap(),
            provider,
            &descriptor,
            ResourceGeneration::new(1).unwrap(),
            ResourceGeneration::new(2).unwrap(),
            ControllerGeneration::new(3).unwrap(),
            ReconnectGeneration::new(4).unwrap(),
            ZoneRevision::new(5),
            ResourceRef::parse("Guest/workload").unwrap(),
            process_provider,
            true,
        )
        .unwrap();
    assert_ne!(host.process_ref(), guest.process_ref());
    assert_eq!(
        host.process_spec().execution().process_class(),
        guest.process_spec().execution().process_class()
    );
    assert_eq!(host.process_provider_ref(), guest.process_provider_ref());
    assert_eq!(
        host.required_effect_classes(),
        guest.required_effect_classes()
    );
}
