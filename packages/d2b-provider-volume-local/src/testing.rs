//! Shared test doubles and fixtures for the volume-local conformance
//! suite.
//!
//! Every double is hermetic: the suite asserts the layout, view,
//! sharing, marker, and ACL obligations without a filesystem, a broker
//! socket, a privileged host, or a real Volume root.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::pin;
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};

use d2b_contracts_resource::v3::ResourceUid;
use d2b_contracts_resource::v3::execution_policy::BoundedToken;
use d2b_contracts_resource::v3::volume::SourceKind;

use crate::error::VolumeLocalError;
use crate::identity::{EntryDigest, MarkerState, OwnerProof, VolumeRootHandle};
use crate::layout::EntryRequest;
use crate::port::{
    DriftClass, ObservedEntry, QuotaCapability, VolumeLayoutEffectPort, VolumeSourceEffectPort,
};

/// Drive a future to completion on the calling thread.
///
/// The suite never waits on I/O or wall time, so a single-threaded
/// driver keeps the crate free of an async runtime dependency.
pub fn block_on<F: Future>(future: F) -> F::Output {
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

/// One recorded effect-port call.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PortCall {
    /// The source policy ID was resolved.
    ResolveRoot,
    /// The provisioning marker was read.
    Marker,
    /// One entry was observed.
    Observe(EntryDigest),
    /// One entry was created.
    Provision(EntryDigest),
    /// One entry was repaired.
    Repair(EntryDigest),
    /// The declared ACLs of one entry were re-applied.
    ApplyAcl(EntryDigest),
    /// One entry was removed.
    Cleanup(EntryDigest),
}

/// A scripted, recording pair of volume-local effect ports.
#[derive(Debug)]
pub struct ScriptedPort {
    observations: BTreeMap<String, ObservedEntry>,
    default_observation: ObservedEntry,
    marker: MarkerState,
    quota: QuotaCapability,
    resolve_error: Option<VolumeLocalError>,
    calls: Mutex<Vec<PortCall>>,
}

impl ScriptedPort {
    /// A port where every declared entry is absent.
    pub fn empty() -> Self {
        Self {
            observations: BTreeMap::new(),
            default_observation: ObservedEntry::absent(),
            marker: MarkerState::NeverProvisioned,
            quota: QuotaCapability::Enforceable,
            resolve_error: None,
            calls: Mutex::new(Vec::new()),
        }
    }

    /// A port where every declared entry already exists and conforms.
    pub fn converged() -> Self {
        Self {
            default_observation: ObservedEntry::conformant(OwnerProof::NotApplicable),
            ..Self::empty()
        }
    }

    /// Script one entry's observation by its anchored path.
    pub fn with_observation(mut self, path: &str, observed: ObservedEntry) -> Self {
        self.observations.insert(path.to_owned(), observed);
        self
    }

    /// Script the provisioning marker.
    pub const fn with_marker(mut self, marker: MarkerState) -> Self {
        self.marker = marker;
        self
    }

    /// Script the backing filesystem's quota capability.
    pub const fn with_quota(mut self, quota: QuotaCapability) -> Self {
        self.quota = quota;
        self
    }

    /// Script a failing source resolution.
    pub const fn with_resolve_error(mut self, error: VolumeLocalError) -> Self {
        self.resolve_error = Some(error);
        self
    }

    /// Return every recorded call in order.
    pub fn calls(&self) -> Vec<PortCall> {
        self.calls
            .lock()
            .map(|calls| calls.clone())
            .unwrap_or_default()
    }

    fn record(&self, call: PortCall) {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push(call);
        }
    }

    fn observation(&self, entry: &EntryRequest) -> ObservedEntry {
        self.observations
            .get(entry.declared().path())
            .cloned()
            .unwrap_or_else(|| self.default_observation.clone())
    }
}

impl VolumeSourceEffectPort for &ScriptedPort {
    async fn resolve_root(
        &self,
        _source_policy_id: Option<&BoundedToken>,
        _system_artifact_id: Option<&BoundedToken>,
        _kind: SourceKind,
    ) -> Result<VolumeRootHandle, VolumeLocalError> {
        self.record(PortCall::ResolveRoot);
        match self.resolve_error {
            Some(error) => Err(error),
            None => Ok(VolumeRootHandle::held()),
        }
    }

    async fn quota_capability(
        &self,
        _root: &VolumeRootHandle,
    ) -> Result<QuotaCapability, VolumeLocalError> {
        Ok(self.quota)
    }
}

impl VolumeLayoutEffectPort for &ScriptedPort {
    async fn observe(
        &self,
        _root: &VolumeRootHandle,
        entry: &EntryRequest,
    ) -> Result<ObservedEntry, VolumeLocalError> {
        self.record(PortCall::Observe(entry.digest()));
        Ok(self.observation(entry))
    }

    async fn provision(
        &self,
        _root: &VolumeRootHandle,
        entry: &EntryRequest,
    ) -> Result<(), VolumeLocalError> {
        self.record(PortCall::Provision(entry.digest()));
        Ok(())
    }

    async fn repair(
        &self,
        _root: &VolumeRootHandle,
        entry: &EntryRequest,
        _drift: &std::collections::BTreeSet<DriftClass>,
    ) -> Result<(), VolumeLocalError> {
        self.record(PortCall::Repair(entry.digest()));
        Ok(())
    }

    async fn apply_acl(
        &self,
        _root: &VolumeRootHandle,
        entry: &EntryRequest,
    ) -> Result<(), VolumeLocalError> {
        self.record(PortCall::ApplyAcl(entry.digest()));
        Ok(())
    }

    async fn cleanup(
        &self,
        _root: &VolumeRootHandle,
        entry: &EntryRequest,
    ) -> Result<(), VolumeLocalError> {
        self.record(PortCall::Cleanup(entry.digest()));
        Ok(())
    }

    async fn marker_state(
        &self,
        _root: &VolumeRootHandle,
    ) -> Result<MarkerState, VolumeLocalError> {
        self.record(PortCall::Marker);
        Ok(self.marker)
    }

    async fn materialize_network_config(
        &self,
        _root: &VolumeRootHandle,
        _projection: &crate::NetworkConfigContentProjection,
    ) -> Result<crate::NetworkConfigMaterializationEvidence, VolumeLocalError> {
        Err(VolumeLocalError::EffectFailed)
    }
}

/// Canonical Volume fixtures.
pub mod fixtures {
    use d2b_contracts_resource::v3::execution_policy::BoundedToken;
    use d2b_contracts_resource::v3::volume::VolumeSpec;
    use serde_json::{Value, json};

    use super::ResourceUid;

    /// A stable Volume UID.
    pub fn volume_uid() -> ResourceUid {
        ResourceUid::parse("6f9619ff-8b86-4d01-b42d-00cf4fc964ff").expect("valid fixture uid")
    }

    /// The Guest name every Guest-scoped fixture uses.
    pub fn guest() -> BoundedToken {
        BoundedToken::parse("work-vm").expect("valid fixture token")
    }

    fn parse(spec: Value) -> VolumeSpec {
        serde_json::from_value(spec).expect("conformant fixture Volume spec")
    }

    fn owned(path: &str, entry_type: &str, mode: &str) -> Value {
        json!({
            "path": path,
            "type": entry_type,
            "ownerRef": "User/d2bd",
            "groupRef": "User/d2bd",
            "mode": mode,
        })
    }

    /// A minimal `state` Volume with one root directory and one view.
    pub fn state_volume() -> VolumeSpec {
        parse(json!({
            "source": {
                "executionRef": "Host/host-system",
                "settings": { "kind": "local-path", "sourcePolicyId": "state-root" },
            },
            "kind": "state",
            "layout": [owned("", "directory", "0700")],
            "views": {
                "controller": {
                    "path": "",
                    "rights": ["read", "write", "create", "delete", "traverse"],
                },
            },
        }))
    }

    /// The minimal `state` Volume plus one read-write Guest attachment.
    pub fn attached_state_volume() -> VolumeSpec {
        parse(json!({
            "source": {
                "executionRef": "Host/host-system",
                "settings": { "kind": "local-path", "sourcePolicyId": "state-root" },
            },
            "kind": "state",
            "layout": [owned("", "directory", "0700")],
            "views": {
                "controller": {
                    "path": "",
                    "rights": ["read", "write", "create", "delete", "traverse"],
                },
                "reader": { "path": "", "rights": ["read", "traverse"] },
            },
            "attachments": [
                {
                    "executionRef": "Guest/work-vm",
                    "transport": "virtiofs",
                    "view": "controller",
                    "access": "read-write",
                    "mountPath": "/state",
                },
            ],
        }))
    }

    /// A Volume whose root entry declares both ACL lists and fails on a
    /// foreign child ACL.
    pub fn acl_volume(foreign_child_policy: &str) -> VolumeSpec {
        let mut root = owned("", "directory", "0750");
        root["accessAcl"] = json!([{ "principal": { "ref": "User/alice" }, "permissions": "rx" }]);
        root["defaultAcl"] = json!([{ "principal": { "ref": "User/alice" }, "permissions": "rx" }]);
        root["foreignChildPolicy"] = json!(foreign_child_policy);
        root["repairPolicy"] = json!("exact-owner-and-acl");
        parse(json!({
            "source": {
                "executionRef": "Host/host-system",
                "settings": { "kind": "local-path", "sourcePolicyId": "state-root" },
            },
            "kind": "durable",
            "layout": [root],
            "views": { "controller": { "path": "", "rights": ["read", "traverse"] } },
        }))
    }

    /// The canonical per-Guest store-view Volume.
    pub fn store_view_volume() -> VolumeSpec {
        let guest = guest();
        let marker = format!("live/.d2b-marker-{}", guest.as_str());
        let mut current = owned("meta/current", "symlink", "0777");
        current["target"] = json!("generations/0");
        current["noFollow"] = json!(false);
        let mut lock = owned("sync.lock", "file", "0640");
        lock["cleanupPolicy"] = json!("never");
        parse(json!({
            "source": {
                "executionRef": "Host/host-system",
                "settings": { "kind": "local-path", "sourcePolicyId": "state-root" },
            },
            "kind": "durable",
            "layout": [
                owned("", "directory", "0755"),
                owned("live", "directory", "0755"),
                owned(&marker, "file", "0444"),
                owned("meta", "directory", "0755"),
                owned("meta/generations", "directory", "0755"),
                current,
                owned("state", "directory", "0700"),
                owned("gcroots", "directory", "0755"),
                lock,
            ],
            "views": {
                "ro-store": { "path": "live", "rights": ["read", "traverse"] },
                "meta": { "path": "meta", "rights": ["read", "traverse"] },
            },
            "attachments": [
                {
                    "executionRef": "Guest/work-vm",
                    "transport": "virtiofs",
                    "view": "ro-store",
                    "access": "read-only",
                    "mountPath": "/nix/.ro-store",
                },
            ],
        }))
    }

    /// The canonical per-Guest TPM state Volume.
    pub fn swtpm_volume() -> VolumeSpec {
        let mut root = owned("", "directory", "0700");
        root["createPolicy"] = json!("create-if-never-provisioned");
        root["repairPolicy"] = json!("exact-mode");
        root["cleanupPolicy"] = json!("never");
        root["sensitivity"] = json!("secret");
        root["invariants"] = json!(["no-symlink", "broker-opaque-id-only"]);
        parse(json!({
            "source": {
                "executionRef": "Host/host-system",
                "settings": { "kind": "local-path", "sourcePolicyId": "state-root" },
            },
            "kind": "state",
            "layout": [root],
            "views": { "controller": { "path": "", "rights": ["read", "traverse"] } },
        }))
    }
}
