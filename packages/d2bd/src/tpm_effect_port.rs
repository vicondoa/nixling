//! Core-owned production adapter for the Device TPM Provider effect boundary.
//!
//! The Provider receives no broker handle, host locator, or Core migration
//! receipt. Core supplies the migration decision and an effect executor for
//! the state/runner operations; this adapter is the only place that maps the
//! private decision to the typed broker operation.

#![allow(dead_code)]

use std::{sync::Mutex, time::Duration};

use d2b_contracts::types::{BundleOpId, PathClass, RoleId, VmId};
use d2b_contracts_broker::broker_wire::{
    BrokerCallerRole, BrokerRequest, BrokerResponse, RunnerRole, SpawnRunnerRequest,
};
use d2b_contracts_resource::v3::{ResourceRef, ResourceUid};
use d2b_core::bundle_resolver::BundleResolver;
use d2b_core::processes::{ProcessNode, ProcessRole};
use d2b_core_controller::migration::LegacyTpmMigrationDecision;
use d2b_provider_device_tpm::{
    BinaryKind, FlushLaunchTicket, LegacyMigrationOutcome, SignedBinaryRef, StateDirIntent,
    SwtpmSettings, SwtpmStartLaunchTicket, TpmEffectError, TpmEffectPort, TpmResourceController,
    TpmResourceEffectError, TpmResourceEffectPort, TpmResourceOutcome, TpmStateObservation,
    TpmStateObservationKind, TpmStatePreparationResult, build_swtpm_flush_spec,
    build_swtpm_process_spec, build_tpm_state_volume_resource,
};
use sha2::{Digest, Sha256};

use crate::provider_effects::{GuestLifecycleOperation, LifecycleAuthorization};

#[allow(dead_code)]
fn map_legacy_migration_outcome(
    outcome: d2b_contracts_broker::broker_wire::LegacySwtpmMigrationOutcome,
) -> LegacyMigrationOutcome {
    match outcome {
        d2b_contracts_broker::broker_wire::LegacySwtpmMigrationOutcome::Migrated => {
            LegacyMigrationOutcome::Migrated
        }
        d2b_contracts_broker::broker_wire::LegacySwtpmMigrationOutcome::AlreadyMigrated => {
            LegacyMigrationOutcome::AlreadyMigrated
        }
        d2b_contracts_broker::broker_wire::LegacySwtpmMigrationOutcome::NotApplicable => {
            LegacyMigrationOutcome::NotApplicable
        }
        d2b_contracts_broker::broker_wire::LegacySwtpmMigrationOutcome::Pending => {
            LegacyMigrationOutcome::Pending
        }
        d2b_contracts_broker::broker_wire::LegacySwtpmMigrationOutcome::Failed => {
            LegacyMigrationOutcome::Failed
        }
        d2b_contracts_broker::broker_wire::LegacySwtpmMigrationOutcome::Ambiguous => {
            LegacyMigrationOutcome::Ambiguous
        }
        d2b_contracts_broker::broker_wire::LegacySwtpmMigrationOutcome::AdoptionRequired
        | d2b_contracts_broker::broker_wire::LegacySwtpmMigrationOutcome::NeverProvisioned => {
            LegacyMigrationOutcome::Ambiguous
        }
    }
}

/// Core-side executor for the non-migration TPM effects.
pub trait CoreTpmEffectExecutor {
    fn prepare_state_dir(
        &mut self,
        intent: &StateDirIntent,
    ) -> Result<TpmStatePreparationResult, TpmEffectError>;
    fn flush(&mut self, ticket: &FlushLaunchTicket) -> Result<(), TpmEffectError>;
    fn start(
        &mut self,
        ticket: &SwtpmStartLaunchTicket,
        settings: SwtpmSettings,
        binary: &SignedBinaryRef,
    ) -> Result<(), TpmEffectError>;
    fn wait_for_endpoint(&mut self) -> Result<(), TpmEffectError>;
    fn stop(&mut self) -> Result<(), TpmEffectError>;
}

struct SwtpmSpawnReservation<'a> {
    table: &'a d2bd_runtime::supervisor::pidfd_table::PidfdTable,
    vm: String,
}

impl Drop for SwtpmSpawnReservation<'_> {
    fn drop(&mut self) {
        self.table.release_spawn_reservation(&self.vm, "swtpm");
    }
}

/// Concrete daemon-side TPM effect executor for the retained legacy TPM
/// connector. v3 Cloud Hypervisor lifecycle reaches swtpm through its owned
/// Process resources instead of this process-DAG lookup.
///
/// All host paths, binaries, state markers, and pidfds remain inside the
/// trusted bundle/broker boundary. The Provider sees only the opaque tickets
/// returned by this executor.
pub(crate) struct LiveTpmEffectExecutor<'a> {
    state: &'a crate::ServerState,
    resolver: &'a BundleResolver,
    vm_id: VmId,
    caller_role: BrokerCallerRole,
    device_uid: ResourceUid,
    lifecycle_authorization: LifecycleAuthorization,
    legacy_migration_required: bool,
    prepared_flush_ticket: Option<FlushLaunchTicket>,
    prepared_swtpm_ticket: Option<SwtpmStartLaunchTicket>,
    adopted_live_worker: bool,
    lifecycle_lease_consumed: bool,
}

impl<'a> LiveTpmEffectExecutor<'a> {
    pub(crate) fn new(
        state: &'a crate::ServerState,
        resolver: &'a BundleResolver,
        vm_id: VmId,
        caller_role: BrokerCallerRole,
        device_uid: ResourceUid,
        lifecycle_authorization: LifecycleAuthorization,
        legacy_migration_required: bool,
    ) -> Self {
        Self {
            state,
            resolver,
            vm_id,
            caller_role,
            device_uid,
            lifecycle_authorization,
            legacy_migration_required,
            prepared_flush_ticket: None,
            prepared_swtpm_ticket: None,
            adopted_live_worker: false,
            lifecycle_lease_consumed: false,
        }
    }

    fn consume_lifecycle_lease(&mut self) -> Result<(), TpmEffectError> {
        if self.lifecycle_lease_consumed {
            return Ok(());
        }
        crate::consume_lifecycle_lease(
            self.state,
            &self.lifecycle_authorization,
            GuestLifecycleOperation::Start,
            &self.caller_role,
        )
        .map_err(|_| TpmEffectError::SpawnRejected)?;
        self.lifecycle_lease_consumed = true;
        Ok(())
    }

    fn ticket_bytes(&self, domain: &str, intent: &StateDirIntent) -> [u8; 16] {
        let mut hasher = Sha256::new();
        hasher.update(domain.as_bytes());
        hasher.update([0]);
        hasher.update(self.vm_id.as_str().as_bytes());
        hasher.update([0]);
        hasher.update(intent.directory().as_bytes());
        hasher.update(intent.marker().as_bytes());
        hasher.update(intent.owner().as_bytes());
        let digest = hasher.finalize();
        let mut out = [0; 16];
        out.copy_from_slice(&digest[..16]);
        out
    }

    fn runner_intent(&self, role: &str) -> Result<BundleOpId, TpmEffectError> {
        let intent_id = crate::intent_id_legacy_runner(self.vm_id.as_str(), role);
        self.resolver
            .find_runner_intent(&intent_id)
            .map(|intent| BundleOpId::new(intent.intent_id.clone()))
            .ok_or(TpmEffectError::SpawnRejected)
    }

    fn swtpm_node(&self) -> Result<&ProcessNode, TpmEffectError> {
        self.resolver
            .find_process_vm(self.vm_id.as_str())
            .and_then(|dag| {
                dag.nodes
                    .iter()
                    .find(|node| node.role == ProcessRole::Swtpm)
            })
            .ok_or(TpmEffectError::SpawnRejected)
    }

    fn spawn(
        &self,
        role: RunnerRole,
        role_id: &str,
        intent: BundleOpId,
        timeout: Duration,
    ) -> Result<
        (
            d2b_contracts_broker::broker_wire::SpawnRunnerResponse,
            Vec<std::os::fd::RawFd>,
        ),
        TpmEffectError,
    > {
        let result = crate::dispatch_broker_request_with_fds_timeout_as(
            self.state,
            BrokerRequest::SpawnRunner(SpawnRunnerRequest {
                vm_id: self.vm_id.clone(),
                role_id: RoleId::new(role_id),
                resource_ref: None,
                resource_uid: None,
                zone_uid: None,
                owner_ref: None,
                owner_uid: None,
                provider_ref: None,
                bundle_content_identity: None,
                provider_identity: None,
                template_identity: None,
                generation: None,
                runtime_scope: None,
                activation_input: None,
                sandbox_plan: None,
                role,
                bundle_runner_intent_ref: intent,
                execution_ref: None,
                execution_domain: None,
                user_ref: None,
                guest_execution: None,
                runtime_allocations: Vec::new(),
                tracing_span_id: None,
                workload_identity: None,
                inherited_fd_count: 0,
                network_tap_context: None,
            }),
            self.caller_role.clone(),
            timeout,
        );
        let (response, fds) = result.map_err(|error| {
            tracing::warn!(
                ?error,
                vm = %self.vm_id,
                role = role_id,
                "TPM runner broker request failed"
            );
            TpmEffectError::Transient
        })?;
        match response {
            BrokerResponse::SpawnRunner(response) => Ok((response, fds)),
            BrokerResponse::Error(error) => {
                tracing::warn!(
                    kind = %error.kind,
                    message = %error.message,
                    vm = %self.vm_id,
                    role = role_id,
                    "TPM runner broker request refused"
                );
                crate::close_received_fds(&fds);
                Err(TpmEffectError::SpawnRejected)
            }
            _ => {
                crate::close_received_fds(&fds);
                Err(TpmEffectError::SpawnRejected)
            }
        }
    }

    fn cleanup_failed_start(
        &self,
        response: &d2b_contracts_broker::broker_wire::SpawnRunnerResponse,
        received_fds: &[std::os::fd::RawFd],
    ) {
        let removed = {
            let _guard = self.state.pidfd_table.mutation_guard();
            let removed = self.state.pidfd_table.deregister_if_matches(
                self.vm_id.as_str(),
                "swtpm",
                response.pid,
                response.start_time_ticks,
            );
            if removed {
                let _ = self.state.pidfd_table.snapshot();
            }
            removed
        };
        if removed {
            tracing::warn!(
                vm = %self.vm_id,
                role = "swtpm",
                "removed failed TPM runner registration"
            );
        }
        crate::stop_unregistered_spawned_runner(
            self.state,
            self.vm_id.as_str(),
            "swtpm",
            response,
            received_fds,
            self.caller_role.clone(),
        );
        crate::close_received_fds(received_fds);
    }

    fn adopt_live_worker_if_present(&mut self) -> Result<bool, TpmEffectError> {
        let pidfd_alive = self
            .state
            .pidfd_table
            .still_alive_same_start_time(self.vm_id.as_str(), "swtpm");
        let snapshot = d2bd_runtime::supervisor::state::SnapshotStore::get(
            &d2bd_runtime::supervisor::state::FilesystemSnapshotStore::new(
                &self.state.daemon_state_dir,
            ),
            self.vm_id.as_str(),
            "swtpm",
        )
        .map_err(|_| TpmEffectError::Transient)?;
        let liveness = if pidfd_alive {
            DurableSwtpmLiveness::Live
        } else if let Some(snapshot) = snapshot.as_ref() {
            match d2bd_runtime::supervisor::pidfd_table::read_proc_start_time_pub(snapshot.pid) {
                Ok(None) => DurableSwtpmLiveness::Missing,
                Ok(Some(_)) | Err(_) => DurableSwtpmLiveness::Ambiguous,
            }
        } else {
            DurableSwtpmLiveness::Missing
        };
        match durable_swtpm_adoption_gate(
            snapshot.as_ref(),
            &self.device_uid,
            liveness,
            Some((
                self.lifecycle_authorization.zone_uid(),
                self.lifecycle_authorization.guest_uid(),
                self.lifecycle_authorization.guest_generation(),
                self.lifecycle_authorization
                    .provider_assignment_generation(),
                self.lifecycle_authorization.policy_revision(),
            )),
        )? {
            DurableSwtpmAdoption::Adopted => {
                self.adopted_live_worker = true;
                Ok(true)
            }
            DurableSwtpmAdoption::ClaimAndAdopt => {
                let mut claimed = snapshot.expect("claim requires a durable snapshot");
                claimed.owner_resource_uid = Some(self.device_uid.as_str().to_owned());
                d2bd_runtime::supervisor::state::SnapshotStore::upsert(
                    &d2bd_runtime::supervisor::state::FilesystemSnapshotStore::new(
                        &self.state.daemon_state_dir,
                    ),
                    &claimed,
                )
                .map_err(|_| TpmEffectError::Transient)?;
                self.adopted_live_worker = true;
                Ok(true)
            }
            DurableSwtpmAdoption::RemoveAndSpawn | DurableSwtpmAdoption::Spawn => Ok(false),
        }
    }

    fn wait_for_endpoint_ready(&self) -> Result<(), TpmEffectError> {
        let swtpm_node = self.swtpm_node()?;
        let liveness = d2bd_runtime::supervisor::readiness_liveness::PidfdLivenessProbe::new(
            &self.state.pidfd_table,
            &self.state.broker_reap_log,
            self.vm_id.as_str(),
            "swtpm",
        );
        crate::wait_for_readiness(
            swtpm_node,
            &swtpm_node.readiness,
            Duration::from_secs(30),
            Some(&liveness),
        )
        .map_err(|_| TpmEffectError::Transient)
    }
}

impl CoreTpmEffectExecutor for LiveTpmEffectExecutor<'_> {
    fn prepare_state_dir(
        &mut self,
        intent: &StateDirIntent,
    ) -> Result<TpmStatePreparationResult, TpmEffectError> {
        let response = crate::dispatch_broker_request_as(
            self.state,
            BrokerRequest::PrepareStateDir(d2b_contracts_broker::broker_wire::PrepareDirRequest {
                vm_id: self.vm_id.clone(),
                path_class: PathClass::Vm,
                tracing_span_id: None,
            }),
            self.caller_role.clone(),
        )
        .map_err(|_| TpmEffectError::Transient)?;
        if !matches!(response, BrokerResponse::Ack(_)) {
            return Err(TpmEffectError::StateIntegrity);
        }
        let flush_ticket =
            FlushLaunchTicket::from_core(self.ticket_bytes("d2b:tpm-flush-ticket/v2", intent));
        let swtpm_ticket =
            SwtpmStartLaunchTicket::from_core(self.ticket_bytes("d2b:tpm-start-ticket/v2", intent));
        self.prepared_flush_ticket = Some(flush_ticket.clone());
        self.prepared_swtpm_ticket = Some(swtpm_ticket.clone());
        Ok(TpmStatePreparationResult {
            observation: TpmStateObservation::from_core(if self.legacy_migration_required {
                TpmStateObservationKind::ExistingWithMarker
            } else {
                TpmStateObservationKind::Fresh
            }),
            flush_ticket,
            swtpm_ticket,
        })
    }

    fn flush(&mut self, ticket: &FlushLaunchTicket) -> Result<(), TpmEffectError> {
        self.consume_lifecycle_lease()?;
        if !self.adopted_live_worker && self.adopt_live_worker_if_present()? {
            return Ok(());
        }
        if self.adopted_live_worker {
            return Ok(());
        }
        if self.prepared_flush_ticket.as_ref() != Some(ticket) {
            return Err(TpmEffectError::StateIntegrity);
        }
        let intent = self.runner_intent("swtpm-flush")?;
        let (response, fds) = self.spawn(
            RunnerRole::SwtpmFlush,
            "swtpm-flush",
            intent,
            Duration::from_secs(30),
        )?;
        let result = crate::wait_for_one_shot_exit(
            response.pid,
            response.start_time_ticks,
            Duration::from_secs(30),
        );
        if result.is_err() {
            crate::stop_unregistered_spawned_runner(
                self.state,
                self.vm_id.as_str(),
                "swtpm-flush",
                &response,
                &fds,
                self.caller_role.clone(),
            );
        }
        crate::close_received_fds(&fds);
        result.map_err(|_| TpmEffectError::FlushFailed)
    }

    fn start(
        &mut self,
        ticket: &SwtpmStartLaunchTicket,
        settings: SwtpmSettings,
        binary: &SignedBinaryRef,
    ) -> Result<(), TpmEffectError> {
        self.consume_lifecycle_lease()?;
        if self.prepared_swtpm_ticket.as_ref() != Some(ticket)
            || binary.kind() != BinaryKind::Swtpm
            || d2b_provider_device_tpm::SwtpmArgv::for_settings(settings).is_err()
        {
            return Err(TpmEffectError::SpawnRejected);
        }
        let pidfd_alive = self
            .state
            .pidfd_table
            .still_alive_same_start_time(self.vm_id.as_str(), "swtpm");
        let snapshot = d2bd_runtime::supervisor::state::SnapshotStore::get(
            &d2bd_runtime::supervisor::state::FilesystemSnapshotStore::new(
                &self.state.daemon_state_dir,
            ),
            self.vm_id.as_str(),
            "swtpm",
        )
        .map_err(|_| TpmEffectError::Transient)?;
        let liveness = if pidfd_alive {
            DurableSwtpmLiveness::Live
        } else if let Some(snapshot) = snapshot.as_ref() {
            match d2bd_runtime::supervisor::pidfd_table::read_proc_start_time_pub(snapshot.pid) {
                Ok(None) => DurableSwtpmLiveness::Missing,
                Ok(Some(_)) | Err(_) => DurableSwtpmLiveness::Ambiguous,
            }
        } else {
            DurableSwtpmLiveness::Missing
        };
        match durable_swtpm_adoption_gate(
            snapshot.as_ref(),
            &self.device_uid,
            liveness,
            Some((
                self.lifecycle_authorization.zone_uid(),
                self.lifecycle_authorization.guest_uid(),
                self.lifecycle_authorization.guest_generation(),
                self.lifecycle_authorization
                    .provider_assignment_generation(),
                self.lifecycle_authorization.policy_revision(),
            )),
        )? {
            DurableSwtpmAdoption::Adopted => {
                self.adopted_live_worker = true;
                return Ok(());
            }
            DurableSwtpmAdoption::ClaimAndAdopt => {
                let mut claimed = snapshot.expect("claim requires a durable snapshot");
                claimed.owner_resource_uid = Some(self.device_uid.as_str().to_owned());
                d2bd_runtime::supervisor::state::SnapshotStore::upsert(
                    &d2bd_runtime::supervisor::state::FilesystemSnapshotStore::new(
                        &self.state.daemon_state_dir,
                    ),
                    &claimed,
                )
                .map_err(|_| TpmEffectError::Transient)?;
                self.adopted_live_worker = true;
                return Ok(());
            }
            DurableSwtpmAdoption::RemoveAndSpawn => {
                d2bd_runtime::supervisor::state::SnapshotStore::remove(
                    &d2bd_runtime::supervisor::state::FilesystemSnapshotStore::new(
                        &self.state.daemon_state_dir,
                    ),
                    self.vm_id.as_str(),
                    "swtpm",
                )
                .map_err(|_| TpmEffectError::Transient)?;
            }
            DurableSwtpmAdoption::Spawn => {}
        }
        if !self
            .state
            .pidfd_table
            .try_reserve_spawn(self.vm_id.as_str(), "swtpm")
        {
            return Err(TpmEffectError::Transient);
        }
        let _spawn_reservation = SwtpmSpawnReservation {
            table: &self.state.pidfd_table,
            vm: self.vm_id.as_str().to_owned(),
        };
        if self
            .state
            .pidfd_table
            .still_alive_same_start_time(self.vm_id.as_str(), "swtpm")
        {
            self.adopted_live_worker = true;
            return Ok(());
        }
        self.adopted_live_worker = false;
        let swtpm_node = self.swtpm_node()?;
        {
            let _mguard = self.state.pidfd_table.mutation_guard();
            if self
                .state
                .pidfd_table
                .deregister(self.vm_id.as_str(), "swtpm")
                .is_some()
            {
                let _ = self.state.pidfd_table.snapshot();
            }
        }
        let intent = self.runner_intent("swtpm")?;
        let (response, fds) =
            self.spawn(RunnerRole::Swtpm, "swtpm", intent, Duration::from_secs(30))?;
        let pidfd = match crate::duplicate_received_fd(&fds, response.pidfd_index, "TPM pidfd") {
            Ok(pidfd) => pidfd,
            Err(_) => {
                self.cleanup_failed_start(&response, &fds);
                return Err(TpmEffectError::Transient);
            }
        };
        let registration_result = {
            let _guard = self.state.pidfd_table.mutation_guard();
            (|| {
                self.state.pidfd_table.register(
                    self.vm_id.as_str().to_owned(),
                    "swtpm".to_owned(),
                    d2bd_runtime::supervisor::pidfd_table::PidfdEntry {
                        pidfd,
                        pid: response.pid,
                        start_time_ticks: response.start_time_ticks,
                    },
                )?;
                self.state.pidfd_table.snapshot()
            })()
        };
        if let Err(error) = registration_result {
            let duplicate = matches!(
                error,
                d2bd_runtime::supervisor::pidfd_table::PidfdTableError::DuplicateRegistration { .. }
            );
            self.cleanup_failed_start(&response, &fds);
            return Err(if duplicate {
                TpmEffectError::SpawnRejected
            } else {
                TpmEffectError::Transient
            });
        }
        if let Err(error) = crate::write_runner_snapshot_with_authorization(
            self.state,
            self.vm_id.as_str(),
            "swtpm",
            RunnerRole::Swtpm,
            response.pid,
            response.start_time_ticks,
            Some(self.device_uid.as_str()),
            Some(&self.lifecycle_authorization),
        ) {
            self.cleanup_failed_start(&response, &fds);
            tracing::warn!(error = %error, "TPM runner snapshot persistence failed");
            return Err(TpmEffectError::Transient);
        }
        crate::close_received_fds(&fds);
        let liveness = d2bd_runtime::supervisor::readiness_liveness::PidfdLivenessProbe::new(
            &self.state.pidfd_table,
            &self.state.broker_reap_log,
            self.vm_id.as_str(),
            "swtpm",
        );
        crate::wait_for_readiness(
            swtpm_node,
            &swtpm_node.readiness,
            Duration::from_secs(30),
            Some(&liveness),
        )
        .map_err(|_| {
            let _ = self.stop();
            TpmEffectError::Transient
        })?;
        Ok(())
    }

    fn wait_for_endpoint(&mut self) -> Result<(), TpmEffectError> {
        self.wait_for_endpoint_ready()
    }

    fn stop(&mut self) -> Result<(), TpmEffectError> {
        crate::stop_vm_pidfd_role(
            self.state,
            self.caller_role.clone(),
            "device-tpm",
            self.vm_id.as_str(),
            "swtpm",
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .map(|_| ())
        .map_err(|_| TpmEffectError::Transient)
    }
}

/// Production adapter bound to one Core-issued migration decision.
#[allow(dead_code)]
pub(crate) struct ProductionTpmEffectPort<'a, E> {
    state: &'a crate::ServerState,
    vm_id: VmId,
    migration_intent_ref: BundleOpId,
    migration_decision: LegacyTpmMigrationDecision,
    executor: E,
}

#[allow(dead_code)]
impl<'a, E> ProductionTpmEffectPort<'a, E> {
    pub(crate) fn new(
        state: &'a crate::ServerState,
        vm_id: VmId,
        migration_intent_ref: BundleOpId,
        migration_decision: LegacyTpmMigrationDecision,
        executor: E,
    ) -> Self {
        Self {
            state,
            vm_id,
            migration_intent_ref,
            migration_decision,
            executor,
        }
    }

    pub(crate) fn into_executor(self) -> E {
        self.executor
    }
}

impl<E: CoreTpmEffectExecutor> TpmEffectPort for ProductionTpmEffectPort<'_, E> {
    fn legacy_migration_required(&self) -> bool {
        self.migration_decision.requires_migration()
    }

    fn migrate_legacy_state(&mut self) -> Result<LegacyMigrationOutcome, TpmEffectError> {
        if !self.migration_decision.requires_migration()
            || !self
                .migration_decision
                .validates_binding(self.vm_id.as_str(), self.migration_intent_ref.as_str())
        {
            return Err(TpmEffectError::StateIntegrity);
        }
        let outcome = crate::dispatch_broker_legacy_tpm_migration(
            self.state,
            self.vm_id.clone(),
            self.migration_intent_ref.clone(),
        )
        .map_err(|_| TpmEffectError::Transient)?;
        Ok(map_legacy_migration_outcome(outcome))
    }

    fn prepare_state_dir(
        &mut self,
        intent: &StateDirIntent,
    ) -> Result<TpmStatePreparationResult, TpmEffectError> {
        self.executor.prepare_state_dir(intent)
    }

    fn flush(&mut self, ticket: &FlushLaunchTicket) -> Result<(), TpmEffectError> {
        self.executor.flush(ticket)
    }

    fn start(
        &mut self,
        ticket: &SwtpmStartLaunchTicket,
        settings: SwtpmSettings,
        binary: &SignedBinaryRef,
    ) -> Result<(), TpmEffectError> {
        self.executor.start(ticket, settings, binary)
    }

    fn stop(&mut self) -> Result<(), TpmEffectError> {
        self.executor.stop()
    }
}

/// Production Device controller reconcile callsite.
///
/// Core supplies the migration decision and opaque state intent; the daemon
/// supplies only the concrete broker-backed executor. The migration receipt
/// never crosses into the Provider crate.
pub(crate) struct AdmittedTpmDevice {
    device_uid: ResourceUid,
    device_ref: ResourceRef,
    zone: String,
    execution_ref: ResourceRef,
    lifecycle_authorization: LifecycleAuthorization,
}

impl AdmittedTpmDevice {
    pub(crate) fn new(
        device_uid: ResourceUid,
        device_ref: ResourceRef,
        zone: impl Into<String>,
        execution_ref: ResourceRef,
        lifecycle_authorization: LifecycleAuthorization,
    ) -> Self {
        Self {
            device_uid,
            device_ref,
            zone: zone.into(),
            execution_ref,
            lifecycle_authorization,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn reconcile_device_tpm(
    state: &crate::ServerState,
    resolver: &BundleResolver,
    vm_id: VmId,
    migration_intent_ref: BundleOpId,
    migration_decision: LegacyTpmMigrationDecision,
    admitted_device: AdmittedTpmDevice,
    state_intent: StateDirIntent,
    settings: SwtpmSettings,
    binary: SignedBinaryRef,
    caller_role: BrokerCallerRole,
) -> Result<TpmResourceOutcome, d2b_provider_device_tpm::TpmResourceControllerError> {
    let AdmittedTpmDevice {
        device_uid,
        device_ref,
        zone,
        execution_ref,
        lifecycle_authorization,
    } = admitted_device;
    let executor = LiveTpmEffectExecutor::new(
        state,
        resolver,
        vm_id.clone(),
        caller_role,
        device_uid.clone(),
        lifecycle_authorization,
        migration_decision.requires_migration(),
    );
    let effect = ProductionTpmEffectPort::new(
        state,
        vm_id,
        migration_intent_ref,
        migration_decision,
        executor,
    );
    let resource_effect = LiveTpmResourceEffectPort {
        effect: Mutex::new(effect),
        device_uid: device_uid.clone(),
        device_ref: device_ref.clone(),
        zone,
        execution_ref: execution_ref.clone(),
        state_intent,
        settings,
        binary,
        preparation: Mutex::new(None),
    };
    let mut controller = TpmResourceController::new(device_uid, device_ref, execution_ref)?;
    crate::block_on_future(controller.reconcile(&resource_effect))
}

struct LiveTpmResourceEffectPort<'a, E> {
    effect: Mutex<ProductionTpmEffectPort<'a, E>>,
    device_uid: ResourceUid,
    device_ref: ResourceRef,
    zone: String,
    execution_ref: ResourceRef,
    state_intent: StateDirIntent,
    settings: SwtpmSettings,
    binary: SignedBinaryRef,
    preparation: Mutex<Option<TpmStatePreparationResult>>,
}

impl<E: CoreTpmEffectExecutor + Send> TpmResourceEffectPort for LiveTpmResourceEffectPort<'_, E> {
    async fn ensure_state_volume(
        &self,
        device_uid: &ResourceUid,
        device_ref: &ResourceRef,
        execution_ref: &ResourceRef,
    ) -> Result<ResourceRef, TpmResourceEffectError> {
        if device_uid != &self.device_uid
            || device_ref != &self.device_ref
            || execution_ref != &self.execution_ref
        {
            return Err(TpmResourceEffectError::StateIntegrity);
        }
        build_tpm_state_volume_resource(device_uid, device_ref, &self.zone, execution_ref)?;
        let mut effect = self
            .effect
            .lock()
            .map_err(|_| TpmResourceEffectError::Transient)?;
        if effect.legacy_migration_required() {
            match effect
                .migrate_legacy_state()
                .map_err(map_resource_effect_error)?
            {
                LegacyMigrationOutcome::Migrated
                | LegacyMigrationOutcome::AlreadyMigrated
                | LegacyMigrationOutcome::NotApplicable => {}
                LegacyMigrationOutcome::Pending => return Err(TpmResourceEffectError::Transient),
                LegacyMigrationOutcome::Failed | LegacyMigrationOutcome::Ambiguous => {
                    return Err(TpmResourceEffectError::StateIntegrity);
                }
            }
        }
        let preparation = effect
            .prepare_state_dir(&self.state_intent)
            .map_err(map_resource_effect_error)?;
        *self
            .preparation
            .lock()
            .map_err(|_| TpmResourceEffectError::Transient)? = Some(preparation);
        child_ref("Volume", device_uid, "tpm-state")
    }

    async fn request_flush_process(
        &self,
        device_uid: &ResourceUid,
        execution_ref: &ResourceRef,
    ) -> Result<ResourceRef, TpmResourceEffectError> {
        if device_uid != &self.device_uid || execution_ref != &self.execution_ref {
            return Err(TpmResourceEffectError::StateIntegrity);
        }
        build_swtpm_flush_spec(device_uid, execution_ref)?;
        let ticket = self
            .preparation
            .lock()
            .map_err(|_| TpmResourceEffectError::Transient)?
            .as_ref()
            .map(|preparation| preparation.flush_ticket.clone())
            .ok_or(TpmResourceEffectError::StateIntegrity)?;
        self.effect
            .lock()
            .map_err(|_| TpmResourceEffectError::Transient)?
            .flush(&ticket)
            .map_err(map_resource_effect_error)?;
        child_ref("EphemeralProcess", device_uid, "tpm-flush")
    }

    async fn request_swtpm_process(
        &self,
        device_uid: &ResourceUid,
        volume_ref: &ResourceRef,
        execution_ref: &ResourceRef,
    ) -> Result<ResourceRef, TpmResourceEffectError> {
        if device_uid != &self.device_uid || execution_ref != &self.execution_ref {
            return Err(TpmResourceEffectError::StateIntegrity);
        }
        let expected_volume = child_ref("Volume", device_uid, "tpm-state")?;
        if volume_ref != &expected_volume {
            return Err(TpmResourceEffectError::StateIntegrity);
        }
        build_swtpm_process_spec(device_uid, execution_ref)?;
        let ticket = self
            .preparation
            .lock()
            .map_err(|_| TpmResourceEffectError::Transient)?
            .as_ref()
            .map(|preparation| preparation.swtpm_ticket.clone())
            .ok_or(TpmResourceEffectError::StateIntegrity)?;
        self.effect
            .lock()
            .map_err(|_| TpmResourceEffectError::Transient)?
            .start(&ticket, self.settings, &self.binary)
            .map_err(map_resource_effect_error)?;
        child_ref("Process", device_uid, "swtpm")
    }

    async fn stop_swtpm_process(
        &self,
        process_ref: &ResourceRef,
    ) -> Result<(), TpmResourceEffectError> {
        let expected = child_ref("Process", &self.device_uid, "swtpm")?;
        if process_ref != &expected {
            return Err(TpmResourceEffectError::StateIntegrity);
        }
        self.effect
            .lock()
            .map_err(|_| TpmResourceEffectError::Transient)?
            .stop()
            .map_err(map_resource_effect_error)
    }

    async fn delete_flush_process(
        &self,
        process_ref: &ResourceRef,
    ) -> Result<(), TpmResourceEffectError> {
        let expected = child_ref("EphemeralProcess", &self.device_uid, "tpm-flush")?;
        if process_ref != &expected {
            return Err(TpmResourceEffectError::StateIntegrity);
        }
        Ok(())
    }

    async fn watch_tpm_endpoint(
        &self,
        process_ref: &ResourceRef,
    ) -> Result<ResourceRef, TpmResourceEffectError> {
        let expected = child_ref("Process", &self.device_uid, "swtpm")?;
        if process_ref != &expected {
            return Err(TpmResourceEffectError::StateIntegrity);
        }
        self.effect
            .lock()
            .map_err(|_| TpmResourceEffectError::Transient)?
            .executor
            .wait_for_endpoint()
            .map_err(map_resource_effect_error)?;
        child_ref("Endpoint", &self.device_uid, "tpm")
    }
}

fn child_ref(
    resource_type: &str,
    device_uid: &ResourceUid,
    suffix: &str,
) -> Result<ResourceRef, TpmResourceEffectError> {
    let short: String = device_uid
        .as_str()
        .bytes()
        .filter(|byte| byte.is_ascii_hexdigit())
        .take(12)
        .map(char::from)
        .collect();
    ResourceRef::parse(&format!("{resource_type}/device-{short}-{suffix}"))
        .map_err(|_| TpmResourceEffectError::InvalidDevice)
}

fn map_resource_effect_error(error: TpmEffectError) -> TpmResourceEffectError {
    match error {
        TpmEffectError::Transient => TpmResourceEffectError::Transient,
        TpmEffectError::StateIntegrity => TpmResourceEffectError::StateIntegrity,
        _ => TpmResourceEffectError::EffectRejected,
    }
}

/// Registered production Device controller entry point.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct DeviceTpmControllerRegistration {
    registered: bool,
}

impl DeviceTpmControllerRegistration {
    pub(crate) const fn is_registered(self) -> bool {
        self.registered
    }

    /// Reconcile one Core-admitted Device through the live broker executor.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn reconcile(
        self,
        state: &crate::ServerState,
        resolver: &BundleResolver,
        vm_id: VmId,
        migration_intent_ref: BundleOpId,
        migration_decision: LegacyTpmMigrationDecision,
        admitted_device: AdmittedTpmDevice,
        state_intent: StateDirIntent,
        settings: SwtpmSettings,
        binary: SignedBinaryRef,
        caller_role: BrokerCallerRole,
    ) -> Result<TpmResourceOutcome, d2b_provider_device_tpm::TpmResourceControllerError> {
        reconcile_device_tpm(
            state,
            resolver,
            vm_id,
            migration_intent_ref,
            migration_decision,
            admitted_device,
            state_intent,
            settings,
            binary,
            caller_role,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DurableSwtpmAdoption {
    Adopted,
    ClaimAndAdopt,
    RemoveAndSpawn,
    Spawn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DurableSwtpmLiveness {
    Live,
    Missing,
    Ambiguous,
}

fn durable_swtpm_adoption_gate(
    snapshot: Option<&d2bd_runtime::supervisor::state::RunnerSnapshotRecord>,
    device_uid: &ResourceUid,
    liveness: DurableSwtpmLiveness,
    expected_lifecycle: Option<(
        &ResourceUid,
        &ResourceUid,
        d2b_contracts_resource::v3::ResourceGeneration,
        d2b_contracts_resource::v3::ResourceGeneration,
        u64,
    )>,
) -> Result<DurableSwtpmAdoption, TpmEffectError> {
    let Some(snapshot) = snapshot else {
        return match liveness {
            DurableSwtpmLiveness::Missing => Ok(DurableSwtpmAdoption::Spawn),
            DurableSwtpmLiveness::Live | DurableSwtpmLiveness::Ambiguous => {
                Err(TpmEffectError::StateIntegrity)
            }
        };
    };
    if !snapshot.has_complete_lifecycle_identity() {
        return Err(TpmEffectError::StateIntegrity);
    }
    if let Some((zone_uid, guest_uid, guest_generation, provider_generation, policy_revision)) =
        expected_lifecycle
        && !snapshot.matches_lifecycle_identity(
            zone_uid,
            guest_uid,
            guest_generation,
            provider_generation,
            policy_revision,
        )
    {
        return Err(TpmEffectError::StateIntegrity);
    }
    if liveness == DurableSwtpmLiveness::Ambiguous {
        return Err(TpmEffectError::Transient);
    }
    match snapshot.owner_resource_uid.as_deref() {
        Some(owner) if owner != device_uid.as_str() => Err(TpmEffectError::StateIntegrity),
        Some(_) if liveness == DurableSwtpmLiveness::Live => Ok(DurableSwtpmAdoption::Adopted),
        Some(_) => Ok(DurableSwtpmAdoption::RemoveAndSpawn),
        None if liveness == DurableSwtpmLiveness::Live => Ok(DurableSwtpmAdoption::ClaimAndAdopt),
        None => Err(TpmEffectError::Transient),
    }
}

/// Register the real Device TPM controller at the daemon/Core composition
/// boundary. The returned registration is retained by the Zone runtime.
pub(crate) fn register_device_tpm_controller() -> DeviceTpmControllerRegistration {
    DeviceTpmControllerRegistration { registered: true }
}

#[cfg(test)]
mod tests {
    use super::*;
    use d2b_contracts_broker::broker_wire::LegacySwtpmMigrationOutcome;

    #[test]
    fn broker_migration_outcomes_are_preserved_at_the_provider_boundary() {
        for (broker, provider) in [
            (
                LegacySwtpmMigrationOutcome::Migrated,
                LegacyMigrationOutcome::Migrated,
            ),
            (
                LegacySwtpmMigrationOutcome::AlreadyMigrated,
                LegacyMigrationOutcome::AlreadyMigrated,
            ),
            (
                LegacySwtpmMigrationOutcome::NotApplicable,
                LegacyMigrationOutcome::NotApplicable,
            ),
            (
                LegacySwtpmMigrationOutcome::Pending,
                LegacyMigrationOutcome::Pending,
            ),
            (
                LegacySwtpmMigrationOutcome::Failed,
                LegacyMigrationOutcome::Failed,
            ),
            (
                LegacySwtpmMigrationOutcome::Ambiguous,
                LegacyMigrationOutcome::Ambiguous,
            ),
        ] {
            assert_eq!(map_legacy_migration_outcome(broker), provider);
        }
    }

    #[test]
    fn confirmed_dead_durable_snapshot_allows_replacement_spawn() {
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let snapshot = d2bd_runtime::supervisor::state::RunnerSnapshotRecord {
            vm: "work-vm".to_owned(),
            role_id: "swtpm".to_owned(),
            role: RunnerRole::Swtpm,
            owner_resource_uid: Some(uid.as_str().to_owned()),
            zone_uid: Some(ResourceUid::parse("223e4567-e89b-42d3-a456-426614174000").unwrap()),
            guest_uid: Some(ResourceUid::parse("323e4567-e89b-42d3-a456-426614174000").unwrap()),
            guest_generation: Some(d2b_contracts_resource::v3::ResourceGeneration::new(1).unwrap()),
            provider_assignment_generation: Some(
                d2b_contracts_resource::v3::ResourceGeneration::new(1).unwrap(),
            ),
            policy_revision: Some(1),
            operation_id: Some("tpm-test-operation".to_owned()),
            pid: 123,
            start_time_ticks: 456,
            snapshotted_at: "2026-08-15T00:00:00Z".to_owned(),
        };
        assert_eq!(
            durable_swtpm_adoption_gate(Some(&snapshot), &uid, DurableSwtpmLiveness::Missing, None,),
            Ok(DurableSwtpmAdoption::RemoveAndSpawn)
        );
    }

    #[test]
    fn live_legacy_snapshot_is_adopted() {
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let snapshot = d2bd_runtime::supervisor::state::RunnerSnapshotRecord {
            vm: "work-vm".to_owned(),
            role_id: "swtpm".to_owned(),
            role: RunnerRole::Swtpm,
            owner_resource_uid: None,
            zone_uid: Some(ResourceUid::parse("223e4567-e89b-42d3-a456-426614174000").unwrap()),
            guest_uid: Some(ResourceUid::parse("323e4567-e89b-42d3-a456-426614174000").unwrap()),
            guest_generation: Some(d2b_contracts_resource::v3::ResourceGeneration::new(1).unwrap()),
            provider_assignment_generation: Some(
                d2b_contracts_resource::v3::ResourceGeneration::new(1).unwrap(),
            ),
            policy_revision: Some(1),
            operation_id: Some("tpm-test-operation".to_owned()),
            pid: 123,
            start_time_ticks: 456,
            snapshotted_at: "2026-08-15T00:00:00Z".to_owned(),
        };
        assert_eq!(
            durable_swtpm_adoption_gate(Some(&snapshot), &uid, DurableSwtpmLiveness::Live, None),
            Ok(DurableSwtpmAdoption::ClaimAndAdopt)
        );
    }

    #[test]
    fn live_pidfd_without_snapshot_is_not_adopted() {
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        assert_eq!(
            durable_swtpm_adoption_gate(None, &uid, DurableSwtpmLiveness::Live, None),
            Err(TpmEffectError::StateIntegrity)
        );
        assert_eq!(
            durable_swtpm_adoption_gate(None, &uid, DurableSwtpmLiveness::Missing, None),
            Ok(DurableSwtpmAdoption::Spawn)
        );
    }

    #[test]
    fn ambiguous_durable_snapshot_stays_fail_closed() {
        let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let snapshot = d2bd_runtime::supervisor::state::RunnerSnapshotRecord {
            vm: "work-vm".to_owned(),
            role_id: "swtpm".to_owned(),
            role: RunnerRole::Swtpm,
            owner_resource_uid: Some(uid.as_str().to_owned()),
            zone_uid: Some(ResourceUid::parse("223e4567-e89b-42d3-a456-426614174000").unwrap()),
            guest_uid: Some(ResourceUid::parse("323e4567-e89b-42d3-a456-426614174000").unwrap()),
            guest_generation: Some(d2b_contracts_resource::v3::ResourceGeneration::new(1).unwrap()),
            provider_assignment_generation: Some(
                d2b_contracts_resource::v3::ResourceGeneration::new(1).unwrap(),
            ),
            policy_revision: Some(1),
            operation_id: Some("tpm-test-operation".to_owned()),
            pid: 123,
            start_time_ticks: 456,
            snapshotted_at: "2026-08-15T00:00:00Z".to_owned(),
        };
        assert_eq!(
            durable_swtpm_adoption_gate(
                Some(&snapshot),
                &uid,
                DurableSwtpmLiveness::Ambiguous,
                None,
            ),
            Err(TpmEffectError::Transient)
        );
    }

    #[test]
    fn durable_snapshot_refuses_replaced_device_uid_for_same_vm() {
        let old_uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let new_uid = ResourceUid::parse("223e4567-e89b-42d3-a456-426614174000").unwrap();
        let snapshot = d2bd_runtime::supervisor::state::RunnerSnapshotRecord {
            vm: "work-vm".to_owned(),
            role_id: "swtpm".to_owned(),
            role: RunnerRole::Swtpm,
            owner_resource_uid: Some(old_uid.as_str().to_owned()),
            zone_uid: Some(ResourceUid::parse("223e4567-e89b-42d3-a456-426614174000").unwrap()),
            guest_uid: Some(ResourceUid::parse("323e4567-e89b-42d3-a456-426614174000").unwrap()),
            guest_generation: Some(d2b_contracts_resource::v3::ResourceGeneration::new(1).unwrap()),
            provider_assignment_generation: Some(
                d2b_contracts_resource::v3::ResourceGeneration::new(1).unwrap(),
            ),
            policy_revision: Some(1),
            operation_id: Some("tpm-test-operation".to_owned()),
            pid: 123,
            start_time_ticks: 456,
            snapshotted_at: "2026-08-15T00:00:00Z".to_owned(),
        };
        assert_eq!(
            durable_swtpm_adoption_gate(
                Some(&snapshot),
                &new_uid,
                DurableSwtpmLiveness::Live,
                None
            ),
            Err(TpmEffectError::StateIntegrity)
        );
    }

    #[test]
    fn durable_snapshot_refuses_stale_guest_lifecycle_identity() {
        let device_uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
        let zone_uid = ResourceUid::parse("223e4567-e89b-42d3-a456-426614174000").unwrap();
        let snapshot_guest_uid =
            ResourceUid::parse("323e4567-e89b-42d3-a456-426614174000").unwrap();
        let current_guest_uid = ResourceUid::parse("423e4567-e89b-42d3-a456-426614174000").unwrap();
        let guest_generation = d2b_contracts_resource::v3::ResourceGeneration::new(1).unwrap();
        let provider_generation = d2b_contracts_resource::v3::ResourceGeneration::new(1).unwrap();
        let snapshot = d2bd_runtime::supervisor::state::RunnerSnapshotRecord {
            vm: "work-vm".to_owned(),
            role_id: "swtpm".to_owned(),
            role: RunnerRole::Swtpm,
            owner_resource_uid: Some(device_uid.as_str().to_owned()),
            zone_uid: Some(zone_uid.clone()),
            guest_uid: Some(snapshot_guest_uid),
            guest_generation: Some(guest_generation),
            provider_assignment_generation: Some(provider_generation),
            policy_revision: Some(1),
            operation_id: Some("tpm-test-operation".to_owned()),
            pid: 123,
            start_time_ticks: 456,
            snapshotted_at: "2026-08-15T00:00:00Z".to_owned(),
        };
        assert_eq!(
            durable_swtpm_adoption_gate(
                Some(&snapshot),
                &device_uid,
                DurableSwtpmLiveness::Live,
                Some((
                    &zone_uid,
                    &current_guest_uid,
                    guest_generation,
                    provider_generation,
                    1,
                )),
            ),
            Err(TpmEffectError::StateIntegrity)
        );
    }
}
