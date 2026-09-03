//! Shared-Runner composition for the Guest runtime Providers.
//!
//! Each runtime Provider receives a separate filtered Runner. The Guest
//! `providerRef` is the only owner selector; the effect adapter receives one
//! fresh Guest snapshot and never falls back to another runtime or Host
//! custody.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use d2b_contracts_resource::v3::{
    ControllerGeneration, ResourceGeneration, ResourceRef, ZoneId, identity::ReconnectGeneration,
};
use d2b_core_controller::{
    ControllerDescriptor, CoreControllerSource, Runner, RunnerConfig, SourceError,
};
use d2b_resource_api::registered::AssignmentFenceResolver;
use d2b_resource_store::{
    ResourceAssignmentFence, ResourceAssignmentScope, StoreErrorKind, StoreGetRequest,
    StoreOperationContext, StoreProjection,
};
use serde_json::Value;

use super::{
    DaemonSharedProviderEffects, ResourceRuntimeError, SharedProviderEffectExecutor,
    GuestRuntimeReconciler, SharedProviderResourceKind, SharedProviderRunnerRegistration,
};

/// The shared-Runner registration shape used by Guest runtime Providers.
pub type SharedGuestRunnerRegistration = SharedProviderRunnerRegistration;

/// The four Guest runtime Providers attached to the production shared Runner.
///
/// Every entry selects Guests through `spec.providerRef`; no runtime Provider
/// may claim a Guest owned by another entry.
pub const U6_SHARED_PROVIDER_RUNNERS: [SharedGuestRunnerRegistration; 4] = [
    SharedProviderRunnerRegistration {
        controller_ref: "Process/cloud-hypervisor-controller",
        provider_ref: "Provider/runtime-cloud-hypervisor",
        resource_type: "Guest",
        finalizer: d2b_provider_runtime_cloud_hypervisor::GUEST_CONTROLLER_FINALIZER,
        repair_interval_ticks:
            d2b_provider_runtime_cloud_hypervisor::CLOUD_HYPERVISOR_REPAIR_INTERVAL_SECS * 1_000,
        legacy_scheduler_disabled:
            d2b_provider_runtime_cloud_hypervisor::cloud_hypervisor_runner_contract()
                .legacy_scheduler_disabled(),
        watched_configuration_is_dependency:
            d2b_provider_runtime_cloud_hypervisor::cloud_hypervisor_runner_contract()
                .watched_configuration_is_dependency(),
    },
    SharedProviderRunnerRegistration {
        controller_ref: "Process/runtime-qemu-media-controller",
        provider_ref: "Provider/runtime-qemu-media",
        resource_type: "Guest",
        finalizer: d2b_provider_runtime_qemu_media::FINALIZER,
        repair_interval_ticks: d2b_provider_runtime_qemu_media::QEMU_MEDIA_REPAIR_INTERVAL_SECS
            * 1_000,
        legacy_scheduler_disabled: d2b_provider_runtime_qemu_media::qemu_media_runner_contract()
            .legacy_scheduler_disabled(),
        watched_configuration_is_dependency:
            d2b_provider_runtime_qemu_media::qemu_media_runner_contract()
                .watched_configuration_is_dependency(),
    },
    SharedProviderRunnerRegistration {
        controller_ref: "Process/aca-controller",
        provider_ref: "Provider/runtime-azure-container-apps",
        resource_type: "Guest",
        finalizer: d2b_provider_runtime_azure_container_apps::FINALIZER,
        repair_interval_ticks: d2b_provider_runtime_azure_container_apps::ACA_REPAIR_INTERVAL_SECS
            * 1_000,
        legacy_scheduler_disabled:
            d2b_provider_runtime_azure_container_apps::azure_container_apps_runner_contract()
                .legacy_scheduler_disabled(),
        watched_configuration_is_dependency:
            d2b_provider_runtime_azure_container_apps::azure_container_apps_runner_contract()
                .watched_configuration_is_dependency(),
    },
    SharedProviderRunnerRegistration {
        controller_ref: "Process/azure-vm-controller-process",
        provider_ref: "Provider/runtime-azure-virtual-machine",
        resource_type: "Guest",
        finalizer: d2b_provider_runtime_azure_virtual_machine::FINALIZER,
        repair_interval_ticks:
            d2b_provider_runtime_azure_virtual_machine::AZURE_VM_REPAIR_INTERVAL_SECS * 1_000,
        legacy_scheduler_disabled:
            d2b_provider_runtime_azure_virtual_machine::azure_virtual_machine_runner_contract()
                .legacy_scheduler_disabled(),
        watched_configuration_is_dependency:
            d2b_provider_runtime_azure_virtual_machine::azure_virtual_machine_runner_contract()
                .watched_configuration_is_dependency(),
    },
];

/// Compose the exact Guest runtime descriptors from authoritative generations.
pub fn compose_shared_guest_runner_descriptors(
    registrations: impl IntoIterator<Item = SharedGuestRunnerRegistration>,
    zone: ZoneId,
    controller_generation: ControllerGeneration,
    provider_generations: &BTreeMap<ResourceRef, ResourceGeneration>,
    session_generation: ReconnectGeneration,
) -> Result<Vec<(SharedGuestRunnerRegistration, ControllerDescriptor)>, ResourceRuntimeError> {
    super::compose_shared_provider_runner_descriptors(
        registrations,
        zone,
        controller_generation,
        provider_generations,
        session_generation,
    )
}

/// Start the U6 Guest runtime Runner wave for one Zone.
pub(crate) async fn start(
    runtime: &super::ZoneResourceRuntime,
    state: Arc<crate::ServerState>,
) -> Result<bool, ResourceRuntimeError> {
    if !runtime.readiness.resource_api_ready {
        return Ok(false);
    }
    let subject_context = runtime
        .core_controller_subject
        .lock()
        .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
        .clone()
        .ok_or(ResourceRuntimeError::AuthenticationUnavailable)?;
    let authorization_state = runtime
        .authorization_state
        .lock()
        .map_err(|_| ResourceRuntimeError::AuthenticationUnavailable)?
        .clone()
        .ok_or(ResourceRuntimeError::AuthenticationUnavailable)?;
    let controller_generation = runtime
        .store_metadata
        .policy_snapshot
        .controller_generation
        .ok_or(ResourceRuntimeError::HandlerNotReady)?;
    let session_generation = subject_context.reconnect_generation();
    let (active_registrations, provider_generations) = provider_generations(runtime).await?;
    if active_registrations.is_empty() {
        return Ok(false);
    }
    let descriptors = compose_shared_guest_runner_descriptors(
        active_registrations,
        runtime.zone.clone(),
        controller_generation,
        &provider_generations,
        session_generation,
    )?;
    let effects: Arc<dyn SharedProviderEffectExecutor> = Arc::new(
        DaemonSharedProviderEffects::new(state, runtime.zone.clone()),
    );
    let mut tasks = Vec::new();
    for (registration, descriptor) in descriptors {
        let kind = SharedProviderResourceKind::from_registration(registration)?;
        let provider_ref = ResourceRef::parse(registration.provider_ref)
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
        let controller_ref = ResourceRef::parse(registration.controller_ref)
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
        let (assignments, authority) = runtime
            .u12_controller_assignments(
                &descriptor,
                controller_ref.clone(),
                *provider_generations
                    .get(&provider_ref)
                    .ok_or(ResourceRuntimeError::HandlerNotReady)?,
                controller_generation,
                session_generation,
            )
            .await?;
        let subject = runtime
            .authorizer
            .issue_authenticated_subject(subject_context.clone(), authorization_state.clone())
            .map_err(|_| ResourceRuntimeError::AuthorizationUnavailable)?;
        let api = runtime
            .api
            .registered_controller_api(subject, authorization_state.clone(), assignments)
            .map_err(|_| ResourceRuntimeError::ResourceApiBindFailed)?;
        let allowed_types = descriptor
            .resource_types()
            .cloned()
            .collect::<BTreeSet<_>>();
        let resolver_store = Arc::clone(&runtime.store);
        let resolver_zone = runtime.zone.clone();
        let resolver_authority = Arc::clone(&authority);
        let resolver: AssignmentFenceResolver = Arc::new(move |target, uid, revision| {
            let store = Arc::clone(&resolver_store);
            let zone = resolver_zone.clone();
            let authority = Arc::clone(&resolver_authority);
            let allowed_types = allowed_types.clone();
            Box::pin(async move {
                if !allowed_types.contains(target.resource_type()) {
                    return Err(SourceError::Integrity);
                }
                if let Some(stored) = store.assignment_fence(zone, target.clone()).await.map_err(
                    |error| match error.kind() {
                        StoreErrorKind::Backpressure | StoreErrorKind::StoreBackpressure => {
                            SourceError::Backpressure
                        }
                        StoreErrorKind::Timeout => SourceError::Timeout,
                        _ => SourceError::Unavailable,
                    },
                )? {
                    if stored.resource_uid != uid
                        || stored.epoch > authority.epoch
                        || (stored.epoch == authority.epoch
                            && (stored.provider_generation != authority.provider_generation
                                || stored.controller_generation != authority.controller_generation
                                || stored.controller_role != authority.controller_role
                                || stored.target != authority.target
                                || stored.session_generation != authority.session_generation))
                    {
                        return Err(SourceError::Integrity);
                    }
                    if stored.epoch == authority.epoch && stored.resource_revision != revision {
                        return Err(SourceError::Conflict(stored.resource_revision));
                    }
                }
                Ok(ResourceAssignmentFence {
                    resource_uid: uid,
                    resource_revision: revision,
                    provider_generation: authority.provider_generation,
                    controller_generation: authority.controller_generation,
                    controller_role: authority.controller_role.clone(),
                    target: authority.target.clone(),
                    session_generation: authority.session_generation,
                    epoch: authority.epoch,
                    scope: ResourceAssignmentScope::Primary,
                })
            })
        });
        let api = api.with_assignment_fence_resolver(resolver);
        let source = CoreControllerSource::new(descriptor.clone(), Arc::new(api));
        let reconciler = GuestRuntimeReconciler::new(descriptor, kind, Arc::clone(&effects));
        let runner = Runner::new(
            reconciler,
            source,
            RunnerConfig {
                policy_revision: authorization_state.snapshot.policy_revision,
                api_revision: authorization_state.snapshot.api_catalog_revision,
                configuration_revision: authorization_state.snapshot.active_configuration_revision,
                deadline_tick: 5_000,
                max_attempts: 3,
            },
        );
        tasks.push(tokio::spawn(async move {
            if let Err(error) = runner.run().await {
                tracing::warn!(error = %error, "U6 Guest runtime shared Runner stopped");
            }
        }));
    }
    let mut slot = runtime
        .u6_runner_tasks
        .lock()
        .map_err(|_| ResourceRuntimeError::WatchUnavailable)?;
    slot.extend(tasks);
    Ok(true)
}

async fn provider_generations(
    runtime: &super::ZoneResourceRuntime,
) -> Result<
    (
        Vec<SharedGuestRunnerRegistration>,
        BTreeMap<ResourceRef, ResourceGeneration>,
    ),
    ResourceRuntimeError,
> {
    let mut generations = BTreeMap::new();
    let mut active = Vec::new();
    for registration in U6_SHARED_PROVIDER_RUNNERS {
        let provider_ref = ResourceRef::parse(registration.provider_ref)
            .map_err(|_| ResourceRuntimeError::HandlerNotReady)?;
        match runtime
            .store
            .get(StoreGetRequest {
                operation: StoreOperationContext {
                    operation_id: "u6-provider-generation".to_owned(),
                    idempotency_key: None,
                    correlation_id: "u6-provider-generation".to_owned(),
                    trace_id: None,
                    deadline_ms: 10_000,
                },
                zone: runtime.zone.clone(),
                target: provider_ref.clone(),
                expected_uid: None,
                projection: StoreProjection::MetadataOnly,
            })
            .await
        {
            Ok(provider) if provider.zone == runtime.zone && provider.generation.get() > 0 => {
                generations.insert(provider_ref, provider.generation);
                active.push(registration);
            }
            Err(error) if error.kind() == StoreErrorKind::ResourceNotFound => {
                let owned_guest_exists = runtime
                    .committed_resources_of_type(registration.resource_type)
                    .await?
                    .into_iter()
                    .any(|guest| {
                        guest.pointer("/spec/providerRef").and_then(Value::as_str)
                            == Some(registration.provider_ref)
                    });
                if owned_guest_exists {
                    return Err(ResourceRuntimeError::ProviderPathUnavailable);
                }
            }
            Err(_) => return Err(ResourceRuntimeError::StoreReadFailed),
            _ => return Err(ResourceRuntimeError::HandlerNotReady),
        }
    }
    Ok((active, generations))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_guest_runtime_registration_is_provider_ref_scoped() {
        assert_eq!(U6_SHARED_PROVIDER_RUNNERS.len(), 4);
        let refs = U6_SHARED_PROVIDER_RUNNERS
            .iter()
            .map(|registration| registration.provider_ref)
            .collect::<BTreeSet<_>>();
        assert_eq!(refs.len(), 4);
        assert!(
            U6_SHARED_PROVIDER_RUNNERS
                .iter()
                .all(|registration| registration.resource_type == "Guest")
        );
        assert!(
            U6_SHARED_PROVIDER_RUNNERS
                .iter()
                .all(|registration| registration.legacy_scheduler_disabled)
        );
        assert!(
            U6_SHARED_PROVIDER_RUNNERS
                .iter()
                .all(|registration| registration.watched_configuration_is_dependency)
        );
    }

    #[test]
    fn guest_runtime_descriptors_require_authoritative_provider_generations() {
        let registration = U6_SHARED_PROVIDER_RUNNERS[0];
        let error = compose_shared_guest_runner_descriptors(
            [registration],
            ZoneId::parse("work").unwrap(),
            ControllerGeneration::new(1).unwrap(),
            &BTreeMap::new(),
            ReconnectGeneration::new(1).unwrap(),
        )
        .expect_err("missing Provider generation must fail closed");
        assert_eq!(error, ResourceRuntimeError::HandlerNotReady);
    }
}
