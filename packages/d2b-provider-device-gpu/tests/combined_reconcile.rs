use d2b_contracts_resource::v3::{
    ResourceGeneration, ResourceRef, ResourceUid, device::DeviceArbitration,
};
use d2b_provider_device_gpu::{
    GpuAuthorityAdmission, GpuAuthorityLease, GpuBackingToken, GpuClosureProof, GpuController,
    GpuDependentResource, GpuEffectError, GpuEffectToken, GpuEffectTokenSet, GpuLaunchTicket,
    GpuLifecycleEffectPort, GpuOwnerProof, GpuPlatformToken, GpuPrincipalToken,
    GpuProcessIdentity, GpuProcessObservation, GpuProcessRole, GpuReconcileOutcome, GpuSettings,
    GpuWorkerSpec, VideoWorkerSpec,
};

#[derive(Default)]
struct FakePort {
    starts: Vec<GpuProcessRole>,
    next: u8,
    missing_roles: Vec<GpuProcessRole>,
    stale_roles: Vec<GpuProcessRole>,
    mismatched_observation: bool,
}

impl GpuLifecycleEffectPort for FakePort {
    fn reserve_authority(
        &mut self,
        _: &GpuAuthorityAdmission,
    ) -> Result<GpuAuthorityLease, GpuEffectError> {
        Ok(GpuAuthorityLease::from_core([1; 16]))
    }

    fn open_authorized_devices(
        &mut self,
        _: &GpuAuthorityAdmission,
        _: &GpuEffectTokenSet,
    ) -> Result<GpuLaunchTicket, GpuEffectError> {
        Ok(GpuLaunchTicket::from_core([2; 16]))
    }

    fn start_gpu_worker(
        &mut self,
        spec: &GpuWorkerSpec,
        _: &GpuLaunchTicket,
        principal: &GpuPrincipalToken,
        platform: &GpuPlatformToken,
        generation: ResourceGeneration,
    ) -> Result<GpuProcessIdentity, GpuEffectError> {
        self.next = self.next.saturating_add(1);
        self.starts.push(spec.process().role());
        Ok(GpuProcessIdentity::from_core(
            [self.next; 16],
            spec.process().role(),
            principal.clone(),
            platform.clone(),
            generation,
        ))
    }

    fn start_video_worker(
        &mut self,
        _: &VideoWorkerSpec,
        _: &GpuLaunchTicket,
        principal: &GpuPrincipalToken,
        platform: &GpuPlatformToken,
        generation: ResourceGeneration,
    ) -> Result<GpuProcessIdentity, GpuEffectError> {
        self.next = self.next.saturating_add(1);
        self.starts.push(GpuProcessRole::Video);
        Ok(GpuProcessIdentity::from_core(
            [self.next; 16],
            GpuProcessRole::Video,
            principal.clone(),
            platform.clone(),
            generation,
        ))
    }

    fn observe_worker(
        &mut self,
        identity: &GpuProcessIdentity,
    ) -> Result<GpuProcessObservation, GpuEffectError> {
        if self.stale_roles.contains(&identity.role()) {
            Ok(GpuProcessObservation::StaleIdentity)
        } else if self.missing_roles.contains(&identity.role()) {
            Ok(GpuProcessObservation::Missing)
        } else if self.mismatched_observation {
            Ok(GpuProcessObservation::Matching(
                GpuProcessIdentity::from_core(
                    [99; 16],
                    identity.role(),
                    identity.principal().clone(),
                    identity.platform().clone(),
                    identity.generation(),
                ),
            ))
        } else {
            Ok(GpuProcessObservation::Matching(identity.clone()))
        }
    }

    fn stop_worker(
        &mut self,
        identity: &GpuProcessIdentity,
    ) -> Result<GpuClosureProof, GpuEffectError> {
        Ok(GpuClosureProof::from_core(identity.clone()))
    }

    fn release_authority(
        &mut self,
        _: GpuAuthorityLease,
        _: &[GpuClosureProof],
    ) -> Result<(), GpuEffectError> {
        Ok(())
    }
}

#[test]
fn video_starts_only_after_gpu_worker_is_ready() {
    let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
    let owner = GpuOwnerProof::new(
        ResourceRef::parse("Zone/dev").unwrap(),
        ResourceRef::parse("Guest/workload").unwrap(),
        uid,
        ResourceUid::parse("223e4567-e89b-42d3-a456-426614174001").unwrap(),
        ResourceGeneration::new(1).unwrap(),
    )
    .unwrap();
    let admission = GpuAuthorityAdmission::new(
        owner,
        GpuBackingToken::from_core([7; 32]),
        GpuPlatformToken::from_core([8; 32]),
        DeviceArbitration::Exclusive,
        1,
        false,
        GpuPrincipalToken::from_core([9; 32]),
    )
    .unwrap()
    .with_video_principal(GpuPrincipalToken::from_core([10; 32]))
    .unwrap();
    let settings = GpuSettings {
        video_sidecar: true,
        ..GpuSettings::default()
    };
    let tokens = GpuEffectTokenSet::from_core(vec![GpuEffectToken::from_core([2; 32])]).unwrap();
    let mut controller = GpuController::new_authorized(admission, settings, tokens).unwrap();
    let mut port = FakePort::default();
    assert_eq!(
        controller.reconcile_lifecycle(&mut port).unwrap(),
        GpuReconcileOutcome::Converged
    );
    assert_eq!(controller.phase(), d2b_provider_device_gpu::GpuPhase::Ready);
    assert_eq!(
        port.starts,
        [GpuProcessRole::FullGpu, GpuProcessRole::Video]
    );
}

#[test]
fn partial_restart_adoption_restarts_only_the_missing_video_worker() {
    let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
    let owner = GpuOwnerProof::new(
        ResourceRef::parse("Zone/dev").unwrap(),
        ResourceRef::parse("Guest/workload").unwrap(),
        uid,
        ResourceUid::parse("223e4567-e89b-42d3-a456-426614174001").unwrap(),
        ResourceGeneration::new(1).unwrap(),
    )
    .unwrap();
    let admission = GpuAuthorityAdmission::new(
        owner,
        GpuBackingToken::from_core([7; 32]),
        GpuPlatformToken::from_core([8; 32]),
        DeviceArbitration::Exclusive,
        1,
        false,
        GpuPrincipalToken::from_core([9; 32]),
    )
    .unwrap()
    .with_video_principal(GpuPrincipalToken::from_core([10; 32]))
    .unwrap();
    let settings = GpuSettings {
        video_sidecar: true,
        ..GpuSettings::default()
    };
    let tokens = GpuEffectTokenSet::from_core(vec![GpuEffectToken::from_core([2; 32])]).unwrap();
    let mut controller =
        GpuController::new_authorized(admission.clone(), settings, tokens).unwrap();
    let gpu = GpuProcessIdentity::from_core(
        [3; 16],
        GpuProcessRole::FullGpu,
        GpuPrincipalToken::from_core([9; 32]),
        GpuPlatformToken::from_core([8; 32]),
        ResourceGeneration::new(1).unwrap(),
    );
    let video = GpuProcessIdentity::from_core(
        [4; 16],
        GpuProcessRole::Video,
        GpuPrincipalToken::from_core([10; 32]),
        GpuPlatformToken::from_core([8; 32]),
        ResourceGeneration::new(1).unwrap(),
    );
    let mut port = FakePort {
        missing_roles: vec![GpuProcessRole::Video],
        ..FakePort::default()
    };

    assert_eq!(
        controller
            .adopt_lifecycle(
                GpuAuthorityLease::from_core([1; 16]),
                &[gpu, video],
                &mut port,
            )
            .unwrap(),
        GpuReconcileOutcome::Retry
    );
    assert_eq!(
        controller.gpu_identity().map(|identity| identity.role()),
        Some(GpuProcessRole::FullGpu)
    );
    assert!(controller.video_identity().is_none());

    assert_eq!(
        controller.reconcile_lifecycle(&mut port).unwrap(),
        GpuReconcileOutcome::Converged
    );
    assert_eq!(port.starts, [GpuProcessRole::Video]);
}

#[test]
fn stale_identity_adoption_is_terminal_and_does_not_respawn() {
    let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
    let owner = GpuOwnerProof::new(
        ResourceRef::parse("Zone/dev").unwrap(),
        ResourceRef::parse("Guest/workload").unwrap(),
        uid,
        ResourceUid::parse("223e4567-e89b-42d3-a456-426614174001").unwrap(),
        ResourceGeneration::new(1).unwrap(),
    )
    .unwrap();
    let admission = GpuAuthorityAdmission::new(
        owner,
        GpuBackingToken::from_core([7; 32]),
        GpuPlatformToken::from_core([8; 32]),
        DeviceArbitration::Exclusive,
        1,
        false,
        GpuPrincipalToken::from_core([9; 32]),
    )
    .unwrap();
    let tokens = GpuEffectTokenSet::from_core(vec![GpuEffectToken::from_core([2; 32])]).unwrap();
    let mut controller =
        GpuController::new_authorized(admission, GpuSettings::default(), tokens).unwrap();
    let expected = GpuProcessIdentity::from_core(
        [3; 16],
        GpuProcessRole::FullGpu,
        GpuPrincipalToken::from_core([9; 32]),
        GpuPlatformToken::from_core([8; 32]),
        ResourceGeneration::new(1).unwrap(),
    );
    let mut port = FakePort {
        stale_roles: vec![GpuProcessRole::FullGpu],
        ..FakePort::default()
    };

    assert_eq!(
        controller.adopt_lifecycle(
            GpuAuthorityLease::from_core([1; 16]),
            std::slice::from_ref(&expected),
            &mut port,
        ),
        Err(d2b_provider_device_gpu::GpuControllerError::Effect(
            GpuEffectError::StaleDeviceIdentity
        ))
    );
    assert_eq!(
        controller.phase(),
        d2b_provider_device_gpu::GpuPhase::Failed
    );
    port.stale_roles.clear();
    port.missing_roles.push(GpuProcessRole::FullGpu);
    assert_eq!(
        controller.adopt_lifecycle(
            GpuAuthorityLease::from_core([1; 16]),
            std::slice::from_ref(&expected),
            &mut port,
        ),
        Err(d2b_provider_device_gpu::GpuControllerError::InvalidState)
    );
    assert_eq!(
        controller.phase(),
        d2b_provider_device_gpu::GpuPhase::Failed
    );
    assert_eq!(
        controller.reconcile_lifecycle(&mut port),
        Err(d2b_provider_device_gpu::GpuControllerError::InvalidState)
    );
    assert!(port.starts.is_empty());
}

#[test]
fn mismatched_matching_observation_is_quarantined() {
    let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
    let owner = GpuOwnerProof::new(
        ResourceRef::parse("Zone/dev").unwrap(),
        ResourceRef::parse("Guest/workload").unwrap(),
        uid,
        ResourceUid::parse("223e4567-e89b-42d3-a456-426614174001").unwrap(),
        ResourceGeneration::new(1).unwrap(),
    )
    .unwrap();
    let admission = GpuAuthorityAdmission::new(
        owner,
        GpuBackingToken::from_core([7; 32]),
        GpuPlatformToken::from_core([8; 32]),
        DeviceArbitration::Exclusive,
        1,
        false,
        GpuPrincipalToken::from_core([9; 32]),
    )
    .unwrap();
    let tokens = GpuEffectTokenSet::from_core(vec![GpuEffectToken::from_core([2; 32])]).unwrap();
    let mut controller =
        GpuController::new_authorized(admission, GpuSettings::default(), tokens).unwrap();
    let expected = GpuProcessIdentity::from_core(
        [3; 16],
        GpuProcessRole::FullGpu,
        GpuPrincipalToken::from_core([9; 32]),
        GpuPlatformToken::from_core([8; 32]),
        ResourceGeneration::new(1).unwrap(),
    );
    let mut port = FakePort {
        mismatched_observation: true,
        ..FakePort::default()
    };

    assert_eq!(
        controller.adopt_lifecycle(
            GpuAuthorityLease::from_core([1; 16]),
            std::slice::from_ref(&expected),
            &mut port,
        ),
        Err(d2b_provider_device_gpu::GpuControllerError::Quarantined)
    );
    assert_eq!(
        controller.phase(),
        d2b_provider_device_gpu::GpuPhase::Quarantined
    );
    port.mismatched_observation = false;
    port.missing_roles.push(GpuProcessRole::FullGpu);
    assert_eq!(
        controller.adopt_lifecycle(
            GpuAuthorityLease::from_core([1; 16]),
            &[expected],
            &mut port,
        ),
        Err(d2b_provider_device_gpu::GpuControllerError::InvalidState)
    );
    assert_eq!(
        controller.phase(),
        d2b_provider_device_gpu::GpuPhase::Quarantined
    );
}

#[test]
fn gpu_upgrade_requires_dependents_to_drain_before_replacement() {
    let uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap();
    let owner = GpuOwnerProof::new(
        ResourceRef::parse("Zone/dev").unwrap(),
        ResourceRef::parse("Guest/workload").unwrap(),
        uid.clone(),
        ResourceUid::parse("223e4567-e89b-42d3-a456-426614174001").unwrap(),
        ResourceGeneration::new(1).unwrap(),
    )
    .unwrap();
    let admission = GpuAuthorityAdmission::new(
        owner,
        GpuBackingToken::from_core([7; 32]),
        GpuPlatformToken::from_core([8; 32]),
        DeviceArbitration::Exclusive,
        1,
        false,
        GpuPrincipalToken::from_core([9; 32]),
    )
    .unwrap();
    let tokens = GpuEffectTokenSet::from_core(vec![GpuEffectToken::from_core([2; 32])]).unwrap();
    let mut controller =
        GpuController::new_authorized(admission, GpuSettings::default(), tokens).unwrap();
    let desired = GpuSettings {
        vulkan: false,
        ..GpuSettings::default()
    };
    let dependency = GpuDependentResource::new(
        ResourceRef::parse("Guest/workload").unwrap(),
        true,
        false,
    )
    .unwrap();
    let plan = controller
        .plan_upgrade(desired, std::slice::from_ref(&dependency))
        .unwrap();
    assert_eq!(
        controller.execute_upgrade(&plan, &mut FakePort::default()),
        Err(d2b_provider_device_gpu::GpuControllerError::DependenciesNotDrained)
    );
}
