//! Effect-free Network reconcile planning.

use d2b_contracts_resource::v3::network::NetworkSpec;

/// Every ordered reconciliation step owned by network-local.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanStep {
    /// Create missing bridges with IPv6 disabled before link-up.
    CreateBridges,
    /// Re-apply IPv6 suppression.
    ApplySysctls,
    /// Apply one ownership-scoped host firewall projection.
    ApplyFirewallProjection,
    /// Reconcile NetworkManager unmanaged policy.
    ApplyNmUnmanaged,
    /// Reconcile host routes.
    ApplyRoutes,
    /// Reconcile the managed hosts block.
    UpdateHosts,
    /// Seed new DHCP reservations.
    SeedDhcp,
    /// Create or update the backing-only config Volume.
    UpsertVolumeBacking,
    /// Write all four config files through the Volume service.
    WriteVolumeContent,
    /// Create or update the net-VM Guest.
    UpsertGuest,
    /// Add the read-only Guest Volume attachment.
    AttachVolume,
    /// Create the guest-agent Process.
    UpsertAgent,
    /// Create or delete mDNS Process resources.
    ReconcileMdns,
    /// Reconcile attachment taps and bridge-port flags.
    ReconcileAttachments,
}

/// Bounded observation used to compute desired versus actual work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ActualState {
    /// Both bridges are present with matching parameters.
    pub bridges_ready: bool,
    /// Host sysctls match the desired values.
    pub sysctls_ready: bool,
    /// The projection-scoped digest matches.
    pub firewall_ready: bool,
    /// The config Volume backing is Ready.
    pub volume_ready: bool,
    /// The net-VM Guest is Ready.
    pub guest_ready: bool,
    /// The Volume attachment is Ready.
    pub attachment_ready: bool,
    /// The guest-agent Process is Ready.
    pub agent_ready: bool,
    /// Owned mDNS Process state matches the toggle.
    pub mdns_matches: bool,
}

/// An ordered, effect-free reconcile plan.
#[derive(Clone, PartialEq, Eq)]
pub struct NetworkReconcilePlan {
    steps: Vec<PlanStep>,
}

impl NetworkReconcilePlan {
    /// Borrow ordered steps.
    pub fn steps(&self) -> &[PlanStep] {
        &self.steps
    }
}

impl core::fmt::Debug for NetworkReconcilePlan {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NetworkReconcilePlan")
            .field("step_count", &self.steps.len())
            .finish()
    }
}

/// Compute the complete ordered plan without performing effects.
pub fn compute_plan(
    _spec: &NetworkSpec,
    _mdns_enabled: bool,
    actual: ActualState,
) -> NetworkReconcilePlan {
    let mut steps = Vec::new();
    if !actual.bridges_ready {
        steps.push(PlanStep::CreateBridges);
    }
    if !actual.sysctls_ready {
        steps.push(PlanStep::ApplySysctls);
    }
    if !actual.firewall_ready {
        steps.push(PlanStep::ApplyFirewallProjection);
    }
    steps.extend([
        PlanStep::ApplyNmUnmanaged,
        PlanStep::ApplyRoutes,
        PlanStep::UpdateHosts,
        PlanStep::SeedDhcp,
    ]);
    if !actual.volume_ready {
        steps.push(PlanStep::UpsertVolumeBacking);
    }
    steps.push(PlanStep::WriteVolumeContent);
    if !actual.guest_ready {
        steps.push(PlanStep::UpsertGuest);
    }
    if actual.guest_ready && !actual.attachment_ready {
        steps.push(PlanStep::AttachVolume);
    }
    if actual.attachment_ready && !actual.agent_ready {
        steps.push(PlanStep::UpsertAgent);
    }
    if !actual.mdns_matches {
        steps.push(PlanStep::ReconcileMdns);
    }
    steps.push(PlanStep::ReconcileAttachments);
    NetworkReconcilePlan { steps }
}
