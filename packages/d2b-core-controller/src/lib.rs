//! Fixed core-controller handlers and pure reconciliation policy.

// `main.rs` is a library module here, not a binary crate root; the crate turns
// off binary auto-discovery so cargo does not claim it as one. The lint that
// warns about the name is emitted while modules are collected, so it can only
// be allowed at the crate root.
#![allow(special_module_name)]

pub mod api_catalog;
pub mod audit;
pub mod authority;
pub mod authority_persistence;
pub mod authz;
pub mod authz_audit;
pub mod binding_children;
pub mod budgets;
pub mod cleanup;
pub mod configuration;
pub mod controller_assignment;
pub mod controllers;
pub mod coordinator;
pub mod dependencies;
pub mod export_import;
pub mod export_import_projection;
pub mod hints;
pub mod main;
pub mod metrics;
pub mod migration;
pub mod optional_state_admission;
pub mod owner_reconcile;
pub mod ownership;
pub mod provider_effects;
pub mod providers;
pub mod rbac;
pub mod resource_store;
pub mod runtime;
pub mod store;
pub mod tracing;
pub mod user_session_authority;
pub mod watches;
pub mod zone_links;
pub mod zone_status;
pub mod zonelink;

pub use binding_children::{
    BindingChildMaterializationError, BindingChildReconciler, BindingChildResource,
    materialize_child_create_payload, observed_child_from_resource, semantic_child_digest,
};
pub use controller_assignment::{
    AssignmentEpoch, AssignmentError, AssignmentGrantError, AssignmentIdentity, AssignmentPhase,
    AssignmentRequest, AssignmentScope, AssignmentTarget, AssignmentTransportError, AssignmentVerb,
    CONTROLLER_ASSIGNMENT_STREAM_CREDIT, CONTROLLER_ASSIGNMENT_STREAM_ID,
    ControllerAssignmentExpectation, ControllerAssignmentGrant, ControllerAssignmentGrantStore,
    ControllerAssignmentRegistry, ControllerRoleContract, ControllerSessionBinding,
    GrantDisposition, MAX_ASSIGNMENT_GRANT_RESOURCE_TYPES, MAX_ASSIGNMENT_GRANT_SCOPES,
    MAX_ASSIGNMENT_GRANT_VERBS, MAX_CONTROLLER_ASSIGNMENT_GRANT_BYTES,
    MAX_SCOPED_COMMIT_TRANSPORT_BYTES, OwnerChildScope, ResourceClientLease, ScopedCommitTransport,
    ScopedResourceFilter, ScopedResourceMutation, ScopedResourceQuery, ScopedResourceScope,
};
pub use controllers::{
    AggregateHealth, CORE_PROVIDER_API_BINDING_FINALIZER, CORE_RESOURCE_CONTROLLER_REGISTRATIONS,
    CoreHandlerKind, CoreHandlerRegistry, CoreResourceControllerRegistration, CurrencyAggregation,
    CurrencyAggregationError, HandlerOutcome, HandlerPhase, HandlerStatus,
};
pub use d2b_controller_toolkit::{
    CommitDecision, CommitOutcome, ControllerDescriptor, ControllerExecutionPolicy,
    ControllerHealth, ControllerIdentity, ControllerSelector, ControllerSource, ControllerVerb,
    DependencySnapshot, DisruptionClass, DrainResult, FinalizeResult, FreshSnapshot,
    HandlerFailure, InitialList, InitialResource, MutationIntent, MutationIntentKind,
    ObservationResult, OperationContext, PriorityLane, ProjectionDisposition, ReconcileContext,
    ReconcileDisposition, ReconcilePlan, ReconcileProjection, ReconcileReason, ReconcileResult,
    ResourceKey, ResourceMutationBatch, ResourceReconciler, ResourceRegistration, ResourceSnapshot,
    ResyncPolicy, Runner, RunnerConfig, SelectorField, SourceError, StatusPersistence,
    TriggerReason, TriggerSet, UpdateAssessment, UpdateAssessmentState, UpgradePlan, UpgradeStage,
    ValidationResult, WatchEvent, WatchFailure, WatchHint,
};
pub use dependencies::{
    DependencyError, DependencyEvent, DependencyIndex, DependencyTeardownPlan, DependencyTrigger,
    UpgradeOrder,
};
pub use export_import::{
    AdmittedExport, AdmittedImport, ExportImportError, ProjectionServiceIdentity,
    admit_binding_target, admit_export, admit_factory_pair, admit_import, projection_identity,
};
pub use export_import_projection::{
    ProjectionAction, ProjectionController, ProjectionLeaseState, ProjectionLifecycleError,
    ProjectionObservation, ProjectionPhase, ProjectionPlan, ProjectionRouteState,
    ProjectionService, ProjectionServiceObservation,
};
pub use hints::{
    ChangeField, ChangeRecord, ControllerBinding, ControllerHint, ControllerLeaseKey,
    CoreTriggerReason, FairAdmission, HintAdmissionError, HintAdmissionOutcome, HintTarget,
    SuppressionDecision, WatchPlan, WatchPlanError, WatchRegistry, WatchSelector,
};
pub use owner_reconcile::{
    DesiredChild, MAX_OWNER_CHILD_BATCH, MAX_OWNER_CHILD_DEPENDENCIES, ObservedChild,
    OwnedChildIntent, OwnedChildKind, OwnerBatchRecovery, OwnerBatchResult, OwnerChildBatch,
    OwnerChildIdentity, OwnerGraph, OwnerGraphError, OwnerIndex, OwnerLimits, OwnerMutation,
    OwnerReconcileError, OwnerReconcilePlan, OwnerTrigger, ProcessSchedulingClass, TeardownPlan,
};
pub use runtime::{
    CoreAdmissionCounts, CoreControllerDescriptorError, CoreControllerSource, CoreDispatchOutcome,
    CoreReconcileError, CoreResourceReconciler, CoreSourceError, RegisteredControllerApi,
    core_controller_descriptors,
};
pub use zone_status::{SystemCoreStatusEmitter, ZoneRuntimeMetadata, ZoneStatusInput};
