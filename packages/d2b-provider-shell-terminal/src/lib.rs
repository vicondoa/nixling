//! Resource, controller, and supervisor contracts for `Provider/shell-terminal`.
//!
//! The Provider owns policy-backed shell pools, sessions, adoption, and the
//! bounded output-ring contract. It does not own an ambient host shell, raw
//! broker connection, or persistent controller state. OS PTY and user-scope
//! effects remain in the unsafe-local helper behind the generic helper wire;
//! the helper has no dependency on this Provider.

#![deny(missing_docs)]

mod authz;
mod guest_rules;
mod host_rules;
mod migration;
mod observability;
mod process_lifecycle;
mod process_templates;
mod resources;
mod service;
mod session;

pub use authz::{Authorizer, CallerOrigin, Role, Subject};
pub use guest_rules::{GuestPlacement, validate_guest_placement};
pub use host_rules::{HostPlacement, IsolationPosture, validate_host_placement};
pub use migration::{MigrationDisposition, ProviderStateSet};
pub use observability::{DiagnosticAccumulator, DiagnosticKind, ExecutionKind, ShellMetrics};
pub use process_lifecycle::SupervisorProcessLifecycle;
pub use process_templates::{ProcessTemplate, TemplateDomain};
pub use resources::{
    DEFAULT_MAX_ATTACHED, DEFAULT_MAX_SESSIONS, DEFAULT_OUTPUT_RING_CAPACITY, ExecutionTarget,
    PoolSpec, SessionPhase, ShellPool, ShellSession, ShellTerminalError,
};
pub use service::{
    AttachReceipt, AttachRequest, Attachment, CONTROLLER_SERVICE, InMemoryShellAuthority,
    OpenSessionRequest, OpenSessionResult, SUPERVISOR_SERVICE, SessionCapability, SessionGrant,
    SessionSupervisor, ShellAuthorityLedger, ShellAuthorityPort, ShellRunnerContract,
    ShellTerminalController, SupervisorProcessResource, TERMINAL_STREAM, shell_runner_contract,
};
pub use session::{
    AdoptionDecision, OutputRing, SupervisorCandidate, SupervisorIdentity, adopt_supervisor,
};
