//! Controller and supervisor ComponentSession service contracts.

mod controller;
mod supervisor;

pub use controller::{
    OpenSessionRequest, OpenSessionResult, SHELL_POOL_FINALIZER, SHELL_REPAIR_INTERVAL_SECS,
    SHELL_SESSION_FINALIZER, ShellRunnerContract, ShellTerminalController, shell_runner_contract,
};
pub use supervisor::{
    AttachReceipt, AttachRequest, Attachment, InMemoryShellAuthority, SessionCapability,
    SessionGrant, SessionSupervisor, ShellAuthorityLedger, ShellAuthorityPort,
    SupervisorProcessResource,
};

/// Public controller ComponentSession service name.
pub const CONTROLLER_SERVICE: &str = "shell-terminal.v3";
/// Per-session supervisor ComponentSession service name.
pub const SUPERVISOR_SERVICE: &str = "shell-session-supervisor.v1";
/// The sole bidirectional terminal stream name.
pub const TERMINAL_STREAM: &str = "terminal";
