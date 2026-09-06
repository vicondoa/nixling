//! Provider-neutral readiness predicates and one-shot process waiting.

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use d2b_core::processes::{ProcessNode, ReadinessPredicate};

use crate::supervisor::{
    readiness_liveness::{LivenessProbe, RunnerLiveness},
    state::{ProcReader, SystemProcReader},
};

pub fn readiness_predicate_ready(predicate: &ReadinessPredicate) -> Result<bool, String> {
    match predicate {
        ReadinessPredicate::ApiSocketInfo(path) => Ok(api_socket_info_ready(path)),
        ReadinessPredicate::VsockNotify(value) => Ok(Path::new(value).exists()),
        ReadinessPredicate::UnixSocketExists(path) => Ok(unix_socket_exists(path)),
        ReadinessPredicate::UnixSocketListening(path) => Ok(unix_socket_listening(path)),
        ReadinessPredicate::TcpPort { host, port } => Ok(tcp_port_ready(host, *port)),
        ReadinessPredicate::Command(command) => command_ready(command),
        ReadinessPredicate::ComponentSpecific(_) => Ok(true),
        // The authenticated Guest ComponentSession readiness probe is evaluated through a
        // daemon-state-aware path (it needs the per-VM vsock socket, peer
        // credentials, and a broker-backed signer that this stateless helper
        // cannot reach). The live readiness path intercepts
        // `ComponentSessionHealth` nodes in `VmStartRunner::spawn_and_wait_ready`
        // before this generic evaluation is reached, so hitting this arm means
        // the state-aware routing regressed. Fail LOUD rather than silently
        // never-ready so the regression surfaces immediately.
        ReadinessPredicate::ComponentSessionHealth { .. } => {
            Err("guest-component-session-needs-state-aware-path".to_owned())
        }
    }
}

pub fn api_socket_info_ready(path: &str) -> bool {
    if !unix_socket_exists(path) {
        return false;
    }
    let Ok(mut socket) = UnixStream::connect(path) else {
        return false;
    };
    let _ = socket.set_read_timeout(Some(Duration::from_millis(250)));
    let _ = socket.set_write_timeout(Some(Duration::from_millis(250)));
    if socket
        .write_all(b"GET /api/v1/vm.info HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut buffer = [0_u8; 4096];
    let Ok(read) = socket.read(&mut buffer) else {
        return false;
    };
    if read == 0 {
        return false;
    }
    let response = String::from_utf8_lossy(&buffer[..read]);
    response.starts_with("HTTP/1.1 200") || response.starts_with("HTTP/1.0 200")
}

pub fn unix_socket_exists(path: &str) -> bool {
    fs::metadata(path)
        .map(|metadata| metadata.file_type().is_socket())
        .unwrap_or(false)
}

pub fn unix_socket_listening(path: &str) -> bool {
    const SO_ACCEPTCON: u64 = 0x0001_0000;
    let Ok(contents) = fs::read_to_string("/proc/net/unix") else {
        return false;
    };
    contents.lines().skip(1).any(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 {
            return false;
        }
        let flags = u64::from_str_radix(fields[3], 16).unwrap_or(0);
        let socket_type = fields[4];
        let socket_path = fields[7];
        socket_path == path && socket_type == "0001" && (flags & SO_ACCEPTCON) != 0
    })
}

pub fn tcp_port_ready(host: &str, port: u16) -> bool {
    let Ok(addrs) = format!("{host}:{port}").to_socket_addrs() else {
        return false;
    };
    addrs
        .into_iter()
        .any(|addr| TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_ok())
}

pub fn wait_for_tcp_port(host: &str, port: u16, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        if tcp_port_ready(host, port) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("tcp-readiness-timeout:{host}:{port}"));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub fn command_ready(command: &[String]) -> Result<bool, String> {
    let Some(program) = command.first() else {
        return Err("command-readiness-empty".to_owned());
    };
    Command::new(program)
        .args(&command[1..])
        .env_remove("NOTIFY_SOCKET")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .map_err(|_| "command-readiness-exec-failed".to_owned())
}

pub fn wait_for_readiness(
    node: &ProcessNode,
    readiness: &[ReadinessPredicate],
    timeout: Duration,
    liveness: Option<&dyn LivenessProbe>,
) -> Result<(), String> {
    fn terminal_liveness_error(
        node: &ProcessNode,
        liveness: Option<&dyn LivenessProbe>,
    ) -> Option<String> {
        match liveness?.probe() {
            RunnerLiveness::Exited(_) => Some(format!("runner-exited:{}", node.id.0)),
            RunnerLiveness::Reused => Some(format!("runner-reused:{}", node.id.0)),
            RunnerLiveness::Alive | RunnerLiveness::Unknown => None,
        }
    }

    if readiness.is_empty() {
        return Ok(());
    }
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(error) = terminal_liveness_error(node, liveness) {
            return Err(error);
        }
        let mut all_ready = true;
        for predicate in readiness {
            if !readiness_predicate_ready(predicate)? {
                all_ready = false;
                break;
            }
        }
        if all_ready {
            if let Some(error) = terminal_liveness_error(node, liveness) {
                return Err(error);
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("readiness-timeout:{}", node.id.0));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Explicit
/// process-state outcomes from `/proc/<pid>/stat`. The previous
/// `Ok(None)` return conflated three different scenarios - file
/// missing (process gone), file unreadable (transient race),
/// and file present-but-unparseable (kernel format regression).
/// Callers can now distinguish these and decide whether to retry,
/// fail-fast, or treat as terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcState {
    /// The process is alive in the given state character (e.g.
    /// 'S' sleeping, 'R' running, 'D' uninterruptible sleep,
    /// 'Z' zombie awaiting reap, 'X' dead).
    Alive(char),
    /// `/proc/<pid>/stat` does not exist - process has been
    /// reaped (no parent holding pidfd) or never existed.
    Gone,
    /// `/proc/<pid>/stat` is present but unparseable. This is
    /// either a transient mid-write race or a kernel-format
    /// regression. Callers may log + retry; treating it as
    /// `Alive` would risk spinning, treating it as `Gone` would
    /// risk false-positive termination.
    ParseFailed,
}

pub fn wait_for_one_shot_exit(
    pid: i32,
    start_time_ticks: u64,
    timeout: Duration,
) -> Result<(), String> {
    let proc_reader = SystemProcReader;
    let deadline = Instant::now() + timeout;
    let mut parse_fail_warned = false;
    loop {
        match ProcReader::proc_starttime(&proc_reader, pid) {
            Ok(Some(observed)) if observed == start_time_ticks => {
                // v1.1.2fu34: the broker holds the pidfd as the spawn parent
                // but never explicitly reaps via waitid; the child becomes a
                // zombie which still has /proc/<pid>/stat returning the same
                // starttime. Treat process-state 'Z' (zombie) or 'X' (dead)
                // as terminated so OneShot DAG nodes don't spin until the
                // polling timeout.
                match read_proc_state(pid) {
                    Ok(ProcState::Alive('Z')) | Ok(ProcState::Alive('X')) => {
                        return Ok(());
                    }
                    Ok(ProcState::Alive(_)) => {} // keep polling
                    Ok(ProcState::Gone) => return Ok(()),
                    Ok(ProcState::ParseFailed) => {
                        if !parse_fail_warned {
                            tracing::warn!(
                                "wait_for_one_shot_exit: /proc/<pid>/stat unparseable; \
                                 continuing to poll (will surface as oneshot-timeout if persistent)"
                            );
                            parse_fail_warned = true;
                        }
                    }
                    Err(err) => {
                        tracing::debug!(%err, "read_proc_state I/O error; continuing to poll");
                    }
                }
                if Instant::now() >= deadline {
                    return Err(format!("oneshot-timeout:{pid}"));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Ok(Some(_)) => return Err(format!("oneshot-starttime-drift:{pid}")),
            Ok(None) => return Ok(()),
            Err(_) => return Err(format!("oneshot-proc-read-failed:{pid}")),
        }
    }
}

/// Parse `/proc/<pid>/stat` to extract the process-state field (field
/// 3, single character). Uses `rfind(')')` to correctly handle
/// comm fields containing `)` (the kernel emits `<pid> (<comm>)
/// <state> ...` and the LAST `)` always closes the comm field).
///
/// Returns:
/// - `Ok(ProcState::Alive(c))` when stat is readable and parses
/// - `Ok(ProcState::Gone)` when `/proc/<pid>/stat` is missing (ENOENT)
/// - `Ok(ProcState::ParseFailed)` when stat is readable but malformed
/// - `Err(io::Error)` for any other I/O error (permission, etc.)
fn read_proc_state(pid: i32) -> Result<ProcState, std::io::Error> {
    let path = format!("/proc/{pid}/stat");
    let data = match fs::read_to_string(&path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ProcState::Gone),
        Err(e) => return Err(e),
    };
    if let Some(close) = data.rfind(')') {
        let after = &data[close + 1..];
        let mut chars = after.split_whitespace();
        if let Some(state_str) = chars.next()
            && let Some(c) = state_str.chars().next()
        {
            return Ok(ProcState::Alive(c));
        }
    }
    Ok(ProcState::ParseFailed)
}

#[cfg(test)]
mod proc_state_tests {
    // Explicit coverage of
    // /proc/<pid>/stat parsing. Each case exercises the parser
    // with a synthetic stat-format string to ensure the
    // `rfind(')')` correctly handles comm names containing `)`
    // and that malformed input maps to `ParseFailed`, not
    // `Alive`.
    use super::*;

    fn parse(data: &str) -> ProcState {
        if let Some(close) = data.rfind(')') {
            let after = &data[close + 1..];
            let mut chars = after.split_whitespace();
            if let Some(state_str) = chars.next()
                && let Some(c) = state_str.chars().next()
            {
                return ProcState::Alive(c);
            }
        }
        ProcState::ParseFailed
    }

    #[test]
    fn simple_zombie() {
        assert_eq!(parse("1234 (sh) Z 1 1234 ..."), ProcState::Alive('Z'));
    }

    #[test]
    fn simple_running() {
        assert_eq!(parse("99 (bash) R 1 99 99 ..."), ProcState::Alive('R'));
    }

    #[test]
    fn comm_with_paren() {
        // Process comm contains ')' - rfind correctly picks the
        // OUTER closing paren that ends the comm field.
        assert_eq!(parse("42 (foo) bar) Z 1 42 ..."), ProcState::Alive('Z'));
    }

    #[test]
    fn comm_with_spaces_and_paren() {
        assert_eq!(parse("7 (cmd (in jail)) S 1 7 ..."), ProcState::Alive('S'));
    }

    #[test]
    fn truncated_stat() {
        // Comm present but no state field after - ParseFailed.
        assert_eq!(parse("1234 (sh)"), ProcState::ParseFailed);
    }

    #[test]
    fn no_paren_at_all() {
        // Garbage input without comm parens - ParseFailed.
        assert_eq!(parse("not a stat line at all"), ProcState::ParseFailed);
    }

    #[test]
    fn empty_input() {
        assert_eq!(parse(""), ProcState::ParseFailed);
    }

    #[test]
    fn dead_process() {
        assert_eq!(parse("88 (init) X 1 88 ..."), ProcState::Alive('X'));
    }
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod unix_socket_readiness_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;

    fn socket_path(name: &str) -> std::path::PathBuf {
        let directory = std::path::Path::new(".scratch");
        std::fs::create_dir_all(directory).expect("create scratch directory");
        directory.join(format!("d2b-{name}-{}.sock", std::process::id()))
    }

    #[test]
    pub fn unix_socket_listening_detects_listening_stream_socket_without_connecting() {
        let path = std::env::temp_dir().join(format!("d2b-usl-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let path_str = path.to_string_lossy().to_string();

        assert!(!unix_socket_listening(&path_str));
        let listener = UnixListener::bind(&path).expect("bind unix listener");
        assert!(unix_socket_exists(&path_str));
        assert!(unix_socket_listening(&path_str));

        drop(listener);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    pub fn api_socket_info_requires_a_live_http_api() {
        let path = socket_path("api-readiness");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind API socket");
        let path_str = path.to_string_lossy().to_string();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept API request");
            let mut request = [0_u8; 256];
            let read = stream.read(&mut request).expect("read API request");
            assert!(read > 0);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .expect("write API response");
        });
        assert!(api_socket_info_ready(&path_str));
        server.join().expect("API server");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    pub fn api_socket_info_rejects_a_spawned_task_without_a_live_api() {
        let path = socket_path("api-readiness-empty");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind placeholder socket");
        let path_str = path.to_string_lossy().to_string();
        drop(listener);
        assert!(!api_socket_info_ready(&path_str));
        let _ = std::fs::remove_file(&path);
    }
}

/// Zombie-detection hermetic tests for `wait_for_one_shot_exit`.
/// Linux-only: depends on `/proc/<pid>/stat`.
///
/// No `unsafe` code: child processes are created via
/// `std::process::Command`.  Rust's `Child` does not call `waitpid` on
/// drop, so an exited child stays in 'Z' state until the test calls
/// `child.wait()` for cleanup.
#[cfg(test)]
#[cfg(target_os = "linux")]
mod wait_for_one_shot_exit_tests {
    use super::*;
    use std::process::{Child, Command};

    /// Read the `starttime` field (column 22) for `pid` from
    /// `/proc/<pid>/stat`.  Panics if the file is missing or
    /// unparseable - this is a test-only helper.
    fn read_start_time_ticks(pid: u32) -> u64 {
        let path = format!("/proc/{pid}/stat");
        let content = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        crate::supervisor::state::parse_proc_stat_starttime(&content)
            .unwrap_or_else(|e| panic!("parse {path}: {e}"))
    }

    /// Spawn `sleep 0` - the child exits in < 1 ms, leaving a zombie
    /// behind because Rust's `Child::drop` does not call `waitpid`.
    fn spawn_zombie_child() -> Child {
        Command::new("sleep")
            .arg("0")
            .spawn()
            .expect("spawn 'sleep 0'")
    }

    /// Spawn `sleep 30` - alive for the duration of the test.
    fn spawn_sleeping_child() -> Child {
        Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn 'sleep 30'")
    }

    // v1.2 asserts the zombie shortcut path: `wait_for_one_shot_exit`
    // must return `Ok(())` immediately (≤100 ms) when the target is in
    // state 'Z', without waiting for the full polling timeout.
    #[test]
    fn wait_for_one_shot_exit_returns_ok_on_zombie_child() {
        let mut child = spawn_zombie_child();
        let pid = child.id();

        // Give 'sleep 0' a moment to exit and become a zombie.
        std::thread::sleep(Duration::from_millis(50));

        // The zombie's /proc/<pid>/stat is still present with 'Z' state
        // and the original starttime; read it now.
        let start_ticks = read_start_time_ticks(pid);

        let t0 = Instant::now();
        let result = wait_for_one_shot_exit(pid as i32, start_ticks, Duration::from_millis(500));
        let elapsed = t0.elapsed();

        // Reap the zombie before asserting so it isn't left around on
        // a test failure.
        child.wait().expect("waitpid zombie child");

        assert_eq!(result, Ok(()), "expected Ok(()) for zombie child");
        assert!(
            elapsed <= Duration::from_millis(100),
            "zombie shortcut must fire in ≤100 ms; took {elapsed:?}"
        );
    }

    // v1.2 asserts the timeout path - `wait_for_one_shot_exit` must
    // return `Err("oneshot-timeout:<pid>")` when the target stays alive
    // through the full polling window.
    #[test]
    fn wait_for_one_shot_exit_times_out_on_alive_process() {
        let mut child = spawn_sleeping_child();
        let pid = child.id();

        // Give the child a moment to be scheduled.
        std::thread::sleep(Duration::from_millis(10));

        let start_ticks = read_start_time_ticks(pid);

        let t0 = Instant::now();
        let result = wait_for_one_shot_exit(pid as i32, start_ticks, Duration::from_millis(100));
        let elapsed = t0.elapsed();

        // Kill and reap the child before asserting.
        child.kill().expect("kill sleeping child");
        child.wait().expect("waitpid sleeping child");

        assert_eq!(
            result,
            Err(format!("oneshot-timeout:{pid}")),
            "expected timeout error for alive process"
        );
        // The timeout is 100 ms; the polling loop sleeps 100 ms per
        // iteration, so elapsed must be ≥ 90 ms.
        assert!(
            elapsed >= Duration::from_millis(90),
            "expected ≥90 ms for timeout path; took {elapsed:?}"
        );
    }
}

#[cfg(test)]
mod notify_socket_spawn_policy_tests {
    #[test]
    fn production_readiness_command_removes_notify_socket() {
        let source = include_str!("readiness.rs");
        let command_ready = source
            .split("pub fn command_ready(command: &[String]) -> Result<bool, String> {")
            .nth(1)
            .and_then(|tail| tail.split("/// Explicit").next())
            .expect("command_ready source slice");
        assert!(
            command_ready.contains(".env_remove(\"NOTIFY_SOCKET\")"),
            "production readiness Command spawn must not pass NOTIFY_SOCKET to children",
        );
    }

    #[test]
    fn readiness_does_not_use_global_notify_socket_mutation() {
        let source = include_str!("readiness.rs");
        let forbidden = ["remove_var", "(\"NOTIFY_SOCKET\")"].concat();
        assert!(
            !source.contains(&forbidden),
            "do not mutate process-global environment; sanitize per Command instead",
        );
    }
}
