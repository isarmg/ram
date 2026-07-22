use super::{
    BLOCKING_POOL_SHUTDOWN_TIMEOUT, build_runtime, connection_lifetime_deadline,
    http1_request_head_semantic_size, prepare_unix_listener, remove_stale_unix_socket,
    response_has_wire_body, validate_stale_unix_socket_owner_policy,
    validate_unix_socket_ancestor_chain_policy, validate_unix_socket_owner_policy,
};
use crate::config::Args;
use crate::http::body_full;
use crate::identity::OutputPathIdentity;
use crate::server::Response;
use anyhow::{Context, Result};
use assert_fs::TempDir;
use hyper::{Method, Request, StatusCode, Version};
use socket2::{Domain, SockAddr, Socket, Type};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn capture_socket(path: &Path) -> Result<(OutputPathIdentity, PathBuf)> {
    let output = OutputPathIdentity::capture_no_symlinks(path)?;
    let operation_path = output.parent().proc_fd_path()?.join(output.basename());
    Ok((output, operation_path))
}

fn socket_bind_diagnostics(path: &Path) -> String {
    let parent_mode = path
        .parent()
        .and_then(|parent| std::fs::metadata(parent).ok())
        .map(|metadata| format!("{:04o}", metadata.mode() & 0o7777))
        .unwrap_or_else(|| "unavailable".to_owned());
    let process_umask = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with("Umask:"))
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "Umask: unavailable".to_owned());
    format!(
        "AF_UNIX test bind failed for `{}` (parent mode {parent_mode}; {process_umask})",
        path.display()
    )
}

#[test]
fn blocking_pool_has_a_hard_global_running_worker_limit() -> Result<()> {
    let runtime = build_runtime(1)?;
    let (first_started_tx, first_started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let first = runtime.handle().spawn_blocking(move || {
        first_started_tx.send(()).unwrap();
        release_rx.recv().unwrap();
    });
    first_started_rx.recv_timeout(Duration::from_secs(1))?;

    let (second_started_tx, second_started_rx) = mpsc::channel();
    let second = runtime.handle().spawn_blocking(move || {
        second_started_tx.send(()).unwrap();
    });
    assert!(
        second_started_rx
            .recv_timeout(Duration::from_millis(50))
            .is_err(),
        "a second blocking worker ran above the configured hard limit"
    );

    release_tx.send(())?;
    runtime.block_on(async {
        first.await.unwrap();
        second.await.unwrap();
    });
    second_started_rx.recv_timeout(Duration::from_secs(1))?;
    runtime.shutdown_timeout(BLOCKING_POOL_SHUTDOWN_TIMEOUT);
    Ok(())
}

#[test]
fn runtime_shutdown_timeout_does_not_claim_to_terminate_stuck_syscall() -> Result<()> {
    let runtime = build_runtime(1)?;
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (exited_tx, exited_rx) = mpsc::channel();
    runtime.handle().spawn_blocking(move || {
        started_tx.send(()).unwrap();
        release_rx.recv().unwrap();
        exited_tx.send(()).unwrap();
    });
    started_rx.recv_timeout(Duration::from_secs(1))?;

    let started = Instant::now();
    runtime.shutdown_timeout(Duration::from_millis(20));
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "runtime shutdown waited indefinitely for a stuck blocking worker"
    );
    assert!(exited_rx.try_recv().is_err());

    // 中文：shutdown_timeout 只分离而不杀 syscall；测试需释放它，避免保留 worker 线程。
    // English: `shutdown_timeout` detaches rather than kills the syscall; release it so tests do not retain the worker.
    release_tx.send(())?;
    exited_rx.recv_timeout(Duration::from_secs(1))?;
    Ok(())
}

#[test]
fn unix_socket_ancestors_require_both_trusted_owners_and_safe_write_policy() {
    let path = Path::new("/example/ram.sock");
    assert!(
        validate_unix_socket_ancestor_chain_policy(
            path,
            [
                (Path::new("/"), 0o755, true),
                (Path::new("/example"), 0o700, true),
            ],
        )
        .is_ok()
    );
    assert!(
        validate_unix_socket_ancestor_chain_policy(
            path,
            [
                (Path::new("/"), 0o755, true),
                (Path::new("/attacker"), 0o700, false),
                (Path::new("/attacker/example"), 0o700, true),
            ],
        )
        .is_err(),
        "a trusted immediate parent beneath an attacker-owned grandparent is unsafe"
    );
    assert!(
        validate_unix_socket_ancestor_chain_policy(
            path,
            [
                (Path::new("/"), 0o755, true),
                (Path::new("/example"), 0o777, true),
            ],
        )
        .is_err(),
        "a non-sticky writable ancestor cannot protect the socket name"
    );
    assert!(
        validate_unix_socket_ancestor_chain_policy(
            path,
            [
                (Path::new("/"), 0o755, true),
                (Path::new("/tmp"), 0o1777, true),
            ],
        )
        .unwrap(),
        "the final ancestor determines whether the parent is shared sticky"
    );
}

#[test]
fn unix_socket_owner_policy_distinguishes_private_and_shared_namespaces() {
    let path = Path::new("/example/ram.sock");
    assert!(validate_unix_socket_owner_policy(path, true, true).is_ok());
    assert!(
        validate_unix_socket_owner_policy(path, true, false).is_err(),
        "an untrusted socket owner can replace its name in a shared sticky directory"
    );
    assert!(
        validate_unix_socket_owner_policy(path, false, false).is_ok(),
        "a private parent makes an explicit target UID an administrator delegation"
    );
}

#[test]
fn stale_unix_socket_cleanup_always_requires_a_trusted_owner() {
    let path = Path::new("/example/ram.sock");
    assert!(validate_stale_unix_socket_owner_policy(path, true).is_ok());
    assert!(
        validate_stale_unix_socket_owner_policy(path, false).is_err(),
        "private parent access alone must not authorize deleting another owner's socket"
    );
}

#[test]
fn live_unix_socket_is_never_removed_by_startup_probe() -> Result<()> {
    let temp = TempDir::new()?;
    let path = temp.path().join("ram.sock");
    let _listener = UnixListener::bind(&path).with_context(|| socket_bind_diagnostics(&path))?;
    let inode = std::fs::symlink_metadata(&path)?.ino();
    let (output, operation_path) = capture_socket(&path)?;

    let error = remove_stale_unix_socket(&output, &operation_path)
        .expect_err("a live listener was incorrectly classified as stale");
    assert!(
        format!("{error:#}").contains("already served by a live process"),
        "unexpected live-socket error: {error:#}"
    );
    assert_eq!(std::fs::symlink_metadata(&path)?.ino(), inode);
    Ok(())
}

#[test]
fn disconnected_unix_socket_is_removed_as_stale() -> Result<()> {
    let temp = TempDir::new()?;
    let path = temp.path().join("ram.sock");
    let listener = UnixListener::bind(&path).with_context(|| socket_bind_diagnostics(&path))?;
    drop(listener);
    let (output, operation_path) = capture_socket(&path)?;

    remove_stale_unix_socket(&output, &operation_path)?;
    assert!(
        !path.exists(),
        "an unserved socket inode survived authoritative ECONNREFUSED"
    );
    Ok(())
}

#[test]
fn retained_unix_listener_parent_cannot_be_redirected_by_namespace_replacement() -> Result<()> {
    let temp = TempDir::new()?;
    let configured_parent = temp.path().join("sockets");
    let pinned_parent = temp.path().join("pinned-sockets");
    std::fs::create_dir(&configured_parent)?;
    let configured_path = configured_parent.join("ram.sock");
    let retained = OutputPathIdentity::capture_no_symlinks(&configured_path)?;

    // 中文：配置捕获后替换同名父目录并放入诱饵文件；启动只能在已固定旧目录中 bind，
    // 最终 namespace 复核必须安全失败，且清理 guard 不得删除新目录中的诱饵。
    // English: Replace the configured parent after capture and plant a decoy. Startup may bind
    // only below the pinned old parent, then must fail namespace verification without unlinking the decoy.
    std::fs::rename(&configured_parent, &pinned_parent)?;
    std::fs::create_dir(&configured_parent)?;
    let decoy = configured_parent.join("ram.sock");
    std::fs::write(&decoy, b"replacement namespace")?;

    let configured = configured_path.to_string_lossy();
    let error = match prepare_unix_listener(&configured, &Args::default(), Some(retained)) {
        Ok(_) => anyhow::bail!("listener startup followed a replaced configured namespace"),
        Err(error) => error,
    };
    assert!(
        format!("{error:#}").contains("is not a socket"),
        "unexpected namespace-replacement failure: {error:#}"
    );
    assert_eq!(
        std::fs::read(&decoy)?,
        b"replacement namespace",
        "pinned cleanup touched the replacement namespace"
    );
    assert!(
        !pinned_parent.join("ram.sock").exists(),
        "failed preparation left its socket in the pinned old parent"
    );
    Ok(())
}

#[test]
fn saturated_unix_backlog_probe_is_nonblocking_and_fail_closed() -> Result<()> {
    let temp = TempDir::new()?;
    let path = temp.path().join("ram.sock");
    let address = SockAddr::unix(&path)?;
    let listener = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    listener
        .bind(&address)
        .with_context(|| socket_bind_diagnostics(&path))?;
    listener.listen(1)?;
    let inode = std::fs::symlink_metadata(&path)?.ino();
    let (output, operation_path) = capture_socket(&path)?;

    let mut queued_clients = Vec::new();
    let mut saturated = false;
    for _ in 0..128 {
        let client = Socket::new(Domain::UNIX, Type::STREAM.nonblocking(), None)?;
        match client.connect(&address) {
            Ok(()) => queued_clients.push(client),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                saturated = true;
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }
    assert!(saturated, "failed to saturate the AF_UNIX accept backlog");

    let started = Instant::now();
    let error = remove_stale_unix_socket(&output, &operation_path)
        .expect_err("a saturated live socket was incorrectly deleted");
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "nonblocking live-socket probe stalled for {:?}",
        started.elapsed()
    );
    assert!(
        format!("{error:#}").contains("live, busy, or could not be verified"),
        "unexpected saturated-socket error: {error:#}"
    );
    assert_eq!(
        std::fs::symlink_metadata(&path)?.ino(),
        inode,
        "fail-closed probe removed the original live socket inode"
    );
    drop(queued_clients);
    drop(listener);
    Ok(())
}

#[test]
fn connection_lifetime_deadline_is_anchored_to_accept_time() {
    let observed_now = tokio::time::Instant::now();
    let accepted_at = observed_now - Duration::from_secs(9);
    let deadline = connection_lifetime_deadline(accepted_at, Duration::from_secs(10));
    assert_eq!(deadline - accepted_at, Duration::from_secs(10));
    assert!(
        deadline <= observed_now + Duration::from_secs(1),
        "time spent before HTTP service incorrectly extended the absolute lifetime"
    );
}

#[test]
fn response_idle_monitor_is_skipped_for_head_and_bodyless_responses() {
    let response = Response::new(body_full("payload"));
    assert!(response_has_wire_body(&Method::GET, &response));
    assert!(!response_has_wire_body(&Method::HEAD, &response));

    let empty = Response::new(body_full(""));
    assert!(!response_has_wire_body(&Method::GET, &empty));

    for status in [
        StatusCode::NO_CONTENT,
        StatusCode::RESET_CONTENT,
        StatusCode::NOT_MODIFIED,
    ] {
        let mut response = Response::new(body_full("must not reach the wire"));
        *response.status_mut() = status;
        assert!(!response_has_wire_body(&Method::GET, &response));
    }
}

#[test]
fn http1_semantic_head_size_matches_its_canonical_wire_form() -> Result<()> {
    let wire =
        "CUSTOM http://example.test/path?q=1 HTTP/1.0\r\nHost: example.test\r\nX-Test: abc\r\n\r\n";
    let request = Request::builder()
        .method("CUSTOM")
        .uri("http://example.test/path?q=1")
        .version(Version::HTTP_10)
        .header("host", "example.test")
        .header("x-test", "abc")
        .body(())?;
    assert_eq!(http1_request_head_semantic_size(&request), Some(wire.len()));

    let h2 = Request::builder()
        .uri("https://example.test/")
        .version(Version::HTTP_2)
        .body(())?;
    assert_eq!(http1_request_head_semantic_size(&h2), None);
    Ok(())
}
