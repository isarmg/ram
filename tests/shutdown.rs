#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/utils.rs"]
mod utils;

use fixtures::{
    Error, ServerProc, TEST_AUTH_PASS, TEST_AUTH_RULE, TEST_AUTH_USER, port, ram_command, tmpdir,
};

use assert_cmd::prelude::*;
use assert_fs::fixture::TempDir;
use predicates::prelude::*;
use rstest::rstest;
use rustix::fs::{FlockOperation, flock};
use std::fs::{File, FileTimes, OpenOptions};
use std::io::Write;
use std::net::TcpStream;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime};

fn spawn_server(tmpdir: &TempDir, port: u16) -> ServerProc {
    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE]);
    ServerProc::spawn(cmd)
}

fn spawn_server_with_cleanup(tmpdir: &TempDir, port: u16) -> ServerProc {
    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args([
        "--auth",
        TEST_AUTH_RULE,
        "--stale-upload-cleanup-age",
        "1s",
        "--stale-upload-cleanup-max-entries",
        "1000",
        "--stale-upload-cleanup-max-depth",
        "16",
        "--stale-upload-cleanup-max-deletions",
        "100",
        "--stale-upload-cleanup-timeout",
        "5s",
    ]);
    ServerProc::spawn(cmd)
}

fn bounded_cleanup_args() -> [&'static str; 12] {
    [
        "--stale-upload-cleanup-age",
        "1s",
        "--stale-upload-cleanup-max-entries",
        "1",
        "--stale-upload-cleanup-max-depth",
        "16",
        "--stale-upload-cleanup-max-deletions",
        "100",
        "--stale-upload-cleanup-timeout",
        "5s",
        "--auth",
        TEST_AUTH_RULE,
    ]
}

fn old_private_file(path: &Path) -> Result<File, Error> {
    let file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.set_times(
        FileTimes::new().set_modified(SystemTime::now() - Duration::from_secs(2 * 60 * 60)),
    )?;
    Ok(file)
}

fn staging_candidate_count(root: &Path) -> Result<usize, Error> {
    Ok(std::fs::read_dir(root)?
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
        .filter(|name| {
            (name.starts_with(".ram-upload-") || name.starts_with(".ram-staging-"))
                && name.ends_with(".tmp")
        })
        .count())
}

fn wait_for_staging_candidate_count(
    root: &Path,
    expected: usize,
    within: Duration,
) -> Result<(), Error> {
    let deadline = Instant::now() + within;
    loop {
        let count = staging_candidate_count(root)?;
        if count == expected {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "staging candidate count did not become {expected} in time (found {count})"
            )
            .into());
        }
        sleep(Duration::from_millis(20));
    }
}

#[rstest]
fn sigterm_triggers_clean_exit(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let mut server = spawn_server(&tmpdir, port);

    // 服务器正常服务。 / The server is serving normally.
    let resp = fetch!(b"GET", format!("http://localhost:{port}/"))
        .basic_auth(TEST_AUTH_USER, Some(TEST_AUTH_PASS))
        .send()?;
    assert_eq!(resp.status(), 200);

    server.sigterm();

    let status = server
        .wait_exit(Duration::from_secs(10))
        .expect("server did not exit within 10s of SIGTERM");
    assert!(status.success(), "expected clean exit, got {status}");
    Ok(())
}

#[rstest]
fn sigterm_stops_accepting_new_connections(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let mut server = spawn_server(&tmpdir, port);
    server.sigterm();

    // 给 accept 循环片刻观察关停信号。 / Give the accept loop time to observe shutdown.
    sleep(Duration::from_millis(300));

    // 关停开始后必须拒绝新连接。 / New connections must be refused once shutdown begins.
    let result = fetch!(b"GET", format!("http://localhost:{port}/"))
        .basic_auth(TEST_AUTH_USER, Some(TEST_AUTH_PASS))
        .timeout(Duration::from_secs(2))
        .send();
    assert!(
        result.is_err(),
        "new connection after SIGTERM should be refused"
    );

    let status = server
        .wait_exit(Duration::from_secs(10))
        .expect("server did not exit within 10s of SIGTERM");
    assert!(status.success(), "expected clean exit, got {status}");
    Ok(())
}

#[rstest]
fn sigterm_during_slow_upload_cleans_the_private_candidate(
    tmpdir: TempDir,
    port: u16,
) -> Result<(), Error> {
    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args([
        "--auth",
        TEST_AUTH_RULE,
        "--allow-upload",
        "--upload-idle-timeout",
        "1s",
        "--upload-total-timeout",
        "10s",
    ]);
    let mut server = ServerProc::spawn(cmd);

    let mut client = TcpStream::connect(("127.0.0.1", port))?;
    write!(
        client,
        "PUT /shutdown-partial.bin HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\nContent-Length: 5\r\nConnection: close\r\n\r\na"
    )?;
    wait_for_staging_candidate_count(tmpdir.path(), 1, Duration::from_secs(2))?;

    // 保持慢客户端连接：优雅关停等待上传的有界空闲超时，其 future Drop 拥有候选清理。
    // Keep the slow client connected; graceful shutdown awaits bounded idle timeout and future-owned cleanup.
    server.sigterm();
    let status = server
        .wait_exit(Duration::from_secs(10))
        .expect("server did not drain the timed-out upload after SIGTERM");
    assert!(status.success(), "expected clean exit, got {status}");
    assert_eq!(staging_candidate_count(tmpdir.path())?, 0);
    assert!(!tmpdir.path().join("shutdown-partial.bin").exists());
    drop(client);
    Ok(())
}

#[rstest]
fn incomplete_startup_scan_allows_reads_but_refuses_writable_start(port: u16) -> Result<(), Error> {
    let root = TempDir::new()?;
    let nested = root.path().join("ordinary-directory");
    std::fs::create_dir(&nested)?;
    let candidate = nested.join(".ram-upload-00000000-0000-4000-8000-000000000011.tmp");
    drop(old_private_file(&candidate)?);

    // 普通目录消耗 max_entries=1，子候选无论目录迭代顺序都确定不在扫描内；只读服务仍可用且仅警告。
    // The ordinary directory consumes max_entries=1, leaving its child deterministically unscanned
    // regardless of iteration order; read-only service remains available and only warns.
    let mut read_only_command = ram_command(root.path(), port);
    read_only_command.args(bounded_cleanup_args());
    let mut read_only = ServerProc::spawn(read_only_command);
    assert!(candidate.exists());
    let response = fetch!(b"GET", format!("http://localhost:{port}/"))
        .basic_auth(TEST_AUTH_USER, Some(TEST_AUTH_PASS))
        .send()?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    read_only.sigterm();
    assert!(
        read_only
            .wait_exit(Duration::from_secs(10))
            .is_some_and(|status| status.success())
    );

    let count_before = staging_candidate_count(&nested)?;
    let mut writable = ram_command(root.path(), port);
    writable.args(bounded_cleanup_args()).arg("--allow-upload");
    writable.assert().failure().stderr(predicate::str::contains(
        "refusing to start writable service because private upload recovery could not prove a complete cleanup",
    ));
    assert_eq!(staging_candidate_count(&nested)?, count_before);
    assert!(candidate.exists());
    Ok(())
}

#[rstest]
fn periodic_incomplete_scan_stickily_disables_new_upload_candidates(
    port: u16,
) -> Result<(), Error> {
    let root = TempDir::new()?;
    let mut command = ram_command(root.path(), port);
    command.args(bounded_cleanup_args()).arg("--allow-upload");
    let mut server = ServerProc::spawn(command);

    // 启动完整扫描空根后，为周期扫描引入确定的条目预算耗尽用例。
    // After complete empty-root startup scan, introduce deterministic entry-budget starvation for periodic pass.
    let nested = root.path().join("ordinary-directory");
    std::fs::create_dir(&nested)?;
    let candidate = nested.join(".ram-upload-00000000-0000-4000-8000-000000000012.tmp");
    drop(old_private_file(&candidate)?);
    sleep(Duration::from_millis(2_500));

    let response = fetch!(b"PUT", format!("http://localhost:{port}/blocked.bin"))
        .basic_auth(TEST_AUTH_USER, Some(TEST_AUTH_PASS))
        .body(b"must not be admitted".to_vec())
        .send()?;
    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert!(!root.path().join("blocked.bin").exists());
    assert!(candidate.exists());
    assert_eq!(staging_candidate_count(root.path())?, 0);

    server.sigterm();
    assert!(
        server
            .wait_exit(Duration::from_secs(10))
            .is_some_and(|status| status.success())
    );
    Ok(())
}

#[rstest]
fn periodic_cleanup_revisits_a_young_candidate_after_it_ages(port: u16) -> Result<(), Error> {
    let root = TempDir::new()?;
    let candidate = root
        .path()
        .join(".ram-upload-00000000-0000-4000-8000-000000000013.tmp");
    std::fs::write(&candidate, b"young")?;
    std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o600))?;

    let mut command = ram_command(root.path(), port);
    command.args([
        "--auth",
        TEST_AUTH_RULE,
        "--stale-upload-cleanup-age",
        "1s",
        "--stale-upload-cleanup-max-entries",
        "100",
        "--stale-upload-cleanup-max-depth",
        "16",
        "--stale-upload-cleanup-max-deletions",
        "100",
        "--stale-upload-cleanup-timeout",
        "5s",
    ]);
    let mut server = ServerProc::spawn(command);
    assert!(
        candidate.exists(),
        "startup incorrectly removed a young file"
    );
    wait_for_staging_candidate_count(root.path(), 0, Duration::from_secs(4))?;

    server.sigterm();
    assert!(
        server
            .wait_exit(Duration::from_secs(10))
            .is_some_and(|status| status.success())
    );
    Ok(())
}

#[rstest]
fn restart_cleanup_deletes_only_safe_unlocked_candidates(
    tmpdir: TempDir,
    port: u16,
) -> Result<(), Error> {
    let stale_upload = tmpdir
        .path()
        .join(".ram-upload-00000000-0000-4000-8000-000000000001.tmp");
    let stale_staging = tmpdir
        .path()
        .join(".ram-staging-00000000-0000-4000-8000-000000000002.tmp");
    drop(old_private_file(&stale_upload)?);
    drop(old_private_file(&stale_staging)?);

    let active = tmpdir
        .path()
        .join(".ram-upload-00000000-0000-4000-8000-000000000003.tmp");
    let active_file = old_private_file(&active)?;
    flock(&active_file, FlockOperation::NonBlockingLockExclusive)?;

    let young = tmpdir
        .path()
        .join(".ram-upload-00000000-0000-4000-8000-000000000004.tmp");
    std::fs::write(&young, b"young")?;
    std::fs::set_permissions(&young, std::fs::Permissions::from_mode(0o600))?;

    let wrong_mode = tmpdir
        .path()
        .join(".ram-upload-00000000-0000-4000-8000-000000000005.tmp");
    drop(old_private_file(&wrong_mode)?);
    std::fs::set_permissions(&wrong_mode, std::fs::Permissions::from_mode(0o640))?;

    let malformed = tmpdir
        .path()
        .join(".ram-upload-00000000-0000-4000-8000-00000000000A.tmp");
    drop(old_private_file(&malformed)?);

    let symlink_target = tmpdir.path().join("cleanup-symlink-target");
    std::fs::write(&symlink_target, b"must survive")?;
    let candidate_symlink = tmpdir
        .path()
        .join(".ram-upload-00000000-0000-4000-8000-000000000006.tmp");
    symlink(&symlink_target, &candidate_symlink)?;

    let mut first = spawn_server_with_cleanup(&tmpdir, port);
    assert!(!stale_upload.exists());
    assert!(!stale_staging.exists());
    for path in [&active, &young, &wrong_mode, &malformed, &candidate_symlink] {
        assert!(
            path.symlink_metadata().is_ok(),
            "startup cleanup removed an ineligible path: {path:?}"
        );
    }
    assert_eq!(std::fs::read(&symlink_target)?, b"must survive");

    let response = fetch!(
        b"GET",
        format!("http://localhost:{port}/.ram-upload-00000000-0000-4000-8000-00000000000A.tmp")
    )
    .basic_auth(TEST_AUTH_USER, Some(TEST_AUTH_PASS))
    .send()?;
    assert_eq!(
        response.status(),
        200,
        "non-canonical names are ordinary files"
    );

    first.sigterm();
    let status = first
        .wait_exit(Duration::from_secs(10))
        .expect("first server did not exit during restart test");
    assert!(
        status.success(),
        "expected clean first shutdown, got {status}"
    );
    drop(first);

    drop(active_file);
    let second = spawn_server_with_cleanup(&tmpdir, port);
    assert!(
        !active.exists(),
        "unlocked stale candidate survived replacement startup"
    );
    assert!(
        malformed.exists(),
        "replacement cleanup broadened the name grammar"
    );
    drop(second);
    Ok(())
}
