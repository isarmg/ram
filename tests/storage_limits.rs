#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/utils.rs"]
mod utils;

use assert_fs::fixture::TempDir;
use fixtures::{
    Error, ServerProc, TEST_AUTH_PASS, TEST_AUTH_RULE, TEST_AUTH_USER, port, ram_command, tmpdir,
};
use rstest::rstest;
use std::fs;
use std::io::Write;
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::thread::{self, sleep};
use std::time::{Duration, Instant};

fn executable_hook(directory: &TempDir, body: &str) -> Result<PathBuf, Error> {
    let path = directory.path().join("quota-hook");
    fs::write(&path, format!("#!/bin/sh\nset -eu\n{body}\n"))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    Ok(path)
}

fn barrier_hook(directory: &TempDir) -> Result<PathBuf, Error> {
    // 固定钩子执行有意调用 `/proc/self/fd/N`，故 `$0` 不是可变原路径。把测试控制目录嵌为
    // 数据；从 `$0` 推导会测试路径执行，并令正确固定的 shebang 在屏障前退出。
    // Pinned hook execution deliberately invokes `/proc/self/fd/N`, so `$0` is not the mutable
    // original path. Embed the test control directory as data: deriving it from `$0` would test
    // pathname execution and make a correctly pinned shebang exit before reaching the barrier.
    let control = format!(
        "'{}'",
        directory.path().to_string_lossy().replace('\'', "'\"'\"'")
    );
    executable_hook(
        directory,
        &format!(
            r#"directory={control}
printf '%s\n' "$$" > "$directory/hook-pid"
: > "$directory/ready"
while [ ! -e "$directory/release" ]; do
    /bin/sleep 0.01
done"#
        ),
    )
}

fn storage_command(root: &Path, port: u16, hook: Option<&Path>) -> std::process::Command {
    let mut command = ram_command(root, port);
    command.args(["--auth", TEST_AUTH_RULE, "-A"]);
    if let Some(hook) = hook {
        command.arg("--storage-quota-hook").arg(hook);
    }
    command
}

fn url(port: u16, path: &str) -> String {
    format!("http://localhost:{port}/{path}")
}

fn copy_request(port: u16, source: &str, destination: &str) -> Result<reqwest::StatusCode, Error> {
    let response = fetch!(b"COPY", url(port, source))
        .header("Destination", url(port, destination))
        .basic_auth(TEST_AUTH_USER, Some(TEST_AUTH_PASS))
        .send()?;
    Ok(response.status())
}

fn listing_mutation_version(port: u16) -> Result<Option<String>, Error> {
    let response = fetch!(b"GET", url(port, "?json"))
        .basic_auth(TEST_AUTH_USER, Some(TEST_AUTH_PASS))
        .send()?;
    assert_eq!(response.status(), 200);
    let header = response
        .headers()
        .get("x-ram-mutation-version")
        .map(|value| value.to_str().map(str::to_owned))
        .transpose()?;
    let data: serde_json::Value = serde_json::from_str(&response.text()?)?;
    assert_eq!(
        data.get("mutation_version")
            .and_then(serde_json::Value::as_str),
        header.as_deref()
    );
    Ok(header)
}

fn candidate_count(root: &Path) -> Result<usize, Error> {
    Ok(fs::read_dir(root)?
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
        .filter(|name| {
            (name.starts_with(".ram-upload-") || name.starts_with(".ram-staging-"))
                && name.ends_with(".tmp")
        })
        .count())
}

fn wait_for_path(path: &Path, expected: bool, within: Duration) -> Result<(), Error> {
    let deadline = Instant::now() + within;
    loop {
        if path.exists() == expected {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "path {} did not become {} before the deadline",
                path.display(),
                if expected { "present" } else { "absent" }
            )
            .into());
        }
        sleep(Duration::from_millis(20));
    }
}

fn wait_for_no_candidates(root: &Path, within: Duration) -> Result<(), Error> {
    let deadline = Instant::now() + within;
    loop {
        let count = candidate_count(root)?;
        if count == 0 {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("{count} upload candidates remained after cleanup").into());
        }
        sleep(Duration::from_millis(20));
    }
}

fn wait_for_log(path: &Path, needle: &str, within: Duration) -> Result<String, Error> {
    let deadline = Instant::now() + within;
    loop {
        let contents = fs::read_to_string(path).unwrap_or_default();
        if contents.contains(needle) {
            return Ok(contents);
        }
        if Instant::now() >= deadline {
            return Err(format!("log did not contain `{needle}`: {contents}").into());
        }
        sleep(Duration::from_millis(20));
    }
}

#[rstest]
fn quota_hook_denial_is_507_and_has_a_stable_reason(
    tmpdir: TempDir,
    port: u16,
) -> Result<(), Error> {
    let control = TempDir::new()?;
    let hook = executable_hook(&control, "exit 23")?;
    let log = control.path().join("ram.log");
    let mut command = storage_command(tmpdir.path(), port, Some(&hook));
    command.arg("--log-file").arg(&log);
    let _server = ServerProc::spawn(command);

    assert_eq!(copy_request(port, "test.html", "denied.html")?, 507);
    assert!(!tmpdir.path().join("denied.html").exists());
    wait_for_no_candidates(tmpdir.path(), Duration::from_secs(2))?;
    let contents = wait_for_log(&log, "reason=quota_hook", Duration::from_secs(2))?;
    assert!(contents.contains("operation=COPY"), "log: {contents}");
    Ok(())
}

#[rstest]
fn quota_hook_denial_during_put_is_507_and_cleans_the_private_candidate(
    tmpdir: TempDir,
    port: u16,
) -> Result<(), Error> {
    let control = TempDir::new()?;
    let hook = executable_hook(&control, "exit 23")?;
    let command = storage_command(tmpdir.path(), port, Some(&hook));
    let _server = ServerProc::spawn(command);

    let response = fetch!(b"PUT", url(port, "denied-upload.bin"))
        .basic_auth(TEST_AUTH_USER, Some(TEST_AUTH_PASS))
        .body(b"payload".to_vec())
        .send()?;
    assert_eq!(response.status(), 507);
    assert!(!tmpdir.path().join("denied-upload.bin").exists());
    wait_for_no_candidates(tmpdir.path(), Duration::from_secs(2))?;
    Ok(())
}

#[rstest]
fn statvfs_preflight_is_advisory_but_denial_is_507_without_residue(
    tmpdir: TempDir,
    port: u16,
) -> Result<(), Error> {
    let mut command = storage_command(tmpdir.path(), port, None);
    command.args([
        "--storage-space-check",
        "--storage-reserve",
        "18446744073709551615",
    ]);
    let _server = ServerProc::spawn(command);

    assert_eq!(copy_request(port, "test.html", "preflight.html")?, 507);
    assert!(!tmpdir.path().join("preflight.html").exists());
    wait_for_no_candidates(tmpdir.path(), Duration::from_secs(2))?;
    Ok(())
}

#[rstest]
fn copy_deadline_cancels_hook_and_leaves_no_destination_or_candidate(
    tmpdir: TempDir,
    port: u16,
) -> Result<(), Error> {
    let control = TempDir::new()?;
    let hook = barrier_hook(&control)?;
    let mut command = storage_command(tmpdir.path(), port, Some(&hook));
    command.args([
        "--copy-timeout",
        "1s",
        "--storage-quota-hook-timeout",
        "10s",
        "--max-expensive-tasks",
        "1",
    ]);
    let _server = ServerProc::spawn(command);

    assert_eq!(copy_request(port, "test.html", "timed-out.html")?, 504);
    wait_for_path(&control.path().join("ready"), true, Duration::from_secs(2))?;
    assert!(!tmpdir.path().join("timed-out.html").exists());
    wait_for_no_candidates(tmpdir.path(), Duration::from_secs(2))?;
    Ok(())
}

#[rstest]
fn abrupt_server_exit_kills_an_active_quota_hook(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let control = TempDir::new()?;
    let hook = barrier_hook(&control)?;
    let mut command = storage_command(tmpdir.path(), port, Some(&hook));
    command.args([
        "--copy-timeout",
        "30s",
        "--storage-quota-hook-timeout",
        "30s",
    ]);
    let server = ServerProc::spawn(command);

    let request = thread::spawn(move || {
        copy_request(port, "test.html", "abrupt-exit.html").map_err(|error| error.to_string())
    });
    let ready = control.path().join("ready");
    wait_for_path(&ready, true, Duration::from_secs(2))?;
    let hook_pid = fs::read_to_string(control.path().join("hook-pid"))?
        .trim()
        .parse::<u32>()?;
    let hook_process = PathBuf::from(format!("/proc/{hook_pid}"));
    assert!(
        hook_process.exists(),
        "quota hook did not remain active at its barrier"
    );

    // 中文：测试失败或服务器被 SIGKILL 时，父进程死亡信号必须清理正在运行的钩子。
    // English: The parent-death signal must clean up an active hook when a
    // test fails or the server is SIGKILLed.
    drop(server);
    wait_for_path(&hook_process, false, Duration::from_secs(2))?;
    let _ = request.join().expect("COPY request thread panicked");
    Ok(())
}

#[rstest]
fn patch_deadline_preserves_original_and_cleans_staging(
    tmpdir: TempDir,
    port: u16,
) -> Result<(), Error> {
    let control = TempDir::new()?;
    let hook = barrier_hook(&control)?;
    let target = tmpdir.path().join("patch.bin");
    fs::write(&target, b"original")?;
    let mut command = storage_command(tmpdir.path(), port, Some(&hook));
    command.args([
        "--copy-timeout",
        "1s",
        "--storage-quota-hook-timeout",
        "10s",
        "--max-expensive-tasks",
        "1",
    ]);
    let _server = ServerProc::spawn(command);

    let response = fetch!(b"PATCH", url(port, "patch.bin"))
        .header("X-Update-Range", "append")
        .basic_auth(TEST_AUTH_USER, Some(TEST_AUTH_PASS))
        .body(b"-new".to_vec())
        .send()?;
    assert_eq!(response.status(), 504);
    assert_eq!(fs::read(&target)?, b"original");
    wait_for_no_candidates(tmpdir.path(), Duration::from_secs(2))?;
    Ok(())
}

#[rstest]
fn concurrent_copy_never_exceeds_expensive_worker_limit(
    tmpdir: TempDir,
    port: u16,
) -> Result<(), Error> {
    let control = TempDir::new()?;
    let hook = barrier_hook(&control)?;
    let mut command = storage_command(tmpdir.path(), port, Some(&hook));
    command.args([
        "--copy-timeout",
        "10s",
        "--storage-quota-hook-timeout",
        "10s",
        "--max-expensive-tasks",
        "1",
    ]);
    let _server = ServerProc::spawn(command);

    let first = thread::spawn(move || {
        copy_request(port, "test.html", "first-copy.html")
            .expect("first concurrent COPY request failed")
    });
    wait_for_path(&control.path().join("ready"), true, Duration::from_secs(2))?;
    assert_eq!(copy_request(port, "test.html", "second-copy.html")?, 503);
    assert!(!tmpdir.path().join("second-copy.html").exists());

    fs::write(control.path().join("release"), b"release")?;
    assert_eq!(first.join().expect("COPY request thread panicked"), 201);
    assert_eq!(
        fs::read(tmpdir.path().join("first-copy.html"))?,
        b"This is test.html"
    );
    wait_for_no_candidates(tmpdir.path(), Duration::from_secs(2))?;
    Ok(())
}

/// 与真实阻塞 COPY worker 重叠的目录扫描不得签名；守卫由 worker 持有，因而覆盖 quota hook/
/// 内核操作寿命，而不只覆盖 HTTP future 的准备阶段。
///
/// 该保护仅限本进程，并假设 Ram 是服务根的唯一写入者；其他进程直接写文件系统不会推进纪元。
///
/// Directory scans overlapping the real blocking COPY worker must remain unsigned. The guard is
/// worker-owned, so it covers the quota-hook/kernel-operation lifetime rather than merely the HTTP
/// future's setup phase.
///
/// This is process-local protection and assumes Ram is the only writer of the served root; direct
/// filesystem writes by another process do not advance the epoch.
#[rstest]
fn active_copy_worker_prevents_listing_snapshot_signature(
    tmpdir: TempDir,
    port: u16,
) -> Result<(), Error> {
    let control = TempDir::new()?;
    let hook = barrier_hook(&control)?;
    let mut command = storage_command(tmpdir.path(), port, Some(&hook));
    command.args([
        "--copy-timeout",
        "10s",
        "--storage-quota-hook-timeout",
        "10s",
        "--max-expensive-tasks",
        "2",
    ]);
    let _server = ServerProc::spawn(command);

    let copy = thread::spawn(move || {
        copy_request(port, "test.html", "snapshot-copy.html")
            .expect("COPY request failed while holding the snapshot barrier")
    });
    wait_for_path(&control.path().join("ready"), true, Duration::from_secs(2))?;
    assert_eq!(listing_mutation_version(port)?, None);

    fs::write(control.path().join("release"), b"release")?;
    assert_eq!(copy.join().expect("COPY request thread panicked"), 201);
    assert!(listing_mutation_version(port)?.is_some());
    Ok(())
}

#[rstest]
fn expensive_task_queue_timeout_is_bounded_and_recovers_after_true_worker_exit(
    tmpdir: TempDir,
    port: u16,
) -> Result<(), Error> {
    let control = TempDir::new()?;
    let hook = barrier_hook(&control)?;
    let mut command = storage_command(tmpdir.path(), port, Some(&hook));
    command.args([
        "--copy-timeout",
        "10s",
        "--storage-quota-hook-timeout",
        "10s",
        "--max-expensive-tasks",
        "1",
        "--expensive-task-timeout",
        "1s",
    ]);
    let _server = ServerProc::spawn(command);

    let copy = thread::spawn(move || {
        copy_request(port, "test.html", "worker-holder.html")
            .expect("permit-holder COPY request failed")
    });
    wait_for_path(&control.path().join("ready"), true, Duration::from_secs(2))?;

    let started = Instant::now();
    let queued = fetch!(b"GET", url(port, "test.html?hash"))
        .basic_auth(TEST_AUTH_USER, Some(TEST_AUTH_PASS))
        .send()?;
    let elapsed = started.elapsed();
    assert_eq!(queued.status(), 503);
    assert_eq!(queued.headers().get("retry-after").unwrap(), "1");
    assert!(elapsed >= Duration::from_millis(750), "elapsed {elapsed:?}");
    assert!(elapsed < Duration::from_secs(3), "elapsed {elapsed:?}");

    fs::write(control.path().join("release"), b"release")?;
    assert_eq!(copy.join().expect("permit-holder COPY panicked"), 201);
    assert_eq!(
        fs::read(tmpdir.path().join("worker-holder.html"))?,
        b"This is test.html"
    );

    // 恢复证明超时等待者未泄漏队列槽，且 permit 一直由原工作线程持有到真实退出，而非等待者
    // 截止时释放。
    // Recovery proves the timed-out waiter leaked no queue slot and that the permit remained with the
    // original worker until its true exit, rather than being released at the waiter's deadline.
    let recovered = fetch!(b"GET", url(port, "test.html?hash"))
        .basic_auth(TEST_AUTH_USER, Some(TEST_AUTH_PASS))
        .send()?;
    assert_eq!(recovered.status(), 200);
    assert_eq!(recovered.text()?.len(), 64);
    wait_for_no_candidates(tmpdir.path(), Duration::from_secs(2))?;
    Ok(())
}

#[rstest]
fn disconnected_copy_cancels_worker_and_releases_permit_after_cleanup(
    tmpdir: TempDir,
    port: u16,
) -> Result<(), Error> {
    let control = TempDir::new()?;
    let hook = barrier_hook(&control)?;
    let mut command = storage_command(tmpdir.path(), port, Some(&hook));
    command.args([
        "--copy-timeout",
        "10s",
        "--storage-quota-hook-timeout",
        "10s",
        "--max-expensive-tasks",
        "1",
    ]);
    let _server = ServerProc::spawn(command);

    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    write!(
        stream,
        "COPY /test.html HTTP/1.1\r\nHost: localhost:{port}\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\nDestination: {}\r\nContent-Length: 0\r\n\r\n",
        url(port, "cancelled-copy.html")
    )?;
    stream.flush()?;
    wait_for_path(&control.path().join("ready"), true, Duration::from_secs(2))?;
    drop(stream);
    sleep(Duration::from_millis(100));

    fs::write(control.path().join("release"), b"release")?;

    // 单元级监督器屏障已证明取消不能在真实工作线程退出前释放 permit；这里证明进程级断连会
    // 取消发布、清理并让后续请求复用槽。
    // Unit-level supervisor barriers already prove cancellation cannot release a permit before the
    // real worker exits; here a process-level disconnect cancels publication, cleans up, and lets a
    // later request reuse the slot.
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match copy_request(port, "test.html", "after-cancel.html")? {
            status if status == 201 => break,
            status if status == 503 && Instant::now() < deadline => {
                sleep(Duration::from_millis(20));
            }
            status => return Err(format!("unexpected recovery COPY status {status}").into()),
        }
    }
    assert!(!tmpdir.path().join("cancelled-copy.html").exists());
    wait_for_no_candidates(tmpdir.path(), Duration::from_secs(2))?;
    Ok(())
}
