#[path = "common/fixtures.rs"]
mod fixtures;

use assert_fs::fixture::TempDir;
use fixtures::{
    Error, ServerProc, TEST_AUTH_PASS, TEST_AUTH_RULE, TEST_AUTH_USER, port, ram_command,
};
use reqwest::blocking::{Client, RequestBuilder};
use reqwest::{Method, StatusCode};
use rstest::rstest;
use rustix::fs::{Mode, OFlags};
use std::ffi::OsStr;
use std::fs::{File, FileTimes};
use std::io::Write;
use std::net::TcpStream;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime};
use uuid::Uuid;

const FILE_MODE: u32 = 0o640;
const DIRECTORY_MODE: u32 = 0o710;

fn spawn_writable_server(root: &Path, port: u16) -> ServerProc {
    let mut command = ram_command(root, port);
    command.args([
        "--auth",
        TEST_AUTH_RULE,
        "--allow-upload",
        "--allow-delete",
        "--upload-file-mode",
        "0640",
        "--upload-dir-mode",
        "0710",
        "--upload-idle-timeout",
        "30s",
        "--upload-total-timeout",
        "5m",
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
    ServerProc::spawn(command)
}

fn authenticated_request(client: &Client, method: Method, url: &str) -> RequestBuilder {
    client
        .request(method, url)
        .basic_auth(TEST_AUTH_USER, Some(TEST_AUTH_PASS))
}

fn private_candidate_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some(uuid) = name
        .strip_prefix(".ram-upload-")
        .or_else(|| name.strip_prefix(".ram-staging-"))
        .and_then(|value| value.strip_suffix(".tmp"))
    else {
        return false;
    };
    Uuid::parse_str(uuid).is_ok_and(|parsed| parsed.to_string() == uuid)
}

fn private_candidates(root: &Path, deadline: Instant) -> Result<Vec<PathBuf>, Error> {
    let mut pending = vec![root.to_path_buf()];
    let mut candidates = Vec::new();
    while let Some(directory) = pending.pop() {
        if Instant::now() >= deadline {
            return Err("timed out while walking the upload-candidate namespace".into());
        }
        for entry in std::fs::read_dir(directory)? {
            if Instant::now() >= deadline {
                return Err("timed out while walking the upload-candidate namespace".into());
            }
            let entry = entry?;
            let path = entry.path();
            // symlink_metadata 不跟随链接；只遍历真实目录，与服务器能力有界恢复遍历一致。
            // symlink_metadata does not follow links; only real directories are traversed like recovery walk.
            let metadata = std::fs::symlink_metadata(&path)?;
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() && private_candidate_name(&entry.file_name()) {
                candidates.push(path);
            }
        }
    }
    candidates.sort();
    Ok(candidates)
}

fn wait_for_private_candidates(
    root: &Path,
    expected: usize,
    within: Duration,
) -> Result<Vec<PathBuf>, Error> {
    let deadline = Instant::now() + within;
    loop {
        let candidates = private_candidates(root, deadline)?;
        if candidates.len() == expected {
            return Ok(candidates);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "private candidate count did not become {expected} in time (found {})",
                candidates.len()
            )
            .into());
        }
        sleep(Duration::from_millis(20));
    }
}

fn make_candidate_stale(path: &Path) -> Result<(), Error> {
    let descriptor = rustix::fs::open(
        path,
        OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    let candidate = File::from(descriptor);
    let metadata = candidate.metadata()?;
    assert!(metadata.is_file(), "candidate must be a regular file");
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());

    candidate
        .set_times(FileTimes::new().set_modified(SystemTime::now() - Duration::from_secs(60)))?;
    candidate.sync_all()?;
    Ok(())
}

#[rstest]
fn committed_http_mutations_survive_sigkill_and_restart(port: u16) -> Result<(), Error> {
    let root = TempDir::new()?;
    let server = spawn_writable_server(root.path(), port);
    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let base = format!("http://localhost:{port}");

    let response = authenticated_request(&client, Method::PUT, &format!("{base}/put.bin"))
        .body(b"durable PUT content".to_vec())
        .send()?;
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = authenticated_request(
        &client,
        Method::from_bytes(b"MKCOL")?,
        &format!("{base}/collection"),
    )
    .send()?;
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = authenticated_request(&client, Method::PUT, &format!("{base}/move-source.bin"))
        .body(b"durable MOVE content".to_vec())
        .send()?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = authenticated_request(
        &client,
        Method::from_bytes(b"MOVE")?,
        &format!("{base}/move-source.bin"),
    )
    .header("Destination", format!("{base}/moved.bin"))
    .header("Overwrite", "F")
    .send()?;
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = authenticated_request(&client, Method::PUT, &format!("{base}/delete.bin"))
        .body(b"must remain deleted".to_vec())
        .send()?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let response =
        authenticated_request(&client, Method::DELETE, &format!("{base}/delete.bin")).send()?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    drop(client);
    // ServerProc::drop 使用 Child::kill（Unix 为 SIGKILL）后 wait，因此崩溃进程回收后才返回。
    // 这证明进程崩溃恢复/持久化连接，不模拟断电或谎报 flush 的存储设备。
    // ServerProc::drop calls Child::kill (SIGKILL on Unix) and then waits, returning only after the
    // crashed process is reaped. This proves process-crash recovery and durability wiring, not power
    // loss or a storage device that lies about flush.
    drop(server);

    let restarted = spawn_writable_server(root.path(), port);
    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;

    let response =
        authenticated_request(&client, Method::GET, &format!("{base}/put.bin")).send()?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.bytes()?.as_ref(), b"durable PUT content");

    let response =
        authenticated_request(&client, Method::GET, &format!("{base}/moved.bin")).send()?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.bytes()?.as_ref(), b"durable MOVE content");

    let response =
        authenticated_request(&client, Method::HEAD, &format!("{base}/collection/")).send()?;
    assert_eq!(response.status(), StatusCode::OK);
    for missing in ["move-source.bin", "delete.bin"] {
        let response =
            authenticated_request(&client, Method::GET, &format!("{base}/{missing}")).send()?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    assert_eq!(
        std::fs::read(root.path().join("put.bin"))?,
        b"durable PUT content"
    );
    assert_eq!(
        std::fs::read(root.path().join("moved.bin"))?,
        b"durable MOVE content"
    );
    assert!(root.path().join("collection").is_dir());
    assert!(!root.path().join("move-source.bin").exists());
    assert!(!root.path().join("delete.bin").exists());
    assert_eq!(
        std::fs::metadata(root.path().join("put.bin"))?.mode() & 0o7777,
        FILE_MODE
    );
    assert_eq!(
        std::fs::metadata(root.path().join("moved.bin"))?.mode() & 0o7777,
        FILE_MODE
    );
    assert_eq!(
        std::fs::metadata(root.path().join("collection"))?.mode() & 0o7777,
        DIRECTORY_MODE
    );
    assert!(wait_for_private_candidates(root.path(), 0, Duration::from_secs(2))?.is_empty());

    drop(client);
    drop(restarted);
    Ok(())
}

#[rstest]
fn restart_removes_stale_candidate_left_by_sigkilled_slow_put(port: u16) -> Result<(), Error> {
    let root = TempDir::new()?;
    let server = spawn_writable_server(root.path(), port);
    let target = root.path().join("crash-partial.bin");

    let mut client = TcpStream::connect(("127.0.0.1", port))?;
    client.write_all(
        format!(
            "PUT /crash-partial.bin HTTP/1.1\r\n\
             Host: localhost:{port}\r\n\
             Authorization: Basic YWRtaW46YWRtaW4=\r\n\
             Content-Length: 1048576\r\n\
             Connection: close\r\n\
             \r\n\
             partial body"
        )
        .as_bytes(),
    )?;
    let candidates = wait_for_private_candidates(root.path(), 1, Duration::from_secs(3))?;
    assert!(!target.exists(), "an incomplete PUT must not be published");

    // 上传拥有候选时突然终止；这是进程崩溃测试，不声称 SIGKILL 模拟断电。
    // Abruptly terminate while the upload owns the candidate; this tests process crash, not sudden power loss.
    drop(server);
    drop(client);

    let candidate = candidates
        .into_iter()
        .next()
        .expect("one private candidate was observed");
    assert!(candidate.exists());
    make_candidate_stale(&candidate)?;

    let restarted = spawn_writable_server(root.path(), port);
    assert!(
        !target.exists(),
        "recovery must not publish a partial upload"
    );
    assert!(
        wait_for_private_candidates(root.path(), 0, Duration::from_secs(2))?.is_empty(),
        "startup recovery must remove the stale private candidate"
    );
    assert!(!candidate.exists());

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let response = authenticated_request(
        &client,
        Method::GET,
        &format!("http://localhost:{port}/crash-partial.bin"),
    )
    .send()?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    drop(client);
    drop(restarted);
    Ok(())
}
