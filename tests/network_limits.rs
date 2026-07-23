#[path = "common/fixtures.rs"]
mod fixtures;

use fixtures::{
    Error, ServerProc, TEST_AUTH_RULE, port, ram_command as fixture_ram_command, tmpdir,
};
use socket2::{Domain, Protocol, Socket, Type};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::thread::{self, sleep};
use std::time::{Duration, Instant};

const BASIC_AUTH: &str = "Authorization: Basic YWRtaW46YWRtaW4=\r\n";
const BOB_AUTH: &str = "Authorization: Basic Ym9iOmJvYg==\r\n";
const HTTP1_REQUEST_HEAD_LIMIT: usize = 64 * 1024;
const HTTP1_HEADER_LIMIT: usize = 100;
const SHA512_CRYPT_DIGEST: &str =
    "4uV7KKMnSUnET2BtWTj/9T5.Jq3h/MdkOlnIl5hdlTxDZ4MZKmJ.kl6C.NL9xnNPqC4lVHC1vuI0E5cLpTJX81";

fn ram_command(root: &Path, port: u16) -> std::process::Command {
    let mut command = fixture_ram_command(root, port);
    command.args(["--storage-reserve", "0"]);
    command
}

#[test]
fn health_and_anonymous_options_bypass_the_password_hash_queue() -> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    let auth_rule = format!("alice:$6$rounds=1000000$test-salt${SHA512_CRYPT_DIGEST}@/:rw");
    let mut cmd = ram_command(root.path(), port);
    cmd.args(["--auth", &auth_rule]);
    let _server = ServerProc::spawn(cmd);

    // 即使攻击者提供错误 Basic 凭据，也不能令未认证健康端点走最高成本哈希 profile。
    // Even attacker-supplied wrong Basic credentials cannot route the health endpoint through maximum-cost hashing.
    let health = http1_request(
        port,
        "GET /__ram__/health HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic YWxpY2U6d3Jvbmc=\r\nConnection: close\r\n\r\n",
    )?;
    assert!(health.starts_with(b"HTTP/1.1 200"), "{health:?}");

    // 无凭据能力发现也是显式轻量路径；单元测试占用全部哈希 permit 时轮询同一守卫。
    // Credential-free discovery is another lightweight path; tests hold every hash permit while polling this guard.
    let options = http1_request(
        port,
        "OPTIONS /index.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )?;
    assert!(options.starts_with(b"HTTP/1.1 200"), "{options:?}");
    Ok(())
}

#[test]
fn http1_request_head_byte_budget_has_an_exact_boundary() -> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    let mut cmd = ram_command(root.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE]);
    let _server = ServerProc::spawn(cmd);

    for accepted_size in [HTTP1_REQUEST_HEAD_LIMIT - 1, HTTP1_REQUEST_HEAD_LIMIT] {
        let request = padded_http1_get(accepted_size);
        assert_eq!(request.len(), accepted_size);
        let response = http1_request(port, &request)?;
        assert!(
            response.starts_with(b"HTTP/1.1 200"),
            "request head of {accepted_size} bytes was rejected: {response:?}"
        );
    }

    let rejected_size = HTTP1_REQUEST_HEAD_LIMIT + 1;
    let request = padded_http1_get(rejected_size);
    assert_eq!(request.len(), rejected_size);
    // 一次写入发送完整请求头。Hyper 可能刚超过其缓冲增长阈值才解析，因此 Ram 的解析后语义
    // 预算必须独立保持公开 N/N+1 边界。
    // Send the complete head in one write. Ram's post-parse semantic budget must preserve the N/N+1 boundary independently of Hyper buffering.
    let response = http1_request(port, &request)?;
    assert!(
        response.starts_with(b"HTTP/1.1 431"),
        "request head of {rejected_size} bytes was not rejected with 431: {response:?}"
    );
    Ok(())
}

#[test]
fn http1_overlong_uri_has_a_stable_status() -> Result<(), Error> {
    const HYPER_MAX_URI_BYTES: usize = u16::MAX as usize - 1;

    let root = tmpdir();
    let port = port();
    let mut cmd = ram_command(root.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE]);
    let _server = ServerProc::spawn(cmd);

    let uri = format!("/{}", "a".repeat(HYPER_MAX_URI_BYTES));
    assert_eq!(uri.len(), HYPER_MAX_URI_BYTES + 1);
    let request =
        format!("GET {uri} HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Connection: close\r\n\r\n");
    assert!(request.len() > HTTP1_REQUEST_HEAD_LIMIT);
    // 请求目标本身超过 Hyper URI 上限，但 Ram 更小的聚合头预算先耗尽。精确喂入该前缀，
    // 避免结果随内核 TCP 分段变化。
    // The request target exceeds Hyper's URI bound, but Ram's smaller aggregate budget fails first; exact prefix makes segmentation irrelevant.
    let response = http1_request_prefix(port, &request, HTTP1_REQUEST_HEAD_LIMIT)?;
    assert!(
        response.starts_with(b"HTTP/1.1 431"),
        "an overlong request target did not receive the budget-first 431: {response:?}"
    );
    Ok(())
}

#[test]
fn http1_header_count_budget_has_an_exact_boundary() -> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    let mut cmd = ram_command(root.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE]);
    let _server = ServerProc::spawn(cmd);

    let accepted = http1_get_with_header_count(HTTP1_HEADER_LIMIT);
    let response = http1_request(port, &accepted)?;
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "{HTTP1_HEADER_LIMIT} request headers were rejected: {response:?}"
    );

    let rejected_count = HTTP1_HEADER_LIMIT + 1;
    let rejected = http1_get_with_header_count(rejected_count);
    let response = http1_request(port, &rejected)?;
    assert!(
        response.starts_with(b"HTTP/1.1 431"),
        "{rejected_count} request headers were not rejected with 431: {response:?}"
    );
    Ok(())
}

#[test]
fn max_connections_holds_excess_clients_in_the_kernel_backlog() -> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    let mut cmd = ram_command(root.path(), port);
    cmd.args([
        "--auth",
        TEST_AUTH_RULE,
        "--bind",
        "127.0.0.1",
        "--max-connections",
        "1",
    ]);
    let _server = ServerProc::spawn(cmd);

    // 不完整请求头占用唯一已接受连接。 / An incomplete request head occupies the sole accepted connection.
    let mut blocker = TcpStream::connect(("127.0.0.1", port))?;
    write!(blocker, "GET / HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}")?;
    sleep(Duration::from_millis(150));

    // 套接字在监听 backlog 中等待，所以 TCP connect 仍成功；permit 释放前应用无法响应。
    // TCP connect succeeds in the listen backlog, but no application response is possible until permit release.
    let mut queued = TcpStream::connect(("127.0.0.1", port))?;
    queued.set_read_timeout(Some(Duration::from_millis(300)))?;
    write!(
        queued,
        "GET /index.html HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Connection: close\r\n\r\n"
    )?;
    let mut byte = [0u8; 1];
    let err = queued
        .read(&mut byte)
        .expect_err("queued connection was accepted above max-connections");
    assert!(matches!(
        err.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));

    blocker.shutdown(Shutdown::Both)?;
    queued.set_read_timeout(Some(Duration::from_secs(3)))?;
    let mut response = Vec::new();
    queued.read_to_end(&mut response)?;
    assert!(response.starts_with(b"HTTP/1.1 200"));
    Ok(())
}

#[test]
fn slow_put_body_is_reaped_without_committing_a_partial_file() -> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    let mut cmd = ram_command(root.path(), port);
    cmd.args([
        "--auth",
        TEST_AUTH_RULE,
        "--allow-upload",
        "--upload-idle-timeout",
        "1s",
    ]);
    let _server = ServerProc::spawn(cmd);

    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(4)))?;
    write!(
        stream,
        "PUT /slow.bin HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Content-Length: 5\r\nConnection: close\r\n\r\na"
    )?;
    let started = Instant::now();
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(800), "elapsed {elapsed:?}");
    assert!(elapsed < Duration::from_secs(4), "elapsed {elapsed:?}");
    assert!(response.starts_with(b"HTTP/1.1 408"), "{response:?}");
    assert!(!root.path().join("slow.bin").exists());
    Ok(())
}

#[test]
fn trickle_put_cannot_outlive_total_upload_deadline() -> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    let mut cmd = ram_command(root.path(), port);
    cmd.args([
        "--auth",
        TEST_AUTH_RULE,
        "--allow-upload",
        "--upload-idle-timeout",
        "2s",
        "--upload-total-timeout",
        "1s",
    ]);
    let _server = ServerProc::spawn(cmd);

    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(4)))?;
    write!(
        stream,
        "PUT /trickle.bin HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Content-Length: 10\r\nConnection: close\r\n\r\na"
    )?;
    let started = Instant::now();
    sleep(Duration::from_millis(400));
    stream.write_all(b"b")?;
    sleep(Duration::from_millis(400));
    stream.write_all(b"c")?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(800), "elapsed {elapsed:?}");
    assert!(elapsed < Duration::from_secs(3), "elapsed {elapsed:?}");
    assert!(response.starts_with(b"HTTP/1.1 408"), "{response:?}");
    assert!(!root.path().join("trickle.bin").exists());
    Ok(())
}

#[test]
fn upload_staging_does_not_create_missing_target_ancestors() -> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    let mut cmd = ram_command(root.path(), port);
    cmd.args([
        "--auth",
        TEST_AUTH_RULE,
        "--allow-upload",
        "--upload-idle-timeout",
        "5s",
    ]);
    let _server = ServerProc::spawn(cmd);

    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    write!(
        stream,
        "PUT /missing/child.bin HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Content-Length: 5\r\nConnection: close\r\n\r\na"
    )?;
    wait_for_staging_candidate(root.path())?;
    assert!(
        !root.path().join("missing").exists(),
        "private staging created the final target hierarchy before commit"
    );
    drop(stream);
    Ok(())
}

#[test]
fn slow_put_body_does_not_hold_the_mutation_lock() -> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    let mut cmd = ram_command(root.path(), port);
    cmd.args([
        "--auth",
        TEST_AUTH_RULE,
        "--allow-all",
        "--upload-idle-timeout",
        "2s",
    ]);
    let _server = ServerProc::spawn(cmd);

    let mut slow = TcpStream::connect(("127.0.0.1", port))?;
    write!(
        slow,
        "PUT /slow.bin HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Content-Length: 5\r\nConnection: close\r\n\r\na"
    )?;
    wait_for_staging_candidate(root.path())?;

    let started = Instant::now();
    let response = http1_request(
        port,
        &format!(
            "DELETE /test.html HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Connection: close\r\n\r\n"
        ),
    )?;
    let elapsed = started.elapsed();
    assert!(response.starts_with(b"HTTP/1.1 204"), "{response:?}");
    assert!(
        elapsed < Duration::from_millis(1500),
        "unrelated mutation waited for the slow upload body: {elapsed:?}"
    );
    drop(slow);
    Ok(())
}

#[test]
fn concurrent_upload_staging_is_bounded() -> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    let mut cmd = ram_command(root.path(), port);
    cmd.args([
        "--auth",
        TEST_AUTH_RULE,
        "--allow-upload",
        "--max-concurrent-uploads",
        "1",
        "--upload-idle-timeout",
        "5s",
    ]);
    let _server = ServerProc::spawn(cmd);

    let mut slow = TcpStream::connect(("127.0.0.1", port))?;
    write!(
        slow,
        "PUT /first.bin HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Content-Length: 5\r\nConnection: close\r\n\r\na"
    )?;
    wait_for_staging_candidate(root.path())?;

    let response = http1_request(
        port,
        &format!(
            "PUT /second.bin HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Content-Length: 1\r\nConnection: close\r\n\r\nx"
        ),
    )?;
    assert!(response.starts_with(b"HTTP/1.1 503"), "{response:?}");
    assert!(
        String::from_utf8_lossy(&response).contains("retry-after: 1"),
        "{response:?}"
    );
    assert!(!root.path().join("second.bin").exists());
    drop(slow);
    Ok(())
}

#[test]
fn per_user_upload_limit_applies_across_different_source_ips() -> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    let mut cmd = ram_command(root.path(), port);
    cmd.args([
        "--auth",
        TEST_AUTH_RULE,
        "--allow-upload",
        "--max-concurrent-uploads",
        "4",
        "--max-concurrent-uploads-per-user",
        "1",
        "--max-concurrent-uploads-per-source",
        "2",
        "--upload-idle-timeout",
        "5s",
    ]);
    let _server = ServerProc::spawn(cmd);

    let mut first = connect_from(port, Ipv4Addr::LOCALHOST)?;
    write!(
        first,
        "PUT /user-first.bin HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Content-Length: 5\r\nConnection: close\r\n\r\na"
    )?;
    wait_for_staging_candidate(root.path())?;

    let response = request_from(
        port,
        Ipv4Addr::new(127, 0, 0, 2),
        &format!(
            "PUT /user-second.bin HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Content-Length: 1\r\nConnection: close\r\n\r\nx"
        ),
    )?;
    assert!(response.starts_with(b"HTTP/1.1 429"), "{response:?}");
    assert!(
        String::from_utf8_lossy(&response).contains("retry-after: 1"),
        "{response:?}"
    );
    drop(first);
    Ok(())
}

#[test]
fn per_source_upload_limit_applies_across_different_users() -> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    let mut cmd = ram_command(root.path(), port);
    cmd.args([
        "--auth",
        TEST_AUTH_RULE,
        "--auth",
        "bob:bob@/:rw",
        "--allow-upload",
        "--max-concurrent-uploads",
        "4",
        "--max-concurrent-uploads-per-user",
        "2",
        "--max-concurrent-uploads-per-source",
        "1",
        "--upload-idle-timeout",
        "5s",
    ]);
    let _server = ServerProc::spawn(cmd);

    let mut first = connect_from(port, Ipv4Addr::LOCALHOST)?;
    write!(
        first,
        "PUT /source-first.bin HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Content-Length: 5\r\nConnection: close\r\n\r\na"
    )?;
    wait_for_staging_candidate(root.path())?;

    let response = request_from(
        port,
        Ipv4Addr::LOCALHOST,
        &format!(
            "PUT /source-second.bin HTTP/1.1\r\nHost: localhost\r\n{BOB_AUTH}Content-Length: 1\r\nConnection: close\r\n\r\nx"
        ),
    )?;
    assert!(response.starts_with(b"HTTP/1.1 429"), "{response:?}");
    drop(first);
    Ok(())
}

#[test]
fn different_user_and_source_uploads_coexist_and_cancel_releases_raii_limits() -> Result<(), Error>
{
    let root = tmpdir();
    let port = port();
    let mut cmd = ram_command(root.path(), port);
    cmd.args([
        "--auth",
        TEST_AUTH_RULE,
        "--auth",
        "bob:bob@/:rw",
        "--allow-upload",
        "--max-concurrent-uploads",
        "2",
        "--max-concurrent-uploads-per-user",
        "1",
        "--max-concurrent-uploads-per-source",
        "1",
        "--upload-idle-timeout",
        "5s",
    ]);
    let _server = ServerProc::spawn(cmd);

    let mut admin = connect_from(port, Ipv4Addr::LOCALHOST)?;
    let mut bob = connect_from(port, Ipv4Addr::new(127, 0, 0, 2))?;
    write!(
        admin,
        "PUT /admin-slow.bin HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Content-Length: 5\r\nConnection: close\r\n\r\na"
    )?;
    write!(
        bob,
        "PUT /bob-slow.bin HTTP/1.1\r\nHost: localhost\r\n{BOB_AUTH}Content-Length: 5\r\nConnection: close\r\n\r\nb"
    )?;
    wait_for_staging_candidates(root.path(), 2)?;

    drop(admin);
    wait_for_staging_candidate_count(root.path(), 1)?;
    // 候选名称消失只证明 unlink 已完成；清理器仍可能正在 fsync 固定父目录，并在此期间
    // 正确保留上传准入守卫。只重试瞬时准入响应，直到整个清理事务释放容量。
    // Candidate disappearance proves only that unlink completed. The reaper may still be fsyncing
    // the pinned parent and correctly retains upload admission guards until that finishes. Retry
    // only transient admission responses until the complete cleanup transaction releases capacity.
    let deadline = Instant::now() + Duration::from_secs(2);
    let response = loop {
        let response = request_from(
            port,
            Ipv4Addr::LOCALHOST,
            &format!(
                "PUT /admin-after-cancel.bin HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Content-Length: 1\r\nConnection: close\r\n\r\nx"
            ),
        )?;
        if response.starts_with(b"HTTP/1.1 201") {
            break response;
        }
        assert!(
            response.starts_with(b"HTTP/1.1 429") || response.starts_with(b"HTTP/1.1 503"),
            "unexpected response while waiting for cancelled upload permits: {response:?}"
        );
        assert!(
            Instant::now() < deadline,
            "cancelled upload permits were not released in time: {response:?}"
        );
        sleep(Duration::from_millis(20));
    };
    assert!(response.starts_with(b"HTTP/1.1 201"), "{response:?}");
    assert_eq!(
        std::fs::read(root.path().join("admin-after-cancel.bin"))?,
        b"x"
    );
    drop(bob);
    Ok(())
}

#[test]
fn staged_put_rechecks_if_match_before_commit() -> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    let mut cmd = ram_command(root.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE, "--allow-all"]);
    let _server = ServerProc::spawn(cmd);

    let client = reqwest::blocking::Client::new();
    let etag = client
        .get(format!("http://localhost:{port}/test.html"))
        .basic_auth("admin", Some("admin"))
        .send()?
        .headers()
        .get("etag")
        .expect("fixture response has an ETag")
        .to_str()?
        .to_string();

    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(4)))?;
    write!(
        stream,
        "PUT /test.html HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}If-Match: {etag}\r\nContent-Length: 5\r\nConnection: close\r\n\r\na"
    )?;
    wait_for_staging_candidate(root.path())?;
    std::fs::write(root.path().join("test.html"), b"external replacement")?;
    stream.write_all(b"bcde")?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    assert!(response.starts_with(b"HTTP/1.1 412"), "{response:?}");
    assert_eq!(
        std::fs::read(root.path().join("test.html"))?,
        b"external replacement"
    );
    Ok(())
}

#[test]
fn concurrent_if_match_puts_to_one_path_have_one_winner() -> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    let mut cmd = ram_command(root.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE, "--allow-all"]);
    let _server = ServerProc::spawn(cmd);

    let client = reqwest::blocking::Client::new();
    let etag = client
        .get(format!("http://localhost:{port}/test.html"))
        .basic_auth("admin", Some("admin"))
        .send()?
        .headers()
        .get("etag")
        .expect("fixture response has an ETag")
        .to_str()?
        .to_string();

    let mut first = TcpStream::connect(("127.0.0.1", port))?;
    let mut second = TcpStream::connect(("127.0.0.1", port))?;
    first.set_read_timeout(Some(Duration::from_secs(4)))?;
    second.set_read_timeout(Some(Duration::from_secs(4)))?;
    write!(
        first,
        "PUT /test.html HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}If-Match: {etag}\r\nContent-Length: 5\r\nConnection: close\r\n\r\na"
    )?;
    write!(
        second,
        "PUT /test.html HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}If-Match: {etag}\r\nContent-Length: 5\r\nConnection: close\r\n\r\nb"
    )?;
    wait_for_staging_candidates(root.path(), 2)?;

    first.write_all(b"lpha")?;
    second.write_all(b"ravo")?;
    let mut first_response = Vec::new();
    let mut second_response = Vec::new();
    first.read_to_end(&mut first_response)?;
    second.read_to_end(&mut second_response)?;

    let success_count = [&first_response, &second_response]
        .into_iter()
        .filter(|response| response.starts_with(b"HTTP/1.1 204"))
        .count();
    let precondition_count = [&first_response, &second_response]
        .into_iter()
        .filter(|response| response.starts_with(b"HTTP/1.1 412"))
        .count();
    assert_eq!(success_count, 1, "{first_response:?} {second_response:?}");
    assert_eq!(
        precondition_count, 1,
        "{first_response:?} {second_response:?}"
    );
    let final_contents = std::fs::read(root.path().join("test.html"))?;
    assert!(
        final_contents == b"alpha" || final_contents == b"bravo",
        "unexpected winning representation: {final_contents:?}"
    );
    Ok(())
}

#[test]
fn active_upload_suspends_connection_idle_but_not_maximum_lifetime() -> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    let mut cmd = ram_command(root.path(), port);
    cmd.args([
        "--auth",
        TEST_AUTH_RULE,
        "--allow-upload",
        "--upload-idle-timeout",
        "5s",
        "--upload-total-timeout",
        "5s",
        "--connection-idle-timeout",
        "1s",
        "--connection-max-lifetime",
        "2s",
    ]);
    let _server = ServerProc::spawn(cmd);

    let started = Instant::now();
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(4)))?;
    write!(
        stream,
        "PUT /lifetime.bin HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Content-Length: 5\r\nConnection: close\r\n\r\na"
    )?;
    wait_for_staging_candidate(root.path())?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(1500),
        "connection idle incorrectly killed an active handler: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(3500),
        "maximum connection lifetime did not bound the handler: {elapsed:?}"
    );
    assert!(!root.path().join("lifetime.bin").exists());
    Ok(())
}

#[test]
fn two_hundred_directory_head_requests_skip_listing_scans() -> Result<(), Error> {
    let root = tmpdir();
    let directory = root.path().join("head-only");
    std::fs::create_dir(&directory)?;
    std::fs::write(directory.join("one"), b"1")?;
    std::fs::write(directory.join("two"), b"2")?;
    // 把路径名 Unix 套接字作为文件内容打开会产生类型化 I/O 错误。保持监听器活跃，使意外目录
    // 枚举确定返回 500，而不依赖时序或低条目预算间接证明。
    // Opening a pathname Unix socket as content yields a typed I/O failure. Keeping the listener
    // alive makes accidental directory enumeration deterministically return 500, without relying on
    // timing or a low entry budget as indirect evidence.
    let _listing_trap = UnixListener::bind(directory.join("must-not-be-scanned.sock"))?;
    let port = port();
    let mut cmd = ram_command(root.path(), port);
    cmd.args([
        "--auth",
        TEST_AUTH_RULE,
        "--max-connections",
        "256",
        "--max-concurrent-requests",
        "256",
        "--max-concurrent-requests-per-source",
        "256",
        "--max-concurrent-requests-per-user",
        "256",
        "--max-request-queue",
        "256",
        "--request-queue-timeout",
        "5s",
        "--max-expensive-tasks",
        "1",
    ]);
    let _server = ServerProc::spawn(cmd);

    let barrier = Arc::new(Barrier::new(201));
    // 该测试隔离目录 HEAD 分派，不测试同一来源的密码猜测预算。每个客户端使用独立的
    // loopback 来源，避免四次暂定认证尝试的安全上限先于 200 路文件系统并发触发；账号、
    // 全局请求和连接上限仍共同覆盖全部请求。
    // This test isolates directory HEAD dispatch rather than the same-source password-guessing
    // budget. Give every client a distinct loopback source so the four provisional-auth-attempt
    // security ceiling does not fire before the 200-way filesystem workload; account, global
    // request, and connection limits still cover the entire burst.
    let workers = (1..=200)
        .map(|source_octet| {
            let barrier = barrier.clone();
            thread::spawn(move || -> Result<Vec<u8>, String> {
                barrier.wait();
                request_from(
                    port,
                    Ipv4Addr::new(127, 0, 1, source_octet),
                    &format!(
                        "HEAD /head-only/ HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Connection: close\r\n\r\n"
                    ),
                )
                .map_err(|error| error.to_string())
            })
        })
        .collect::<Vec<_>>();
    let started = Instant::now();
    barrier.wait();
    for worker in workers {
        let response = worker
            .join()
            .expect("HEAD test worker panicked")
            .map_err(|error| -> Error { error.into() })?;
        assert!(response.starts_with(b"HTTP/1.1 200"), "{response:?}");
        assert!(
            !String::from_utf8_lossy(&response)
                .to_ascii_lowercase()
                .contains("content-length:"),
            "directory HEAD fabricated a listing length: {response:?}"
        );
    }
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "HEAD requests behaved like serialized directory scans: {:?}",
        started.elapsed()
    );
    Ok(())
}

fn padded_http1_get(total_head_bytes: usize) -> String {
    let prefix = format!(
        "GET /index.html HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Connection: close\r\nX-Pad: "
    );
    let suffix = "\r\n\r\n";
    let fixed_bytes = prefix.len() + suffix.len();
    assert!(
        total_head_bytes >= fixed_bytes,
        "requested head is too small for the fixed request fields"
    );
    format!(
        "{prefix}{}{suffix}",
        "a".repeat(total_head_bytes - fixed_bytes)
    )
}

fn http1_get_with_header_count(header_count: usize) -> String {
    const FIXED_HEADER_COUNT: usize = 3;
    assert!(header_count >= FIXED_HEADER_COUNT);
    let mut request =
        format!("GET /index.html HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Connection: close\r\n");
    for index in 0..header_count - FIXED_HEADER_COUNT {
        request.push_str(&format!("X-Test-{index}: x\r\n"));
    }
    request.push_str("\r\n");
    assert_eq!(request.split("\r\n").count() - 3, header_count);
    request
}

fn http1_request(port: u16, request: &str) -> Result<Vec<u8>, Error> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(4)))?;
    stream.write_all(request.as_bytes())?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    Ok(response)
}

fn http1_request_prefix(port: u16, request: &str, transmitted: usize) -> Result<Vec<u8>, Error> {
    assert!(transmitted < request.len());
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(4)))?;
    stream.write_all(&request.as_bytes()[..transmitted])?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    Ok(response)
}

fn connect_from(port: u16, local_ip: Ipv4Addr) -> Result<TcpStream, Error> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.bind(&SocketAddr::from((local_ip, 0)).into())?;
    socket.connect(&SocketAddr::from((Ipv4Addr::LOCALHOST, port)).into())?;
    let stream: TcpStream = socket.into();
    stream.set_read_timeout(Some(Duration::from_secs(4)))?;
    Ok(stream)
}

fn request_from(port: u16, local_ip: Ipv4Addr, request: &str) -> Result<Vec<u8>, Error> {
    let mut stream = connect_from(port, local_ip)?;
    stream.write_all(request.as_bytes())?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    Ok(response)
}

fn wait_for_staging_candidate(root: &Path) -> Result<(), Error> {
    wait_for_staging_candidates(root, 1)
}

fn wait_for_staging_candidates(root: &Path, expected: usize) -> Result<(), Error> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let found = std::fs::read_dir(root)?
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
            .filter(|name| is_staging_candidate(name))
            .count();
        if found >= expected {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "{expected} upload staging candidates were not created in time (found {found})"
            )
            .into());
        }
        sleep(Duration::from_millis(20));
    }
}

fn wait_for_staging_candidate_count(root: &Path, expected: usize) -> Result<(), Error> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let found = std::fs::read_dir(root)?
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
            .filter(|name| is_staging_candidate(name))
            .count();
        if found == expected {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "upload staging candidate count did not become {expected} in time (found {found})"
            )
            .into());
        }
        sleep(Duration::from_millis(20));
    }
}

fn is_staging_candidate(name: &str) -> bool {
    (name.starts_with(".ram-upload-") || name.starts_with(".ram-staging-"))
        && name.ends_with(".tmp")
}
