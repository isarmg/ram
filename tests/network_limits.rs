#[path = "common/fixtures.rs"]
mod fixtures;

use fixtures::{Error, ServerProc, TEST_AUTH_RULE, port, ram_command, tmpdir};
use hyper::{Method, Request, StatusCode, Version};
use socket2::{Domain, Protocol, Socket, Type};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
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
fn unix_socket_serves_a_real_authenticated_http_request() -> Result<(), Error> {
    let root = tmpdir();
    let socket_root = tmpdir();
    let socket = socket_root.path().join("ram.sock");
    let mut cmd = ram_command(root.path(), port());
    cmd.args(["--auth", TEST_AUTH_RULE, "--bind"]).arg(&socket);
    let _server = ServerProc::spawn(cmd);

    let mut stream = UnixStream::connect(&socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    write!(
        stream,
        "GET /index.html HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Connection: close\r\n\r\n"
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with("This is index.html"), "{response}");
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
fn max_connections_is_strict_across_multiple_listeners() -> Result<(), Error> {
    let root = tmpdir();
    let socket_root = tmpdir();
    let socket_path = socket_root.path().join("ram.sock");
    let port = port();
    let mut cmd = ram_command(root.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE, "--bind", "127.0.0.1", "--bind"])
        .arg(&socket_path)
        .args(["--max-connections", "1"]);
    let _server = ServerProc::spawn(cmd);
    let baseline = process_socket_fd_count(_server.pid())?;
    assert!(baseline >= 2, "expected both listener descriptors");

    let mut blocker = TcpStream::connect(("127.0.0.1", port))?;
    write!(blocker, "GET / HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}")?;
    wait_for_socket_fd_count(_server.pid(), baseline + 1)?;

    let mut queued = UnixStream::connect(&socket_path)?;
    queued.set_read_timeout(Some(Duration::from_millis(300)))?;
    write!(
        queued,
        "GET /index.html HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Connection: close\r\n\r\n"
    )?;
    sleep(Duration::from_millis(150));
    assert_eq!(
        process_socket_fd_count(_server.pid())?,
        baseline + 1,
        "an idle listener accepted and retained a connection above the global limit"
    );
    let mut byte = [0u8; 1];
    let error = queued
        .read(&mut byte)
        .expect_err("queued Unix request ran above max-connections");
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));

    blocker.shutdown(Shutdown::Both)?;
    queued.set_read_timeout(Some(Duration::from_secs(3)))?;
    let mut response = Vec::new();
    queued.read_to_end(&mut response)?;
    assert!(response.starts_with(b"HTTP/1.1 200"), "{response:?}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_connection_holds_the_global_connection_permit_until_close() -> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    let mut cmd = ram_command(root.path(), port);
    cmd.args([
        "--auth",
        TEST_AUTH_RULE,
        "--allow-h2c",
        "--max-connections",
        "1",
        "--h2-max-concurrent-streams",
        "8",
    ]);
    let _server = ServerProc::spawn(cmd);

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    let (sender, connection) = h2::client::handshake(stream).await?;
    let connection_task = tokio::spawn(connection);
    let mut sender = sender.ready().await?;
    let (response, _) = sender.send_request(h2_get(port, "/index.html")?, true)?;
    let mut body = response.await?.into_body();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        body.flow_control().release_capacity(chunk.len())?;
    }

    // 第二个 TCP 握手可在内核 backlog 完成，但活跃 H2 连接持有唯一进程级连接 permit 时，
    // 应用不得接受或服务它。
    // A second handshake may finish in backlog, but the app cannot accept/serve it while H2 owns the sole permit.
    let mut queued = TcpStream::connect(("127.0.0.1", port))?;
    queued.set_read_timeout(Some(Duration::from_millis(300)))?;
    write!(
        queued,
        "GET /index.html HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Connection: close\r\n\r\n"
    )?;
    let mut byte = [0u8; 1];
    let error = queued
        .read(&mut byte)
        .expect_err("HTTP/1 request ran above max-connections while H2 remained open");
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));

    drop(sender);
    connection_task.abort();
    let _ = connection_task.await;
    queued.set_read_timeout(Some(Duration::from_secs(3)))?;
    let mut response = Vec::new();
    queued.read_to_end(&mut response)?;
    assert!(response.starts_with(b"HTTP/1.1 200"), "{response:?}");
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
fn staged_patch_rechecks_projected_size_against_the_commit_target() -> Result<(), Error> {
    let root = tmpdir();
    let path = root.path().join("patch-limit.bin");
    std::fs::write(&path, b"12345")?;
    let port = port();
    let mut cmd = ram_command(root.path(), port);
    cmd.args([
        "--auth",
        TEST_AUTH_RULE,
        "--allow-upload",
        "--max-upload-size",
        "8",
    ]);
    let _server = ServerProc::spawn(cmd);

    // 声明请求体相对乐观五字节探测恰到上限，故允许暂存。请求体完成前把目标替换为七字节表示；
    // 权威提交投影变为十字节，必须以 413 失败。
    // The declared body exactly fits the optimistic five-byte probe. Replacing the target with seven bytes makes authoritative projection ten and must return 413.
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(4)))?;
    write!(
        stream,
        "PATCH /patch-limit.bin HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}X-Update-Range: append\r\nContent-Length: 3\r\nConnection: close\r\n\r\na"
    )?;
    wait_for_staging_candidate(root.path())?;
    std::fs::write(&path, b"1234567")?;
    stream.write_all(b"bc")?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    assert!(response.starts_with(b"HTTP/1.1 413"), "{response:?}");
    assert_eq!(std::fs::read(path)?, b"1234567");
    wait_for_staging_candidate_count(root.path(), 0)?;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn global_request_limit_times_out_and_releases_on_body_drop() -> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    // 有意不消费 h2 接收窗口，因此文件足够大，服务器无法到达响应 EOS。
    // The h2 receive window is left unconsumed, making the file large enough that response EOS cannot be reached.
    std::fs::File::create(root.path().join("large.bin"))?.set_len(4 * 1024 * 1024)?;
    let mut cmd = ram_command(root.path(), port);
    cmd.args([
        "--auth",
        TEST_AUTH_RULE,
        "--max-concurrent-requests",
        "1",
        "--request-queue-timeout",
        "1s",
        "--allow-h2c",
        "--h2-max-concurrent-streams",
        "8",
    ]);
    let _server = ServerProc::spawn(cmd);

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    let (sender, connection) = h2::client::handshake(stream).await?;
    let connection_task = tokio::spawn(connection);
    let mut sender = sender.ready().await?;
    let (response, _) = sender.send_request(h2_get(port, "/large.bin")?, true)?;
    let response = response.await?;
    assert_eq!(response.status(), StatusCode::OK);
    let blocked_body = response.into_body();

    let started = Instant::now();
    // 全局上限为一时有效键上限也为一。使用不同内核来源，使请求进入全局队列，而非先在来源
    // 阶段按预期失败。
    // With a global limit of one, the effective keyed limit is also one. Use a distinct kernel source
    // so the request reaches the global queue instead of failing earlier at the source stage.
    let overloaded = request_from(
        port,
        Ipv4Addr::new(127, 0, 0, 2),
        &format!(
            "GET /index.html HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Connection: close\r\n\r\n"
        ),
    )?;
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(800), "elapsed {elapsed:?}");
    assert!(elapsed < Duration::from_secs(3), "elapsed {elapsed:?}");
    assert!(overloaded.starts_with(b"HTTP/1.1 503"), "{overloaded:?}");
    assert!(
        String::from_utf8_lossy(&overloaded).contains("retry-after: 1"),
        "{overloaded:?}"
    );

    // 丢弃未消费 h2 请求体会发送流重置；响应体包装器随后必须为下一请求释放全局 permit。
    // Dropping an unconsumed h2 body resets the stream; the response wrapper must release the global permit.
    drop(blocked_body);
    // 流重置必须经过客户端连接任务、内核和服务器 h2 任务传播；并行测试负载下不存在可靠的
    // 固定 200ms 上界。使用有截止时间的状态轮询，仍能区分最终释放和真实 permit 泄漏。
    // The reset crosses the client connection task, kernel, and server h2 task, so a fixed 200 ms
    // bound is not reliable under parallel test load. Deadline-bounded state polling still
    // distinguishes eventual release from a real permit leak.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let recovered = request_from(
            port,
            Ipv4Addr::new(127, 0, 0, 2),
            &format!(
                "GET /index.html HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Connection: close\r\n\r\n"
            ),
        )?;
        if recovered.starts_with(b"HTTP/1.1 200") {
            break;
        }
        assert!(recovered.starts_with(b"HTTP/1.1 503"), "{recovered:?}");
        if Instant::now() >= deadline {
            return Err("global request permit was not released after the h2 body reset".into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    connection_task.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bounded_global_queue_rejects_one_request_and_times_out_one_waiter() -> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    std::fs::File::create(root.path().join("large.bin"))?.set_len(4 * 1024 * 1024)?;
    let mut cmd = ram_command(root.path(), port);
    cmd.args([
        "--auth",
        TEST_AUTH_RULE,
        "--max-concurrent-requests",
        "1",
        "--max-concurrent-requests-per-source",
        "8",
        "--max-concurrent-requests-per-user",
        "8",
        "--max-request-queue",
        "1",
        "--request-queue-timeout",
        "2s",
        "--allow-h2c",
        "--h2-max-concurrent-streams",
        "8",
    ]);
    let _server = ServerProc::spawn(cmd);

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    let (sender, connection) = h2::client::handshake(stream).await?;
    let connection_task = tokio::spawn(connection);
    let mut sender = sender.ready().await?;
    let (response, _) = sender.send_request(h2_get(port, "/large.bin")?, true)?;
    let blocked_body = response.await?.into_body();

    let barrier = Arc::new(Barrier::new(3));
    let workers = (0..2)
        .map(|index| {
            let barrier = barrier.clone();
            thread::spawn(move || -> Result<(Vec<u8>, Duration), String> {
                barrier.wait();
                let started = Instant::now();
                // 键请求上限受全局值约束。使用独立内核来源对端，使两请求都到达全局队列，而非
                // 竞争 h2 响应或彼此持有的来源槽。
                // Keyed limits are capped globally. Independent kernel-source peers make both requests
                // reach the global queue instead of competing over h2 responses or source slots held
                // by one another.
                let response = request_from(
                    port,
                    Ipv4Addr::new(127, 0, 0, 2 + index),
                    &format!(
                        "GET /index.html HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Connection: close\r\n\r\n"
                    ),
                )
                .map_err(|err| err.to_string())?;
                Ok((response, started.elapsed()))
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let mut results = workers
        .into_iter()
        .map(|worker| worker.join().expect("queue test worker panicked"))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| -> Error { error.into() })?;
    results.sort_by_key(|(_, elapsed)| *elapsed);

    for (response, _) in &results {
        assert!(response.starts_with(b"HTTP/1.1 503"), "{response:?}");
        assert!(
            String::from_utf8_lossy(response).contains("retry-after: 1"),
            "{response:?}"
        );
    }
    assert!(
        results[0].1 < Duration::from_secs(1),
        "the full queue did not fail fast: {:?}",
        results[0].1
    );
    assert!(
        results[1].1 >= Duration::from_millis(1700),
        "the admitted queue waiter did not observe its timeout: {:?}",
        results[1].1
    );
    assert!(
        results[1].1 < Duration::from_secs(4),
        "queue timeout exceeded its configured bound: {:?}",
        results[1].1
    );

    drop(blocked_body);
    connection_task.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_interrupts_a_global_queue_waiter() -> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    std::fs::File::create(root.path().join("large.bin"))?.set_len(4 * 1024 * 1024)?;
    let mut cmd = ram_command(root.path(), port);
    cmd.args([
        "--auth",
        TEST_AUTH_RULE,
        "--max-concurrent-requests",
        "1",
        "--max-concurrent-requests-per-source",
        "8",
        "--max-concurrent-requests-per-user",
        "8",
        "--max-request-queue",
        "1",
        "--request-queue-timeout",
        "10s",
        "--allow-h2c",
    ]);
    let mut server = ServerProc::spawn(cmd);

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    let (sender, connection) = h2::client::handshake(stream).await?;
    let connection_task = tokio::spawn(connection);
    let mut sender = sender.ready().await?;
    let (response, _) = sender.send_request(h2_get(port, "/large.bin")?, true)?;
    let blocked_body = response.await?.into_body();

    let waiter = thread::spawn(move || {
        request_from(
            port,
            Ipv4Addr::new(127, 0, 0, 2),
            &format!(
                "GET /index.html HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Connection: close\r\n\r\n"
            ),
        )
        .map_err(|error| error.to_string())
    });
    // 队列超时为十秒，因此调度窗口后仍阻塞的等待者只能通过关闭准入迅速释放。
    // Queue timeout is ten seconds; a waiter still blocked after this window can only be promptly released by closing admission.
    sleep(Duration::from_millis(250));
    let started = Instant::now();
    server.sigterm();
    let response = waiter
        .join()
        .expect("queue waiter panicked")
        .map_err(|error| -> Error { error.into() })?;
    assert!(response.starts_with(b"HTTP/1.1 503"), "{response:?}");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "shutdown did not interrupt the queue waiter: {:?}",
        started.elapsed()
    );

    drop(blocked_body);
    connection_task.abort();
    assert!(
        server.wait_exit(Duration::from_secs(3)).is_some(),
        "server did not complete graceful shutdown"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn source_request_permit_is_held_until_response_eos() -> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    std::fs::File::create(root.path().join("large.bin"))?.set_len(4 * 1024 * 1024)?;
    let mut cmd = ram_command(root.path(), port);
    cmd.args([
        "--auth",
        TEST_AUTH_RULE,
        "--max-concurrent-requests",
        "4",
        "--max-concurrent-requests-per-source",
        "1",
        "--max-concurrent-requests-per-user",
        "4",
        "--allow-h2c",
        "--h2-max-concurrent-streams",
        "8",
    ]);
    let _server = ServerProc::spawn(cmd);

    let stream = h2_stream_from(port, Ipv4Addr::LOCALHOST).await?;
    let (sender, connection) = h2::client::handshake(stream).await?;
    let connection_task = tokio::spawn(connection);
    let mut sender = sender.ready().await?;
    let (response, _) = sender.send_request(h2_get(port, "/large.bin")?, true)?;
    let response = response.await?;
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();

    let same_source = http1_get(port, "/index.html")?;
    assert!(same_source.starts_with(b"HTTP/1.1 429"), "{same_source:?}");
    let other_source = request_from(
        port,
        Ipv4Addr::new(127, 0, 0, 2),
        &format!(
            "GET /index.html HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Connection: close\r\n\r\n"
        ),
    )?;
    assert!(
        other_source.starts_with(b"HTTP/1.1 200"),
        "{other_source:?}"
    );

    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        body.flow_control().release_capacity(chunk.len())?;
    }
    assert!(body.is_end_stream());

    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let recovered = http1_get(port, "/index.html")?;
        if recovered.starts_with(b"HTTP/1.1 200") {
            break;
        }
        assert!(recovered.starts_with(b"HTTP/1.1 429"), "{recovered:?}");
        if Instant::now() >= deadline {
            return Err("source request permit was not released at response EOS".into());
        }
        sleep(Duration::from_millis(20));
    }

    connection_task.abort();
    Ok(())
}

#[test]
fn trusted_forwarded_clients_have_independent_request_source_buckets() -> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    std::fs::File::create(root.path().join("large.bin"))?.set_len(16 * 1024 * 1024)?;
    let mut cmd = ram_command(root.path(), port);
    cmd.args([
        "--auth",
        TEST_AUTH_RULE,
        "--trusted-proxy",
        "127.0.0.1/32",
        "--trusted-proxy-header",
        "x-forwarded-for",
        "--max-concurrent-requests",
        "4",
        "--max-concurrent-requests-per-source",
        "1",
        "--max-concurrent-requests-per-user",
        "4",
        "--response-write-idle-timeout",
        "5s",
    ]);
    let _server = ServerProc::spawn(cmd);

    let mut blocked = TcpStream::connect(("127.0.0.1", port))?;
    blocked.set_read_timeout(Some(Duration::from_secs(2)))?;
    write!(
        blocked,
        "GET /large.bin HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}X-Forwarded-For: 198.51.100.10\r\nConnection: close\r\n\r\n"
    )?;
    let mut first_byte = [0u8; 1];
    blocked.read_exact(&mut first_byte)?;

    let same_client = http1_request(
        port,
        &format!(
            "GET /index.html HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}X-Forwarded-For: 198.51.100.10\r\nConnection: close\r\n\r\n"
        ),
    )?;
    assert!(same_client.starts_with(b"HTTP/1.1 429"), "{same_client:?}");
    let independent_client = http1_request(
        port,
        &format!(
            "GET /index.html HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}X-Forwarded-For: 198.51.100.11\r\nConnection: close\r\n\r\n"
        ),
    )?;
    assert!(
        independent_client.starts_with(b"HTTP/1.1 200"),
        "{independent_client:?}"
    );
    drop(blocked);
    Ok(())
}

#[test]
fn trusted_forwarded_clients_have_independent_upload_source_buckets() -> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    let mut cmd = ram_command(root.path(), port);
    cmd.args([
        "--auth",
        TEST_AUTH_RULE,
        "--allow-upload",
        "--trusted-proxy",
        "127.0.0.1/32",
        "--trusted-proxy-header",
        "x-forwarded-for",
        "--max-concurrent-uploads",
        "4",
        "--max-concurrent-uploads-per-source",
        "1",
        "--max-concurrent-uploads-per-user",
        "2",
        "--upload-idle-timeout",
        "5s",
    ]);
    let _server = ServerProc::spawn(cmd);

    let mut blocked = TcpStream::connect(("127.0.0.1", port))?;
    write!(
        blocked,
        "PUT /first.bin HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}X-Forwarded-For: 198.51.100.20\r\nContent-Length: 5\r\nConnection: close\r\n\r\na"
    )?;
    wait_for_staging_candidate(root.path())?;

    let same_client = http1_request(
        port,
        &format!(
            "PUT /same.bin HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}X-Forwarded-For: 198.51.100.20\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx"
        ),
    )?;
    assert!(same_client.starts_with(b"HTTP/1.1 429"), "{same_client:?}");
    let independent_client = http1_request(
        port,
        &format!(
            "PUT /independent.bin HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}X-Forwarded-For: 198.51.100.21\r\nContent-Length: 1\r\nConnection: close\r\n\r\ny"
        ),
    )?;
    assert!(
        independent_client.starts_with(b"HTTP/1.1 201"),
        "{independent_client:?}"
    );
    assert_eq!(std::fs::read(root.path().join("independent.bin"))?, b"y");
    drop(blocked);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn account_request_permit_spans_sources_and_response_lifetime() -> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    std::fs::File::create(root.path().join("large.bin"))?.set_len(4 * 1024 * 1024)?;
    let mut cmd = ram_command(root.path(), port);
    cmd.args([
        "--auth",
        TEST_AUTH_RULE,
        "--auth",
        "bob:bob@/:rw",
        "--max-concurrent-requests",
        "4",
        "--max-concurrent-requests-per-source",
        "2",
        "--max-concurrent-requests-per-user",
        "1",
        "--allow-h2c",
        "--h2-max-concurrent-streams",
        "8",
    ]);
    let _server = ServerProc::spawn(cmd);

    let stream = h2_stream_from(port, Ipv4Addr::LOCALHOST).await?;
    let (sender, connection) = h2::client::handshake(stream).await?;
    let connection_task = tokio::spawn(connection);
    let mut sender = sender.ready().await?;
    let (response, _) = sender.send_request(h2_get(port, "/large.bin")?, true)?;
    let mut body = response.await?.into_body();

    let admin_other_source = request_from(
        port,
        Ipv4Addr::new(127, 0, 0, 2),
        &format!(
            "GET /index.html HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Connection: close\r\n\r\n"
        ),
    )?;
    assert!(
        admin_other_source.starts_with(b"HTTP/1.1 429"),
        "{admin_other_source:?}"
    );
    let bob_same_source = request_from(
        port,
        Ipv4Addr::new(127, 0, 0, 2),
        &format!(
            "GET /index.html HTTP/1.1\r\nHost: localhost\r\n{BOB_AUTH}Connection: close\r\n\r\n"
        ),
    )?;
    assert!(
        bob_same_source.starts_with(b"HTTP/1.1 200"),
        "{bob_same_source:?}"
    );

    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        body.flow_control().release_capacity(chunk.len())?;
    }
    let recovered = request_from(
        port,
        Ipv4Addr::new(127, 0, 0, 2),
        &format!(
            "GET /index.html HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Connection: close\r\n\r\n"
        ),
    )?;
    assert!(recovered.starts_with(b"HTTP/1.1 200"), "{recovered:?}");

    connection_task.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_max_concurrent_streams_is_advertised_and_enforced() -> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    std::fs::File::create(root.path().join("large.bin"))?.set_len(4 * 1024 * 1024)?;
    let mut cmd = ram_command(root.path(), port);
    cmd.args([
        "--auth",
        TEST_AUTH_RULE,
        "--max-concurrent-requests",
        "8",
        "--allow-h2c",
        "--h2-max-concurrent-streams",
        "1",
    ]);
    let _server = ServerProc::spawn(cmd);

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    let (sender, connection) = h2::client::handshake(stream).await?;
    let connection_task = tokio::spawn(connection);
    let mut sender = sender.ready().await?;
    let (response, _) = sender.send_request(h2_get(port, "/large.bin")?, true)?;
    let first_body = response.await?.into_body();

    // h2 允许在对端活跃流上限之外本地排队一条流，故仅 `ready()` 不能证明服务器已准入。首个
    // 流控阻塞流仍开启时，排队请求不得收到响应头。
    // h2 can locally queue one stream beyond peer limits, so `ready()` is not admission proof; no headers while the blocked stream remains open.
    sender = sender.ready().await?;
    let (second_response, _) = sender.send_request(h2_get(port, "/index.html")?, true)?;
    tokio::pin!(second_response);
    assert!(
        tokio::time::timeout(Duration::from_millis(300), second_response.as_mut())
            .await
            .is_err(),
        "a second stream received a response above the configured h2 limit"
    );

    drop(first_body);
    let response = tokio::time::timeout(Duration::from_secs(2), second_response).await??;
    assert_eq!(response.status(), StatusCode::OK);

    connection_task.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn active_h2_stream_cannot_hide_another_streams_write_idle_timeout() -> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    std::fs::File::create(root.path().join("large.bin"))?.set_len(8 * 1024 * 1024)?;
    let mut cmd = ram_command(root.path(), port);
    cmd.args([
        "--auth",
        TEST_AUTH_RULE,
        "--max-concurrent-requests",
        "8",
        "--max-concurrent-requests-per-source",
        "8",
        "--max-concurrent-requests-per-user",
        "8",
        "--allow-h2c",
        "--h2-max-concurrent-streams",
        "8",
        "--response-write-idle-timeout",
        "1s",
        "--connection-idle-timeout",
        "10s",
        "--connection-max-lifetime",
        "10s",
    ]);
    let _server = ServerProc::spawn(cmd);

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    let mut client_builder = h2::client::Builder::new();
    client_builder
        .initial_window_size(64 * 1024)
        .initial_connection_window_size(1024 * 1024);
    let (sender, connection) = client_builder.handshake::<_, bytes::Bytes>(stream).await?;
    let mut connection_task = tokio::spawn(connection);
    let mut sender = sender.ready().await?;
    let (response, _) = sender.send_request(h2_get(port, "/large.bin")?, true)?;
    let mut stalled_body = response.await?.into_body();
    let first_chunk = tokio::time::timeout(Duration::from_secs(1), stalled_body.data())
        .await?
        .ok_or_else(|| {
            std::io::Error::other(
                "large response ended before it could become flow-control blocked",
            )
        })??;
    assert!(!first_chunk.is_empty());
    // 有意不释放此流接收容量；它会耗尽自身 H2 窗口，而其他流继续前进。
    // Deliberately withhold this stream's receive capacity so its H2 window exhausts while others progress.

    let started = tokio::time::Instant::now();
    let mut active_responses = 0usize;
    let connection_closed = loop {
        if connection_task.is_finished() {
            break true;
        }
        if started.elapsed() > Duration::from_millis(2500) {
            break false;
        }

        match tokio::time::timeout(
            Duration::from_millis(800),
            std::future::poll_fn(|cx| sender.poll_ready(cx)),
        )
        .await
        {
            Ok(Ok(())) => {}
            _ => break true,
        }
        let (response, _) = match sender.send_request(h2_get(port, "/index.html")?, true) {
            Ok(sent) => sent,
            Err(_) => break true,
        };
        let response = match tokio::time::timeout(Duration::from_millis(800), response).await {
            Ok(Ok(response)) => response,
            _ => break true,
        };
        assert_eq!(response.status(), StatusCode::OK);
        let mut body = response.into_body();
        let consumed = tokio::time::timeout(Duration::from_millis(800), async {
            while let Some(chunk) = body.data().await {
                let chunk = chunk?;
                body.flow_control().release_capacity(chunk.len())?;
            }
            Ok::<(), h2::Error>(())
        })
        .await;
        match consumed {
            Ok(Ok(())) => active_responses += 1,
            _ => break true,
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    };

    assert!(
        active_responses >= 5,
        "the connection did not sustain independent H2 activity before timeout: {active_responses}"
    );
    assert!(
        connection_closed,
        "active H2 traffic masked the stalled stream beyond its write-idle deadline"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(700),
        "stalled stream was closed implausibly early: {:?}",
        started.elapsed()
    );
    assert!(
        started.elapsed() < Duration::from_millis(2500),
        "stalled stream exceeded its response-local deadline: {:?}",
        started.elapsed()
    );

    drop(sender);
    let _ = tokio::time::timeout(Duration::from_secs(2), &mut connection_task)
        .await
        .expect("client H2 driver did not observe the server-side timeout");
    drop(stalled_body);
    Ok(())
}

#[test]
fn silent_and_partial_h2_prefaces_obey_the_absolute_header_deadline() -> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    let mut cmd = ram_command(root.path(), port);
    cmd.args([
        "--auth",
        TEST_AUTH_RULE,
        "--allow-h2c",
        "--header-read-timeout",
        "1s",
        "--connection-idle-timeout",
        "10s",
        "--connection-max-lifetime",
        "10s",
    ]);
    let _server = ServerProc::spawn(cmd);

    let mut silent = TcpStream::connect(("127.0.0.1", port))?;
    silent.set_read_timeout(Some(Duration::from_secs(3)))?;
    let started = Instant::now();
    let mut silent_response = Vec::new();
    read_to_end_allowing_connection_reset(&mut silent, &mut silent_response)?;
    let silent_elapsed = started.elapsed();
    assert!(silent_response.is_empty(), "{silent_response:?}");
    assert!(
        silent_elapsed >= Duration::from_millis(750),
        "silent preface closed too early: {silent_elapsed:?}"
    );
    assert!(
        silent_elapsed < Duration::from_millis(2500),
        "silent preface escaped the header deadline: {silent_elapsed:?}"
    );

    let mut partial = TcpStream::connect(("127.0.0.1", port))?;
    partial.set_read_timeout(Some(Duration::from_secs(2)))?;
    let started = Instant::now();
    for byte in b"PRI * ".iter() {
        if partial.write_all(std::slice::from_ref(byte)).is_err() {
            break;
        }
        sleep(Duration::from_millis(200));
    }
    let mut partial_response = Vec::new();
    read_to_end_allowing_connection_reset(&mut partial, &mut partial_response)?;
    let partial_elapsed = started.elapsed();
    assert!(partial_response.is_empty(), "{partial_response:?}");
    assert!(
        partial_elapsed >= Duration::from_millis(750),
        "partial preface closed too early: {partial_elapsed:?}"
    );
    assert!(
        partial_elapsed < Duration::from_millis(2500),
        "preface trickle extended the absolute header deadline: {partial_elapsed:?}"
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plaintext_h2c_is_disabled_by_default() -> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    let mut cmd = ram_command(root.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE]);
    let _server = ServerProc::spawn(cmd);

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    let (sender, connection) = h2::client::handshake(stream).await?;
    let connection_task = tokio::spawn(connection);
    let request = h2_get(port, "/index.html")?;
    let request = async move {
        let mut sender = sender.ready().await?;
        let (response, _) = sender.send_request(request, true)?;
        response.await
    };
    let result = tokio::time::timeout(Duration::from_secs(2), request)
        .await
        .expect("the HTTP/1-only listener did not reject h2c in time");
    assert!(
        result.is_err(),
        "a plaintext listener accepted prior-knowledge HTTP/2 without --allow-h2c"
    );

    connection_task.abort();
    Ok(())
}

fn h2_get(port: u16, path: &str) -> Result<Request<()>, Error> {
    Ok(Request::builder()
        .version(Version::HTTP_2)
        .method(Method::GET)
        .uri(format!("http://localhost:{port}{path}"))
        .header("authorization", "Basic YWRtaW46YWRtaW4=")
        .body(())?)
}

async fn h2_stream_from(port: u16, local_ip: Ipv4Addr) -> Result<tokio::net::TcpStream, Error> {
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.bind(SocketAddr::from((local_ip, 0)))?;
    Ok(socket
        .connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .await?)
}

fn http1_get(port: u16, path: &str) -> Result<Vec<u8>, Error> {
    http1_request(
        port,
        &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Connection: close\r\n\r\n"),
    )
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

fn process_socket_fd_count(pid: u32) -> Result<usize, Error> {
    let mut count = 0usize;
    for entry in std::fs::read_dir(format!("/proc/{pid}/fd"))? {
        let target = std::fs::read_link(entry?.path())?;
        if target.to_string_lossy().starts_with("socket:[") {
            count += 1;
        }
    }
    Ok(count)
}

fn read_to_end_allowing_connection_reset(
    stream: &mut TcpStream,
    response: &mut Vec<u8>,
) -> Result<(), Error> {
    match stream.read_to_end(response) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn wait_for_socket_fd_count(pid: u32, expected: usize) -> Result<(), Error> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let observed = process_socket_fd_count(pid)?;
        if observed == expected {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "socket fd count did not reach {expected}; last observed {observed}"
            )
            .into());
        }
        sleep(Duration::from_millis(10));
    }
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
