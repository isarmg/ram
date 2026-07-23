#[path = "common/digest_auth_util.rs"]
mod digest_auth_util;
#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/utils.rs"]
mod utils;

use digest_auth_util::send_with_digest_auth;
use fixtures::{
    Error, ServerProc, TEST_AUTH_PASS, TEST_AUTH_RULE, TEST_AUTH_USER, port, ram_command, tmpdir,
};

use assert_cmd::prelude::*;
use assert_fs::fixture::TempDir;
use rstest::rstest;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread::sleep;
use std::time::Duration;

/// 日志行最迟应在响应返回前写入 stdout；给捕获线程留的宽限时间。
/// Grace period for the capture thread; the log line should reach stdout before the response returns.
const LOG_WAIT: Duration = Duration::from_secs(2);

fn spawn_server(tmpdir: &TempDir, port: u16, extra_args: &[&str]) -> ServerProc {
    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE]);
    cmd.args(extra_args);
    ServerProc::spawn(cmd)
}

#[rstest]
#[case(&["-a", "user:pass@/:rw", "--log-format", "$remote_user"], false)]
#[case(&["-a", "user:pass@/:rw", "--log-format", "$remote_user"], true)]
fn log_remote_user(
    tmpdir: TempDir,
    port: u16,
    #[case] args: &[&str],
    #[case] is_basic: bool,
) -> Result<(), Error> {
    let server = spawn_server(&tmpdir, port, args);

    let req_builder = fetch!(b"GET", &format!("http://localhost:{port}"));

    let resp = if is_basic {
        req_builder.basic_auth("user", Some("pass")).send()?
    } else {
        send_with_digest_auth(req_builder, "user", "pass")?
    };

    assert_eq!(resp.status(), 200);
    let _ = resp.bytes()?;

    let line = server.wait_for_stdout_line(|line| line.ends_with("user"), LOG_WAIT);
    assert!(
        line.is_some(),
        "expected a log line ending with the user name, got: {:?}",
        server.stdout_lines()
    );
    Ok(())
}

#[rstest]
fn log_redacts_token(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let server = spawn_server(&tmpdir, port, &["--log-format", "$request"]);

    // 查询串凭据有意不受支持，但客户端仍可能误发一个 `token=` 参数；日志必须脱敏其值。
    // Query-string credentials are deliberately unsupported, but a client may accidentally send a
    // `token=` parameter; its value must be redacted in the log.
    let secret = "s3cr3t-download-value";
    let token_url = format!("http://localhost:{port}/index.html?token={secret}");
    let resp = fetch!(b"GET", &token_url).send()?;
    assert_eq!(resp.status(), 401);
    let _ = resp.bytes()?;

    let line = server.wait_for_stdout_line(|line| line.contains("token=***"), LOG_WAIT);
    assert!(line.is_some(), "expected a redacted token log line");
    assert!(
        server
            .stdout_lines()
            .iter()
            .all(|line| !line.contains(secret)),
        "token leaked into log"
    );
    Ok(())
}

/// 即使查询键使用百分号编码（`%74oken`），令牌值也必须脱敏。查询凭据虽被拒绝，日志仍不得
/// 泄露误提供的秘密。回归测试确保脱敏先于 URL 解码。
/// The token value stays redacted even when its query key is percent-encoded. Rejected query
/// credentials must not leak, and redaction must run before URL decoding.
#[rstest]
fn log_redacts_percent_encoded_token_key(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let server = spawn_server(&tmpdir, port, &["--log-format", "$request"]);

    let secret = "s3cr3t-download-value";
    // `%74` 解码为 `t`，日志器仍必须识别该键。
    // `%74` decodes to `t`, so the logger must still recognize the key.
    let token_url = format!("http://localhost:{port}/index.html?%74oken={secret}");
    let resp = fetch!(b"GET", &token_url).send()?;
    assert_eq!(resp.status(), 401);
    let _ = resp.bytes()?;

    let line = server.wait_for_stdout_line(|line| line.contains("token=***"), LOG_WAIT);
    assert!(line.is_some(), "expected a redacted token log line");
    assert!(
        server
            .stdout_lines()
            .iter()
            .all(|line| !line.contains(secret)),
        "token leaked into log: {:?}",
        server.stdout_lines()
    );
    Ok(())
}

#[rstest]
#[case(&["--log-format", ""])]
fn no_log(tmpdir: TempDir, port: u16, #[case] args: &[&str]) -> Result<(), Error> {
    let server = spawn_server(&tmpdir, port, args);

    let resp = fetch!(b"GET", &format!("http://localhost:{port}"))
        .basic_auth(TEST_AUTH_USER, Some(TEST_AUTH_PASS))
        .send()?;
    assert_eq!(resp.status(), 200);
    let _ = resp.bytes()?;

    // 消极断言只能给写入留一小段宽限：若访问日志被错误地输出，
    // 它会以 "GET /" 请求行的形式出现。标记必须带上 "/"——启动横幅里
    // 有随机临时目录名，理论上可能含 "GET" 子串，但不可能含 "GET /"。
    // A negative assertion can allow only a short write grace period. An erroneous access log would
    // contain the "GET /" request line; include the slash because a random startup path might contain
    // "GET" by chance, but cannot contain that request marker.
    sleep(Duration::from_millis(300));
    assert!(
        server
            .stdout_lines()
            .iter()
            .all(|line| !line.contains("GET /")),
        "unexpected access log line: {:?}",
        server.stdout_lines()
    );
    Ok(())
}

#[rstest]
fn log_escapes_decoded_crlf_without_forging_a_second_record(
    tmpdir: TempDir,
    port: u16,
) -> Result<(), Error> {
    let server = spawn_server(&tmpdir, port, &["--log-format", "$request_uri"]);
    let resp = fetch!(b"GET", format!("http://localhost:{port}/%0d%0aFORGED")).send()?;
    assert!(resp.status().is_client_error());
    let _ = resp.bytes()?;

    let escaped = server.wait_for_stdout_line(|line| line.contains(r"\x0d\x0aFORGED"), LOG_WAIT);
    assert!(escaped.is_some(), "logs: {:?}", server.stdout_lines());
    assert!(
        server.stdout_lines().iter().all(|line| line != "FORGED"),
        "CRLF created a forged log line"
    );
    Ok(())
}

#[rstest]
fn invalid_credentials_never_become_the_logged_remote_user(
    tmpdir: TempDir,
    port: u16,
) -> Result<(), Error> {
    let server = spawn_server(&tmpdir, port, &["--log-format", "$remote_user"]);
    let resp = fetch!(b"GET", format!("http://localhost:{port}/"))
        .basic_auth("forged-auditor", Some("wrong"))
        .send()?;
    assert_eq!(resp.status(), 401);
    let _ = resp.bytes()?;
    assert!(
        server
            .wait_for_stdout_line(|line| line == "-", LOG_WAIT)
            .is_some()
    );
    assert!(
        server
            .stdout_lines()
            .iter()
            .all(|line| !line.contains("forged-auditor"))
    );
    Ok(())
}

#[rstest]
#[case("$http_authorization")]
#[case("$http_Authorization")]
#[case("$http_proxy_authorization")]
#[case("$http_cookie")]
#[case("$http_set_cookie")]
#[case("$http_x_api_key")]
#[case("$http_x_auth_token")]
#[case("$http_x_client_secret")]
#[case("$http_x_user_password")]
fn sensitive_headers_cannot_be_added_to_access_log(
    tmpdir: TempDir,
    port: u16,
    #[case] format: &str,
) -> Result<(), Error> {
    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE, "--log-format", format]);
    cmd.assert()
        .failure()
        .stderr(predicates::str::contains("is sensitive"));
    Ok(())
}

#[rstest]
fn completed_response_log_has_request_id_timing_and_wire_bytes(
    tmpdir: TempDir,
    port: u16,
) -> Result<(), Error> {
    let server = spawn_server(
        &tmpdir,
        port,
        &[
            "--log-format",
            "$request_id $status $response_outcome $body_bytes $bytes_sent $expected_body_bytes $client_cancelled $response_started $request_time $response_ready_time",
        ],
    );

    let resp = fetch!(b"GET", format!("http://localhost:{port}/test.txt"))
        .basic_auth(TEST_AUTH_USER, Some(TEST_AUTH_PASS))
        .send()?;
    assert_eq!(resp.status(), 200);
    let request_id = resp
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .expect("response request id")
        .to_string();
    assert_eq!(request_id.len(), 32);
    assert!(
        request_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "request id must be a lowercase simple UUID: {request_id}"
    );
    let body = resp.bytes()?;

    let line = server
        .wait_for_stdout_line(|line| line.starts_with(&request_id), LOG_WAIT)
        .expect("completion access log");
    let fields = line.split_whitespace().collect::<Vec<_>>();
    assert_eq!(fields[0], request_id);
    assert_eq!(fields[1], "200");
    assert_eq!(fields[2], "complete");
    assert_eq!(fields[3].parse::<usize>()?, body.len());
    assert_eq!(fields[4].parse::<usize>()?, body.len());
    assert_eq!(fields[5].parse::<usize>()?, body.len());
    assert_eq!(fields[6], "0");
    assert_eq!(fields[7], "1");
    let request_time = fields[8].parse::<f64>()?;
    let response_ready_time = fields[9].parse::<f64>()?;
    assert!(request_time >= response_ready_time);
    assert!(response_ready_time >= 0.0);

    // 一个响应必须只产生一条完成记录，即使不同协议内部同时观察到 EOF 和 Drop 生命周期路径。
    // A response must produce one completion record even if protocol internals observe both EOF and Drop.
    sleep(Duration::from_millis(50));
    assert_eq!(
        server
            .stdout_lines()
            .iter()
            .filter(|candidate| candidate.starts_with(&request_id))
            .count(),
        1
    );
    Ok(())
}

#[rstest]
fn dropped_file_download_is_logged_as_downstream_cancelled(
    tmpdir: TempDir,
    port: u16,
) -> Result<(), Error> {
    const LARGE_FILE_BYTES: usize = 32 * 1024 * 1024;
    fs::write(
        tmpdir.path().join("large.bin"),
        vec![b'x'; LARGE_FILE_BYTES],
    )?;
    let server = spawn_server(
        &tmpdir,
        port,
        &[
            "--log-format",
            "$request_id $response_outcome $body_bytes $client_cancelled",
        ],
    );

    let mut socket = TcpStream::connect(("127.0.0.1", port))?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    socket.write_all(
        format!(
            "GET /large.bin HTTP/1.1\r\nHost: localhost:{port}\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )?;

    let mut received = Vec::new();
    let header_end = loop {
        let mut chunk = [0_u8; 4096];
        let count = socket.read(&mut chunk)?;
        assert!(count > 0, "connection ended before response headers");
        received.extend_from_slice(&chunk[..count]);
        if let Some(index) = received.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = std::str::from_utf8(&received[..header_end])?;
    assert!(headers.starts_with("HTTP/1.1 200"), "{headers}");
    let request_id = headers
        .lines()
        .find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                name.eq_ignore_ascii_case("x-request-id")
                    .then(|| value.trim().to_string())
            })
        })
        .expect("x-request-id response header");
    // linger=0 使 close 发送 RST，而非在测试停止读取后让内核排空剩余响应；快速回环接口上
    // 下游取消信号也因此保持确定。
    // Linger zero makes close send RST instead of draining the response after the test stops reading,
    // keeping downstream cancellation deterministic even on a fast loopback interface.
    socket2::SockRef::from(&socket).set_linger(Some(Duration::ZERO))?;
    drop(socket);

    let line = server
        .wait_for_stdout_line(|line| line.starts_with(&request_id), LOG_WAIT)
        .expect("cancelled response access log");
    let fields = line.split_whitespace().collect::<Vec<_>>();
    assert_eq!(fields[1], "downstream_cancelled", "{line}");
    assert_eq!(fields[3], "1", "{line}");
    assert!(fields[2].parse::<usize>()? < LARGE_FILE_BYTES, "{line}");
    Ok(())
}
