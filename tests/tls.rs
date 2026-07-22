#![cfg(feature = "tls")]

#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/utils.rs"]
mod utils;

use fixtures::{
    Error, ServerProc, TEST_AUTH_PASS, TEST_AUTH_RULE, TEST_AUTH_USER, TestServer, port,
    ram_command, server, tmpdir,
};
use predicates::str::contains;
use reqwest::blocking::ClientBuilder;
use rstest::rstest;
use std::io::Read;
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

/// 可使用 TLS 启动服务器并接收加密响应。 / Start with TLS and receive encrypted responses.
#[rstest]
#[case(server(&[
        "--tls-cert", "tests/fixtures/tls/cert.pem",
        "--tls-key", "tests/fixtures/tls/key_pkcs8.pem",
]))]
#[case(server(&[
        "--tls-cert", "tests/fixtures/tls/cert.pem",
        "--tls-key", "tests/fixtures/tls/key_pkcs1.pem",
]))]
#[case(server(&[
        "--tls-cert", "tests/fixtures/tls/cert_ecdsa.pem",
        "--tls-key", "tests/fixtures/tls/key_ecdsa.pem",
]))]
fn tls_works(#[case] server: TestServer) -> Result<(), Error> {
    let client = ClientBuilder::new()
        .tls_danger_accept_invalid_certs(true)
        .build()?;
    let resp = client.get(server.url()).send()?.error_for_status()?;
    assert!(
        !resp.headers().contains_key("strict-transport-security"),
        "HSTS must remain opt-in even on a direct TLS listener"
    );
    assert_resp_paths!(resp);
    Ok(())
}

#[test]
fn direct_tls_prefers_http2_via_alpn() -> Result<(), Error> {
    let root = tmpdir();
    let secrets = tmpdir();
    let certificate = secrets.path().join("cert.pem");
    let private_key = secrets.path().join("key.pem");
    std::fs::copy("tests/fixtures/tls/cert.pem", &certificate)?;
    std::fs::copy("tests/fixtures/tls/key_pkcs8.pem", &private_key)?;
    std::fs::set_permissions(&private_key, std::fs::Permissions::from_mode(0o600))?;
    let listen_port = port();
    let mut command = ram_command(root.path(), listen_port);
    command
        .args(["--auth", TEST_AUTH_RULE, "--tls-cert"])
        .arg(&certificate)
        .arg("--tls-key")
        .arg(&private_key)
        .args(["--h2-max-concurrent-streams", "2"]);
    let _server = ServerProc::spawn(command);

    let client = ClientBuilder::new()
        .tls_danger_accept_invalid_certs(true)
        .build()?;
    let response = client
        .get(format!("https://127.0.0.1:{listen_port}/"))
        .basic_auth(TEST_AUTH_USER, Some(TEST_AUTH_PASS))
        .send()?
        .error_for_status()?;
    assert_eq!(
        response.version(),
        reqwest::Version::HTTP_2,
        "TLS client and server did not negotiate h2 through ALPN"
    );
    Ok(())
}

#[rstest]
fn direct_tls_can_enable_hsts(
    #[with(&[
        "--tls-cert",
        "tests/fixtures/tls/cert.pem",
        "--tls-key",
        "tests/fixtures/tls/key_pkcs8.pem",
        "--hsts-max-age",
        "31536000",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    let client = ClientBuilder::new()
        .tls_danger_accept_invalid_certs(true)
        .build()?;
    let resp = client.get(server.url()).send()?.error_for_status()?;
    assert_eq!(
        resp.headers().get("strict-transport-security").unwrap(),
        "max-age=31536000"
    );
    Ok(())
}

#[test]
fn stalled_tls_handshake_is_bounded_by_lifetime_from_accept() -> Result<(), Error> {
    let root = fixtures::tmpdir();
    let secrets = tmpdir();
    let private_key = secrets.path().join("key.pem");
    std::fs::copy("tests/fixtures/tls/key_pkcs8.pem", &private_key)?;
    std::fs::set_permissions(&private_key, std::fs::Permissions::from_mode(0o600))?;
    let listen_port = port();
    let mut command = ram_command(root.path(), listen_port);
    command
        .args([
            "--auth",
            TEST_AUTH_RULE,
            "--tls-cert",
            "tests/fixtures/tls/cert.pem",
            "--tls-key",
        ])
        .arg(&private_key)
        .args(["--connection-max-lifetime", "1s"]);
    let _server = fixtures::ServerProc::spawn(command);

    let mut stalled = TcpStream::connect(("127.0.0.1", listen_port))?;
    stalled.set_read_timeout(Some(Duration::from_secs(3)))?;
    let started = Instant::now();
    let mut response = Vec::new();
    stalled.read_to_end(&mut response)?;
    let elapsed = started.elapsed();
    assert!(
        response.is_empty(),
        "a silent TLS peer received bytes: {response:?}"
    );
    assert!(
        elapsed >= Duration::from_millis(750),
        "TLS connection closed before its configured lifetime: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(2500),
        "TLS handshake time extended the accept-anchored lifetime: {elapsed:?}"
    );
    Ok(())
}

#[rstest]
fn hsts_without_direct_tls_is_rejected() -> Result<(), Error> {
    let port = port().to_string();
    assert_cmd::cargo::cargo_bin_cmd!("ram")
        .env_remove("RAM_CONFIG")
        .args([
            "--auth",
            TEST_AUTH_RULE,
            "--hsts-max-age",
            "31536000",
            "--port",
            &port,
        ])
        .assert()
        .failure()
        .stderr(contains("hsts-max-age requires Ram's direct TLS"));
    Ok(())
}

/// 错误证书路径会报错。 / A wrong certificate path reports an error.
#[rstest]
fn wrong_path_cert() -> Result<(), Error> {
    let port = port().to_string();
    assert_cmd::cargo::cargo_bin_cmd!("ram")
        .env_remove("RAM_CONFIG")
        .args([
            "--auth",
            TEST_AUTH_RULE,
            "--tls-cert",
            "wrong",
            "--tls-key",
            "tests/fixtures/tls/key.pem",
            "--port",
            &port,
        ])
        .assert()
        .failure()
        .stderr(contains("Failed to load cert file at `wrong`"));

    Ok(())
}

/// 错误密钥路径会报错。 / A wrong key path reports an error.
#[rstest]
fn wrong_path_key() -> Result<(), Error> {
    let port = port().to_string();
    assert_cmd::cargo::cargo_bin_cmd!("ram")
        .env_remove("RAM_CONFIG")
        .args([
            "--auth",
            TEST_AUTH_RULE,
            "--tls-cert",
            "tests/fixtures/tls/cert.pem",
            "--tls-key",
            "wrong",
            "--port",
            &port,
        ])
        .assert()
        .failure()
        .stderr(contains("Failed to inspect TLS private key file"));

    Ok(())
}
