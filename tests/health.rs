#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/utils.rs"]
mod utils;

use assert_fs::fixture::TempDir;
use fixtures::{
    Error, ServerProc, TEST_AUTH_PASS, TEST_AUTH_RULE, TEST_AUTH_USER, TestServer, port,
    ram_command, server, tmpdir,
};
use reqwest::StatusCode;
use rstest::rstest;

const HEALTH_CHECK_PATH: &str = "__ram__/health";
const HEALTH_CHECK_RESPONSE: &str = r#"{"status":"OK"}"#;
const HEALTH_UNAVAILABLE_RESPONSE: &str = r#"{"status":"UNAVAILABLE"}"#;

#[rstest]
fn normal_health(server: TestServer) -> Result<(), Error> {
    let resp = reqwest::blocking::get(format!("{}{HEALTH_CHECK_PATH}", server.url()))?;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("cache-control").unwrap(), "no-store");
    assert_eq!(resp.text()?, HEALTH_CHECK_RESPONSE);
    Ok(())
}

#[rstest]
fn auth_health(
    #[with(&["--auth", "user:pass@/:rw", "-A"])] server: TestServer,
) -> Result<(), Error> {
    let resp = reqwest::blocking::get(format!("{}{HEALTH_CHECK_PATH}", server.url()))?;
    assert_eq!(resp.text()?, HEALTH_CHECK_RESPONSE);
    Ok(())
}

#[rstest]
fn path_prefix_health(#[with(&["--path-prefix", "xyz"])] server: TestServer) -> Result<(), Error> {
    let resp = reqwest::blocking::get(format!("{}xyz/{HEALTH_CHECK_PATH}", server.url()))?;
    assert_eq!(resp.text()?, HEALTH_CHECK_RESPONSE);
    Ok(())
}

#[rstest]
fn health_becomes_unavailable_when_directory_root_disappears(
    server: TestServer,
) -> Result<(), Error> {
    std::fs::remove_dir_all(server.path())?;
    let url = format!("{}{HEALTH_CHECK_PATH}", server.url());
    let resp = reqwest::blocking::get(&url)?;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(resp.text()?, HEALTH_UNAVAILABLE_RESPONSE);

    let head = fetch!(b"HEAD", &url).send()?;
    assert_eq!(head.status(), StatusCode::SERVICE_UNAVAILABLE);
    let declared_length = head
        .headers()
        .get("content-length")
        .unwrap()
        .to_str()?
        .parse::<usize>()?;
    assert_eq!(declared_length, HEALTH_UNAVAILABLE_RESPONSE.len());
    assert!(head.bytes()?.is_empty());
    Ok(())
}

#[rstest]
fn single_file_health_tracks_file_readiness(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let served_file = tmpdir.path().join("served.txt");
    std::fs::write(&served_file, "ready")?;
    let mut cmd = ram_command(&served_file, port);
    cmd.args(["--auth", TEST_AUTH_RULE]);
    let _server = ServerProc::spawn(cmd);
    let url = format!("http://localhost:{port}/{HEALTH_CHECK_PATH}");

    let ready = reqwest::blocking::get(&url)?;
    assert_eq!(ready.status(), StatusCode::OK);
    assert_eq!(ready.text()?, HEALTH_CHECK_RESPONSE);

    std::fs::remove_file(&served_file)?;
    let unavailable = reqwest::blocking::get(&url)?;
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(unavailable.text()?, HEALTH_UNAVAILABLE_RESPONSE);
    Ok(())
}

#[rstest]
fn single_file_health_detects_ancestor_replacement_but_reads_stay_pinned(
    tmpdir: TempDir,
    port: u16,
) -> Result<(), Error> {
    let configured_parent = tmpdir.path().join("configured-parent");
    let startup_parent = tmpdir.path().join("startup-parent");
    std::fs::create_dir(&configured_parent)?;
    let served_file = configured_parent.join("served.txt");
    std::fs::write(&served_file, "startup inode")?;
    let mut cmd = ram_command(&served_file, port);
    cmd.args(["--auth", TEST_AUTH_RULE]);
    let _server = ServerProc::spawn(cmd);

    std::fs::rename(&configured_parent, &startup_parent)?;
    std::fs::create_dir(&configured_parent)?;
    std::fs::write(&served_file, "replacement inode")?;

    let health = reqwest::blocking::get(format!("http://localhost:{port}/{HEALTH_CHECK_PATH}"))?;
    assert_eq!(health.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(health.text()?, HEALTH_UNAVAILABLE_RESPONSE);

    let file = reqwest::blocking::Client::new()
        .get(format!("http://localhost:{port}/served.txt"))
        .basic_auth(TEST_AUTH_USER, Some(TEST_AUTH_PASS))
        .send()?;
    assert_eq!(file.status(), StatusCode::OK);
    assert_eq!(file.text()?, "startup inode");
    Ok(())
}
