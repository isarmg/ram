#[path = "common/fixtures.rs"]
mod fixtures;

use fixtures::{
    Error, ServerProc, TEST_AUTH_PASS, TEST_AUTH_RULE, TEST_AUTH_USER, TestServer, port,
    ram_command, server, tmpdir,
};

use assert_cmd::prelude::*;
use assert_fs::fixture::TempDir;
use regex::Regex;
use rstest::rstest;
use std::process::Command;
use std::time::Duration;

#[rstest]
#[case(&["-b", "20.205.243.166"])]
fn bind_fails(tmpdir: TempDir, port: u16, #[case] args: &[&str]) -> Result<(), Error> {
    Command::new(assert_cmd::cargo::cargo_bin!("ram"))
        .env_remove("RAM_CONFIG")
        .arg(tmpdir.path())
        .arg("-p")
        .arg(port.to_string())
        .args(["--auth", TEST_AUTH_RULE])
        .arg("--allow-insecure-http")
        .args(args)
        .assert()
        .stderr(predicates::str::contains("Failed to bind"))
        .failure();

    Ok(())
}

#[rstest]
#[case(server(&[] as &[&str]), true, true)]
#[case(server(&["-b", "0.0.0.0", "--allow-insecure-http"]), true, false)]
#[case(server(&["-b", "127.0.0.1", "-b", "::1"]), true, true)]
fn bind_ipv4_ipv6(
    #[case] server: TestServer,
    #[case] bind_ipv4: bool,
    #[case] bind_ipv6: bool,
) -> Result<(), Error> {
    assert_eq!(
        reqwest::blocking::get(format!("http://127.0.0.1:{}", server.port()).as_str()).is_ok(),
        bind_ipv4
    );
    assert_eq!(
        reqwest::blocking::get(format!("http://[::1]:{}", server.port()).as_str()).is_ok(),
        bind_ipv6
    );

    Ok(())
}

#[rstest]
#[case(&[] as &[&str])]
#[case(&["--path-prefix", "/prefix"])]
fn validate_printed_urls(tmpdir: TempDir, port: u16, #[case] args: &[&str]) -> Result<(), Error> {
    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE]).args(args);
    let server = ServerProc::spawn(cmd);

    server
        .wait_for_stdout_line(|line| line.contains("http://"), Duration::from_secs(2))
        .expect("no URL line in the startup banner");
    let banner = server.stdout_lines().join("\n");

    let urls = Regex::new(r"http://[a-zA-Z0-9\.\[\]:/]+")
        .unwrap()
        .captures_iter(&banner)
        .filter_map(|captures| captures.get(0).map(|value| value.as_str().to_string()))
        .collect::<Vec<_>>();

    assert!(!urls.is_empty());
    reqwest::blocking::Client::new()
        .get(&urls[0])
        .basic_auth(TEST_AUTH_USER, Some(TEST_AUTH_PASS))
        .send()?
        .error_for_status()?;

    Ok(())
}
