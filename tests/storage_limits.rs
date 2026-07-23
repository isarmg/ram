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
use std::path::Path;
use std::thread::sleep;
use std::time::{Duration, Instant};

fn storage_command(root: &Path, port: u16, reserve: &str) -> std::process::Command {
    let mut command = ram_command(root, port);
    command.args([
        "--auth",
        TEST_AUTH_RULE,
        "-A",
        "--storage-space-check",
        "--storage-reserve",
        reserve,
    ]);
    command
}

fn url(port: u16, path: &str) -> String {
    format!("http://localhost:{port}/{path}")
}

fn candidate_count(root: &Path) -> Result<usize, Error> {
    Ok(fs::read_dir(root)?
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
        .filter(|name| name.starts_with(".ram-upload-") && name.ends_with(".tmp"))
        .count())
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

#[rstest]
fn storage_reserve_denies_put_without_publishing_or_leaving_staging(
    tmpdir: TempDir,
    port: u16,
) -> Result<(), Error> {
    let command = storage_command(tmpdir.path(), port, "18446744073709551615");
    let _server = ServerProc::spawn(command);

    let response = fetch!(b"PUT", url(port, "denied-upload.bin"))
        .basic_auth(TEST_AUTH_USER, Some(TEST_AUTH_PASS))
        .body(b"payload".to_vec())
        .send()?;
    assert_eq!(response.status(), reqwest::StatusCode::INSUFFICIENT_STORAGE);
    assert!(!tmpdir.path().join("denied-upload.bin").exists());
    wait_for_no_candidates(tmpdir.path(), Duration::from_secs(2))?;
    Ok(())
}

#[rstest]
fn storage_reserve_denial_preserves_existing_file(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let target = tmpdir.path().join("existing.bin");
    fs::write(&target, b"original")?;
    let command = storage_command(tmpdir.path(), port, "18446744073709551615");
    let _server = ServerProc::spawn(command);

    let response = fetch!(b"PUT", url(port, "existing.bin"))
        .basic_auth(TEST_AUTH_USER, Some(TEST_AUTH_PASS))
        .body(b"replacement".to_vec())
        .send()?;
    assert_eq!(response.status(), reqwest::StatusCode::INSUFFICIENT_STORAGE);
    assert_eq!(fs::read(target)?, b"original");
    wait_for_no_candidates(tmpdir.path(), Duration::from_secs(2))?;
    Ok(())
}

#[rstest]
fn storage_check_with_zero_reserve_allows_put(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let command = storage_command(tmpdir.path(), port, "0");
    let _server = ServerProc::spawn(command);

    let response = fetch!(b"PUT", url(port, "accepted-upload.bin"))
        .basic_auth(TEST_AUTH_USER, Some(TEST_AUTH_PASS))
        .body(b"payload".to_vec())
        .send()?;
    assert_eq!(response.status(), reqwest::StatusCode::CREATED);
    assert_eq!(
        fs::read(tmpdir.path().join("accepted-upload.bin"))?,
        b"payload"
    );
    wait_for_no_candidates(tmpdir.path(), Duration::from_secs(2))?;
    Ok(())
}
