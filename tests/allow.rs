#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/utils.rs"]
mod utils;

use fixtures::{Error, TestServer, server};
use rstest::rstest;
use std::io::Cursor;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

fn upload_candidates(root: &Path) -> Result<Vec<String>, Error> {
    Ok(std::fs::read_dir(root)?
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
        .filter(|name| name.starts_with(".ram-upload-") && name.ends_with(".tmp"))
        .collect())
}

fn wait_for_no_upload_candidates(root: &Path, within: Duration) -> Result<(), Error> {
    let deadline = Instant::now() + within;
    loop {
        let candidates = upload_candidates(root)?;
        if candidates.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "upload candidates remained after the cleanup deadline: {candidates:?}"
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[rstest]
fn default_not_allow_upload(server: TestServer) -> Result<(), Error> {
    let url = format!("{}file1", server.url());
    let resp = fetch!(b"PUT", &url).body(b"abc".to_vec()).send()?;
    assert_eq!(resp.status(), 403);
    Ok(())
}

#[rstest]
fn default_not_allow_delete(server: TestServer) -> Result<(), Error> {
    let url = format!("{}test.html", server.url());
    let resp = fetch!(b"DELETE", &url).send()?;
    assert_eq!(resp.status(), 403);
    Ok(())
}

#[rstest]
fn default_not_allow_archive(server: TestServer) -> Result<(), Error> {
    let resp = reqwest::blocking::get(format!("{}?zip", server.url()))?;
    assert_eq!(resp.status(), 404);
    Ok(())
}

#[rstest]
fn default_not_exist_dir(server: TestServer) -> Result<(), Error> {
    let resp = reqwest::blocking::get(format!("{}404/", server.url()))?;
    assert_eq!(resp.status(), 404);
    Ok(())
}

#[rstest]
fn allow_upload_not_exist_dir(
    #[with(&["--allow-upload"])] server: TestServer,
) -> Result<(), Error> {
    let resp = reqwest::blocking::get(format!("{}404/", server.url()))?;
    assert_eq!(resp.status(), 200);
    Ok(())
}

#[rstest]
fn allow_upload_no_override(#[with(&["--allow-upload"])] server: TestServer) -> Result<(), Error> {
    let url = format!("{}index.html", server.url());
    let resp = fetch!(b"PUT", &url).body(b"abc".to_vec()).send()?;
    assert_eq!(resp.status(), 403);
    Ok(())
}

#[rstest]
fn allow_delete_no_override(#[with(&["--allow-delete"])] server: TestServer) -> Result<(), Error> {
    let url = format!("{}index.html", server.url());
    let resp = fetch!(b"PUT", &url).body(b"abc".to_vec()).send()?;
    assert_eq!(resp.status(), 403);
    Ok(())
}

#[rstest]
fn allow_upload_delete_can_override(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    let url = format!("{}index.html", server.url());
    let resp = fetch!(b"PUT", &url).body(b"abc".to_vec()).send()?;
    // 覆盖现有资源成功但未新建资源，因此返回 204 而非 201。
    // Overwriting succeeds without creating a resource, so return 204 rather than 201.
    assert_eq!(resp.status(), 204);
    assert_eq!(reqwest::blocking::get(&url)?.text()?, "abc");
    Ok(())
}

#[rstest]
fn allow_search(#[with(&["--allow-search"])] server: TestServer) -> Result<(), Error> {
    let resp = reqwest::blocking::get(format!("{}?q={}", server.url(), "test.html"))?;
    assert_eq!(resp.status(), 200);
    let paths = utils::retrieve_index_paths(&resp.text()?);
    assert!(!paths.is_empty());
    for p in paths {
        assert!(p.contains("test.html"));
    }
    Ok(())
}

#[rstest]
fn allow_archive(#[with(&["--allow-archive"])] server: TestServer) -> Result<(), Error> {
    let resp = reqwest::blocking::get(format!("{}?zip", server.url()))?;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/zip"
    );
    assert!(resp.headers().contains_key("content-disposition"));
    Ok(())
}

#[rstest]
fn max_upload_size_rejects_oversized(
    #[with(&["--allow-upload", "--max-upload-size", "8"])] server: TestServer,
) -> Result<(), Error> {
    let url = format!("{}big.bin", server.url());
    // 9 字节超过 8 字节上限：返回 413 且不创建文件。
    // Nine bytes exceed the eight-byte cap: reject with 413 and create no file.
    let resp = fetch!(b"PUT", &url).body(b"123456789".to_vec()).send()?;
    assert_eq!(resp.status(), 413);
    let resp = reqwest::blocking::get(&url)?;
    assert_eq!(resp.status(), 404);
    Ok(())
}

#[rstest]
fn max_upload_size_allows_within_limit(
    #[with(&["--allow-upload", "--max-upload-size", "8"])] server: TestServer,
) -> Result<(), Error> {
    let url = format!("{}ok.bin", server.url());
    // 8 字节恰好等于上限：接受。 / Eight bytes exactly meet the cap and are accepted.
    let resp = fetch!(b"PUT", &url).body(b"12345678".to_vec()).send()?;
    assert_eq!(resp.status(), 201);
    Ok(())
}

#[rstest]
fn max_upload_size_allows_small_put_to_replace_larger_file(
    #[with(&["--allow-upload", "--allow-delete", "--max-upload-size", "8"])] server: TestServer,
) -> Result<(), Error> {
    let path = server.path().join("replace.bin");
    std::fs::write(
        &path,
        b"this old representation is larger than the upload cap",
    )?;
    let url = format!("{}replace.bin", server.url());

    let resp = fetch!(b"PUT", &url).body(b"small".to_vec()).send()?;
    assert_eq!(resp.status(), 204);
    assert_eq!(std::fs::read(path)?, b"small");
    Ok(())
}

#[rstest]
fn put_does_not_preserve_special_mode_bits(
    #[with(&["-A"])] server: TestServer,
) -> Result<(), Error> {
    let path = server.path().join("privileged.bin");
    std::fs::write(&path, b"old")?;
    let mut permissions = std::fs::metadata(&path)?.permissions();
    permissions.set_mode(0o6755);
    std::fs::set_permissions(&path, permissions)?;

    let resp = fetch!(b"PUT", format!("{}privileged.bin", server.url()))
        .body(b"replacement".to_vec())
        .send()?;
    assert_eq!(resp.status(), 204);
    assert_eq!(std::fs::metadata(path)?.mode() & 0o7777, 0o755);
    Ok(())
}

#[rstest]
fn configured_upload_modes_apply_to_new_files_and_ancestors(
    #[with(&[
        "-A",
        "--upload-file-mode",
        "0640",
        "--upload-dir-mode",
        "0710",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    let response = fetch!(b"PUT", format!("{}nested/deep/new.bin", server.url()))
        .body(b"new".to_vec())
        .send()?;
    assert_eq!(response.status(), 201);
    assert_eq!(
        std::fs::metadata(server.path().join("nested"))?.mode() & 0o7777,
        0o710
    );
    assert_eq!(
        std::fs::metadata(server.path().join("nested/deep"))?.mode() & 0o7777,
        0o710
    );
    assert_eq!(
        std::fs::metadata(server.path().join("nested/deep/new.bin"))?.mode() & 0o7777,
        0o640
    );
    let response = fetch!(b"MKCOL", format!("{}collection", server.url())).send()?;
    assert_eq!(response.status(), 201);
    assert_eq!(
        std::fs::metadata(server.path().join("collection"))?.mode() & 0o7777,
        0o710
    );
    Ok(())
}

#[rstest]
fn uploads_refuse_to_replace_a_non_regular_node(
    #[with(&["--allow-upload"])] server: TestServer,
) -> Result<(), Error> {
    let fifo = server.path().join("pipe");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
    )?;

    let resp = fetch!(b"PUT", format!("{}pipe", server.url()))
        .body("replacement")
        .send()?;
    assert_eq!(resp.status(), 403);
    assert!(std::fs::symlink_metadata(fifo)?.file_type().is_fifo());
    Ok(())
}

#[rstest]
fn put_size_limit_has_identical_declared_and_streaming_boundaries(
    #[with(&["--allow-upload", "--max-upload-size", "8"])] server: TestServer,
) -> Result<(), Error> {
    let client = reqwest::blocking::Client::new();
    for (transport, streaming) in [("declared", false), ("streaming", true)] {
        for (length, expected) in [
            (7usize, reqwest::StatusCode::CREATED),
            (8, reqwest::StatusCode::CREATED),
            (9, reqwest::StatusCode::PAYLOAD_TOO_LARGE),
        ] {
            let name = format!("{transport}-{length}.bin");
            let url = format!("{}{name}", server.url());
            let bytes = vec![b'x'; length];
            let request = client.put(&url);
            let response = if streaming {
                request
                    .body(reqwest::blocking::Body::new(Cursor::new(bytes)))
                    .send()?
            } else {
                request.body(bytes).send()?
            };
            assert_eq!(response.status(), expected, "{transport} length={length}");
            if expected == reqwest::StatusCode::CREATED {
                assert_eq!(
                    std::fs::metadata(server.path().join(name))?.len(),
                    length as u64
                );
            } else {
                assert!(!server.path().join(name).exists());
            }
        }
    }
    wait_for_no_upload_candidates(server.path(), Duration::from_secs(3))?;
    Ok(())
}
