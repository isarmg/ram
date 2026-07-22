#[path = "common/fixtures.rs"]
mod fixtures;

use bytes::Bytes;
use fixtures::{Error, ServerProc, TEST_AUTH_RULE, TestServer, port, ram_command, server, tmpdir};
use h2::client::SendRequest;
use hyper::{Method, Request, StatusCode, Version};
use reqwest::blocking::Response as BlockingResponse;
use rstest::rstest;
use serde_json::Value;
use std::fs;
use std::io::Cursor;
use std::path::Path;
use std::time::{Duration, Instant};

const BASIC_AUTH: &str = "Basic YWRtaW46YWRtaW4=";

fn write_entries(directory: &Path, prefix: &str, count: usize) -> Result<(), Error> {
    fs::create_dir_all(directory)?;
    for index in 0..count {
        fs::write(directory.join(format!("{prefix}-{index}")), b"x")?;
    }
    Ok(())
}

fn json_path_count(response: BlockingResponse) -> Result<usize, Error> {
    let value: Value = serde_json::from_str(&response.text()?)?;
    Ok(value["paths"]
        .as_array()
        .ok_or("directory response did not contain a paths array")?
        .len())
}

fn assert_no_staging_candidates(root: &Path) -> Result<(), Error> {
    let candidates = staging_candidates(root)?;
    assert!(candidates.is_empty(), "staging residue: {candidates:?}");
    Ok(())
}

fn staging_candidates(root: &Path) -> Result<Vec<std::path::PathBuf>, Error> {
    Ok(fs::read_dir(root)?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(".ram-upload-") && name.ends_with(".tmp"))
        })
        .map(|entry| entry.path())
        .collect())
}

fn wait_for_staging_candidate(root: &Path) -> Result<(), Error> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if !staging_candidates(root)?.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("upload did not create a bounded staging candidate".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_no_staging_candidates(root: &Path) -> Result<(), Error> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let candidates = staging_candidates(root)?;
        if candidates.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("staging residue after cleanup deadline: {candidates:?}").into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn h2_request(port: u16, method: Method, path: &str) -> Result<Request<()>, Error> {
    Ok(Request::builder()
        .version(Version::HTTP_2)
        .method(method)
        .uri(format!("http://localhost:{port}{path}"))
        .header("authorization", BASIC_AUTH)
        .body(())?)
}

async fn send_h2(
    mut sender: SendRequest<Bytes>,
    request: Request<()>,
    body: Option<Bytes>,
) -> Result<(SendRequest<Bytes>, hyper::Response<h2::RecvStream>), Error> {
    sender = sender.ready().await?;
    let end_stream = body.is_none();
    let (response, mut request_body) = sender.send_request(request, end_stream)?;
    if let Some(body) = body {
        request_body.send_data(body, true)?;
    }
    Ok((sender, response.await?))
}

async fn collect_h2_body(mut body: h2::RecvStream) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        body.flow_control().release_capacity(chunk.len())?;
        output.extend_from_slice(&chunk);
    }
    Ok(output)
}

#[rstest]
fn directory_result_budget_has_exact_boundaries_and_head_skips_the_scan(
    #[with(&[
        "--max-directory-entries",
        "2",
        "--max-walk-entries",
        "100",
        "--max-expensive-tasks",
        "1",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    for (name, count) in [("minus", 1), ("exact", 2), ("plus", 3)] {
        write_entries(&server.path().join(name), "visible", count)?;
    }

    for (name, expected, truncated) in [("minus", 1, false), ("exact", 2, false), ("plus", 2, true)]
    {
        let response = reqwest::blocking::get(format!("{}{name}/?json", server.url()))?;
        assert_eq!(response.status(), StatusCode::OK, "{name}");
        assert_eq!(
            response.headers().get("x-ram-list-truncated").is_some(),
            truncated,
            "{name}"
        );
        assert_eq!(json_path_count(response)?, expected, "{name}");
    }

    let head = reqwest::blocking::Client::new()
        .head(format!("{}plus/?json", server.url()))
        .send()?;
    assert_eq!(head.status(), StatusCode::OK);
    assert!(!head.headers().contains_key("x-ram-list-truncated"));
    assert!(!head.headers().contains_key("etag"));
    assert!(!head.headers().contains_key("content-length"));
    assert!(head.bytes()?.is_empty());
    Ok(())
}

#[rstest]
fn search_result_budget_has_exact_boundaries_and_releases_its_worker(
    #[with(&[
        "--allow-search",
        "--max-search-results",
        "2",
        "--max-walk-entries",
        "100",
        "--max-expensive-tasks",
        "1",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    for (name, count) in [("minus", 1), ("exact", 2), ("plus", 3)] {
        write_entries(&server.path().join(name), "needle", count)?;
    }

    for (name, expected, truncated) in [("minus", 1, false), ("exact", 2, false), ("plus", 2, true)]
    {
        let response = reqwest::blocking::get(format!("{}{name}/?q=needle&json", server.url()))?;
        assert_eq!(response.status(), StatusCode::OK, "{name}");
        assert_eq!(
            response.headers().get("x-ram-list-truncated").is_some(),
            truncated,
            "{name}"
        );
        assert_eq!(json_path_count(response)?, expected, "{name}");
    }

    // 完成遍历必须归还唯一昂贵任务 permit。 / A completed traversal must return the sole expensive-task permit.
    let recovered = reqwest::blocking::get(format!("{}minus/?q=needle&json", server.url()))?;
    assert_eq!(recovered.status(), StatusCode::OK);
    assert_eq!(json_path_count(recovered)?, 1);

    let head = reqwest::blocking::Client::new()
        .head(format!("{}plus/?q=needle&json", server.url()))
        .send()?;
    assert_eq!(head.status(), StatusCode::OK);
    assert!(!head.headers().contains_key("x-ram-list-truncated"));
    assert!(!head.headers().contains_key("etag"));
    assert!(!head.headers().contains_key("content-length"));
    assert!(head.bytes()?.is_empty());
    Ok(())
}

#[rstest]
fn walk_entry_budget_rejects_only_n_plus_one_and_then_releases_the_permit(
    #[with(&[
        "--allow-search",
        "--max-walk-entries",
        "2",
        "--max-walk-depth",
        "8",
        "--max-search-results",
        "100",
        "--max-expensive-tasks",
        "1",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    for (name, count) in [("minus", 1), ("exact", 2), ("plus", 3)] {
        write_entries(&server.path().join(name), "match", count)?;
    }

    for (name, expected) in [
        ("minus", StatusCode::OK),
        ("exact", StatusCode::OK),
        ("plus", StatusCode::UNPROCESSABLE_ENTITY),
    ] {
        let response = reqwest::blocking::get(format!("{}{name}/?q=match&json", server.url()))?;
        assert_eq!(response.status(), expected, "{name}");
        assert!(!response.headers().contains_key("retry-after"), "{name}");
    }

    let recovered = reqwest::blocking::get(format!("{}exact/?q=match&json", server.url()))?;
    assert_eq!(recovered.status(), StatusCode::OK);
    Ok(())
}

#[rstest]
fn walk_depth_budget_has_n_minus_one_n_and_n_plus_one(
    #[with(&[
        "--allow-search",
        "--max-walk-entries",
        "100",
        "--max-walk-depth",
        "2",
        "--max-search-results",
        "100",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    for path in ["minus/d1/match", "exact/d1/d2/match", "plus/d1/d2/d3/match"] {
        let path = server.path().join(path);
        fs::create_dir_all(path.parent().unwrap())?;
        fs::write(path, b"x")?;
    }

    for (name, expected) in [
        ("minus", StatusCode::OK),
        ("exact", StatusCode::OK),
        ("plus", StatusCode::UNPROCESSABLE_ENTITY),
    ] {
        let response = reqwest::blocking::get(format!("{}{name}/?q=match&json", server.url()))?;
        assert_eq!(response.status(), expected, "{name}");
        assert!(!response.headers().contains_key("retry-after"), "{name}");
    }
    Ok(())
}

#[rstest]
fn hash_budget_is_identical_for_get_and_head_at_exact_boundaries(
    #[with(&["--allow-hash", "--max-hash-size", "8"])] server: TestServer,
) -> Result<(), Error> {
    for (name, size) in [("minus.bin", 7), ("exact.bin", 8), ("plus.bin", 9)] {
        fs::write(server.path().join(name), vec![b'x'; size])?;
    }

    for name in ["minus.bin", "exact.bin"] {
        let response = reqwest::blocking::get(format!("{}{name}?hash", server.url()))?;
        assert_eq!(response.status(), StatusCode::OK, "{name}");
        assert_eq!(response.headers()["content-length"], "64");
        assert_eq!(response.text()?.len(), 64);
    }
    let over = reqwest::blocking::get(format!("{}plus.bin?hash", server.url()))?;
    assert_eq!(over.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(!over.headers().contains_key("retry-after"));
    assert_eq!(over.text()?, "Payload Too Large");

    for (name, expected) in [
        ("exact.bin", StatusCode::OK),
        ("plus.bin", StatusCode::PAYLOAD_TOO_LARGE),
    ] {
        let response = reqwest::blocking::Client::new()
            .head(format!("{}{name}?hash", server.url()))
            .send()?;
        assert_eq!(response.status(), expected, "{name}");
        assert!(!response.headers().contains_key("etag"), "{name}");
        assert!(response.bytes()?.is_empty(), "{name}");
    }
    Ok(())
}

#[rstest]
fn archive_uncompressed_budget_has_exact_boundaries_and_an_early_error_status(
    #[with(&[
        "--allow-archive",
        "--compress",
        "none",
        "--max-archive-size",
        "8",
        "--max-walk-entries",
        "100",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    for (name, size) in [("minus", 7), ("exact", 8), ("plus", 9)] {
        fs::create_dir(server.path().join(name))?;
        fs::write(
            server.path().join(name).join("payload.bin"),
            vec![b'x'; size],
        )?;
    }

    for name in ["minus", "exact"] {
        let response = reqwest::blocking::get(format!("{}{name}/?zip", server.url()))?;
        assert_eq!(response.status(), StatusCode::OK, "{name}");
        assert_eq!(response.headers()["content-type"], "application/zip");
        let archive = response.bytes()?;
        let mut archive = zip::ZipArchive::new(Cursor::new(archive))?;
        assert_eq!(archive.len(), 2, "{name}");
        assert_eq!(
            archive.by_name("archive/payload.bin")?.size(),
            if name == "minus" { 7 } else { 8 }
        );
    }

    // 生产者提交响应头前必须验证稳定元数据。先返回 200 再重置截断 ZIP 流，对 HTTP/1 或 H2
    // 客户端都不是可处理的超预算响应。
    // The producer must validate stable metadata before committing headers; a 200 followed by a
    // reset of a truncated ZIP stream is not an actionable over-budget response for HTTP/1 or H2 clients.
    let response = reqwest::blocking::get(format!("{}plus/?zip", server.url()))?;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(!response.headers().contains_key("content-disposition"));
    assert_eq!(response.text()?, "Unprocessable Entity");

    let head = reqwest::blocking::Client::new()
        .head(format!("{}plus/?zip", server.url()))
        .send()?;
    assert_eq!(head.status(), StatusCode::OK);
    assert!(head.bytes()?.is_empty());

    let recovered = reqwest::blocking::get(format!("{}exact/?zip", server.url()))?;
    assert_eq!(recovered.status(), StatusCode::OK);
    let _ = zip::ZipArchive::new(Cursor::new(recovered.bytes()?))?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn archive_and_hash_budget_rejections_have_h2_parity() -> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    fs::create_dir(root.path().join("exact-archive"))?;
    fs::write(root.path().join("exact-archive/payload.bin"), vec![b'x'; 8])?;
    fs::create_dir(root.path().join("plus-archive"))?;
    fs::write(root.path().join("plus-archive/payload.bin"), vec![b'x'; 9])?;
    fs::write(root.path().join("plus-hash.bin"), vec![b'x'; 9])?;
    let mut command = ram_command(root.path(), port);
    command.args([
        "--auth",
        TEST_AUTH_RULE,
        "--allow-h2c",
        "--allow-archive",
        "--allow-hash",
        "--compress",
        "none",
        "--max-archive-size",
        "8",
        "--max-hash-size",
        "8",
        "--h2-max-concurrent-streams",
        "8",
    ]);
    let _server = ServerProc::spawn(command);

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    let (mut sender, connection) = h2::client::handshake(stream).await?;
    let connection_task = tokio::spawn(connection);

    let request = h2_request(port, Method::GET, "/plus-archive/?zip")?;
    let (next_sender, response) = send_h2(sender, request, None).await?;
    sender = next_sender;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(!response.headers().contains_key("content-disposition"));
    assert_eq!(
        collect_h2_body(response.into_body()).await?,
        b"Unprocessable Entity"
    );

    let request = h2_request(port, Method::GET, "/exact-archive/?zip")?;
    let (next_sender, response) = send_h2(sender, request, None).await?;
    sender = next_sender;
    assert_eq!(response.status(), StatusCode::OK);
    let archive = collect_h2_body(response.into_body()).await?;
    let archive = zip::ZipArchive::new(Cursor::new(archive))?;
    assert_eq!(archive.len(), 2);

    for method in [Method::GET, Method::HEAD] {
        let request = h2_request(port, method.clone(), "/plus-hash.bin?hash")?;
        let (next_sender, response) = send_h2(sender, request, None).await?;
        sender = next_sender;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE, "{method}");
        let body = collect_h2_body(response.into_body()).await?;
        if method == Method::HEAD {
            assert!(body.is_empty());
        } else {
            assert_eq!(body, b"Payload Too Large");
        }
    }
    connection_task.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_copy_size_budget_covers_n_minus_one_n_plus_one_without_residue() -> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    for (name, size) in [("minus.bin", 7), ("exact.bin", 8), ("plus.bin", 9)] {
        fs::write(root.path().join(name), vec![b'x'; size])?;
    }
    let mut command = ram_command(root.path(), port);
    command.args([
        "--auth",
        TEST_AUTH_RULE,
        "--allow-upload",
        "--allow-h2c",
        "--max-copy-size",
        "8",
        "--h2-max-concurrent-streams",
        "8",
    ]);
    let _server = ServerProc::spawn(command);

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    let (mut sender, connection) = h2::client::handshake(stream).await?;
    let connection_task = tokio::spawn(connection);
    for (source, destination, expected) in [
        ("minus.bin", "minus-copy.bin", StatusCode::CREATED),
        ("exact.bin", "exact-copy.bin", StatusCode::CREATED),
        (
            "plus.bin",
            "plus-copy.bin",
            StatusCode::INSUFFICIENT_STORAGE,
        ),
    ] {
        let request = Request::builder()
            .version(Version::HTTP_2)
            .method("COPY")
            .uri(format!("http://localhost:{port}/{source}"))
            .header("authorization", BASIC_AUTH)
            .header(
                "destination",
                format!("http://localhost:{port}/{destination}"),
            )
            .body(())?;
        let (next_sender, response) = send_h2(sender, request, None).await?;
        sender = next_sender;
        assert_eq!(response.status(), expected, "{source}");
        let _ = collect_h2_body(response.into_body()).await?;
        assert_eq!(
            root.path().join(destination).exists(),
            expected == StatusCode::CREATED,
            "{source}"
        );
    }
    assert_no_staging_candidates(root.path())?;
    connection_task.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_upload_idle_timeout_cancellation_and_size_boundaries_release_all_guards()
-> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    let mut command = ram_command(root.path(), port);
    command.args([
        "--auth",
        TEST_AUTH_RULE,
        "--allow-upload",
        "--allow-h2c",
        "--h2-max-concurrent-streams",
        "8",
        "--max-concurrent-uploads",
        "1",
        "--max-upload-size",
        "8",
        "--upload-idle-timeout",
        "1s",
        "--upload-total-timeout",
        "5s",
    ]);
    let _server = ServerProc::spawn(command);

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    let (mut sender, connection) = h2::client::handshake(stream).await?;
    let connection_task = tokio::spawn(connection);

    sender = sender.ready().await?;
    let request = h2_request(port, Method::PUT, "/idle.bin")?;
    let (idle_response, mut idle_body) = sender.send_request(request, false)?;
    idle_body.send_data(Bytes::from_static(b"x"), false)?;
    let started = tokio::time::Instant::now();
    let response = tokio::time::timeout(Duration::from_secs(3), idle_response).await??;
    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    assert!(started.elapsed() >= Duration::from_millis(750));
    drop(idle_body);
    // 返回 408 后服务器可用 H2 NO_ERROR 重置关闭请求侧；状态码是权威结果，不要求错误体。
    // After 408 the server may close request side with H2 NO_ERROR; status is authoritative and no error body is required.
    drop(response.into_body());
    wait_for_no_staging_candidates(root.path())?;
    assert!(!root.path().join("idle.bin").exists());

    sender = sender.ready().await?;
    let request = h2_request(port, Method::PUT, "/cancel.bin")?;
    let (cancel_response, mut cancel_body) = sender.send_request(request, false)?;
    cancel_body.send_data(Bytes::from_static(b"x"), false)?;
    wait_for_staging_candidate(root.path())?;
    cancel_body.send_reset(h2::Reason::CANCEL);
    drop(cancel_response);
    wait_for_no_staging_candidates(root.path())?;
    assert!(!root.path().join("cancel.bin").exists());

    for (name, size, expected) in [
        ("minus.bin", 7usize, StatusCode::CREATED),
        ("exact.bin", 8, StatusCode::CREATED),
        ("plus.bin", 9, StatusCode::PAYLOAD_TOO_LARGE),
    ] {
        let request = h2_request(port, Method::PUT, &format!("/{name}"))?;
        let (next_sender, response) =
            send_h2(sender, request, Some(Bytes::from(vec![b'x'; size]))).await?;
        sender = next_sender;
        assert_eq!(response.status(), expected, "{name}");
        let _ = collect_h2_body(response.into_body()).await?;
        assert_eq!(
            root.path().join(name).exists(),
            expected == StatusCode::CREATED,
            "{name}"
        );
    }
    wait_for_no_staging_candidates(root.path())?;
    connection_task.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_trickle_upload_cannot_extend_the_total_deadline() -> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    let mut command = ram_command(root.path(), port);
    command.args([
        "--auth",
        TEST_AUTH_RULE,
        "--allow-upload",
        "--allow-h2c",
        "--h2-max-concurrent-streams",
        "8",
        "--max-concurrent-uploads",
        "1",
        "--upload-idle-timeout",
        "2s",
        "--upload-total-timeout",
        "1s",
    ]);
    let _server = ServerProc::spawn(command);

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    let (mut sender, connection) = h2::client::handshake(stream).await?;
    let connection_task = tokio::spawn(connection);
    sender = sender.ready().await?;
    let request = h2_request(port, Method::PUT, "/trickle.bin")?;
    let (response, mut body) = sender.send_request(request, false)?;
    let started = tokio::time::Instant::now();
    body.send_data(Bytes::from_static(b"a"), false)?;
    tokio::time::sleep(Duration::from_millis(400)).await;
    body.send_data(Bytes::from_static(b"b"), false)?;
    tokio::time::sleep(Duration::from_millis(400)).await;
    body.send_data(Bytes::from_static(b"c"), false)?;

    let response = tokio::time::timeout(Duration::from_secs(2), response).await??;
    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    assert!(started.elapsed() >= Duration::from_millis(750));
    assert!(started.elapsed() < Duration::from_secs(2));
    drop(body);
    drop(response.into_body());
    wait_for_no_staging_candidates(root.path())?;
    assert!(!root.path().join("trickle.bin").exists());

    let request = h2_request(port, Method::PUT, "/after-trickle.bin")?;
    let (_sender, response) = send_h2(sender, request, Some(Bytes::from_static(b"ok"))).await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let _ = collect_h2_body(response.into_body()).await?;
    assert_eq!(fs::read(root.path().join("after-trickle.bin"))?, b"ok");
    connection_task.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn webdav_property_and_response_budgets_have_h2_parity_and_release_resources()
-> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    let mut command = ram_command(root.path(), port);
    command.args([
        "--auth",
        TEST_AUTH_RULE,
        "--allow-h2c",
        "--max-webdav-properties",
        "2",
        "--max-webdav-rendered-properties",
        "4",
        "--max-webdav-response-size",
        "64K",
        "--h2-max-concurrent-streams",
        "8",
    ]);
    let _server = ServerProc::spawn(command);

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    let (mut sender, connection) = h2::client::handshake(stream).await?;
    let connection_task = tokio::spawn(connection);
    for (count, expected) in [
        (1, StatusCode::MULTI_STATUS),
        (2, StatusCode::MULTI_STATUS),
        (3, StatusCode::UNPROCESSABLE_ENTITY),
    ] {
        let properties = (0..count)
            .map(|index| format!("<T:p{index}/>"))
            .collect::<String>();
        let xml = format!(
            r#"<D:propfind xmlns:D="DAV:" xmlns:T="urn:budget"><D:prop>{properties}</D:prop></D:propfind>"#
        );
        let request = Request::builder()
            .version(Version::HTTP_2)
            .method("PROPFIND")
            .uri(format!("http://localhost:{port}/test.html"))
            .header("authorization", BASIC_AUTH)
            .header("content-type", "application/xml")
            .header("depth", "0")
            .body(())?;
        let (next_sender, response) = send_h2(sender, request, Some(Bytes::from(xml))).await?;
        sender = next_sender;
        assert_eq!(response.status(), expected, "property count {count}");
        let body = collect_h2_body(response.into_body()).await?;
        assert!(body.len() <= 64 * 1024, "property count {count}");
    }

    let xml = r#"<D:propfind xmlns:D="DAV:"><D:prop><D:displayname/><D:getcontentlength/></D:prop></D:propfind>"#;
    let request = Request::builder()
        .version(Version::HTTP_2)
        .method("PROPFIND")
        .uri(format!("http://localhost:{port}/dir1"))
        .header("authorization", BASIC_AUTH)
        .header("content-type", "application/xml")
        .header("depth", "1")
        .body(())?;
    let (next_sender, response) =
        send_h2(sender, request, Some(Bytes::from_static(xml.as_bytes()))).await?;
    sender = next_sender;
    assert_eq!(response.status(), StatusCode::INSUFFICIENT_STORAGE);
    assert_eq!(
        collect_h2_body(response.into_body()).await?,
        b"WebDAV response budget exceeded"
    );

    let request = h2_request(port, Method::GET, "/index.html")?;
    let (_sender, response) = send_h2(sender, request, None).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!collect_h2_body(response.into_body()).await?.is_empty());
    connection_task.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multipart_range_count_and_byte_failures_have_h2_headers_and_recover() -> Result<(), Error>
{
    const MAX_MULTIPART_RANGE_BYTES: u64 = 64 * 1024 * 1024;
    let root = tmpdir();
    let port = port();
    fs::File::create(root.path().join("large.bin"))?.set_len(MAX_MULTIPART_RANGE_BYTES + 1)?;
    let mut command = ram_command(root.path(), port);
    command.args([
        "--auth",
        TEST_AUTH_RULE,
        "--allow-h2c",
        "--h2-max-concurrent-streams",
        "8",
    ]);
    let _server = ServerProc::spawn(command);

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    let (mut sender, connection) = h2::client::handshake(stream).await?;
    let connection_task = tokio::spawn(connection);

    let too_many = std::iter::repeat_n("0-0", 17).collect::<Vec<_>>().join(",");
    let request = Request::builder()
        .version(Version::HTTP_2)
        .method(Method::GET)
        .uri(format!("http://localhost:{port}/index.html"))
        .header("authorization", BASIC_AUTH)
        .header("range", format!("bytes={too_many}"))
        .body(())?;
    let (next_sender, response) = send_h2(sender, request, None).await?;
    sender = next_sender;
    assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(response.headers()["content-range"], "bytes */18");
    assert_eq!(response.headers()["accept-ranges"], "bytes");
    let _ = collect_h2_body(response.into_body()).await?;

    let size = MAX_MULTIPART_RANGE_BYTES + 1;
    let midpoint = size / 2;
    let request = Request::builder()
        .version(Version::HTTP_2)
        .method(Method::GET)
        .uri(format!("http://localhost:{port}/large.bin"))
        .header("authorization", BASIC_AUTH)
        .header(
            "range",
            format!("bytes=0-{},{}-{}", midpoint - 1, midpoint, size - 1),
        )
        .body(())?;
    let (next_sender, response) = send_h2(sender, request, None).await?;
    sender = next_sender;
    assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        response.headers()["content-range"],
        format!("bytes */{size}")
    );
    assert_eq!(response.headers()["accept-ranges"], "bytes");
    let _ = collect_h2_body(response.into_body()).await?;

    let request = Request::builder()
        .version(Version::HTTP_2)
        .method(Method::GET)
        .uri(format!("http://localhost:{port}/index.html"))
        .header("authorization", BASIC_AUTH)
        .header("range", "bytes=0-0")
        .body(())?;
    let (_sender, response) = send_h2(sender, request, None).await?;
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(collect_h2_body(response.into_body()).await?, b"T");
    connection_task.abort();
    Ok(())
}
