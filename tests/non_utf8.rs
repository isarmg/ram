//! 非有效 UTF-8 的 Linux 文件名的黑盒契约。
//! Black-box contract for Linux filenames that are not valid UTF-8.
//!
//! HTTP URL、JSON、HTML 和搜索结果刻意不创造有损别名；ZIP 是唯一无损导出表示。
//! HTTP URLs, JSON, HTML, and search results do not invent a lossy alias. ZIP is the sole lossless export.

#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/utils.rs"]
mod utils;

use fixtures::{Error, ServerProc, TestServer, port, ram_command};
use reqwest::blocking::Client;
use serde_json::Value;
use std::ffi::OsStr;
use std::io::{Cursor, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;

fn path_names(value: &Value) -> Vec<&str> {
    value["paths"]
        .as_array()
        .expect("listing paths array")
        .iter()
        .map(|item| item["name"].as_str().expect("UTF-8 listing name"))
        .collect()
}

fn assert_omission_header(response: &reqwest::blocking::Response) {
    assert_eq!(
        response.headers().get("x-ram-list-omitted"),
        Some(&reqwest::header::HeaderValue::from_static("non-utf8"))
    );
}

#[rstest::rstest]
#[case(fixtures::server(&["-A"] as &[&str]))]
fn non_utf8_names_have_an_observable_fail_closed_contract(
    #[case] server: TestServer,
) -> Result<(), Error> {
    let raw_file = server.path().join(OsStr::from_bytes(b"raw-\xff.txt"));
    std::fs::write(&raw_file, b"raw file")?;
    let mixed_file = server
        .path()
        .join(OsStr::from_bytes(b"caf\xc3\xa9-\xff-\xe6\x96\x87.txt"));
    std::fs::write(&mixed_file, b"mixed name")?;
    let raw_dir = server.path().join(OsStr::from_bytes(b"raw-dir-\xfe"));
    std::fs::create_dir(&raw_dir)?;
    std::fs::write(raw_dir.join("inside.txt"), b"inside raw directory")?;
    std::fs::write(server.path().join("%FF"), b"literal percent name")?;
    std::fs::write(server.path().join("control-\u{1}.txt"), b"xml control")?;
    symlink(
        OsStr::from_bytes(b"raw-\xff.txt"),
        server.path().join("raw-alias"),
    )?;

    let json_response = reqwest::blocking::get(format!("{}?json", server.url()))?;
    assert_eq!(json_response.status(), 200);
    assert_omission_header(&json_response);
    let listing: Value = serde_json::from_str(&json_response.text()?)?;
    assert_eq!(listing["omitted_non_utf8"], true);
    let names = path_names(&listing);
    assert!(names.contains(&"%FF"));
    assert!(names.contains(&"control-\u{1}.txt"));
    assert!(!names.contains(&"raw-alias"));
    assert!(!names.iter().any(|name| name.starts_with("raw-")));

    let simple_response = reqwest::blocking::get(format!("{}?simple", server.url()))?;
    assert_eq!(simple_response.status(), 200);
    assert_omission_header(&simple_response);
    let simple = simple_response.text()?;
    assert!(simple.lines().any(|name| name == "%FF"));
    assert!(!simple.contains("raw-alias"));

    let html_response = reqwest::blocking::get(server.url())?;
    assert_eq!(html_response.status(), 200);
    assert_omission_header(&html_response);
    let html = html_response.text()?;
    let embedded = utils::retrieve_json(&html).expect("embedded index data");
    assert_eq!(embedded["omitted_non_utf8"], true);

    // HEAD 刻意避免目录扫描，因此允许缺少表示派生的省略/截断字段。
    // HEAD deliberately avoids directory scanning, so representation-derived omission fields may be absent.
    let head = Client::new().head(server.url()).send()?;
    assert_eq!(head.status(), 200);
    assert!(!head.headers().contains_key("x-ram-list-omitted"));
    assert!(head.bytes()?.is_empty());

    // 搜索不进入不可表示目录，也不发布真实目标不可表示的 UTF-8 符号链接别名。
    // Search never enters an unrepresentable directory or publishes a UTF-8 alias for an unrepresentable target.
    for query in ["inside", "raw-alias"] {
        let response = reqwest::blocking::get(format!("{}?q={query}&json", server.url()))?;
        assert_eq!(response.status(), 200);
        assert_omission_header(&response);
        let result: Value = serde_json::from_str(&response.text()?)?;
        assert_eq!(result["omitted_non_utf8"], true);
        assert!(path_names(&result).is_empty());
    }

    // 合法字面百分号文件名仍可独立寻址，从而区分 HTTP URL 编码与 ZIP 原始字节记法。
    // A literal-percent filename remains addressable, distinguishing HTTP encoding from ZIP raw-byte notation.
    let literal = reqwest::blocking::get(format!("{}%25FF", server.url()))?;
    assert_eq!(literal.status(), 200);
    assert_eq!(literal.bytes()?.as_ref(), b"literal percent name");
    let invalid = reqwest::blocking::get(format!("{}%FF", server.url()))?;
    assert_eq!(invalid.status(), 400);
    let alias = reqwest::blocking::get(format!("{}raw-alias", server.url()))?;
    assert_eq!(alias.status(), 404);

    // ZIP 有意成为唯一无损表示；原始字节使用大写 %HH，字面 `%` 转义为 %25。
    // ZIP is the sole lossless representation; raw bytes use upper-case %HH and literal `%` becomes %25.
    let zip_response = reqwest::blocking::get(format!("{}?zip", server.url()))?;
    assert_eq!(zip_response.status(), 200);
    let mut archive = zip::ZipArchive::new(Cursor::new(zip_response.bytes()?))?;
    assert!(archive.by_name("archive/raw-%FF.txt").is_ok());
    assert!(archive.by_name("archive/café-%FF-文.txt").is_ok());
    assert!(archive.by_name("archive/raw-dir-%FE/inside.txt").is_ok());
    assert!(archive.by_name("archive/%25FF").is_ok());
    Ok(())
}

#[rstest::rstest]
#[case(fixtures::server(&["-A"] as &[&str]))]
fn invalid_utf8_request_paths_are_rejected_before_every_route(
    #[case] server: TestServer,
) -> Result<(), Error> {
    let client = Client::new();
    let invalid_url = format!("{}%FF", server.url());
    for method in ["GET", "HEAD", "PUT", "DELETE", "MKCOL"] {
        let request = client.request(
            reqwest::Method::from_bytes(method.as_bytes())?,
            &invalid_url,
        );
        let response = request.body("must not be published").send()?;
        assert_eq!(response.status(), 400, "method {method}");
    }

    let destination = format!("http://localhost:{}/%FF", server.port());
    let response = client
        .request(
            reqwest::Method::from_bytes(b"MOVE")?,
            format!("{}test.html", server.url()),
        )
        .header("Destination", destination)
        .send()?;
    assert_eq!(response.status(), 400, "method MOVE");
    assert_eq!(
        std::fs::read_to_string(server.path().join("test.html"))?,
        "This is test.html"
    );
    assert!(!server.path().join(OsStr::from_bytes(b"\xff")).exists());
    Ok(())
}

#[rstest::rstest]
fn index_only_does_not_expose_raw_names_as_a_namespace_oracle(port: u16) -> Result<(), Error> {
    let tmpdir = assert_fs::TempDir::new()?;
    std::fs::write(tmpdir.path().join("visible.txt"), b"visible")?;
    std::fs::write(
        tmpdir.path().join(OsStr::from_bytes(b"secret-\xff.txt")),
        b"secret",
    )?;
    let mut command = ram_command(tmpdir.path(), port);
    command.args(["--auth", "user:pass@/visible.txt:ro"]);
    let _server = ServerProc::spawn(command);

    let response = Client::new()
        .get(format!("http://localhost:{port}/?json"))
        .basic_auth("user", Some("pass"))
        .send()?;
    assert_eq!(response.status(), 200);
    assert!(!response.headers().contains_key("x-ram-list-omitted"));
    let listing: Value = serde_json::from_str(&response.text()?)?;
    assert_eq!(listing["omitted_non_utf8"], false);
    assert_eq!(path_names(&listing), vec!["visible.txt"]);
    Ok(())
}

#[rstest::rstest]
fn index_only_file_roots_are_walked_without_trusting_a_raw_symlink_target(
    port: u16,
) -> Result<(), Error> {
    let tmpdir = assert_fs::TempDir::new()?;
    std::fs::write(tmpdir.path().join("visible.txt"), b"visible content")?;
    std::fs::write(
        tmpdir.path().join(OsStr::from_bytes(b"raw-\xff.txt")),
        b"raw target secret",
    )?;
    symlink(
        OsStr::from_bytes(b"raw-\xff.txt"),
        tmpdir.path().join("raw-alias"),
    )?;
    let mut command = ram_command(tmpdir.path(), port);
    command.args([
        "--auth",
        "user:pass@/raw-alias:ro,/visible.txt:ro",
        "--allow-symlink",
        "--allow-search",
        "--allow-archive",
    ]);
    let _server = ServerProc::spawn(command);
    let client = Client::new();
    let base = format!("http://localhost:{port}/");

    let raw_search = client
        .get(format!("{base}?q=raw-alias&json"))
        .basic_auth("user", Some("pass"))
        .send()?;
    assert_eq!(raw_search.status(), 200);
    assert_omission_header(&raw_search);
    let raw_result: Value = serde_json::from_str(&raw_search.text()?)?;
    assert_eq!(raw_result["omitted_non_utf8"], true);
    assert!(path_names(&raw_result).is_empty());

    // AccessPaths::entry_paths 可返回普通文件；它是有效遍历根，仍须出现在搜索/归档结果中。
    // AccessPaths::entry_paths may return a regular file, a valid walk root that must appear in results.
    let visible_search = client
        .get(format!("{base}?q=visible&json"))
        .basic_auth("user", Some("pass"))
        .send()?;
    assert_eq!(visible_search.status(), 200);
    let visible_result: Value = serde_json::from_str(&visible_search.text()?)?;
    assert_eq!(path_names(&visible_result), vec!["visible.txt"]);

    // 归档正常完成并包含普通已授权文件，但绝不经由无法按描述符身份重新授权的原始目标别名读取。
    // The archive completes normally and contains the regular authorized file, but never reads
    // through an original-target alias that descriptor identity cannot re-authorize.
    let zip_response = client
        .get(format!("{base}?zip"))
        .basic_auth("user", Some("pass"))
        .send()?;
    assert_eq!(zip_response.status(), 200);
    let mut archive = zip::ZipArchive::new(Cursor::new(zip_response.bytes()?))?;
    let mut visible = archive.by_name("archive/visible.txt")?;
    let mut content = String::new();
    visible.read_to_string(&mut content)?;
    assert_eq!(content, "visible content");
    drop(visible);
    assert!(archive.by_name("archive/raw-alias").is_err());
    assert!(archive.by_name("archive/raw-%FF.txt").is_err());
    Ok(())
}

#[rstest::rstest]
fn index_only_walk_reauthorizes_utf8_symlink_roots_before_search_or_zip(
    port: u16,
) -> Result<(), Error> {
    let tmpdir = assert_fs::TempDir::new()?;
    std::fs::create_dir(tmpdir.path().join("secret-dir"))?;
    std::fs::write(
        tmpdir.path().join("secret-dir/top-secret.txt"),
        b"directory secret",
    )?;
    std::fs::write(tmpdir.path().join("secret-file.txt"), b"file secret")?;
    symlink("secret-dir", tmpdir.path().join("dir-alias"))?;
    symlink("secret-file.txt", tmpdir.path().join("file-alias"))?;
    let mut command = ram_command(tmpdir.path(), port);
    command.args([
        "--auth",
        "user:pass@/dir-alias:ro,/file-alias:ro",
        "--allow-symlink",
        "--allow-search",
        "--allow-archive",
    ]);
    let _server = ServerProc::spawn(command);
    let client = Client::new();
    let base = format!("http://localhost:{port}/");

    let search = client
        .get(format!("{base}?q=secret&json"))
        .basic_auth("user", Some("pass"))
        .send()?;
    assert_eq!(search.status(), 200);
    assert!(!search.headers().contains_key("x-ram-list-omitted"));
    let result: Value = serde_json::from_str(&search.text()?)?;
    assert!(path_names(&result).is_empty());

    let zip_response = client
        .get(format!("{base}?zip"))
        .basic_auth("user", Some("pass"))
        .send()?;
    assert_eq!(zip_response.status(), 200);
    let mut archive = zip::ZipArchive::new(Cursor::new(zip_response.bytes()?))?;
    let names = (0..archive.len())
        .map(|index| archive.by_index(index).map(|entry| entry.name().to_owned()))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(names, vec!["archive/"]);
    assert!(names.iter().all(|name| !name.contains("secret")));
    Ok(())
}
