#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/utils.rs"]
mod utils;

use fixtures::{
    BIN_FILE, Error, ServerProc, TEST_AUTH_PASS, TEST_AUTH_RULE, TEST_AUTH_USER, TestServer, port,
    ram_command, server,
};
use rstest::rstest;
use serde_json::Value;
use std::ffi::OsStr;
use std::io::{Cursor, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::unix::ffi::OsStrExt;
use std::time::Duration;

#[rstest]
fn get_dir(server: TestServer) -> Result<(), Error> {
    let resp = reqwest::blocking::get(server.url())?;
    assert_resp_paths!(resp);
    Ok(())
}

#[rstest]
fn security_headers(server: TestServer) -> Result<(), Error> {
    let resp = reqwest::blocking::get(server.url())?;
    assert_eq!(
        resp.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert_eq!(
        resp.headers().get("referrer-policy").unwrap(),
        "no-referrer"
    );
    assert_eq!(resp.headers().get("x-frame-options").unwrap(), "DENY");
    Ok(())
}

#[rstest]
fn head_dir(server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"HEAD", server.url()).send()?;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "text/html; charset=utf-8"
    );
    assert_eq!(resp.text()?, "");
    Ok(())
}

#[rstest]
fn get_dir_404(server: TestServer) -> Result<(), Error> {
    let resp = reqwest::blocking::get(format!("{}404/", server.url()))?;
    assert_eq!(resp.status(), 404);
    Ok(())
}

/// 已存在 FIFO 属于 `ResourceTarget::Other`，不是可上传的缺失集合；尾斜杠绝不能把它
/// 伪装成 `dir_exists:false` 的创建页面。
/// An existing FIFO is `ResourceTarget::Other`, not a missing uploadable collection. A trailing
/// slash must never turn it into the `dir_exists:false` creation UI.
#[rstest]
fn existing_special_node_with_trailing_slash_is_not_a_missing_directory(
    #[with(&["--allow-upload"])] server: TestServer,
) -> Result<(), Error> {
    let fifo = server.path().join("occupied.pipe");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
    )?;
    let target = format!("{}occupied.pipe/", server.url());
    let response = reqwest::blocking::get(&target)?;
    assert_eq!(response.status(), 404);

    // 两个只读查找方法都隐藏不可表示的节点；OPTIONS 仍从同一能力表声明可路由方法。
    // Both read-only lookups hide an unrepresentable node; OPTIONS advertises routable methods from
    // that same capability table.
    let head = fetch!(b"HEAD", &target).send()?;
    assert_eq!(head.status(), 404);
    let options = fetch!(b"OPTIONS", &target).send()?;
    assert_eq!(options.status(), 200);
    let allow = options.headers().get("allow").unwrap().to_str()?;
    for method in ["GET", "HEAD"] {
        assert!(allow.split(", ").any(|candidate| candidate == method));
    }

    let missing = reqwest::blocking::get(format!("{}new-directory/", server.url()))?;
    assert_eq!(missing.status(), 200);
    assert_eq!(
        utils::retrieve_json(&missing.text()?)
            .and_then(|value| value.get("dir_exists").and_then(Value::as_bool)),
        Some(false)
    );
    Ok(())
}

#[rstest]
fn nul_in_decoded_path_is_bad_request(server: TestServer) -> Result<(), Error> {
    let resp = reqwest::blocking::get(format!("{}bad%00path", server.url()))?;
    assert_eq!(resp.status(), 400);
    Ok(())
}

#[rstest]
fn head_dir_404(server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"HEAD", format!("{}404/", server.url())).send()?;
    assert_eq!(resp.status(), 404);
    Ok(())
}

#[rstest]
#[case(server(&["--allow-archive"] as &[&str]))]
#[case(server(&["--allow-archive", "--compress", "none"]))]
#[case(server(&["--allow-archive", "--compress", "low"]))]
#[case(server(&["--allow-archive", "--compress", "medium"]))]
#[case(server(&["--allow-archive", "--compress", "high"]))]
fn get_dir_zip(#[case] server: TestServer) -> Result<(), Error> {
    std::fs::create_dir(server.path().join("empty-dir"))?;
    std::fs::write(server.path().join(r"dir\file:ads.txt"), b"portable")?;
    std::fs::write(server.path().join(r"..\..\evil"), b"backslash traversal")?;
    std::fs::write(server.path().join(r"C:\evil"), b"drive path")?;
    // Unix 上反斜杠是普通文件名字节；归档仍须为 Windows 解压器中和该名称。
    // On Unix backslashes are ordinary filename bytes; the archive must still neutralize them for Windows extractors.
    let mut unc_path = server.path().to_path_buf();
    unc_path.push(r"\\server\share");
    std::fs::write(unc_path, b"UNC path")?;
    std::fs::write(
        server.path().join(OsStr::from_bytes(b"raw-\xff.bin")),
        b"non-UTF-8 file",
    )?;
    std::fs::write(
        server
            .path()
            .join(OsStr::from_bytes(b"caf\xc3\xa9-\xff-\xe6\x96\x87.txt")),
        b"mixed valid and invalid UTF-8",
    )?;
    std::fs::write(server.path().join("COM¹.txt"), b"device superscript")?;
    std::fs::write(server.path().join("lpt²"), b"device superscript lowercase")?;
    let raw_dir = server.path().join(OsStr::from_bytes(b"raw-dir-\xfe"));
    std::fs::create_dir(&raw_dir)?;
    std::fs::write(raw_dir.join("inside.txt"), b"non-UTF-8 directory")?;
    let resp = reqwest::blocking::get(format!("{}?zip", server.url()))?;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/zip"
    );
    assert!(resp.headers().contains_key("content-disposition"));
    let bytes = resp.bytes()?;
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
    assert!(archive.by_name("archive/").is_ok());
    let mut index = archive.by_name("archive/index.html")?;
    let mut contents = String::new();
    index.read_to_string(&mut contents)?;
    assert_eq!(contents, "This is index.html");
    drop(index);
    assert!(archive.by_name("archive/empty-dir/").is_ok());
    let mut encoded = archive.by_name("archive/dir%5Cfile%3Aads.txt")?;
    let mut contents = String::new();
    encoded.read_to_string(&mut contents)?;
    assert_eq!(contents, "portable");
    drop(encoded);
    assert!(archive.by_name("archive/😀.bin").is_ok());
    assert!(archive.by_name("archive/..%5C..%5Cevil").is_ok());
    assert!(archive.by_name("archive/C%3A%5Cevil").is_ok());
    assert!(archive.by_name("archive/%5C%5Cserver%5Cshare").is_ok());
    assert!(archive.by_name("archive/raw-%FF.bin").is_ok());
    assert!(archive.by_name("archive/café-%FF-文.txt").is_ok());
    assert!(archive.by_name("archive/%43OM¹.txt").is_ok());
    assert!(archive.by_name("archive/%6Cpt²").is_ok());
    assert!(archive.by_name("archive/raw-dir-%FE/").is_ok());
    assert!(archive.by_name("archive/raw-dir-%FE/inside.txt").is_ok());
    let entries = (0..archive.len())
        .map(|index| {
            archive
                .by_index(index)
                .map(|entry| (entry.name().to_owned(), entry.is_dir()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    for (name, directory) in &entries {
        assert_portable_zip_entry(name, *directory);
    }
    Ok(())
}

#[rstest]
fn head_zip_for_filesystem_root_uses_safe_download_name(port: u16) -> Result<(), Error> {
    let mut command = ram_command(std::path::Path::new("/"), port);
    command.args([
        "--auth",
        TEST_AUTH_RULE,
        "--allow-filesystem-root",
        "--allow-archive",
        "--stale-upload-cleanup-age",
        "7d",
        "--stale-upload-cleanup-max-entries",
        "1",
        "--stale-upload-cleanup-max-depth",
        "1",
        "--stale-upload-cleanup-timeout",
        "1s",
    ]);
    let _server = ServerProc::spawn(command);

    // HEAD 覆盖真实路由和 Content-Disposition 路径，又不在测试中递归遍历宿主文件系统。
    // HEAD exercises real routing and Content-Disposition without recursively traversing the host filesystem.
    let response = reqwest::blocking::Client::new()
        .head(format!("http://localhost:{port}/?zip"))
        .basic_auth(TEST_AUTH_USER, Some(TEST_AUTH_PASS))
        .send()?;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers().get("content-disposition").unwrap(),
        "attachment; filename=\"archive.zip\""
    );
    Ok(())
}

fn assert_portable_zip_entry(name: &str, directory: bool) {
    assert!(
        !name.starts_with(['/', '\\']),
        "absolute ZIP entry: {name:?}"
    );
    assert!(
        !name.contains('\\'),
        "Windows separator in ZIP entry: {name:?}"
    );
    assert!(
        !name.contains(':'),
        "Windows drive/stream syntax in ZIP entry: {name:?}"
    );
    let logical = if directory {
        name.strip_suffix('/')
            .unwrap_or_else(|| panic!("ZIP directory lacks trailing slash: {name:?}"))
    } else {
        assert!(
            !name.ends_with('/'),
            "ZIP file has trailing slash: {name:?}"
        );
        name
    };
    let components = logical.split('/').collect::<Vec<_>>();
    assert_eq!(
        components.first(),
        Some(&"archive"),
        "wrong ZIP root: {name:?}"
    );
    assert!(
        components.iter().all(|component| {
            !component.is_empty()
                && !matches!(*component, "." | "..")
                && !component.ends_with(['.', ' '])
                && !is_windows_device_component(component)
                && portable_component_bytes(component)
        }),
        "entry is unsafe under POSIX or Windows component semantics: {name:?}"
    );
}

fn portable_component_bytes(component: &str) -> bool {
    let bytes = component.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            if index + 2 >= bytes.len()
                || !matches!(bytes[index + 1], b'0'..=b'9' | b'A'..=b'F')
                || !matches!(bytes[index + 2], b'0'..=b'9' | b'A'..=b'F')
            {
                return false;
            }
            index += 3;
            continue;
        }
        if matches!(
            byte,
            0..=0x1f | 0x7f | b'<' | b'>' | b'"' | b'|' | b'?' | b'*'
        ) {
            return false;
        }
        index += 1;
    }
    true
}

fn is_windows_device_component(component: &str) -> bool {
    let stem = component
        .split(['.', ':'])
        .next()
        .unwrap_or(component)
        .trim_end_matches(' ');
    let upper = stem.to_uppercase();
    if matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL") {
        return true;
    }
    ["COM", "LPT"].iter().any(|prefix| {
        upper.strip_prefix(prefix).is_some_and(|suffix| {
            matches!(
                suffix,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    })
}

#[rstest]
fn get_dir_json(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    let resp = reqwest::blocking::get(format!("{}?json", server.url()))?;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/json"
    );
    let json: Value = serde_json::from_str(&resp.text().unwrap()).unwrap();
    assert!(json["paths"].as_array().is_some());
    Ok(())
}

#[rstest]
fn get_dir_simple(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    std::fs::write(server.path().join("a&<b>.txt"), b"special")?;
    let resp = reqwest::blocking::get(format!("{}?simple", server.url()))?;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "text/plain; charset=utf-8"
    );
    let text = resp.text().unwrap();
    assert!(text.split('\n').any(|v| v == "index.html"));
    assert!(text.split('\n').any(|v| v == "a&<b>.txt"));
    Ok(())
}

#[rstest]
fn head_dir_zip(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"HEAD", format!("{}?zip", server.url())).send()?;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/zip"
    );
    assert!(resp.headers().contains_key("content-disposition"));
    assert_eq!(resp.text()?, "");
    Ok(())
}

#[rstest]
fn get_dir_search(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
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
fn get_dir_search2(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    let resp = reqwest::blocking::get(format!("{}?q={BIN_FILE}", server.url()))?;
    assert_eq!(resp.status(), 200);
    let paths = utils::retrieve_index_paths(&resp.text()?);
    assert!(!paths.is_empty());
    for p in paths {
        assert!(p.contains(BIN_FILE));
    }
    Ok(())
}

#[rstest]
fn get_dir_search3(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    let resp = reqwest::blocking::get(format!("{}?q={}&simple", server.url(), "test.html"))?;
    assert_eq!(resp.status(), 200);
    let text = resp.text().unwrap();
    assert!(text.split('\n').any(|v| v == "test.html"));
    Ok(())
}

#[rstest]
fn get_dir_search4(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    let resp = reqwest::blocking::get(format!("{}dir1?q=dir1&simple", server.url()))?;
    assert_eq!(resp.status(), 200);
    let text = resp.text().unwrap();
    assert!(text.is_empty());
    Ok(())
}

#[rstest]
fn head_dir_search(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"HEAD", format!("{}?q={}", server.url(), "test.html")).send()?;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "text/html; charset=utf-8"
    );
    assert_eq!(resp.text()?, "");
    Ok(())
}

#[rstest]
fn empty_search(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    let resp = reqwest::blocking::get(format!("{}?q=", server.url()))?;
    assert_resp_paths!(resp);
    Ok(())
}

#[rstest]
fn get_file(server: TestServer) -> Result<(), Error> {
    let resp = reqwest::blocking::get(format!("{}index.html", server.url()))?;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "text/html; charset=UTF-8"
    );
    assert_eq!(resp.headers().get("accept-ranges").unwrap(), "bytes");
    assert!(resp.headers().contains_key("etag"));
    assert!(resp.headers().contains_key("last-modified"));
    assert!(resp.headers().contains_key("content-length"));
    assert_eq!(resp.text()?, "This is index.html");
    Ok(())
}

#[rstest]
fn head_file(server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"HEAD", format!("{}index.html", server.url())).send()?;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "text/html; charset=UTF-8"
    );
    assert_eq!(resp.headers().get("accept-ranges").unwrap(), "bytes");
    assert!(resp.headers().contains_key("content-disposition"));
    assert!(resp.headers().contains_key("etag"));
    assert!(resp.headers().contains_key("last-modified"));
    assert!(resp.headers().contains_key("content-length"));
    assert_eq!(resp.text()?, "");
    Ok(())
}

#[rstest]
fn get_file_404(server: TestServer) -> Result<(), Error> {
    let resp = reqwest::blocking::get(format!("{}404", server.url()))?;
    assert_eq!(resp.status(), 404);
    Ok(())
}

#[rstest]
fn get_file_emoji_path(server: TestServer) -> Result<(), Error> {
    let resp = reqwest::blocking::get(format!("{}{BIN_FILE}", server.url()))?;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-disposition").unwrap(),
        "inline; filename=\"😀.bin\"; filename*=UTF-8''%F0%9F%98%80.bin"
    );
    Ok(())
}

#[rstest]
fn get_file_download_forces_attachment(server: TestServer) -> Result<(), Error> {
    let resp = reqwest::blocking::get(format!("{}{BIN_FILE}?download", server.url()))?;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-disposition").unwrap(),
        "attachment; filename=\"😀.bin\"; filename*=UTF-8''%F0%9F%98%80.bin"
    );
    Ok(())
}

#[rstest]
fn get_file_newline_path(server: TestServer) -> Result<(), Error> {
    let resp = reqwest::blocking::get(format!("{}file%0A1.txt", server.url()))?;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-disposition").unwrap(),
        "inline; filename=\"file 1.txt\""
    );
    Ok(())
}

#[rstest]
fn get_file_quoted_path(server: TestServer) -> Result<(), Error> {
    let filename = "quote\"slash\\file.txt";
    std::fs::write(server.path().join(filename), "quoted")?;
    let resp = reqwest::blocking::get(format!("{}{}", server.url(), utils::encode_uri(filename)))?;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-disposition").unwrap(),
        "inline; filename=\"quote\\\"slash\\\\file.txt\""
    );
    Ok(())
}

#[rstest]
fn get_file_view(server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"GET", format!("{}index.html?view", server.url())).send()?;
    assert_eq!(resp.status(), 200);
    let view = utils::retrieve_json(&resp.text()?).expect("embedded viewer data");
    assert_eq!(view["text_viewable"], true);
    Ok(())
}

#[rstest]
fn get_file_view_bin(server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"GET", format!("{}{BIN_FILE}?view", server.url())).send()?;
    assert_eq!(resp.status(), 200);
    let view = utils::retrieve_json(&resp.text()?).expect("embedded viewer data");
    assert_eq!(view["text_viewable"], false);
    Ok(())
}

#[rstest]
fn head_file_404(server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"HEAD", format!("{}404", server.url())).send()?;
    assert_eq!(resp.status(), 404);
    Ok(())
}

#[rstest]
fn options_dir(server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"OPTIONS", format!("{}index.html", server.url())).send()?;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("allow").unwrap(),
        "GET, HEAD, OPTIONS, CHECKAUTH, LOGOUT"
    );
    assert!(!resp.headers().contains_key("dav"));
    Ok(())
}

#[rstest]
fn put_file(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    let url = format!("{}file1", server.url());
    let resp = fetch!(b"PUT", &url).body(b"abc".to_vec()).send()?;
    assert_eq!(resp.status(), 201);
    let resp = reqwest::blocking::get(url)?;
    assert_eq!(resp.status(), 200);
    Ok(())
}

#[rstest]
fn interrupted_put_preserves_existing_file(
    #[with(&["-A"])] server: TestServer,
) -> Result<(), Error> {
    let url = server.url();
    let addr = (
        url.host_str().unwrap(),
        url.port_or_known_default().unwrap(),
    );
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    // 声明一个更长的 body，只发送一部分后关闭写端，模拟网络中断。
    // Basic(admin:admin) 的值是固定测试凭据，不涉及真实秘密。
    // Declare a longer body, send only a prefix, then close the write side to simulate a network
    // interruption. Basic(admin:admin) is a fixed test credential, not a real secret.
    let request = concat!(
        "PUT /index.html HTTP/1.1\r\n",
        "Host: localhost\r\n",
        "Authorization: Basic YWRtaW46YWRtaW4=\r\n",
        "Content-Length: 100\r\n",
        "Connection: close\r\n\r\n",
        "partial replacement"
    );
    stream.write_all(request.as_bytes())?;
    stream.shutdown(Shutdown::Write)?;
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);

    assert_eq!(
        std::fs::read_to_string(server.path().join("index.html"))?,
        "This is index.html",
        "an incomplete PUT must not truncate or replace the live file"
    );
    assert!(
        std::fs::read_dir(server.path())?.all(|entry| {
            !entry
                .ok()
                .and_then(|entry| entry.file_name().to_str().map(str::to_owned))
                .is_some_and(|name| name.starts_with(".ram-upload-") && name.ends_with(".tmp"))
        }),
        "failed uploads must clean their temporary files"
    );
    Ok(())
}

#[rstest]
fn atomic_write_candidates_are_never_http_visible(server: TestServer) -> Result<(), Error> {
    let name = ".ram-upload-00000000-0000-4000-8000-000000000000.tmp";
    std::fs::write(server.path().join(name), "unfinished secret")?;

    let direct = reqwest::blocking::get(format!("{}{name}", server.url()))?;
    assert_eq!(direct.status(), 400);

    let listing = reqwest::blocking::get(server.url())?.text()?;
    assert!(!utils::retrieve_index_paths(&listing).contains(&name.to_string()));
    Ok(())
}

#[rstest]
fn put_file_create_dir(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    let url = format!("{}xyz/file1", server.url());
    let resp = fetch!(b"PUT", &url).body(b"abc".to_vec()).send()?;
    assert_eq!(resp.status(), 201);
    let resp = reqwest::blocking::get(url)?;
    assert_eq!(resp.status(), 200);
    Ok(())
}

#[rstest]
fn put_file_create_deep_dir(#[with(&["--allow-upload"])] server: TestServer) -> Result<(), Error> {
    let url = format!("{}newdir/subdir/file1", server.url());
    let resp = fetch!(b"PUT", &url).body(b"abc".to_vec()).send()?;
    assert_eq!(resp.status(), 201);
    let resp = reqwest::blocking::get(url)?;
    assert_eq!(resp.status(), 200);
    Ok(())
}

#[rstest]
fn put_file_conflict_dir(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    let url = format!("{}dir1", server.url());
    let resp = fetch!(b"PUT", &url).body(b"abc".to_vec()).send()?;
    assert_eq!(resp.status(), 403);
    Ok(())
}

#[rstest]
fn delete_file(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    let url = format!("{}test.html", server.url());
    let resp = fetch!(b"DELETE", &url).send()?;
    assert_eq!(resp.status(), 204);
    let resp = reqwest::blocking::get(url)?;
    assert_eq!(resp.status(), 404);
    Ok(())
}

#[rstest]
fn delete_file_404(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"DELETE", format!("{}file1", server.url())).send()?;
    assert_eq!(resp.status(), 404);
    Ok(())
}

#[rstest]
fn get_file_content_type(server: TestServer) -> Result<(), Error> {
    let resp = reqwest::blocking::get(format!("{}content-types/bin.tar", server.url()))?;
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/x-tar"
    );
    let resp = reqwest::blocking::get(format!("{}content-types/bin", server.url()))?;
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/octet-stream"
    );
    let resp = reqwest::blocking::get(format!("{}content-types/file-utf8.txt", server.url()))?;
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "text/plain; charset=UTF-8"
    );
    let resp = reqwest::blocking::get(format!("{}content-types/file-gbk.txt", server.url()))?;
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "text/plain; charset=GBK"
    );
    let resp = reqwest::blocking::get(format!("{}content-types/file", server.url()))?;
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "text/plain; charset=UTF-8"
    );
    Ok(())
}
