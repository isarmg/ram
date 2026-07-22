//! 使用不同参数运行单文件服务器。
//! Run the single-file server with different arguments.

#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/utils.rs"]
mod utils;

use assert_fs::fixture::TempDir;
use fixtures::{
    Error, ServerProc, TEST_AUTH_PASS, TEST_AUTH_RULE, TEST_AUTH_USER, port, ram_command, tmpdir,
};
use rstest::rstest;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

#[rstest]
#[case("index.html")]
fn single_file(tmpdir: TempDir, port: u16, #[case] file: &str) -> Result<(), Error> {
    let mut cmd = ram_command(&tmpdir.path().join(file), port);
    cmd.args(["--auth", TEST_AUTH_RULE]);
    let _server = ServerProc::spawn(cmd);

    let resp = reqwest::blocking::get(format!(
        "http://{TEST_AUTH_USER}:{TEST_AUTH_PASS}@localhost:{port}"
    ))?;
    assert_eq!(resp.text()?, "This is index.html");
    let resp = reqwest::blocking::get(format!(
        "http://{TEST_AUTH_USER}:{TEST_AUTH_PASS}@localhost:{port}/"
    ))?;
    assert_eq!(resp.text()?, "This is index.html");
    let resp = reqwest::blocking::get(format!(
        "http://{TEST_AUTH_USER}:{TEST_AUTH_PASS}@localhost:{port}/index.html"
    ))?;
    assert_eq!(resp.text()?, "This is index.html");
    Ok(())
}

#[rstest]
fn non_utf8_single_file_name_is_rejected(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let file = tmpdir.path().join(OsStr::from_bytes(b"single-\xff.txt"));
    std::fs::write(&file, b"not addressable over HTTP")?;
    let mut cmd = ram_command(&file, port);
    cmd.args(["--auth", TEST_AUTH_RULE, "--check-config"]);
    let output = cmd.output()?;
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(
        stderr.contains("single-file mode requires a non-empty UTF-8 filename"),
        "unexpected stderr: {stderr}"
    );
    Ok(())
}

#[rstest]
#[case("index.html")]
fn path_prefix_single_file(tmpdir: TempDir, port: u16, #[case] file: &str) -> Result<(), Error> {
    let mut cmd = ram_command(&tmpdir.path().join(file), port);
    cmd.arg("--path-prefix")
        .arg("xyz")
        .args(["--auth", TEST_AUTH_RULE]);
    let _server = ServerProc::spawn(cmd);

    let resp = reqwest::blocking::get(format!(
        "http://{TEST_AUTH_USER}:{TEST_AUTH_PASS}@localhost:{port}/xyz"
    ))?;
    assert_eq!(resp.text()?, "This is index.html");
    let resp = reqwest::blocking::get(format!(
        "http://{TEST_AUTH_USER}:{TEST_AUTH_PASS}@localhost:{port}/xyz/"
    ))?;
    assert_eq!(resp.text()?, "This is index.html");
    let resp = reqwest::blocking::get(format!(
        "http://{TEST_AUTH_USER}:{TEST_AUTH_PASS}@localhost:{port}/xyz/index.html"
    ))?;
    assert_eq!(resp.text()?, "This is index.html");
    let resp = reqwest::blocking::get(format!(
        "http://{TEST_AUTH_USER}:{TEST_AUTH_PASS}@localhost:{port}"
    ))?;
    assert_eq!(resp.status(), 400);
    Ok(())
}

#[rstest]
fn single_file_method_matrix(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let file = tmpdir.path().join("index.html");
    let mut cmd = ram_command(&file, port);
    cmd.args(["--auth", TEST_AUTH_RULE]);
    let _server = ServerProc::spawn(cmd);
    let url = format!("http://localhost:{port}/");

    // OPTIONS 是匿名能力探测，但绝不能走文件发送分支。
    // OPTIONS is anonymous capability discovery and must never enter file delivery.
    let resp = fetch!(b"OPTIONS", &url).send()?;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("allow").unwrap(), "GET, HEAD, OPTIONS");
    assert!(resp.text()?.is_empty());

    // HEAD 保留 GET 的表示头，但不发正文。
    // HEAD preserves GET representation headers without sending a body.
    let resp = fetch!(b"HEAD", &url)
        .basic_auth(TEST_AUTH_USER, Some(TEST_AUTH_PASS))
        .send()?;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("content-length").unwrap(), "18");
    assert!(resp.bytes()?.is_empty());

    // 即使凭据具有 rw，单文件路由也不会把 PUT/PATCH/DELETE
    // 误当成下载；它们统一返回带 Allow 的 405。
    // Even with read-write credentials, single-file routing must not treat PUT/PATCH/DELETE as
    // downloads; all return 405 with Allow.
    for method in [b"PUT".as_ref(), b"PATCH".as_ref(), b"DELETE".as_ref()] {
        let resp = reqwest::blocking::Client::new()
            .request(reqwest::Method::from_bytes(method)?, &url)
            .basic_auth(TEST_AUTH_USER, Some(TEST_AUTH_PASS))
            .body("must not be returned")
            .send()?;
        assert_eq!(resp.status(), 405);
        assert_eq!(resp.headers().get("allow").unwrap(), "GET, HEAD, OPTIONS");
        assert!(resp.text()?.is_empty());
    }
    Ok(())
}

#[rstest]
fn single_file_aliases_share_one_acl_identity(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let file = tmpdir.path().join("index.html");
    let mut cmd = ram_command(&file, port);
    cmd.args([
        "--auth",
        "allowed:pass@/index.html|blocked:pass@/unrelated|intermediate:pass@/index.html/descendant",
    ]);
    let _server = ServerProc::spawn(cmd);

    for path in ["", "/", "/index.html"] {
        let url = format!("http://localhost:{port}{path}");

        // 仅拥有无关深层路径的用户在根节点只是 IndexOnly，
        // 不得因 `/` 别名而读到文件正文。
        // A user authorized only for an unrelated deep path is IndexOnly at root and must not read
        // file contents through the `/` alias.
        let resp = fetch!(b"GET", &url)
            .basic_auth("blocked", Some("pass"))
            .send()?;
        assert_eq!(resp.status(), 403, "blocked alias {path:?}");

        // 与文件同名的 IndexOnly ACL 中间节点也不能把单文件别名变成可读资源。
        // An IndexOnly ACL intermediate with the file's own name must not make
        // any single-file alias readable.
        let resp = fetch!(b"GET", &url)
            .basic_auth("intermediate", Some("pass"))
            .send()?;
        assert_eq!(resp.status(), 403, "IndexOnly alias {path:?}");

        // 授权给唯一规范文件名后，所有公开别名的结果一致。
        // Once the canonical filename is authorized, all public aliases behave identically.
        let resp = fetch!(b"GET", &url)
            .basic_auth("allowed", Some("pass"))
            .send()?;
        assert_eq!(resp.status(), 200, "allowed alias {path:?}");
        assert_eq!(resp.text()?, "This is index.html");
    }
    Ok(())
}

#[rstest]
fn single_file_token_uses_canonical_alias_path(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let file = tmpdir.path().join("index.html");
    let mut cmd = ram_command(&file, port);
    cmd.args(["--auth", "user:pass@/index.html"]);
    let _server = ServerProc::spawn(cmd);

    let resp = fetch!(b"POST", format!("http://localhost:{port}/?tokengen"))
        .basic_auth("user", Some("pass"))
        .send()?;
    assert_eq!(resp.status(), 200);
    let token = resp.text()?;

    // 令牌与规范资源绑定，而不是与签发时恰好使用的 `/`
    // URL 别名绑定，所以换成 `/index.html` 仍是同一文件。
    // The token binds the canonical resource, not the `/` alias used at issuance; `/index.html`
    // therefore addresses the same file.
    let resp = fetch!(b"GET", format!("http://localhost:{port}/index.html"))
        .bearer_auth(&token)
        .send()?;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text()?, "This is index.html");
    Ok(())
}
