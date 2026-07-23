#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/utils.rs"]
mod utils;

use assert_cmd::prelude::*;
use assert_fs::fixture::TempDir;
use fixtures::{
    DIR_ASSETS, Error, ServerProc, TEST_AUTH_PASS, TEST_AUTH_RULE, TEST_AUTH_USER, TestServer,
    port, ram_command, server, tmpdir,
};
use rstest::rstest;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

#[test]
fn asset_js_syntax_is_valid() -> Result<(), Error> {
    for path in [
        "web/index.js",
        "web/api.js",
        "web/app-utils.js",
        "web/editor.js",
        "web/file-operations.js",
        "web/icons.js",
        "web/page-init.js",
        "web/ui-state.js",
        "web/upload-scheduler.js",
    ] {
        let output = match Command::new("node").args(["--check", path]).output() {
            Ok(output) => output,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("Skipping JavaScript syntax checks because node is unavailable");
                return Ok(());
            }
            Err(err) => return Err(err.into()),
        };
        assert!(
            output.status.success(),
            "{path}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

#[rstest]
fn assets(server: TestServer) -> Result<(), Error> {
    let ver = env!("CARGO_PKG_VERSION");
    let resp = reqwest::blocking::get(server.url())?;
    let index_js = format!("/__ram_v{ver}__/index.js");
    let index_css = format!("/__ram_v{ver}__/index.css");
    let favicon_ico = format!("/__ram_v{ver}__/favicon.ico");
    let text = resp.text()?;
    println!("{text}");
    assert!(text.contains(&format!(r#"href="{index_css}""#)));
    assert!(text.contains(&format!(r#"href="{favicon_ico}""#)));
    assert!(text.contains(&format!(r#"src="{index_js}""#)));
    Ok(())
}

#[rstest]
fn asset_js(server: TestServer) -> Result<(), Error> {
    for name in [
        "index.js",
        "api.js",
        "app-utils.js",
        "editor.js",
        "file-operations.js",
        "icons.js",
        "page-init.js",
        "ui-state.js",
        "upload-scheduler.js",
    ] {
        let url = format!(
            "{}__ram_v{}__/{name}",
            server.url(),
            env!("CARGO_PKG_VERSION")
        );
        let resp = reqwest::blocking::get(url)?;
        assert_eq!(resp.status(), 200, "missing embedded module {name}");
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/javascript; charset=UTF-8"
        );
    }
    Ok(())
}

#[rstest]
fn asset_css(server: TestServer) -> Result<(), Error> {
    let url = format!(
        "{}__ram_v{}__/index.css",
        server.url(),
        env!("CARGO_PKG_VERSION")
    );
    let resp = reqwest::blocking::get(url)?;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "text/css; charset=UTF-8"
    );
    Ok(())
}

#[rstest]
fn asset_ico(server: TestServer) -> Result<(), Error> {
    let url = format!(
        "{}__ram_v{}__/favicon.ico",
        server.url(),
        env!("CARGO_PKG_VERSION")
    );
    let resp = reqwest::blocking::get(url)?;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("content-type").unwrap(), "image/x-icon");
    Ok(())
}

#[rstest]
fn head_asset_has_get_headers_without_body(server: TestServer) -> Result<(), Error> {
    let url = format!(
        "{}__ram_v{}__/index.js",
        server.url(),
        env!("CARGO_PKG_VERSION")
    );
    let get = fetch!(b"GET", &url).send()?;
    let head = fetch!(b"HEAD", &url).send()?;
    assert_eq!(head.status(), get.status());
    for name in ["content-type", "content-length", "cache-control"] {
        assert_eq!(head.headers().get(name), get.headers().get(name));
    }
    assert!(head.bytes()?.is_empty());
    Ok(())
}

/// 内置资源针对编译期字节解析并求值条件；HEAD 复用精确的 GET 验证器，304 保留它，而空的
/// 412 绝不能继续声明资源的非零长度。
/// Embedded assets parse and evaluate conditions against their compile-time bytes; HEAD reuses the
/// exact GET validator, 304 retains it, and an empty 412 never advertises the asset's nonzero length.
#[rstest]
fn embedded_asset_conditions_use_the_selected_representation(
    server: TestServer,
) -> Result<(), Error> {
    let url = format!(
        "{}__ram_v{}__/index.js",
        server.url(),
        env!("CARGO_PKG_VERSION")
    );
    let client = reqwest::blocking::Client::new();
    let get = client.get(&url).send()?;
    assert_eq!(get.status(), 200);
    let etag = get.headers().get("etag").cloned().expect("asset ETag");
    let length = get
        .headers()
        .get("content-length")
        .cloned()
        .expect("asset length");

    let head = client.head(&url).send()?;
    assert_eq!(head.headers().get("etag"), Some(&etag));
    assert_eq!(head.headers().get("content-length"), Some(&length));

    for method in [reqwest::Method::GET, reqwest::Method::HEAD] {
        let not_modified = client
            .request(method.clone(), &url)
            .header("if-none-match", etag.clone())
            .send()?;
        assert_eq!(not_modified.status(), 304, "{method}");
        assert_eq!(not_modified.headers().get("etag"), Some(&etag));
        assert!(not_modified.bytes()?.is_empty());

        let failed = client
            .request(method.clone(), &url)
            .header("if-match", "\"stale-asset\"")
            .send()?;
        assert_eq!(failed.status(), 412, "{method}");
        assert_eq!(failed.headers().get("content-length").unwrap(), "0");
        assert!(failed.bytes()?.is_empty());
    }
    Ok(())
}

#[rstest]
fn head_health_has_get_headers_without_body(server: TestServer) -> Result<(), Error> {
    let url = format!("{}__ram__/health", server.url());
    let get = fetch!(b"GET", &url).send()?;
    let head = fetch!(b"HEAD", &url).send()?;
    assert_eq!(head.status(), get.status());
    assert_eq!(
        head.headers().get("content-type"),
        get.headers().get("content-type")
    );
    assert_eq!(
        head.headers().get("content-length"),
        get.headers().get("content-length")
    );
    assert!(head.bytes()?.is_empty());
    Ok(())
}

#[rstest]
fn assets_with_prefix(#[with(&["--path-prefix", "xyz"])] server: TestServer) -> Result<(), Error> {
    let ver = env!("CARGO_PKG_VERSION");
    let resp = reqwest::blocking::get(format!("{}xyz/", server.url()))?;
    let index_js = format!("/xyz/__ram_v{ver}__/index.js");
    let index_css = format!("/xyz/__ram_v{ver}__/index.css");
    let favicon_ico = format!("/xyz/__ram_v{ver}__/favicon.ico");
    let text = resp.text()?;
    assert!(text.contains(&format!(r#"href="{index_css}""#)));
    assert!(text.contains(&format!(r#"href="{favicon_ico}""#)));
    assert!(text.contains(&format!(r#"src="{index_js}""#)));
    Ok(())
}

#[rstest]
fn asset_js_with_prefix(
    #[with(&["--path-prefix", "xyz"])] server: TestServer,
) -> Result<(), Error> {
    let url = format!(
        "{}xyz/__ram_v{}__/index.js",
        server.url(),
        env!("CARGO_PKG_VERSION")
    );
    let resp = reqwest::blocking::get(url)?;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/javascript; charset=UTF-8"
    );
    Ok(())
}

#[rstest]
fn assets_override(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE])
        .arg("--assets")
        .arg(tmpdir.join(DIR_ASSETS));
    let _server = ServerProc::spawn(cmd);

    let url = format!("http://{TEST_AUTH_USER}:{TEST_AUTH_PASS}@localhost:{port}");
    let resp = reqwest::blocking::get(&url)?;
    assert!(
        resp.text()?
            .starts_with("/__ram_custom_assets__/index.js;<template id=\"index-data\">")
    );
    let resp = reqwest::blocking::get(&url)?;
    assert_resp_paths!(resp);
    Ok(())
}

#[rstest]
fn writable_assets_inside_served_tree_are_rejected(
    tmpdir: TempDir,
    port: u16,
) -> Result<(), Error> {
    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE, "--allow-upload", "--assets"])
        .arg(tmpdir.join(DIR_ASSETS));
    cmd.assert()
        .failure()
        .stderr(predicates::str::contains("writable assets directory"));
    Ok(())
}

#[rstest]
fn assets_directory_cannot_contain_served_tree(port: u16) -> Result<(), Error> {
    let assets_root = TempDir::new()?;
    std::fs::write(assets_root.path().join("index.html"), "trusted ui")?;
    let served = assets_root.path().join("served");
    std::fs::create_dir(&served)?;
    std::fs::write(served.join("private.txt"), "must require authentication")?;

    let mut cmd = ram_command(&served, port);
    cmd.args(["--auth", TEST_AUTH_RULE, "--assets"])
        .arg(assets_root.path());
    cmd.assert()
        .failure()
        .stderr(predicates::str::contains("would bypass authentication"));
    Ok(())
}

#[rstest]
fn token_secret_cannot_be_exposed_by_custom_assets(
    tmpdir: TempDir,
    port: u16,
) -> Result<(), Error> {
    let assets_root = TempDir::new()?;
    std::fs::write(assets_root.path().join("index.html"), "trusted ui")?;
    let secret = assets_root.path().join("token.secret");
    std::fs::write(&secret, "0123456789abcdef0123456789abcdef")?;
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600))?;

    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE, "--assets"])
        .arg(assets_root.path())
        .arg("--token-secret-file")
        .arg(&secret);
    cmd.assert()
        .failure()
        .stderr(predicates::str::contains("custom assets"));
    Ok(())
}

#[rstest]
fn group_or_world_writable_assets_are_rejected(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let assets_root = TempDir::new()?;
    std::fs::write(assets_root.path().join("index.html"), "untrusted ui")?;
    let mut permissions = std::fs::metadata(assets_root.path())?.permissions();
    permissions.set_mode(0o777);
    std::fs::set_permissions(assets_root.path(), permissions)?;

    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE, "--assets"])
        .arg(assets_root.path());
    cmd.assert().failure().stderr(predicates::str::contains(
        "must not be writable by group or other users",
    ));
    Ok(())
}

#[rstest]
fn group_or_world_writable_asset_file_is_rejected(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let assets_root = TempDir::new()?;
    std::fs::write(assets_root.path().join("index.html"), "trusted ui")?;
    let script = assets_root.path().join("index.js");
    std::fs::write(&script, "console.log('replaceable')")?;
    let mut permissions = std::fs::metadata(&script)?.permissions();
    permissions.set_mode(0o666);
    std::fs::set_permissions(&script, permissions)?;

    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE, "--assets"])
        .arg(assets_root.path());
    cmd.assert()
        .failure()
        .stderr(predicates::str::contains("untrusted file or directory"))
        .stderr(predicates::str::contains("group/world writable"));
    Ok(())
}

#[rstest]
fn asset_replaced_with_writable_file_is_rejected_as_internal_trust_failure(
    tmpdir: TempDir,
    port: u16,
) -> Result<(), Error> {
    let assets = tmpdir.join(DIR_ASSETS);
    let script = assets.join("runtime.js");
    std::fs::write(&script, "console.log('initially trusted')")?;
    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE, "--assets"])
        .arg(&assets);
    let _server = ServerProc::spawn(cmd);

    let mut permissions = std::fs::metadata(&script)?.permissions();
    permissions.set_mode(0o666);
    std::fs::set_permissions(&script, permissions)?;
    let resp = reqwest::blocking::get(format!(
        "http://localhost:{port}/__ram_custom_assets__/runtime.js"
    ))?;
    assert_eq!(resp.status(), 500);
    assert_eq!(resp.text()?, "Internal Server Error");
    Ok(())
}

#[rstest]
fn assets_override_not_found_page(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let not_found_html = "<html><body>custom 404 page</body></html>";
    std::fs::write(
        tmpdir.join(format!("{}404.html", DIR_ASSETS)),
        not_found_html,
    )?;

    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE])
        .arg("--assets")
        .arg(tmpdir.join(DIR_ASSETS));
    let _server = ServerProc::spawn(cmd);

    let url = format!("http://{TEST_AUTH_USER}:{TEST_AUTH_PASS}@localhost:{port}/missing-path");
    let resp = reqwest::blocking::get(&url)?;
    assert_eq!(resp.status(), 404);
    assert_eq!(resp.text()?, not_found_html);

    let url =
        format!("http://{TEST_AUTH_USER}:{TEST_AUTH_PASS}@localhost:{port}/missing-path?noscript");
    let resp = reqwest::blocking::get(&url)?;
    assert_eq!(resp.status(), 404);
    // 自定义 404 页是服务端响应策略，对启用/禁用脚本客户端同样适用。
    // A custom 404 page is server-side policy and applies equally to script and no-script clients.
    assert_eq!(resp.text()?, not_found_html);
    Ok(())
}

#[rstest]
fn custom_not_found_ignores_original_conditions_and_range(
    tmpdir: TempDir,
    port: u16,
) -> Result<(), Error> {
    let not_found_html = "<html><body>complete custom 404 page</body></html>";
    std::fs::write(
        tmpdir.join(format!("{}404.html", DIR_ASSETS)),
        not_found_html,
    )?;
    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE])
        .arg("--assets")
        .arg(tmpdir.join(DIR_ASSETS));
    let _server = ServerProc::spawn(cmd);

    let url = format!("http://{TEST_AUTH_USER}:{TEST_AUTH_PASS}@localhost:{port}/missing");
    let resp = fetch!(b"GET", url)
        .header("Range", "bytes=0-3")
        .header("If-None-Match", "*")
        .send()?;
    assert_eq!(resp.status(), 404);
    assert!(!resp.headers().contains_key("content-range"));
    assert_eq!(resp.text()?, not_found_html);
    Ok(())
}

#[cfg(unix)]
#[rstest]
fn custom_asset_symlink_escape_is_rejected_as_internal_trust_failure(
    tmpdir: TempDir,
    port: u16,
) -> Result<(), Error> {
    use std::os::unix::fs::symlink;

    let secret = tmpdir.join("private-outside-assets.txt");
    std::fs::write(&secret, "must stay private")?;
    let asset = tmpdir.join(format!("{}leak.txt", DIR_ASSETS));
    std::fs::write(&asset, "initial trusted asset")?;

    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE])
        .arg("--assets")
        .arg(tmpdir.join(DIR_ASSETS));
    let _server = ServerProc::spawn(cmd);

    std::fs::remove_file(&asset)?;
    symlink(&secret, &asset)?;

    // 自定义资源端点在认证之前处理，所以特意不带凭据。运行期越根替换表示
    // 服务端可信资源能力已损坏：应公开稳定的 500，但绝不能泄露目标内容。
    // Custom assets are handled before authentication, so send no credentials. A runtime escape means
    // the trusted server capability is broken: expose a stable 500, never the target contents.
    let url = format!("http://localhost:{port}/__ram_custom_assets__/leak.txt");
    let resp = reqwest::blocking::get(url)?;
    assert_eq!(resp.status(), 500);
    assert_eq!(resp.text()?, "Internal Server Error");
    Ok(())
}

#[cfg(unix)]
#[rstest]
fn custom_asset_symlink_is_rejected_during_complete_startup_scan(
    tmpdir: TempDir,
    port: u16,
) -> Result<(), Error> {
    use std::os::unix::fs::symlink;

    let secret = tmpdir.join("private-startup-secret.txt");
    std::fs::write(&secret, "must stay private")?;
    let nested = tmpdir.join(format!("{}nested", DIR_ASSETS));
    std::fs::create_dir(&nested)?;
    symlink(&secret, nested.join("leak.txt"))?;

    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE])
        .arg("--assets")
        .arg(tmpdir.join(DIR_ASSETS));
    cmd.assert().failure().stderr(predicates::str::contains(
        "Custom assets contain an untrusted file or directory",
    ));
    Ok(())
}

#[cfg(unix)]
#[rstest]
fn custom_index_symlink_cannot_escape_assets_root(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    use std::os::unix::fs::symlink;

    let secret = tmpdir.join("private-index-outside-assets.html");
    std::fs::write(&secret, "must stay private")?;
    let index = tmpdir.join(format!("{}index.html", DIR_ASSETS));
    std::fs::remove_file(&index)?;
    symlink(&secret, index)?;

    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE])
        .arg("--assets")
        .arg(tmpdir.join(DIR_ASSETS));
    cmd.assert().failure().stderr(predicates::str::contains(
        "Custom assets contain an untrusted file or directory",
    ));
    Ok(())
}
