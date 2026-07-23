#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/utils.rs"]
mod utils;

use assert_fs::fixture::TempDir;
use fixtures::{Error, TestServer, server, tmpdir};
use rstest::rstest;

use std::fs;
use std::io::Cursor;
use std::os::unix::fs::symlink as symlink_dir;

#[rstest]
fn default_not_allow_symlink(server: TestServer, tmpdir: TempDir) -> Result<(), Error> {
    // 创建指向根外的符号链接目录 `foo`。 / Create symlink directory `foo` pointing outside the root.
    let dir = "foo";
    symlink_dir(tmpdir.path(), server.path().join(dir)).expect("Couldn't create symlink");
    let resp = reqwest::blocking::get(format!("{}{}", server.url(), dir))?;
    assert_eq!(resp.status(), 404);
    let resp = reqwest::blocking::get(format!("{}{}/index.html", server.url(), dir))?;
    assert_eq!(resp.status(), 404);
    let resp = reqwest::blocking::get(server.url())?;
    let paths = utils::retrieve_index_paths(&resp.text()?);
    assert!(!paths.is_empty());
    assert!(!paths.contains(&format!("{dir}/")));
    Ok(())
}

#[rstest]
fn allow_symlink(#[with(&["--allow-symlink"])] server: TestServer) -> Result<(), Error> {
    // 显式启用允许跟随规范目标仍在根内的链接。
    // Explicit opt-in follows a link whose canonical target remains inside root.
    let dir = "foo";
    symlink_dir(server.path().join("dir1"), server.path().join(dir))?;
    let resp = reqwest::blocking::get(format!("{}{}", server.url(), dir))?;
    assert_eq!(resp.status(), 200);
    let resp = reqwest::blocking::get(format!("{}{}/index.html", server.url(), dir))?;
    assert_eq!(resp.status(), 200);
    let resp = reqwest::blocking::get(server.url())?;
    let paths = utils::retrieve_index_paths(&resp.text()?);
    assert!(!paths.is_empty());
    assert!(paths.contains(&format!("{dir}/")));
    Ok(())
}

/// 启用符号链接后，规范 ACL 选择发生在认证前。客户端可制造的命名空间失败必须统一隐藏为
/// 404，不能把 ENOTDIR 暴露为 409、把链接环暴露为 500；有效受保护路径仍应正常挑战认证。
/// Canonical ACL selection runs before authentication when symlinks are enabled. Client-created
/// namespace failures must therefore share one hidden 404 instead of exposing ENOTDIR as 409 or a
/// symlink loop as 500; a valid protected path still challenges normally.
#[rstest]
fn unavailable_canonical_paths_are_hidden_before_authentication(
    #[with(&["--allow-symlink"])] server: TestServer,
) -> Result<(), Error> {
    symlink_dir("loop", server.path().join("loop"))?;

    let mut anonymous = server.url();
    anonymous.set_username("").unwrap();
    anonymous.set_password(None).unwrap();
    assert_eq!(
        reqwest::blocking::get(anonymous.join("test.html")?)?.status(),
        401
    );
    assert_eq!(
        reqwest::blocking::get(anonymous.join("test.html/child")?)?.status(),
        404
    );
    assert_eq!(
        reqwest::blocking::get(anonymous.join("loop")?)?.status(),
        404
    );
    Ok(())
}

#[rstest]
fn allow_symlink_still_confines_targets_to_root(
    #[with(&["--allow-symlink"])] server: TestServer,
    tmpdir: TempDir,
) -> Result<(), Error> {
    symlink_dir(tmpdir.path(), server.path().join("outside"))?;
    let resp = reqwest::blocking::get(format!("{}outside/index.html", server.url()))?;
    assert_eq!(resp.status(), 404);
    assert_eq!(resp.text()?, "Not Found");
    let root = reqwest::blocking::get(server.url())?.text()?;
    assert!(!utils::retrieve_index_paths(&root).contains(&"outside/".to_string()));
    Ok(())
}

#[rstest]
fn dangling_terminal_symlink_cannot_escape_put(
    #[with(&["--allow-upload", "--allow-delete"])] server: TestServer,
    tmpdir: TempDir,
) -> Result<(), Error> {
    let outside = tmpdir.path().join("outside-created-by-put");
    symlink_dir(&outside, server.path().join("dangling"))?;

    let resp = fetch!(b"PUT", format!("{}dangling", server.url()))
        .body("secret")
        .send()?;
    assert!(matches!(resp.status().as_u16(), 400 | 403 | 404));
    assert!(
        !outside.exists(),
        "a dangling terminal symlink must never create a file outside the root"
    );
    Ok(())
}

#[rstest]
fn internal_symlink_is_reauthorized_against_canonical_acl(
    #[with(&[
        "--auth",
        "user:pass@/visible:ro",
        "--allow-symlink"
    ])]
    server: TestServer,
) -> Result<(), Error> {
    symlink_dir(server.path().join("dir2"), server.path().join("visible"))?;
    let resp = fetch!(b"GET", format!("{}visible/test.txt", server.url()))
        .basic_auth("user", Some("pass"))
        .send()?;
    assert_eq!(resp.status(), 403);
    Ok(())
}

#[rstest]
fn search_does_not_follow_an_allowed_symlink_into_another_acl_subtree(
    #[with(&[
        "--auth",
        "user:pass@/visible:ro",
        "--allow-symlink",
        "--allow-search"
    ])]
    server: TestServer,
) -> Result<(), Error> {
    fs::create_dir(server.path().join("visible"))?;
    fs::create_dir(server.path().join("private"))?;
    fs::write(server.path().join("visible/safe.txt"), "safe")?;
    fs::write(
        server.path().join("private/acl-secret-needle.txt"),
        "secret",
    )?;
    symlink_dir(
        server.path().join("private"),
        server.path().join("visible/private-link"),
    )?;

    let resp = fetch!(
        b"GET",
        format!("{}visible/?q=acl-secret-needle", server.url())
    )
    .basic_auth("user", Some("pass"))
    .send()?;
    assert_eq!(resp.status(), 200);
    let paths = utils::retrieve_index_paths(&resp.text()?);
    assert!(!paths.iter().any(|path| path.contains("acl-secret-needle")));
    Ok(())
}

#[rstest]
fn zip_does_not_follow_an_allowed_symlink_into_another_acl_subtree(
    #[with(&[
        "--auth",
        "user:pass@/visible:ro",
        "--allow-symlink",
        "--allow-archive"
    ])]
    server: TestServer,
) -> Result<(), Error> {
    fs::create_dir(server.path().join("visible"))?;
    fs::create_dir(server.path().join("private"))?;
    fs::write(server.path().join("visible/safe.txt"), "safe")?;
    fs::write(server.path().join("private/acl-secret.txt"), "secret")?;
    symlink_dir(
        server.path().join("private"),
        server.path().join("visible/private-link"),
    )?;

    let resp = fetch!(b"GET", format!("{}visible/?zip", server.url()))
        .basic_auth("user", Some("pass"))
        .send()?;
    assert_eq!(resp.status(), 200);
    let bytes = resp.bytes()?;
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
    let names = (0..archive.len())
        .map(|index| {
            archive
                .by_index(index)
                .map(|entry| entry.name().to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert!(names.iter().any(|name| name == "archive/safe.txt"));
    assert!(
        names
            .iter()
            .all(|name| name == "archive/" || name.starts_with("archive/"))
    );
    assert!(!names.iter().any(|name| name.contains("acl-secret")));
    Ok(())
}
