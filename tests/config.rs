#[path = "common/digest_auth_util.rs"]
mod digest_auth_util;
#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/utils.rs"]
mod utils;

use assert_cmd::prelude::*;
use assert_fs::TempDir;
use digest_auth_util::send_with_digest_auth;
use fixtures::{Error, ServerProc, TEST_AUTH_RULE, port, ram_command, tmpdir};
use rstest::rstest;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::process::Command;

#[rstest]
fn explicit_config_file_is_loaded(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let bindir = TempDir::new()?;
    let bin_path = bindir.path().join("ram");
    fs::copy(assert_cmd::cargo::cargo_bin!("ram"), &bin_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(&bin_path)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&bin_path, permissions)?;
    }
    let config_path = bindir.path().join("config.yaml");
    fs::copy(get_config_path(), &config_path)?;

    let mut cmd = Command::new(&bin_path);
    cmd.arg(tmpdir.path())
        .arg("--config")
        .arg(&config_path)
        .arg("-p")
        .arg(port.to_string());
    let _server = ServerProc::spawn(cmd);

    let url = format!("http://localhost:{port}/ram/index.html");
    let resp = fetch!(b"GET", &url).send()?;
    assert_eq!(resp.status(), 401);

    let url = format!("http://localhost:{port}/ram/index.html");
    let resp = send_with_digest_auth(fetch!(b"GET", &url), "user", "pass")?;
    assert_eq!(resp.text()?, "This is index.html");

    let url = format!("http://localhost:{port}/ram?simple");
    let resp = send_with_digest_auth(fetch!(b"GET", &url), "user", "pass")?;
    let text: String = resp.text().unwrap();
    assert!(text.split('\n').any(|c| c == "dir1/"));
    assert!(!text.split('\n').any(|c| c == "dir3/"));
    assert!(!text.split('\n').any(|c| c == "test.txt"));

    let url = format!("http://localhost:{port}/ram/dir1/upload.txt");
    let resp = send_with_digest_auth(fetch!(b"PUT", &url).body("Hello"), "user", "pass")?;
    assert_eq!(resp.status(), 201);
    Ok(())
}

#[rstest]
fn executable_and_cwd_config_is_ignored_without_selector(
    tmpdir: TempDir,
    port: u16,
) -> Result<(), Error> {
    let bindir = TempDir::new()?;
    let bin_path = bindir.path().join("ram");
    fs::copy(assert_cmd::cargo::cargo_bin!("ram"), &bin_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(&bin_path)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&bin_path, permissions)?;
    }
    // 把 cwd 也设为二进制目录，使同一 config.yaml 同时位于两个曾可能被误认为会隐式
    // 搜索的位置。未显式选择时它必须被忽略，由 CLI `--auth` 生效。
    // Use the executable directory as cwd so the same config.yaml occupies both locations that
    // could otherwise be mistaken for implicit search roots. It must remain ignored without a selector.
    fs::copy(get_config_path(), bindir.path().join("config.yaml"))?;

    let mut cmd = Command::new(&bin_path);
    cmd.current_dir(bindir.path())
        .env_remove("RAM_CONFIG")
        .arg(tmpdir.path())
        .arg("-p")
        .arg(port.to_string())
        .args(["--auth", "cli:cli@/:rw"]);
    let _server = ServerProc::spawn(cmd);

    // 忽略相邻配置的 path-prefix，直接服务根。 / Ignore the adjacent path-prefix and serve root directly.
    let url = format!("http://localhost:{port}/index.html");
    let resp = send_with_digest_auth(fetch!(b"GET", &url), "cli", "cli")?;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text()?, "This is index.html");

    // 配置中的前缀路径不得存在。 / The configured prefixed path must not exist.
    let url = format!("http://localhost:{port}/ram/index.html");
    let resp = send_with_digest_auth(fetch!(b"GET", &url), "cli", "cli")?;
    assert_eq!(resp.status(), 404);
    Ok(())
}

#[rstest]
fn filesystem_root_requires_explicit_dangerous_opt_in(port: u16) -> Result<(), Error> {
    let mut cmd = ram_command(std::path::Path::new("/"), port);
    cmd.args(["--auth", TEST_AUTH_RULE]);
    cmd.assert()
        .failure()
        .stderr(predicates::str::contains("--allow-filesystem-root"));
    Ok(())
}

#[rstest]
fn explicit_config_and_boolean_source_matrix(tmpdir: TempDir) -> Result<(), Error> {
    struct Case<'a> {
        yaml: &'a str,
        env: Option<(&'a str, &'a str)>,
        cli: &'a [&'a str],
        allow_upload: bool,
    }
    let cases = [
        // CLI 的字段级 false 关闭 YAML true。 / CLI-specific false disables YAML true.
        Case {
            yaml: "allow-upload: true",
            env: None,
            cli: &["--allow-upload=false"],
            allow_upload: false,
        },
        // 环境变量的字段级 false 关闭 YAML true。 / Environment-specific false disables YAML true.
        Case {
            yaml: "allow-upload: true",
            env: Some(("RAM_ALLOW_UPLOAD", "false")),
            cli: &[],
            allow_upload: false,
        },
        // 环境聚合值后应用 CLI 字段例外。 / A CLI-specific exception follows an environment aggregate.
        Case {
            yaml: "allow-all: false",
            env: Some(("RAM_ALLOW_ALL", "true")),
            cli: &["--allow-upload=false"],
            allow_upload: false,
        },
        // 字段特异性有意跨 CLI/环境来源取胜：环境字段例外可跟随 CLI 聚合值。
        // Specificity intentionally wins across CLI/env: an environment-specific exception follows a CLI aggregate.
        Case {
            yaml: "allow-all: false",
            env: Some(("RAM_ALLOW_UPLOAD", "false")),
            cli: &["--allow-all"],
            allow_upload: false,
        },
        // 环境聚合 false 关闭 YAML 聚合 true。 / Environment aggregate false closes YAML aggregate true.
        Case {
            yaml: "allow-all: true",
            env: Some(("RAM_ALLOW_ALL", "false")),
            cli: &[],
            allow_upload: false,
        },
        // 每个更高优先级来源也可开启 YAML false。 / Every higher-priority source can enable a YAML false.
        Case {
            yaml: "allow-upload: false",
            env: Some(("RAM_ALLOW_UPLOAD", "true")),
            cli: &[],
            allow_upload: true,
        },
        Case {
            yaml: "allow-upload: false",
            env: None,
            cli: &["--allow-upload=true"],
            allow_upload: true,
        },
        // 同一具体字段上 CLI 优先于环境变量。 / CLI wins over environment for the same concrete field.
        Case {
            yaml: "allow-upload: false",
            env: Some(("RAM_ALLOW_UPLOAD", "false")),
            cli: &["--allow-upload=true"],
            allow_upload: true,
        },
        Case {
            yaml: "allow-upload: false",
            env: Some(("RAM_ALLOW_UPLOAD", "true")),
            cli: &["--allow-upload=false"],
            allow_upload: false,
        },
        // 更高来源的聚合值有意覆盖较低来源字段值；同级/更高来源字段值随后可覆盖该聚合值。
        // A higher-source aggregate overrides a lower-specific value; a same/higher-specific value can override it later.
        Case {
            yaml: "allow-upload: false",
            env: Some(("RAM_ALLOW_ALL", "true")),
            cli: &[],
            allow_upload: true,
        },
        Case {
            yaml: "allow-upload: true",
            env: Some(("RAM_ALLOW_ALL", "false")),
            cli: &[],
            allow_upload: false,
        },
    ];

    for (index, case) in cases.iter().enumerate() {
        let case_port = fixtures::next_port();
        let state = TempDir::new()?;
        let config = state.path().join("config.yaml");
        fs::write(
            &config,
            format!(
                "serve-path: {}\nauth:\n  - user:password@/:rw\nstorage-reserve: 0\n{}\n",
                tmpdir.path().display(),
                case.yaml
            ),
        )?;

        let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("ram"));
        cmd.arg("--config")
            .arg(&config)
            .args(case.cli)
            .arg("-p")
            .arg(case_port.to_string());
        if let Some((name, value)) = case.env {
            cmd.env(name, value);
        }
        let _server = ServerProc::spawn(cmd);
        let response = reqwest::blocking::Client::new()
            .put(format!(
                "http://localhost:{}/source-matrix-{index}.txt",
                case_port
            ))
            .basic_auth("user", Some("password"))
            .body("matrix")
            .send()?;
        assert_eq!(
            response.status().as_u16(),
            if case.allow_upload { 201 } else { 403 },
            "case {index}"
        );
    }
    Ok(())
}

#[rstest]
#[case(false)]
#[case(true)]
fn explicit_config_path_uses_process_cwd(
    tmpdir: TempDir,
    port: u16,
    #[case] use_environment: bool,
) -> Result<(), Error> {
    let state = TempDir::new()?;
    fs::create_dir(state.path().join("share"))?;
    fs::write(
        state.path().join("config.yaml"),
        "serve-path: share\nauth:\n  - user:password@/:rw\n",
    )?;

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("ram"));
    cmd.current_dir(state.path())
        .arg("-p")
        .arg(port.to_string());
    if use_environment {
        cmd.env("RAM_CONFIG", "config.yaml");
    } else {
        cmd.args(["--config", "config.yaml"]);
    }
    let _server = ServerProc::spawn(cmd);
    let response = reqwest::blocking::Client::new()
        .get(format!("http://localhost:{port}/"))
        .basic_auth("user", Some("password"))
        .send()?;
    assert_eq!(response.status(), 200);

    // 明确测试夹具所有权，避免所选 YAML 服务路径相对此无关夹具意外解析。
    // Keep fixture ownership explicit so the YAML serve path is not resolved relative to an unrelated fixture.
    assert_ne!(
        fs::canonicalize(state.path().join("share"))?,
        fs::canonicalize(tmpdir.path())?
    );
    Ok(())
}

#[rstest]
fn auth_file_cli_is_safe_bounded_and_exclusive(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;

    let state = TempDir::new()?;
    let auth_file = state.path().join("ram-auth");
    fs::write(&auth_file, "user:password@/:rw\n")?;
    fs::set_permissions(&auth_file, fs::Permissions::from_mode(0o600))?;

    let mut valid = ram_command(tmpdir.path(), port);
    valid
        .arg("--check-config")
        .arg("--auth-file")
        .arg(&auth_file);
    valid
        .assert()
        .success()
        .stdout(predicates::str::contains("Configuration OK"));

    let config = state.path().join("config.yaml");
    fs::write(
        &config,
        format!(
            "serve-path: {}\nauth:\n  - configured:password@/:rw\n",
            tmpdir.path().display()
        ),
    )?;
    let mut mixed = Command::new(assert_cmd::cargo::cargo_bin!("ram"));
    mixed
        .arg("--config")
        .arg(config)
        .arg("--auth-file")
        .arg(auth_file)
        .arg("-p")
        .arg(port.to_string());
    mixed.assert().failure().stderr(predicates::str::contains(
        "cannot be combined across configuration sources",
    ));
    Ok(())
}

#[rstest]
fn filesystem_root_dangerous_opt_in_reaches_later_validation(port: u16) -> Result<(), Error> {
    let mut cmd = ram_command(std::path::Path::new("/"), port);
    cmd.args([
        "--auth",
        TEST_AUTH_RULE,
        "--allow-filesystem-root",
        "--max-upload-size",
        "0",
    ]);
    cmd.assert().failure().stderr(predicates::str::contains(
        "max-upload-size must be greater than zero",
    ));
    Ok(())
}

#[rstest]
fn served_symlink_cannot_escape_to_sensitive_file(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let control = TempDir::new()?;
    let secret = control.path().join("outside-secret");
    fs::write(&secret, b"must stay outside the capability")?;
    symlink(&secret, tmpdir.path().join("outside-link"))?;

    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE, "--allow-symlink"]);
    let _server = ServerProc::spawn(cmd);

    let url = format!("http://admin:admin@localhost:{port}/outside-link");
    let response = reqwest::blocking::get(url)?;
    assert_eq!(response.status(), 404);
    assert_ne!(
        response.bytes()?.as_ref(),
        b"must stay outside the capability"
    );
    Ok(())
}

#[test]
fn check_config_rejects_invalid_configuration_and_honors_source_priority() -> Result<(), Error> {
    let state = TempDir::new()?;
    let served = state.path().join("served");
    fs::create_dir(&served)?;
    let config = state.path().join("config.yaml");
    fs::write(
        &config,
        format!(
            "serve-path: '{}'\nbind: 0.0.0.0\nauth:\n  - admin:password@/:rw\nallow-insecure-http: false\n",
            served.display()
        ),
    )?;

    let accepted = Command::new(assert_cmd::cargo::cargo_bin!("ram"))
        .env("RAM_ALLOW_INSECURE_HTTP", "true")
        .args(["--check-config", "--config"])
        .arg(&config)
        .output()?;
    assert!(accepted.status.success());
    assert_eq!(accepted.stdout, b"Configuration OK\n");

    Command::new(assert_cmd::cargo::cargo_bin!("ram"))
        .env("RAM_ALLOW_INSECURE_HTTP", "true")
        .args(["--check-config", "--config"])
        .arg(&config)
        .arg("--allow-insecure-http=false")
        .assert()
        .failure()
        .stderr(predicates::str::contains("authenticated cleartext HTTP"));

    fs::write(&config, "definitely-not-a-setting: true\n")?;
    Command::new(assert_cmd::cargo::cargo_bin!("ram"))
        .args(["--check-config", "--config"])
        .arg(&config)
        .assert()
        .failure()
        .stdout(predicates::str::is_empty())
        .stderr(predicates::str::contains("unknown field"));
    Ok(())
}

fn get_config_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/config.yaml")
}
