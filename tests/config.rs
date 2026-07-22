#[path = "common/digest_auth_util.rs"]
mod digest_auth_util;
#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/utils.rs"]
mod utils;

use assert_cmd::prelude::*;
use assert_fs::TempDir;
use digest_auth_util::send_with_digest_auth;
use fixtures::{
    Error, ServerProc, TEST_AUTH_RULE, command_output_with_exec_retry, port, ram_command, tmpdir,
};
use rstest::rstest;
use std::fs;
use std::net::TcpListener;
use std::os::unix::fs::{PermissionsExt, chown, symlink};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;

#[rstest]
fn use_config_file(tmpdir: TempDir, port: u16) -> Result<(), Error> {
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
    fs::copy(get_config_path(), bindir.path().join("config.yaml"))?;

    let mut cmd = Command::new(&bin_path);
    cmd.arg(tmpdir.path()).arg("-p").arg(port.to_string());
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
fn no_config_env_disables_config_file(tmpdir: TempDir, port: u16) -> Result<(), Error> {
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
    // 二进制旁虽有 config.yaml，RAM_NO_CONFIG 必须令 ram 完全忽略它，因此不应用配置的
    // `path-prefix: ram`，改由 CLI `--auth` 生效。
    // A nearby config.yaml must be ignored under RAM_NO_CONFIG, leaving its path-prefix unapplied and CLI auth effective.
    fs::copy(get_config_path(), bindir.path().join("config.yaml"))?;

    let mut cmd = Command::new(&bin_path);
    cmd.env("RAM_NO_CONFIG", "1")
        .arg(tmpdir.path())
        .arg("-p")
        .arg(port.to_string())
        .args(["--auth", "cli:cli@/:rw"]);
    let _server = ServerProc::spawn(cmd);

    // 忽略配置 path-prefix，直接服务根。 / Config path-prefix is ignored; serve root directly.
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
fn access_log_cannot_be_placed_in_served_tree(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let log_path = tmpdir.path().join("access.log");
    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE, "--log-file"])
        .arg(log_path);
    cmd.assert()
        .failure()
        .stderr(predicates::str::contains("access log"))
        .stderr(predicates::str::contains("served path"));
    Ok(())
}

#[rstest]
fn storage_quota_hook_cannot_be_served(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let hook = tmpdir.path().join("quota-hook");
    fs::write(&hook, b"#!/bin/sh\nexit 0\n")?;
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o700))?;
    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE, "--storage-quota-hook"])
        .arg(hook);
    cmd.assert()
        .failure()
        .stderr(predicates::str::contains("storage quota hook"))
        .stderr(predicates::str::contains("served path"));
    Ok(())
}

#[rstest]
fn storage_quota_hook_must_be_a_private_executable(
    tmpdir: TempDir,
    port: u16,
) -> Result<(), Error> {
    let control = TempDir::new()?;
    let hook = control.path().join("quota-hook");
    fs::write(&hook, b"#!/bin/sh\nexit 0\n")?;
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o722))?;
    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE, "--storage-quota-hook"])
        .arg(hook);
    cmd.assert()
        .failure()
        .stderr(predicates::str::contains("storage quota hook"))
        .stderr(predicates::str::contains(
            "must not be writable by group or other users",
        ));
    Ok(())
}

#[rstest]
fn token_secret_cannot_be_served(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let secret_path = tmpdir.path().join("token.secret");
    write_test_secret(&secret_path)?;
    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE, "--token-secret-file"])
        .arg(secret_path);
    cmd.assert()
        .failure()
        .stderr(predicates::str::contains("token secret"))
        .stderr(predicates::str::contains("served path"));
    Ok(())
}

#[rstest]
fn token_secret_with_untrusted_owner_is_rejected(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    if !rustix::process::geteuid().is_root() {
        return Ok(());
    }
    let state_dir = TempDir::new()?;
    let secret = state_dir.path().join("token.secret");
    write_test_secret(&secret)?;
    chown(&secret, Some(65_534), None)?;

    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE, "--token-secret-file"])
        .arg(secret);
    cmd.assert()
        .failure()
        .stderr(predicates::str::contains("token secret"))
        .stderr(predicates::str::contains("untrusted owner"));
    Ok(())
}

#[rstest]
#[case(0o640)]
#[case(0o644)]
#[case(0o1600)]
#[case(0o2600)]
#[case(0o4600)]
fn token_secret_non_exact_private_mode_is_rejected(
    tmpdir: TempDir,
    port: u16,
    #[case] mode: u32,
) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;

    let state_dir = TempDir::new()?;
    let secret = state_dir.path().join("token.secret");
    fs::write(&secret, b"0123456789abcdef0123456789abcdef")?;
    fs::set_permissions(&secret, fs::Permissions::from_mode(mode))?;

    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE, "--token-secret-file"])
        .arg(secret);
    cmd.assert()
        .failure()
        .stderr(predicates::str::contains("must use mode 0400 or 0600"));
    Ok(())
}

#[rstest]
fn token_revocation_symlink_is_rejected(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let state_dir = TempDir::new()?;
    let secret = state_dir.path().join("token.secret");
    write_test_secret(&secret)?;
    let target = state_dir.path().join("actual-revocations.json");
    fs::write(&target, br#"{"version":1,"revoked":{}}"#)?;
    let link = state_dir.path().join("revocations.json");
    symlink(&target, &link)?;

    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE, "--token-secret-file"])
        .arg(secret)
        .arg("--token-revocation-file")
        .arg(link);
    cmd.assert()
        .failure()
        .stderr(predicates::str::contains("token revocation state"))
        .stderr(predicates::str::contains("symlink"));
    Ok(())
}

#[rstest]
fn derived_token_revocation_symlink_is_rejected(tmpdir: TempDir, port: u16) -> Result<(), Error> {
    let state_dir = TempDir::new()?;
    let secret = state_dir.path().join("token.secret");
    write_test_secret(&secret)?;
    let target = state_dir.path().join("actual-revocations.json");
    fs::write(&target, br#"{"version":1,"revoked":{}}"#)?;
    let derived = state_dir.path().join("token.secret.revocations.json");
    symlink(&target, &derived)?;

    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE, "--token-secret-file"])
        .arg(secret);
    cmd.assert()
        .failure()
        .stderr(predicates::str::contains("token revocation state"))
        .stderr(predicates::str::contains("symlink"));
    Ok(())
}

#[rstest]
fn persistent_revocation_state_can_be_shared_by_multiple_processes(
    tmpdir: TempDir,
    port: u16,
) -> Result<(), Error> {
    let state_dir = TempDir::new()?;
    let secret = state_dir.path().join("token.secret");
    let revocations = state_dir.path().join("revocations.json");
    write_test_secret(&secret)?;

    let second_port = {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
        listener.local_addr()?.port()
    };
    let command = |listen_port| {
        let mut cmd = ram_command(tmpdir.path(), listen_port);
        cmd.args(["--auth", TEST_AUTH_RULE, "--token-secret-file"])
            .arg(&secret)
            .args(["--token-audience", "shared-test", "--token-revocation-file"])
            .arg(&revocations);
        cmd
    };

    let _first = ServerProc::spawn(command(port));
    let _second = ServerProc::spawn(command(second_port));
    let document: serde_json::Value = serde_json::from_slice(&fs::read(&revocations)?)?;
    assert_eq!(document["version"], 2);
    assert_eq!(document["generation"], 1);
    Ok(())
}

#[rstest]
fn oversized_token_revocation_state_is_rejected_before_json_parsing(
    tmpdir: TempDir,
    port: u16,
) -> Result<(), Error> {
    let state_dir = TempDir::new()?;
    let secret = state_dir.path().join("token.secret");
    let revocations = state_dir.path().join("revocations.json");
    write_test_secret(&secret)?;
    fs::File::create(&revocations)?.set_len(8 * 1024 * 1024 + 1)?;

    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE, "--token-secret-file"])
        .arg(secret)
        .args([
            "--token-audience",
            "bounded-test",
            "--token-revocation-file",
        ])
        .arg(revocations);
    cmd.assert()
        .failure()
        .stderr(predicates::str::contains("8 MiB size limit"));
    Ok(())
}

#[rstest]
fn upload_and_render_require_active_content_opt_in(
    tmpdir: TempDir,
    port: u16,
) -> Result<(), Error> {
    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE, "--allow-upload", "--render-index"]);
    cmd.assert()
        .failure()
        .stderr(predicates::str::contains("--allow-active-content-risk"));
    Ok(())
}

#[rstest]
#[case(
    "--max-webdav-properties",
    "65",
    "max-webdav-properties must be between 1 and 64"
)]
#[case(
    "--max-webdav-rendered-properties",
    "65537",
    "max-webdav-rendered-properties must be between"
)]
#[case(
    "--max-webdav-response-size",
    "8388609",
    "max-webdav-response-size must be between 1024 and 8388608 bytes"
)]
fn webdav_config_cannot_exceed_hard_safety_ceiling(
    tmpdir: TempDir,
    port: u16,
    #[case] option: &str,
    #[case] value: &str,
    #[case] message: &str,
) -> Result<(), Error> {
    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE, option, value]);
    cmd.assert()
        .failure()
        .stderr(predicates::str::contains(message));
    Ok(())
}

#[rstest]
fn webdav_render_budget_must_fit_one_allowed_depth_zero_request(
    tmpdir: TempDir,
    port: u16,
) -> Result<(), Error> {
    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args([
        "--auth",
        TEST_AUTH_RULE,
        "--max-webdav-properties",
        "8",
        "--max-webdav-rendered-properties",
        "7",
    ]);
    cmd.assert().failure().stderr(predicates::str::contains(
        "max-webdav-rendered-properties must be between 8 and 65536",
    ));
    Ok(())
}

#[rstest]
#[case("--cors-origins", "https://example.test/path", "Invalid CORS origin")]
#[case(
    "--cors-origins",
    "*,https://example.test",
    "wildcard `*` must be the only"
)]
#[case("--cors-methods", "POST", "Unsupported CORS resource method")]
#[case("--cors-headers", "*", "does not accept wildcard `*`")]
fn cors_allowlists_fail_closed_at_startup(
    tmpdir: TempDir,
    port: u16,
    #[case] option: &str,
    #[case] value: &str,
    #[case] message: &str,
) -> Result<(), Error> {
    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE, "--enable-cors", option, value]);
    cmd.assert()
        .failure()
        .stderr(predicates::str::contains(message));
    Ok(())
}

#[rstest]
fn explicit_config_and_boolean_source_matrix(tmpdir: TempDir, port: u16) -> Result<(), Error> {
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
        let state = TempDir::new()?;
        let config = state.path().join("config.yaml");
        fs::write(
            &config,
            format!(
                "serve-path: {}\nauth:\n  - user:password@/:rw\nrender-index: true\n{}\n",
                tmpdir.path().display(),
                case.yaml
            ),
        )?;

        let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("ram"));
        cmd.env("RAM_NO_CONFIG", "1")
            .arg("--config")
            .arg(&config)
            .args(case.cli)
            .args(["--max-webdav-properties", "65"])
            .arg("-p")
            .arg((port + index as u16).to_string());
        if let Some((name, value)) = case.env {
            cmd.env(name, value);
        }
        let expected_error = if case.allow_upload {
            "Refusing to combine uploads with same-origin render modes"
        } else {
            "max-webdav-properties must be between 1 and 64"
        };
        cmd.assert()
            .failure()
            .stderr(predicates::str::contains(expected_error));
    }
    Ok(())
}

#[rstest]
#[case(false)]
#[case(true)]
fn explicit_config_uses_cwd_and_is_not_disabled_by_ram_no_config(
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
        .env("RAM_NO_CONFIG", "1")
        .args(["--max-webdav-properties", "65", "-p"])
        .arg(port.to_string());
    if use_environment {
        cmd.env("RAM_CONFIG", "config.yaml");
    } else {
        cmd.args(["--config", "config.yaml"]);
    }
    cmd.assert().failure().stderr(predicates::str::contains(
        "max-webdav-properties must be between 1 and 64",
    ));

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
        .arg("--auth-file")
        .arg(&auth_file)
        .args(["--max-webdav-properties", "65"]);
    valid.assert().failure().stderr(predicates::str::contains(
        "max-webdav-properties must be between 1 and 64",
    ));

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
        .env("RAM_NO_CONFIG", "1")
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
        "--max-webdav-properties",
        "65",
    ]);
    cmd.assert().failure().stderr(predicates::str::contains(
        "max-webdav-properties must be between 1 and 64",
    ));
    Ok(())
}

#[rstest]
fn relative_sensitive_outputs_use_yaml_directory_and_cli_cwd(port: u16) -> Result<(), Error> {
    let yaml_state = TempDir::new()?;
    fs::create_dir(yaml_state.path().join("share"))?;
    let config = yaml_state.path().join("config.yaml");
    fs::write(
        &config,
        "serve-path: share\nlog-file: share/access.log\nauth:\n  - user:password@/:rw\n",
    )?;
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600))?;
    let mut yaml = Command::new(assert_cmd::cargo::cargo_bin!("ram"));
    yaml.env("RAM_NO_CONFIG", "1")
        .arg("--config")
        .arg(&config)
        .arg("-p")
        .arg(port.to_string());
    yaml.assert()
        .failure()
        .stderr(predicates::str::contains("access log"))
        .stderr(predicates::str::contains("served path"));

    let cli_state = TempDir::new()?;
    fs::create_dir(cli_state.path().join("share"))?;
    let mut cli = ram_command(std::path::Path::new("share"), port);
    cli.current_dir(cli_state.path()).args([
        "--auth",
        TEST_AUTH_RULE,
        "--log-file",
        "share/access.log",
    ]);
    cli.assert()
        .failure()
        .stderr(predicates::str::contains("access log"))
        .stderr(predicates::str::contains("served path"));
    Ok(())
}

#[rstest]
fn relative_yaml_socket_uses_config_directory_in_a_mixed_bind_set(port: u16) -> Result<(), Error> {
    let yaml_state = TempDir::new()?;
    fs::create_dir(yaml_state.path().join("share"))?;
    let config = yaml_state.path().join("config.yaml");
    fs::write(
        &config,
        "serve-path: share\nbind:\n  - 127.0.0.1\n  - yaml.sock\nauth:\n  - admin:admin@/:rw\n",
    )?;
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600))?;
    let process_cwd = TempDir::new()?;
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("ram"));
    command
        .env("RAM_NO_CONFIG", "1")
        .current_dir(process_cwd.path())
        .arg("--config")
        .arg(&config)
        .arg("--port")
        .arg(port.to_string());
    let mut server = ServerProc::spawn(command);

    assert!(yaml_state.path().join("yaml.sock").exists());
    assert!(!process_cwd.path().join("yaml.sock").exists());
    reqwest::blocking::Client::new()
        .get(format!("http://127.0.0.1:{port}/"))
        .basic_auth("admin", Some("admin"))
        .send()?
        .error_for_status()?;
    server.sigterm();
    assert!(
        server
            .wait_exit(std::time::Duration::from_secs(3))
            .is_some()
    );
    Ok(())
}

#[rstest]
fn cli_mixed_bind_overrides_yaml_and_uses_process_cwd(port: u16) -> Result<(), Error> {
    let yaml_state = TempDir::new()?;
    fs::create_dir(yaml_state.path().join("share"))?;
    let config = yaml_state.path().join("config.yaml");
    fs::write(
        &config,
        "serve-path: share\nbind: ignored-yaml.sock\nauth:\n  - admin:admin@/:rw\n",
    )?;
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600))?;
    let process_cwd = TempDir::new()?;
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("ram"));
    command
        .env("RAM_NO_CONFIG", "1")
        .current_dir(process_cwd.path())
        .arg("--config")
        .arg(&config)
        .args(["--bind", "127.0.0.1", "--bind", "cli.sock", "--port"])
        .arg(port.to_string());
    let mut server = ServerProc::spawn(command);

    assert!(process_cwd.path().join("cli.sock").exists());
    assert!(!yaml_state.path().join("ignored-yaml.sock").exists());
    assert!(!yaml_state.path().join("cli.sock").exists());
    reqwest::blocking::Client::new()
        .get(format!("http://127.0.0.1:{port}/"))
        .basic_auth("admin", Some("admin"))
        .send()?
        .error_for_status()?;
    server.sigterm();
    assert!(
        server
            .wait_exit(std::time::Duration::from_secs(3))
            .is_some()
    );
    Ok(())
}

#[rstest]
fn symlinked_output_parent_into_served_tree_is_rejected(
    tmpdir: TempDir,
    port: u16,
) -> Result<(), Error> {
    let control = TempDir::new()?;
    symlink(tmpdir.path(), control.path().join("served-alias"))?;
    let log = control.path().join("served-alias/access.log");
    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE, "--log-file"]).arg(log);
    cmd.assert()
        .failure()
        .stderr(predicates::str::contains("access log"))
        .stderr(predicates::str::contains("served path"));
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
fn check_config_is_successful_and_has_no_runtime_side_effects() -> Result<(), Error> {
    let state = TempDir::new()?;
    let served = state.path().join("served");
    let assets = state.path().join("assets");
    fs::create_dir(&served)?;
    fs::create_dir(&assets)?;
    fs::write(assets.join("index.html"), "<main>safe</main>")?;

    let stale = served.join(".ram-upload-00000000-0000-4000-8000-000000000001.tmp");
    fs::write(&stale, b"candidate")?;
    fs::set_permissions(&stale, fs::Permissions::from_mode(0o600))?;
    thread::sleep(Duration::from_millis(1_100));

    let auth_file = state.path().join("auth.rules");
    fs::write(&auth_file, "admin:correct-password@/:rw\n")?;
    fs::set_permissions(&auth_file, fs::Permissions::from_mode(0o600))?;
    let token_secret = state.path().join("token.secret");
    write_test_secret(&token_secret)?;
    let revocations = state.path().join("revocations.json");
    let revocation_lock = state.path().join("revocations.json.lock");
    let log_file = state.path().join("access.log");
    let socket = state.path().join("ram.sock");
    let hook_marker = state.path().join("hook-ran");
    let hook = state.path().join("quota-hook");
    fs::write(
        &hook,
        format!("#!/bin/sh\n: > '{}'\n", hook_marker.display()),
    )?;
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o700))?;

    // 保持配置端口被占用，可证明 check 模式从不绑定它。
    // Keeping the configured port occupied proves check mode never binds it.
    let occupied = TcpListener::bind(("127.0.0.1", 0))?;
    let occupied_port = occupied.local_addr()?.port();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("ram"))
        .env("RAM_NO_CONFIG", "0")
        .arg("--check-config")
        .arg(&served)
        .arg("--bind")
        .arg(format!("127.0.0.1,{}", socket.display()))
        .args(["--port", &occupied_port.to_string()])
        .arg("--auth-file")
        .arg(&auth_file)
        .arg("--token-secret-file")
        .arg(&token_secret)
        .arg("--token-revocation-file")
        .arg(&revocations)
        .arg("--log-file")
        .arg(&log_file)
        .arg("--storage-quota-hook")
        .arg(&hook)
        .arg("--assets")
        .arg(&assets)
        .args(["--stale-upload-cleanup-age", "1s", "--allow-upload"])
        .output()?;

    assert!(
        output.status.success(),
        "check-config failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"Configuration OK\n");
    assert!(
        stale.exists(),
        "check-config removed a stale upload candidate"
    );
    for path in [
        &socket,
        &log_file,
        &revocations,
        &revocation_lock,
        &hook_marker,
    ] {
        assert!(!path.exists(), "check-config created {}", path.display());
    }
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!combined.contains("correct-password"));
    assert!(!combined.contains("0123456789abcdef0123456789abcdef"));
    drop(occupied);
    Ok(())
}

#[test]
fn check_config_counts_the_automatically_derived_persistent_revocation_backend() -> Result<(), Error>
{
    let state = TempDir::new()?;
    let served = state.path().join("served");
    fs::create_dir(&served)?;
    let config = state.path().join("config.yaml");
    let revocations = state.path().join(".ram-token-revocations.json");
    let revocation_lock = state.path().join(".ram-token-revocations.json.lock");
    let write_config = |max_blocking_threads: u64| -> Result<(), Error> {
        fs::write(
            &config,
            format!(
                "serve-path: '{}'\nbind: 127.0.0.1\nauth:\n  - admin:correct-password@/:rw\ntoken-secret: 0123456789abcdef0123456789abcdef\ntoken-audience: config-order-test\nmax-blocking-threads: {max_blocking_threads}\n",
                served.display()
            ),
        )?;
        Ok(())
    };

    // 中文：未显式配置 token-revocation-file；持久 secret 必须先派生默认后端，再计算
    // blocking pool 下限。旧顺序在后端不可见时错误接受 1。
    // English: No token-revocation-file is explicit. The persistent secret must derive its default
    // backend before the blocking-pool minimum is computed; the former ordering incorrectly accepted 1.
    write_config(1)?;
    Command::new(assert_cmd::cargo::cargo_bin!("ram"))
        .env("RAM_NO_CONFIG", "1")
        .args(["--check-config", "--config"])
        .arg(&config)
        .assert()
        .failure()
        .stdout(predicates::str::is_empty())
        .stderr(predicates::str::contains(
            "max-blocking-threads must be at least 5",
        ));
    assert!(!revocations.exists());
    assert!(!revocation_lock.exists());

    // 中文：把池提高到实际下限后同一真实 YAML 解析成功，且 CheckConfig 仍完全只读。
    // English: Raising the pool to the effective minimum makes the same real YAML parse succeed,
    // while CheckConfig remains side-effect free.
    write_config(5)?;
    Command::new(assert_cmd::cargo::cargo_bin!("ram"))
        .env("RAM_NO_CONFIG", "1")
        .args(["--check-config", "--config"])
        .arg(&config)
        .assert()
        .success()
        .stdout("Configuration OK\n");
    assert!(!revocations.exists());
    assert!(!revocation_lock.exists());
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
        .env("RAM_NO_CONFIG", "1")
        .env("RAM_ALLOW_INSECURE_HTTP", "true")
        .args(["--check-config", "--config"])
        .arg(&config)
        .output()?;
    assert!(accepted.status.success());
    assert_eq!(accepted.stdout, b"Configuration OK\n");

    Command::new(assert_cmd::cargo::cargo_bin!("ram"))
        .env("RAM_NO_CONFIG", "1")
        .env("RAM_ALLOW_INSECURE_HTTP", "true")
        .args(["--check-config", "--config"])
        .arg(&config)
        .arg("--allow-insecure-http=false")
        .assert()
        .failure()
        .stderr(predicates::str::contains("authenticated cleartext HTTP"));

    fs::write(&config, "definitely-not-a-setting: true\n")?;
    Command::new(assert_cmd::cargo::cargo_bin!("ram"))
        .env("RAM_NO_CONFIG", "1")
        .args(["--check-config", "--config"])
        .arg(&config)
        .assert()
        .failure()
        .stdout(predicates::str::is_empty())
        .stderr(predicates::str::contains("unknown field"));
    Ok(())
}

#[test]
fn legacy_auto_config_warning_is_exactly_scoped_to_actual_discovery() -> Result<(), Error> {
    const WARNING: &str = "automatic executable-adjacent config.yaml discovery is deprecated";
    let bindir = TempDir::new()?;
    let bin_path = bindir.path().join("ram");
    fs::copy(assert_cmd::cargo::cargo_bin!("ram"), &bin_path)?;
    fs::set_permissions(&bin_path, fs::Permissions::from_mode(0o755))?;
    let served = bindir.path().join("served");
    fs::create_dir(&served)?;
    let adjacent = bindir.path().join("config.yaml");
    fs::write(
        &adjacent,
        format!(
            "serve-path: '{}'\nauth:\n  - admin:password@/:rw\n",
            served.display()
        ),
    )?;

    let mut command = Command::new(&bin_path);
    command
        .env_remove("RAM_CONFIG")
        .env_remove("RAM_NO_CONFIG")
        .arg("--check-config");
    let automatic = command_output_with_exec_retry(&mut command)?;
    assert!(automatic.status.success());
    assert_eq!(automatic.stdout, b"Configuration OK\n");
    let stderr = String::from_utf8(automatic.stderr)?;
    assert_eq!(stderr.matches(WARNING).count(), 1);

    let explicit = bindir.path().join("explicit.yaml");
    fs::write(
        &explicit,
        format!(
            "serve-path: '{}'\nauth:\n  - explicit:password@/:rw\n",
            served.display()
        ),
    )?;
    fs::write(&adjacent, "unknown-adjacent-setting: true\n")?;
    for use_environment in [false, true] {
        let mut command = Command::new(&bin_path);
        command
            .env_remove("RAM_CONFIG")
            .env_remove("RAM_NO_CONFIG")
            .arg("--check-config");
        if use_environment {
            command.env("RAM_CONFIG", &explicit);
        } else {
            command.arg("--config").arg(&explicit);
        }
        let output = command_output_with_exec_retry(&mut command)?;
        assert!(output.status.success());
        assert!(!String::from_utf8_lossy(&output.stderr).contains(WARNING));
    }

    for value in ["", "0", "false"] {
        let mut command = Command::new(&bin_path);
        command
            .env_remove("RAM_CONFIG")
            .env("RAM_NO_CONFIG", value)
            .arg("--check-config")
            .arg(&served)
            .args(["--auth", "disabled:password@/:rw"]);
        let disabled = command_output_with_exec_retry(&mut command)?;
        assert!(disabled.status.success(), "RAM_NO_CONFIG={value:?}");
        assert!(!String::from_utf8_lossy(&disabled.stderr).contains(WARNING));
    }
    Ok(())
}

#[test]
fn check_config_reads_existing_revocation_state_without_creating_lock() -> Result<(), Error> {
    let state = TempDir::new()?;
    let served = state.path().join("served");
    fs::create_dir(&served)?;
    let secret = state.path().join("token.secret");
    write_test_secret(&secret)?;
    let revocations = state.path().join("revocations.json");
    fs::write(&revocations, b"not valid JSON")?;
    fs::set_permissions(&revocations, fs::Permissions::from_mode(0o600))?;
    let lock = state.path().join("revocations.json.lock");

    Command::new(assert_cmd::cargo::cargo_bin!("ram"))
        .env("RAM_NO_CONFIG", "1")
        .arg("--check-config")
        .arg(&served)
        .args(["--auth", TEST_AUTH_RULE])
        .arg("--token-secret-file")
        .arg(&secret)
        .arg("--token-revocation-file")
        .arg(&revocations)
        .assert()
        .failure()
        .stdout(predicates::str::is_empty())
        .stderr(predicates::str::contains(
            "failed to validate existing token revocation state",
        ));
    assert!(!lock.exists());
    assert_eq!(fs::read(&revocations)?, b"not valid JSON");
    Ok(())
}

#[test]
fn check_config_requires_existing_revocation_lock_to_be_read_write_capable() -> Result<(), Error> {
    let state = TempDir::new()?;
    let served = state.path().join("served");
    fs::create_dir(&served)?;
    let secret = state.path().join("token.secret");
    write_test_secret(&secret)?;
    let revocations = state.path().join("revocations.json");
    fs::write(
        &revocations,
        br#"{"version":2,"generation":1,"revoked":{}}"#,
    )?;
    fs::set_permissions(&revocations, fs::Permissions::from_mode(0o600))?;
    let lock = state.path().join("revocations.json.lock");
    fs::write(&lock, b"")?;
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o400))?;

    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("ram"));
    if rustix::process::geteuid().is_root() {
        const UNPRIVILEGED_UID: u32 = 65_534;
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o755))?;
        fs::set_permissions(&served, fs::Permissions::from_mode(0o755))?;
        chown(&secret, Some(UNPRIVILEGED_UID), Some(UNPRIVILEGED_UID))?;
        chown(&revocations, Some(UNPRIVILEGED_UID), Some(UNPRIVILEGED_UID))?;
        chown(&lock, Some(UNPRIVILEGED_UID), Some(UNPRIVILEGED_UID))?;
        command.uid(UNPRIVILEGED_UID).gid(UNPRIVILEGED_UID);
    }
    command
        .env("RAM_NO_CONFIG", "1")
        .arg("--check-config")
        .arg(&served)
        .args(["--auth", TEST_AUTH_RULE])
        .arg("--token-secret-file")
        .arg(&secret)
        .arg("--token-revocation-file")
        .arg(&revocations);
    command
        .assert()
        .failure()
        .stdout(predicates::str::is_empty());
    assert_eq!(fs::metadata(&lock)?.permissions().mode() & 0o7777, 0o400);
    Ok(())
}

#[test]
fn check_config_validates_custom_asset_metadata_and_contents() -> Result<(), Error> {
    let state = TempDir::new()?;
    let served = state.path().join("served");
    let assets = state.path().join("assets");
    fs::create_dir(&served)?;
    fs::create_dir(&assets)?;
    let index = assets.join("index.html");
    fs::write(&index, "safe")?;
    fs::set_permissions(&index, fs::Permissions::from_mode(0o666))?;

    let command = || {
        let mut command = Command::new(assert_cmd::cargo::cargo_bin!("ram"));
        command
            .env("RAM_NO_CONFIG", "1")
            .arg("--check-config")
            .arg(&served)
            .args(["--auth", TEST_AUTH_RULE])
            .arg("--assets")
            .arg(&assets);
        command
    };
    command()
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "Custom assets contain an untrusted",
        ));

    fs::set_permissions(&index, fs::Permissions::from_mode(0o644))?;
    fs::write(&index, b"invalid UTF-8: \xff")?;
    command()
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "Custom asset index escapes the assets root or cannot be read securely",
        ));
    Ok(())
}

#[test]
fn check_config_validates_existing_log_without_creating_or_chmodding() -> Result<(), Error> {
    let state = TempDir::new()?;
    let served = state.path().join("served");
    fs::create_dir(&served)?;
    let command = |log: &std::path::Path| {
        let mut command = Command::new(assert_cmd::cargo::cargo_bin!("ram"));
        command
            .env("RAM_NO_CONFIG", "1")
            .arg("--check-config")
            .arg(&served)
            .args(["--auth", TEST_AUTH_RULE])
            .arg("--log-file")
            .arg(log);
        command
    };

    let missing = state.path().join("missing.log");
    command(&missing).assert().success();
    assert!(!missing.exists());

    let existing = state.path().join("existing.log");
    fs::write(&existing, b"existing")?;
    fs::set_permissions(&existing, fs::Permissions::from_mode(0o644))?;
    command(&existing).assert().success();
    assert_eq!(
        fs::metadata(&existing)?.permissions().mode() & 0o7777,
        0o644
    );

    let read_only = state.path().join("read-only.log");
    fs::write(&read_only, b"must remain unchanged")?;
    fs::set_permissions(&read_only, fs::Permissions::from_mode(0o400))?;
    let mut read_only_command = command(&read_only);
    if rustix::process::geteuid().is_root() {
        const UNPRIVILEGED_UID: u32 = 65_534;
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o755))?;
        fs::set_permissions(&served, fs::Permissions::from_mode(0o755))?;
        chown(&read_only, Some(UNPRIVILEGED_UID), Some(UNPRIVILEGED_UID))?;
        read_only_command
            .uid(UNPRIVILEGED_UID)
            .gid(UNPRIVILEGED_UID);
    }
    read_only_command
        .assert()
        .failure()
        .stdout(predicates::str::is_empty());
    assert_eq!(fs::read(&read_only)?, b"must remain unchanged");
    assert_eq!(
        fs::metadata(&read_only)?.permissions().mode() & 0o7777,
        0o400
    );

    let directory = state.path().join("log-directory");
    fs::create_dir(&directory)?;
    command(&directory)
        .assert()
        .failure()
        .stderr(predicates::str::contains("Log path must be a regular file"));

    let linked = state.path().join("linked.log");
    let alias = state.path().join("linked-alias.log");
    fs::write(&linked, b"linked")?;
    fs::hard_link(&linked, &alias)?;
    command(&linked)
        .assert()
        .failure()
        .stderr(predicates::str::contains("must not have hard-link aliases"));
    Ok(())
}

#[test]
fn check_config_validates_unix_socket_paths_without_touching_them() -> Result<(), Error> {
    let state = TempDir::new()?;
    let served = state.path().join("served");
    fs::create_dir(&served)?;
    let command = |socket: &std::path::Path| {
        let mut command = Command::new(assert_cmd::cargo::cargo_bin!("ram"));
        command
            .env("RAM_NO_CONFIG", "1")
            .arg("--check-config")
            .arg(&served)
            .args(["--auth", TEST_AUTH_RULE, "--bind"])
            .arg(socket);
        command
    };

    let missing = state.path().join("missing.sock");
    command(&missing).assert().success();
    assert!(!missing.exists());

    Command::new(assert_cmd::cargo::cargo_bin!("ram"))
        .env("RAM_NO_CONFIG", "1")
        .arg("--check-config")
        .arg(&served)
        .args([
            "--auth",
            TEST_AUTH_RULE,
            "--bind",
            "@ram-check-config-abstract",
            "--allow-abstract-unix-socket",
        ])
        .assert()
        .success()
        .stdout("Configuration OK\n");

    let conflict = state.path().join("conflict.sock");
    fs::write(&conflict, b"not a socket")?;
    command(&conflict)
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "already exists and is not a socket",
        ));

    let unsafe_parent = state.path().join("unsafe-parent");
    fs::create_dir(&unsafe_parent)?;
    fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777))?;
    command(&unsafe_parent.join("ram.sock"))
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "group/world writable without the sticky bit",
        ));

    let long_name = "s".repeat(160);
    command(&state.path().join(long_name))
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "cannot be represented by clients",
        ));
    Ok(())
}

#[cfg(feature = "tls")]
#[test]
fn check_config_validates_tls_certificate_key_and_pairing() -> Result<(), Error> {
    let state = TempDir::new()?;
    let served = state.path().join("served");
    fs::create_dir(&served)?;
    let cert = state.path().join("cert.pem");
    let key = state.path().join("key.pem");
    fs::copy("tests/data/cert.pem", &cert)?;
    fs::copy("tests/data/key_pkcs8.pem", &key)?;
    fs::set_permissions(&cert, fs::Permissions::from_mode(0o600))?;
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600))?;

    let command = |cert: &std::path::Path, key: &std::path::Path| {
        let mut command = Command::new(assert_cmd::cargo::cargo_bin!("ram"));
        command
            .env("RAM_NO_CONFIG", "1")
            .arg("--check-config")
            .arg(&served)
            .args(["--auth", TEST_AUTH_RULE])
            .arg("--tls-cert")
            .arg(cert)
            .arg("--tls-key")
            .arg(key);
        command
    };
    command(&cert, &key)
        .assert()
        .success()
        .stdout("Configuration OK\n");

    let invalid_cert = state.path().join("invalid-cert.pem");
    fs::write(&invalid_cert, b"not a certificate\n")?;
    fs::set_permissions(&invalid_cert, fs::Permissions::from_mode(0o600))?;
    command(&invalid_cert, &key).assert().failure();

    let invalid_key = state.path().join("invalid-key.pem");
    fs::write(&invalid_key, b"not a private key\n")?;
    fs::set_permissions(&invalid_key, fs::Permissions::from_mode(0o600))?;
    command(&cert, &invalid_key).assert().failure();

    let mismatched_key = state.path().join("mismatched-key.pem");
    fs::copy("tests/data/key_ecdsa.pem", &mismatched_key)?;
    fs::set_permissions(&mismatched_key, fs::Permissions::from_mode(0o600))?;
    command(&cert, &mismatched_key).assert().failure();
    Ok(())
}

fn get_config_path() -> PathBuf {
    let mut path = std::env::current_dir().expect("Failed to get current directory");
    path.push("tests");
    path.push("data");
    path.push("config.yaml");
    path
}

fn write_test_secret(path: &std::path::Path) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;

    fs::write(path, b"0123456789abcdef0123456789abcdef")?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}
