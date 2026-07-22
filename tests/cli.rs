//! 使用不同参数运行 CLI，但不启动服务器。
//! Run the CLI with different arguments without starting a server.

#[path = "common/fixtures.rs"]
mod fixtures;

use assert_cmd::prelude::*;
use clap::ValueEnum;
use clap_complete::Shell;
use fixtures::Error;
use std::process::Command;

#[test]
/// 显示帮助并退出。 / Show help and exit.
fn help_shows() -> Result<(), Error> {
    Command::new(assert_cmd::cargo::cargo_bin!("ram"))
        .env("RAM_NO_CONFIG", "1")
        .arg("-h")
        .assert()
        .success()
        .stdout(predicates::str::contains("--check-config"));

    Ok(())
}

#[test]
/// 报告已安装命令名，而非库 crate 名。 / Report the installed command name rather than the library crate name.
fn version_uses_public_command_name() -> Result<(), Error> {
    Command::new(assert_cmd::cargo::cargo_bin!("ram"))
        .env("RAM_NO_CONFIG", "1")
        .arg("--version")
        .assert()
        .success()
        .stdout(format!("ram {}\n", env!("CARGO_PKG_VERSION")));

    Ok(())
}

#[test]
/// 输出补全脚本并退出。 / Print completions and exit.
fn print_completions() -> Result<(), Error> {
    // 示例 / Example: let shell_enums = EnumValueParser::<Shell>::new();
    for shell in Shell::value_variants() {
        Command::new(assert_cmd::cargo::cargo_bin!("ram"))
            .env("RAM_NO_CONFIG", "1")
            .arg("--completions")
            .arg(shell.to_string())
            .assert()
            .success();
    }

    Ok(())
}

#[test]
fn check_config_conflicts_with_completion_generation() -> Result<(), Error> {
    Command::new(assert_cmd::cargo::cargo_bin!("ram"))
        .env("RAM_NO_CONFIG", "1")
        .args(["--check-config", "--completions", "bash"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("cannot be used with"));
    Ok(())
}

#[cfg(not(feature = "tls"))]
#[test]
fn tls_environment_is_rejected_without_tls_feature() -> Result<(), Error> {
    Command::new(assert_cmd::cargo::cargo_bin!("ram"))
        .env("RAM_NO_CONFIG", "1")
        .env("RAM_TLS_CERT", "cert.pem")
        .env("RAM_TLS_KEY", "key.pem")
        .args(["--check-config", "--auth", "user:pass@/:rw"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("built without the `tls` feature"));

    Ok(())
}
