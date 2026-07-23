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
        .env_remove("RAM_CONFIG")
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
        .env_remove("RAM_CONFIG")
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
            .env_remove("RAM_CONFIG")
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
        .env_remove("RAM_CONFIG")
        .args(["--check-config", "--completions", "bash"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("cannot be used with"));
    Ok(())
}
