//! 启动配置：命令行参数（clap）与显式选择的 YAML（serde_yaml）
//! 合并成一份 [`Args`]。YAML 只会通过 `--config` 或 `RAM_CONFIG` 加载；
//! 不会扫描进程工作目录或可执行文件所在目录。
//!
//! 合并规则：若显式选择 YAML，先把它作为基底加载，再由命令行参数逐项覆盖。
//! 环境变量（`RAM_*`）由 clap 的 `.env(...)` 声明自动接入，
//! 优先级介于两者之间（命令行 > 环境变量 > 显式 YAML > 默认值）。
//!
//! ## 本模块的 Rust 知识点
//! - **clap builder 风格**：`build_cli()` 手工声明每个参数的名称、
//!   短/长选项、取值解析器；对比 derive 风格更啰嗦但更灵活。
//! - **serde 自定义反序列化**：`#[serde(deserialize_with = "...")]`
//!   搭配手写 Visitor，让 YAML 里同一字段既可写字符串也可写数组
//!   （如 `hidden: a,b` 或 `hidden: [a, b]`）。
//! - **`SmartDefault`**：给结构体字段声明非零默认值的派生宏，
//!   与 serde 的 `#[serde(default)]` 配合使用。
//!
//! ## 本 fork 的安全强化（相对上游 dufs）
//! - 必须配置至少一个认证用户，匿名访问被禁用；
//! - 检出示例密码 `change-me` 时拒绝启动；
//! - 配置文件里的相对路径按配置文件所在目录解析（而非进程 cwd）；
//! - serve 根目录是 `/` 时打印醒目警告。
//!
//! ## English overview
//! Startup configuration merges command-line arguments (clap) and explicitly selected YAML
//! (serde_yaml) into one [`Args`] value. YAML is loaded only through `--config` or `RAM_CONFIG`;
//! neither the process working directory nor the executable directory is scanned.
//!
//! When selected, YAML is loaded as the base and command-line arguments override individual fields.
//! `RAM_*` environment variables enter through clap `.env(...)` declarations, giving the
//! precedence command line > environment > explicitly selected YAML > defaults.
//!
//! ## Rust concepts in this module
//! - **clap builder style**: `build_cli()` declares each argument name, short/long option, and value
//!   parser manually. It is more verbose than derive style but more flexible.
//! - **Custom serde deserialization**: `#[serde(deserialize_with = "...")]` plus a handwritten
//!   Visitor lets one YAML field accept either a string or an array, such as `hidden: a,b` or
//!   `hidden: [a, b]`.
//! - **`SmartDefault`**: a derive macro declares nonzero structure-field defaults and works together
//!   with serde `#[serde(default)]`.
//!
//! ## Security hardening in this fork relative to upstream dufs
//! - at least one authenticated named user is required; anonymous access is disabled;
//! - startup rejects the example password `change-me`;
//! - relative paths from the configuration file resolve against that file's directory, not the
//!   process current working directory;
//! - serving `/` as the root emits a prominent warning.

use anyhow::{Context, Result, bail};
use clap::builder::PossibleValue;
use clap::parser::ValueSource;
use clap::{Arg, ArgAction, ArgMatches, Command, ValueEnum, value_parser};
use clap_complete::{Generator, Shell, generate};
use serde::{Deserialize, Deserializer};
use smart_default::SmartDefault;
use std::collections::HashSet;
use std::env;
#[cfg(test)]
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::auth::{AccessControl, TokenRevocationCapabilities};
use crate::identity::{
    ForwardedHeader, IpCidr, OutputPathIdentity, PathIdentity, ServedPathIdentity,
    TrustedProxyPolicy,
};
use crate::logging::HttpLogger;
use crate::utils::{encode_uri, is_ipv6_available, is_trusted_file_owner};

const PRIVATE_CONFIG_MAX_BYTES: u64 = 4 * 1024 * 1024;
const AUTH_FILE_MAX_BYTES: u64 = 1024 * 1024;
const AUTH_FILE_MAX_LINES: usize = 4096;
const AUTH_FILE_MAX_LINE_BYTES: usize = 16 * 1024;
const TOKEN_SECRET_FILE_MAX_BYTES: u64 = 64 * 1024;
const PATH_PREFIX_MAX_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ParsePurpose {
    Run,
    Check,
}

// 中文：小型部署可以降低 WebDAV 预算，但远程输入绝不能把它提高到进程安全包络之外；
// 硬上限放在配置层，使 CLI、环境变量和 YAML 的越界值在启动时被拒绝而非静默截断。
// English: Operators may lower WebDAV budgets, but remote input must never
// raise them beyond the process safety envelope. Reject excessive CLI, env,
// and YAML values at startup instead of silently clamping them.
pub(crate) const WEBDAV_HARD_MAX_PROPERTIES: u64 = 64;
pub(crate) const WEBDAV_HARD_MAX_RENDERED_PROPERTIES: u64 = 64 * 1024;
pub(crate) const WEBDAV_HARD_MAX_RESPONSE_SIZE: u64 = 8 * 1024 * 1024;
const WEBDAV_MIN_RESPONSE_SIZE: u64 = 1024;
pub(crate) const KEYED_UPLOAD_LIMIT_HARD_MAX: u64 = 1024;
pub(crate) const KEYED_REQUEST_LIMIT_HARD_MAX: u64 = 4096;
const TRUSTED_PROXY_MAX_ENTRIES: usize = 256;
pub(crate) const STALE_UPLOAD_CLEANUP_MAX_ENTRIES_HARD_MAX: u64 = 1_000_000;
pub(crate) const STALE_UPLOAD_CLEANUP_MAX_DEPTH_HARD_MAX: u64 = 256;
pub(crate) const STALE_UPLOAD_CLEANUP_MAX_DELETIONS_HARD_MAX: u64 = 100_000;
pub(crate) const STALE_UPLOAD_CLEANUP_TIMEOUT_HARD_MAX_SECS: u64 = 60;
/// 两年是刻意设置的上限而非默认值；只有运维者为 Ram 自身 TLS 监听显式启用时才发送 HSTS。
/// Two years is a ceiling, not a default; HSTS stays disabled unless explicitly enabled for Ram's TLS listener.
pub(crate) const HSTS_MAX_AGE_HARD_MAX_SECS: u64 = 2 * 365 * 24 * 60 * 60;

mod cli;
mod path_resolution;
mod schema;
mod sources;
mod validation;

pub use cli::{build_cli, print_completions};
#[allow(unused_imports)]
pub(crate) use path_resolution::{StartupInputKind, StartupOutputKind, StartupPathIdentities};
pub use schema::{Args, BindAddr, Compress, SecretValue};
#[cfg(feature = "fuzzing")]
pub(crate) use validation::fuzz_path_prefix;
pub(crate) use validation::normalize_path_prefix;

// 中文：同级实现模块只共享配置内部帮助函数；公开调用方继续使用上面的稳定 facade。
// English: Sibling modules share only configuration-internal helpers; public
// callers continue to use the stable `crate::config` facade above.
use path_resolution::*;
use schema::*;
#[cfg(test)]
use sources::*;
use validation::*;

#[cfg(test)]
mod tests;
