#![forbid(unsafe_code)]

//! Ram 文件服务的库入口。
//!
//! 具体实现按职责拆分到认证、配置、HTTP、日志、运行时和服务器模块；
//! 对外只暴露启动入口 [`run`]。
//!
//! Library entry point for the Ram file server. Implementation details are
//! split by responsibility across authentication, configuration, HTTP,
//! logging, runtime, and server modules; only [`run`] is public.

#[macro_use]
extern crate log;

mod auth;
mod config;
mod http;
mod logging;
mod path_identity;
mod runtime;
mod server;
mod source_identity;
mod utils;

#[cfg(not(target_os = "linux"))]
compile_error!("ram supports only Linux targets");

pub use runtime::run;

/// 仅供仓库外 cargo-fuzz 包使用的解析器入口。 / Parser entry points used
/// only by the out-of-tree cargo-fuzz package.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing {
    /// 覆盖 Digest auth-param token/quoted-string 解析及其资源预算。
    /// Exercise Digest auth-param token/quoted-string parsing and its resource budgets.
    pub fn digest_auth_params(data: &[u8]) {
        crate::auth::fuzz_digest_auth_params(data);
    }

    /// 覆盖百分号解码、路径前缀规范化和相对能力路径规范化。
    /// Exercise percent decoding, path-prefix canonicalization, and relative capability-path normalization.
    pub fn uri_path(data: &[u8]) {
        crate::server::fuzz_uri_path(data);
        crate::config::fuzz_path_prefix(data);
    }

    /// 覆盖字节 Range 与 If-Range 的解析和求值。 / Exercise byte Range and If-Range parsing/evaluation.
    pub fn range_if_range(data: &[u8]) {
        crate::server::fuzz_range_if_range(data);
    }

    /// 用同一任意输入覆盖两种有界 DAV XML 请求语法及响应名称渲染。
    /// Exercise both bounded DAV XML request grammars and their response-name rendering using one arbitrary input.
    pub fn webdav_xml(data: &[u8]) {
        crate::server::fuzz_webdav_xml(data);
    }

    /// 把 Destination/Host 同源校验与 URI 前缀规范化作为一个路由边界覆盖。
    /// Exercise Destination/Host same-origin validation and URI-prefix normalization as one routing boundary.
    pub fn destination_host_prefix(data: &[u8]) {
        crate::server::fuzz_destination_host_prefix(data);
    }

    /// 覆盖有界访问日志格式解析器和渲染器。 / Exercise the bounded access-log format parser and renderer.
    pub fn log_format(data: &[u8]) {
        crate::logging::fuzz_log_format(data);
    }

    /// 覆盖 Linux 文件名无损编码和跨平台 ZIP 条目包含性校验。
    /// Exercise lossless Linux filename encoding and cross-platform ZIP-entry containment validation.
    pub fn zip_entry_name(data: &[u8]) {
        crate::server::fuzz_zip_entry_name(data);
    }
}
