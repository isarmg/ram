//! 构造 HTTP 响应的小工具：常用状态码的快捷函数、WebDAV `multistatus`
//! 信封、`Content-Disposition` 头的格式化。
//!
//! ## 本模块的 Rust 知识点
//! - **`&mut` 出参风格**：本项目的处理函数都接收 `res: &mut Response`
//!   并就地修改（设置状态码、头、响应体），而不是层层返回新 Response。
//! - **HTTP 头注入防御**：文件名要过滤控制字符、转义引号后才能放进
//!   `Content-Disposition`，否则携带 `\r\n` 的文件名可以伪造额外响应头。
//!
//! HTTP response helpers for common status codes, WebDAV `multistatus` envelopes, and
//! `Content-Disposition` header formatting.
//!
//! ## Rust concepts in this module
//! - **`&mut` output style**: project handlers receive `res: &mut Response` and modify its status,
//!   headers, and body in place instead of returning a new response through every layer.
//! - **HTTP-header injection defense**: a filename must have controls filtered and quotes escaped
//!   before entering `Content-Disposition`; otherwise a name containing `\r\n` could forge
//!   additional response headers.

use super::Response;
use super::error::{HttpError, PublicErrorBody, ResponseError};
use crate::http::body_full;
use crate::utils::encode_uri;

use anyhow::Result;
use hyper::StatusCode;
use hyper::header::{CONTENT_DISPOSITION, HeaderValue};

/// 用 207 Multi-Status 包裹 WebDAV XML。 / Wrap WebDAV XML in a 207 Multi-Status response.
pub(super) fn res_multistatus(res: &mut Response, content: &str) {
    *res.status_mut() = StatusCode::MULTI_STATUS;
    res.headers_mut().insert(
        "content-type",
        HeaderValue::from_static("application/xml; charset=utf-8"),
    );
    *res.body_mut() = body_full(format!(
        r#"<?xml version="1.0" encoding="utf-8" ?>
<D:multistatus xmlns:D="DAV:">
{content}
</D:multistatus>"#,
    ));
}

/// 403 Forbidden：请求合法但权限不允许。 / The request is valid but authorization forbids it.
pub(super) fn status_forbid(res: &mut Response) {
    ResponseError::http(HttpError::forbidden(anyhow::anyhow!(
        "authorization policy denied the request"
    )))
    .apply(res);
}

/// 404 Not Found：资源不存在，也用于向无权限者隐藏存在性。 / Missing, or existence hidden from an unauthorized caller.
pub(super) fn status_not_found(res: &mut Response) {
    ResponseError::http(HttpError::not_found(anyhow::anyhow!(
        "the requested resource is unavailable"
    )))
    .apply(res);
}

/// 204 No Content：操作成功且无正文。 / The operation succeeded without a response body.
pub(super) fn status_no_content(res: &mut Response) {
    *res.status_mut() = StatusCode::NO_CONTENT;
}

/// 400 Bad Request：请求格式错误，`body` 给出短原因。 / Malformed request with a short reason in `body`.
pub(super) fn status_bad_request(res: &mut Response, body: &'static str) {
    let error = ResponseError::bad_request(anyhow::anyhow!("request validation failed"));
    if body.is_empty() {
        error.apply(res);
    } else {
        error.apply_with_body(res, PublicErrorBody::plain(body));
    }
}

/// 设置 `Content-Disposition` 响应头，决定浏览器"内联打开"（inline）
/// 还是"下载保存"（attachment），并给出建议文件名。
///
/// 非 ASCII 文件名按 RFC 5987 用 `filename*=UTF-8''...` 编码，
/// 同时保留普通 `filename` 供老客户端回退。
/// Set inline/attachment disposition and a safe suggested filename. Non-ASCII
/// names use RFC 5987 while retaining a legacy `filename` fallback.
pub(super) fn set_content_disposition(
    res: &mut Response,
    inline: bool,
    filename: &str,
) -> Result<()> {
    let kind = if inline { "inline" } else { "attachment" };
    let filename = sanitize_header_filename(filename);
    let quoted_filename = quote_header_filename(&filename);
    let value = if filename.is_ascii() {
        HeaderValue::from_str(&format!("{kind}; filename=\"{quoted_filename}\"",))?
    } else {
        HeaderValue::from_str(&format!(
            "{kind}; filename=\"{}\"; filename*=UTF-8''{}",
            quoted_filename,
            encode_uri(&filename),
        ))?
    };
    res.headers_mut().insert(CONTENT_DISPOSITION, value);
    Ok(())
}

/// 把文件名中的 ASCII 控制字符（含 `\r\n`）替换为空格，避免响应拆分。
/// Replace ASCII controls (including CR/LF) with spaces to prevent HTTP response splitting.
fn sanitize_header_filename(filename: &str) -> String {
    filename
        .chars()
        .map(|ch| if ch.is_ascii_control() { ' ' } else { ch })
        .collect()
}

/// 转义引号和反斜杠，防止 `filename="..."` 提前闭合。 / Escape quotes and backslashes so the filename parameter cannot close early.
fn quote_header_filename(filename: &str) -> String {
    let mut output = String::with_capacity(filename.len());
    for ch in filename.chars() {
        if matches!(ch, '"' | '\\') {
            output.push('\\');
        }
        output.push(ch);
    }
    output
}
