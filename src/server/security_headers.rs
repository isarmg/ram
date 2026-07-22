//! 出口响应头：CORS 跨域头与安全响应头。
//! 这两个函数在 `Server::call` 的最后统一调用，保证**每一个**响应
//! （包括错误响应和 500）都带上这些头。
//! CORS 预检把路由的有效能力与运维允许列表取交集，且绝不反射畸形或被拒绝的输入。
//!
//! Outbound CORS and security headers are applied centrally to every response,
//! including errors. Preflights intersect effective route capabilities with
//! the operator allowlist and never reflect malformed/disallowed input.

use super::capabilities::{CorsPreflightCapabilities, ResourceCapabilities};
use super::{Response, body_full};
use crate::config::Args;
use crate::http::ResourceMethod;
use headers::{CacheControl, HeaderMapExt};
use hyper::header::{
    ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
    ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_EXPOSE_HEADERS, ACCESS_CONTROL_REQUEST_HEADERS,
    ACCESS_CONTROL_REQUEST_METHOD, CONTENT_LENGTH, HeaderName, HeaderValue, ORIGIN,
    STRICT_TRANSPORT_SECURITY, VARY,
};
use hyper::{HeaderMap, Method, StatusCode};
use std::collections::HashSet;

/// 内置/自定义文件管理 UI 仅同源加载版本化脚本、样式与 API；sandbox preview 使用本地有界 blob，不允许文档 framing。与可信 render-* 应用策略分离。
/// File-manager UI is same-origin only; sandboxed bounded blob previews grant no framing. Trusted render-* applications have a separate policy.
const MANAGEMENT_UI_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-src blob:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
const MANAGEMENT_UI_PERMISSIONS_POLICY: &str =
    "camera=(), geolocation=(), microphone=(), payment=(), usb=()";

pub fn add_management_ui_csp(res: &mut Response) {
    res.headers_mut().insert(
        "content-security-policy",
        HeaderValue::from_static(MANAGEMENT_UI_CSP),
    );
    res.headers_mut().insert(
        "permissions-policy",
        HeaderValue::from_static(MANAGEMENT_UI_PERMISSIONS_POLICY),
    );
}

/// 定义 CORS 的三个请求字段，保留所有出现；Origin/Method 单值，Request-Headers 可重复逗号列表。
/// Preserve all CORS field occurrences: Origin/Method are singleton, Request-Headers is a repeatable comma-list.
#[derive(Clone, Debug, Default)]
pub(super) struct CorsRequest {
    origins: Vec<HeaderValue>,
    methods: Vec<HeaderValue>,
    headers: Vec<HeaderValue>,
}

impl CorsRequest {
    pub(super) fn from_headers(headers: &HeaderMap) -> Self {
        Self {
            origins: headers.get_all(ORIGIN).iter().cloned().collect(),
            methods: headers
                .get_all(ACCESS_CONTROL_REQUEST_METHOD)
                .iter()
                .cloned()
                .collect(),
            headers: headers
                .get_all(ACCESS_CONTROL_REQUEST_HEADERS)
                .iter()
                .cloned()
                .collect(),
        }
    }
}

/// 路由附加有效能力后应用 CORS；绝不发 Allow-Credentials。接受预检为 204/no-store，畸形/拒绝输入 fail closed 不反射。
/// Apply CORS after effective capabilities; never allow credentials, return 204/no-store only for accepted preflights, and fail closed otherwise.
pub(super) fn add_cors(
    res: &mut Response,
    request_method: &Method,
    request: &CorsRequest,
    args: &Args,
) {
    if !args.enable_cors {
        return;
    }

    let is_preflight = request_method == Method::OPTIONS && !request.methods.is_empty();
    append_vary(res.headers_mut(), "Origin");
    if is_preflight {
        append_vary(res.headers_mut(), "Access-Control-Request-Method");
        append_vary(res.headers_mut(), "Access-Control-Request-Headers");
    }

    if request.origins.len() != 1 {
        if is_preflight || !request.origins.is_empty() {
            reject_preflight(res, StatusCode::BAD_REQUEST, "Invalid CORS Origin header");
        }
        return;
    }
    let Ok(origin) = request.origins[0].to_str() else {
        if is_preflight {
            reject_preflight(res, StatusCode::BAD_REQUEST, "Invalid CORS Origin header");
        }
        return;
    };
    let allowed_origin = if args.cors_origins.iter().any(|candidate| candidate == "*") {
        Some(HeaderValue::from_static("*"))
    } else if args
        .cors_origins
        .iter()
        .any(|candidate| candidate == origin)
    {
        HeaderValue::from_str(origin).ok()
    } else {
        None
    };
    let Some(allowed_origin) = allowed_origin else {
        if is_preflight {
            reject_preflight(res, StatusCode::FORBIDDEN, "CORS origin is not allowed");
        }
        return;
    };

    // 中文：防御性删除避免 handler/自定义响应把无凭据策略与 credentialed CORS 组合。
    // English: Defensive removal prevents any path from combining this policy with credentialed CORS.
    res.headers_mut().remove(ACCESS_CONTROL_ALLOW_CREDENTIALS);
    res.headers_mut()
        .insert(ACCESS_CONTROL_ALLOW_ORIGIN, allowed_origin);
    res.headers_mut().insert(
        ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static(
            "Content-Disposition, Content-Length, Content-Range, Content-Type, ETag, Last-Modified, Accept-Ranges, Allow, X-Ram-List-Truncated, X-Ram-List-Omitted, X-Ram-Mutation-Version",
        ),
    );

    if !is_preflight {
        return;
    }
    if request.methods.len() != 1 {
        reject_preflight(
            res,
            StatusCode::BAD_REQUEST,
            "Invalid CORS requested method",
        );
        return;
    }
    let Ok(requested_method) = request.methods[0].to_str() else {
        reject_preflight(
            res,
            StatusCode::BAD_REQUEST,
            "Invalid CORS requested method",
        );
        return;
    };
    let Some(requested_method) = ResourceMethod::parse_name(requested_method) else {
        reject_preflight(res, StatusCode::FORBIDDEN, "CORS method is not allowed");
        return;
    };

    let target_capabilities = res
        .extensions()
        .get::<CorsPreflightCapabilities>()
        .copied()
        .unwrap_or_default()
        .0;
    let configured =
        ResourceCapabilities::from_method_names(args.cors_methods.iter().map(String::as_str));
    let allowed_methods = target_capabilities.intersection(configured);
    if !allowed_methods.contains(requested_method) {
        reject_preflight(
            res,
            StatusCode::FORBIDDEN,
            "CORS method is not allowed for this resource",
        );
        return;
    }

    let requested_headers = match parse_requested_headers(&request.headers) {
        Ok(headers) => headers,
        Err(message) => {
            reject_preflight(res, StatusCode::BAD_REQUEST, message);
            return;
        }
    };
    let configured_headers: HashSet<&str> = args.cors_headers.iter().map(String::as_str).collect();
    if requested_headers
        .iter()
        .any(|header| !configured_headers.contains(header.as_str()))
    {
        reject_preflight(
            res,
            StatusCode::FORBIDDEN,
            "CORS request header is not allowed",
        );
        return;
    }

    let allow_methods = allowed_methods.allow_header();
    if let Ok(value) = HeaderValue::from_str(&allow_methods) {
        res.headers_mut()
            .insert(ACCESS_CONTROL_ALLOW_METHODS, value);
    }
    if !requested_headers.is_empty()
        && let Ok(value) = HeaderValue::from_str(&requested_headers.join(", "))
    {
        res.headers_mut()
            .insert(ACCESS_CONTROL_ALLOW_HEADERS, value);
    }
    *res.status_mut() = StatusCode::NO_CONTENT;
    *res.body_mut() = body_full("");
    res.headers_mut()
        .insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
    res.headers_mut()
        .typed_insert(CacheControl::new().with_no_store());
}

fn parse_requested_headers(values: &[HeaderValue]) -> Result<Vec<String>, &'static str> {
    let mut headers = Vec::new();
    let mut seen = HashSet::new();
    for value in values {
        let value = value
            .to_str()
            .map_err(|_| "Invalid CORS requested header")?;
        for item in value.split(',') {
            let item = item.trim();
            if item.is_empty() {
                return Err("Invalid CORS requested header");
            }
            let header = HeaderName::from_bytes(item.as_bytes())
                .map_err(|_| "Invalid CORS requested header")?
                .as_str()
                .to_string();
            if seen.insert(header.clone()) {
                headers.push(header);
            }
        }
    }
    Ok(headers)
}

fn reject_preflight(res: &mut Response, status: StatusCode, message: &'static str) {
    *res.status_mut() = status;
    *res.body_mut() = body_full(message);
    let headers = res.headers_mut();
    headers.remove(ACCESS_CONTROL_ALLOW_ORIGIN);
    headers.remove(ACCESS_CONTROL_ALLOW_METHODS);
    headers.remove(ACCESS_CONTROL_ALLOW_HEADERS);
    headers.remove(ACCESS_CONTROL_EXPOSE_HEADERS);
    headers.remove(ACCESS_CONTROL_ALLOW_CREDENTIALS);
    headers.remove(CONTENT_LENGTH);
    headers.typed_insert(CacheControl::new().with_no_store());
}

fn append_vary(headers: &mut HeaderMap, value: &'static str) {
    if !headers.get_all(VARY).iter().any(|current| {
        current.to_str().is_ok_and(|current| {
            current
                .split(',')
                .any(|item| item.trim().eq_ignore_ascii_case(value))
        })
    }) {
        headers.append(VARY, HeaderValue::from_static(value));
    }
}

/// 给所有响应补充安全头：
/// - `x-content-type-options: nosniff`：禁止浏览器猜测内容类型，
///   防止把用户上传的文本文件当 HTML/JS 执行；
/// - `referrer-policy: no-referrer`：跳出站外时不泄露内网 URL。
/// - `x-frame-options: DENY`：文件管理界面不能被第三方页面套进 iframe
///   实施点击劫持。
///
/// 用 `entry().or_insert_with()`（"不存在才插入"）而不是 `insert`，
/// 这样具体处理函数如果已经设置过同名头，不会被这里覆盖。
/// Add nosniff, no-referrer, and DENY framing to every response without overwriting a handler's explicit same-name header.
pub fn add_security_headers(res: &mut Response, hsts_max_age: Option<u64>) {
    let headers = res.headers_mut();
    headers
        .entry("x-content-type-options")
        .or_insert_with(|| HeaderValue::from_static("nosniff"));
    headers
        .entry("referrer-policy")
        .or_insert_with(|| HeaderValue::from_static("no-referrer"));
    headers
        .entry("x-frame-options")
        .or_insert_with(|| HeaderValue::from_static("DENY"));
    if let Some(max_age) = hsts_max_age {
        // 中文：配置把此值限制为短十进制 u64 且只允许 Ram TLS；终止 TLS 的反代必须在 HTTPS 边界设置自身策略。
        // English: Validation permits a short u64 only with Ram TLS; terminating proxies own HSTS at their HTTPS boundary.
        let value = HeaderValue::from_str(&format!("max-age={max_age}"))
            .expect("a decimal u64 always forms a valid HSTS header value");
        headers.entry(STRICT_TRANSPORT_SECURITY).or_insert(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::body_full;
    use hyper::Response as HyperResponse;

    #[test]
    fn management_ui_policy_contains_all_security_boundaries() {
        let mut response = HyperResponse::new(body_full(""));
        add_management_ui_csp(&mut response);
        let policy = response
            .headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap();
        for directive in [
            "default-src 'none'",
            "script-src 'self'",
            "style-src 'self'",
            "connect-src 'self'",
            "frame-src blob:",
            "object-src 'none'",
            "base-uri 'none'",
            "form-action 'self'",
            "frame-ancestors 'none'",
        ] {
            assert!(
                policy.contains(directive),
                "missing CSP directive: {directive}"
            );
        }
        assert!(!policy.contains("'unsafe-inline'"));
        assert!(!policy.contains("'unsafe-eval'"));
        assert!(!policy.contains("frame-src 'self'"));
        assert_eq!(
            response.headers().get("permissions-policy").unwrap(),
            MANAGEMENT_UI_PERMISSIONS_POLICY
        );
    }

    #[test]
    fn hsts_is_explicit_and_can_be_cleared() {
        let mut disabled = HyperResponse::new(body_full(""));
        add_security_headers(&mut disabled, None);
        assert!(!disabled.headers().contains_key(STRICT_TRANSPORT_SECURITY));

        let mut enabled = HyperResponse::new(body_full(""));
        add_security_headers(&mut enabled, Some(31_536_000));
        assert_eq!(
            enabled.headers().get(STRICT_TRANSPORT_SECURITY).unwrap(),
            "max-age=31536000"
        );

        let mut cleared = HyperResponse::new(body_full(""));
        add_security_headers(&mut cleared, Some(0));
        assert_eq!(
            cleared.headers().get(STRICT_TRANSPORT_SECURITY).unwrap(),
            "max-age=0"
        );
    }
}
