//! 服务端统一响应安全头。
//!
//! Ram 只提供同源浏览器界面；跨域策略与 HSTS 由部署它的反向代理负责。

use super::Response;
use hyper::header::HeaderValue;

/// 文件管理界面只加载同源脚本、样式与 API；预览内容来自本地有界 blob。
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

/// 给所有响应补充基础浏览器安全头，同时保留处理器显式设置的值。
pub fn add_security_headers(res: &mut Response) {
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
        assert_eq!(
            response.headers().get("permissions-policy").unwrap(),
            MANAGEMENT_UI_PERMISSIONS_POLICY
        );
    }

    #[test]
    fn adds_only_basic_security_headers() {
        let mut response = HyperResponse::new(body_full(""));
        add_security_headers(&mut response);
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert_eq!(response.headers()["referrer-policy"], "no-referrer");
        assert_eq!(response.headers()["x-frame-options"], "DENY");
        assert!(!response.headers().contains_key("strict-transport-security"));
    }
}
