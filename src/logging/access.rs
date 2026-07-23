//! HTTP 访问日志：支持 nginx 风格的自定义格式串（`--log-format`），
//! 默认格式同时包含 request id、实际响应体字节、终态和请求耗时。
//!
//! 格式串在启动时被解析成元素列表（变量 / 请求头 / 字面量），
//! 每个请求到来时先采集数据（[`HttpLogger::data`]），响应完成后
//! 拼装输出（[`HttpLogger::log`]）。
//!
//! ## 本模块的 Rust 知识点
//! - **`FromStr` trait**：实现它之后就能写 `"格式串".parse::<HttpLogger>()`，
//!   这是 Rust 里"字符串 → 类型"的标准姿势。
//! - **日志注入防御**：写进日志的一切外部输入（URL、用户名、请求头）
//!   都要先经 `sanitize_log_value` 转义控制字符，防止恶意请求伪造日志行；
//!   URL 里的 `token` 等凭据参数要打码，防止可复用 secret 泄露到日志。
//!
//! ## Rust concepts used here
//! - **The `FromStr` trait**: implementing it makes
//!   `"format".parse::<HttpLogger>()` the standard typed conversion from a
//!   configuration string into a pre-parsed logging plan.
//! - **Log-injection defense**: every external URL, username, and request-header
//!   value passes through `sanitize_log_value` before durable output, so control
//!   characters cannot forge extra records. Query `token` values are redacted
//!   before decoding or rendering so reusable bearer-equivalent secrets do not
//!   enter the access log.

use std::{
    collections::HashMap,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use chrono::{Local, SecondsFormat};
use hyper::header::HeaderName;

use super::MAX_LOG_LINE_BYTES;
use crate::{server::Request, utils::decode_uri};

pub const DEFAULT_LOG_FORMAT: &str = r#"$time_iso8601 $log_level request_id=$request_id - $remote_addr $remote_user "$request" $status bytes=$body_bytes outcome=$response_outcome request_time=$request_time"#;

/// 可能携带可复用凭据或 bearer 等价 secret 的请求头；格式解析时直接拒绝而非事后条件脱敏。
/// Headers carrying reusable credentials are rejected at format-parse time so configuration cannot expose them accidentally.
const SENSITIVE_LOG_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
];

/// 解析后的日志格式元素序列。 / Parsed log format as a sequence of render elements.
#[derive(Debug, Clone, PartialEq)]
pub struct HttpLogger {
    elements: Vec<LogElement>,
}

impl Default for HttpLogger {
    fn default() -> Self {
        DEFAULT_LOG_FORMAT.parse().unwrap()
    }
}

/// 格式串的变量、请求头与字面量三类元素。 / Variable, request-header, and literal format elements.
#[derive(Debug, Clone, PartialEq)]
enum LogElement {
    Variable(String),
    Header(String),
    Literal(String),
}

impl HttpLogger {
    /// 请求到达时采集日志所需数据。必须在处理请求**之前**做，
    /// 因为请求体可能被处理函数消费掉；状态码等响应侧数据由调用方
    /// （server 模块的 `call`）事后补充进这个 HashMap。
    /// Capture request-side fields before body consumption; the caller adds response-side status later.
    pub fn data(&self, req: &Request) -> HashMap<String, String> {
        let mut data = HashMap::default();
        for element in self.elements.iter() {
            match element {
                LogElement::Variable(name) => match name.as_str() {
                    "request" | "request_method" | "request_uri" => {
                        let uri = req.uri().to_string();
                        // 查询串必须先按原始 `&` 边界切分，再分别解码参数名。
                        // 若先解码整个 URI，token 值里的 `%26` 会被误当作新参数
                        // 边界，导致后半段凭据绕过整值脱敏。
                        // English: Split on raw `&` boundaries before decoding each parameter name.
                        // Decoding the complete URI first could turn `%26` inside a token value into
                        // a false parameter boundary and let the remaining credential bypass whole-value redaction.
                        let decoded_uri = sanitize_log_value(&redact_and_decode_uri(&uri));
                        data.entry("request".to_string())
                            .or_insert_with(|| format!("{} {decoded_uri}", req.method()));
                        data.entry("request_method".to_string())
                            .or_insert_with(|| req.method().to_string());
                        data.entry("request_uri".to_string())
                            .or_insert_with(|| decoded_uri);
                    }
                    "remote_user" => {
                        // 请求到达时凭据尚未验证。绝不能把 Authorization
                        // 中自称的用户名记成 remote_user，否则攻击者可伪造
                        // 审计身份。认证后的用户名后续应由请求上下文注入；
                        // 在此之前保持缺省值 `-` 比记录错误身份更安全。
                        // English: The name claimed by Authorization is still unverified when the
                        // request arrives. Never record it as `remote_user`; retain `-` until the
                        // authentication layer injects the verified principal into request context.
                    }
                    _ => {}
                },
                LogElement::Header(name) => {
                    if let Some(value) = req.headers().get(name).and_then(|v| v.to_str().ok()) {
                        data.insert(name.to_string(), sanitize_log_value(value));
                    }
                }
                LogElement::Literal(_) => {}
            }
        }
        data
    }

    /// 只有认证/授权层完成密码或 Digest 校验后，才允许把用户
    /// 写入访问日志。这样 `$remote_user` 既保留审计价值，也不会信任
    /// Authorization 头中未经验证的自报身份。
    /// Set remote_user only after authentication, preserving audit value without trusting a claimed header identity.
    pub fn set_authenticated_user(&self, data: &mut HashMap<String, String>, user: &str) {
        data.insert("remote_user".to_string(), sanitize_log_value(user));
    }

    /// 响应完成后拼装并输出一行日志。`err` 有值时说明处理过程报错
    /// （已转成 500），错误信息附在行尾并按 ERROR 级别输出。
    /// Render one line after response completion; append processing errors and emit them at ERROR level.
    pub fn log(&self, data: &HashMap<String, String>, err: Option<String>) {
        let Some((output, is_error)) = self.render_line(data, err.as_deref()) else {
            return;
        };
        emit_http_access(&output, is_error);
    }

    fn render_line(
        &self,
        data: &HashMap<String, String>,
        err: Option<&str>,
    ) -> Option<(String, bool)> {
        if self.elements.is_empty() {
            return None;
        }
        let is_error = err.is_some();
        let now = Local::now();
        let time_local = now.to_rfc3339_opts(SecondsFormat::Secs, false);
        let time_iso8601 = now.to_rfc3339_opts(SecondsFormat::Secs, true);
        let msec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| format!("{:.3}", d.as_secs_f64()))
            .unwrap_or_default();
        let log_level = if is_error { "ERROR" } else { "INFO" };

        let mut output = String::with_capacity(
            self.elements
                .len()
                .saturating_mul(16)
                .min(MAX_LOG_LINE_BYTES),
        );
        let mut complete = true;
        for element in self.elements.iter() {
            let value = match element {
                LogElement::Literal(value) => value.as_str(),
                LogElement::Variable(name) => {
                    let resolved = match name.as_str() {
                        "time_local" => Some(time_local.as_str()),
                        "time_iso8601" => Some(time_iso8601.as_str()),
                        "msec" => Some(msec.as_str()),
                        "log_level" => Some(log_level),
                        _ => None,
                    };
                    resolved
                        .or_else(|| data.get(name.as_str()).map(|v| v.as_str()))
                        .unwrap_or("-")
                }
                LogElement::Header(name) => data.get(name.as_str()).map_or("-", String::as_str),
            };
            if !push_bounded_log_text(&mut output, value) {
                complete = false;
                break;
            }
        }
        if complete && let Some(err) = err {
            complete = push_bounded_log_text(&mut output, " ");
            if complete {
                let remaining = MAX_LOG_LINE_BYTES.saturating_sub(output.len());
                let err = sanitize_log_value_with_limit(err, remaining);
                push_bounded_log_text(&mut output, &err);
            }
        }
        Some((output, is_error))
    }
}

const LOG_TRUNCATION_SUFFIX: &str = "...[truncated]";

fn push_bounded_log_text(output: &mut String, value: &str) -> bool {
    let remaining = MAX_LOG_LINE_BYTES.saturating_sub(output.len());
    if value.len() <= remaining {
        output.push_str(value);
        return true;
    }

    let content_budget = remaining.saturating_sub(LOG_TRUNCATION_SUFFIX.len());
    let mut end = content_budget.min(value.len());
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    output.push_str(&value[..end]);
    if remaining >= LOG_TRUNCATION_SUFFIX.len() {
        output.push_str(LOG_TRUNCATION_SUFFIX);
    }
    false
}

/// 经 `log` crate 输出，target 设为 `http_access`，让系统日志器
/// 原样打印这一行（时间戳等前缀已由格式串自己控制，不再额外加）。
/// Emit through the `http_access` target without extra prefixes because the format owns them.
fn emit_http_access(msg: &str, is_error: bool) {
    let level = if is_error {
        log::Level::Error
    } else {
        log::Level::Info
    };
    log::logger().log(
        &log::Record::builder()
            .args(format_args!("{}", msg))
            .level(level)
            .target("http_access")
            .build(),
    );
}

// 中文：逐字符扫描 `$name` 为变量/请求头，其余为字面量；`$http_x_y` 映射到 `x-y`。
// English: Scan `$name` into variables/headers and retain other text as literals; `$http_x_y` maps to `x-y`.
impl FromStr for HttpLogger {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > MAX_LOG_LINE_BYTES {
            anyhow::bail!("access log format exceeds {MAX_LOG_LINE_BYTES} bytes");
        }
        if s.chars().any(char::is_control) {
            anyhow::bail!("access log format must not contain control characters");
        }

        let mut elements = vec![];
        let mut literal = String::new();
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c != '$' {
                literal.push(c);
                continue;
            }

            // 中文：双美元是普通文本，不是空变量加数字变量（如 `$$5`）；保留两字节并越过它。
            // English: A doubled dollar is literal text, not empty plus numeric variables; preserve both and skip the pair.
            if chars.peek().is_some_and(|next| *next == '$') {
                chars.next();
                literal.push('$');
                literal.push('$');
                continue;
            }

            if !literal.is_empty() {
                elements.push(LogElement::Literal(std::mem::take(&mut literal)));
            }
            let mut name = String::new();
            while chars
                .peek()
                .is_some_and(|next| next.is_ascii_alphanumeric() || *next == '_')
            {
                name.push(chars.next().expect("peeked log variable character exists"));
            }
            if name.is_empty() {
                literal.push('$');
                continue;
            }

            if let Some(value) = name.strip_prefix("http_") {
                let name = value.replace('_', "-").to_ascii_lowercase();
                HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| anyhow::anyhow!("invalid access-log request header `{name}`"))?;
                if is_sensitive_log_header(&name) {
                    anyhow::bail!(
                        "request header `{name}` is sensitive and cannot be included in the access log"
                    );
                }
                elements.push(LogElement::Header(name));
            } else {
                elements.push(LogElement::Variable(name));
            }
        }
        if !literal.is_empty() {
            elements.push(LogElement::Literal(literal));
        }
        Ok(Self { elements })
    }
}

fn is_sensitive_log_header(name: &str) -> bool {
    SENSITIVE_LOG_HEADERS.contains(&name)
        || [
            "authorization",
            "cookie",
            "token",
            "secret",
            "password",
            "passwd",
            "credential",
            "api-key",
            "apikey",
            "signature",
        ]
        .iter()
        .any(|marker| name.contains(marker))
}

fn decode_component(value: &str) -> String {
    decode_uri(value)
        .map(|decoded| decoded.into_owned())
        .unwrap_or_else(|| value.to_string())
}

fn is_sensitive_query_key(key: &str) -> bool {
    let key = key.trim().to_ascii_lowercase().replace('-', "_");
    matches!(
        key.as_str(),
        "token"
            | "access_token"
            | "id_token"
            | "refresh_token"
            | "api_key"
            | "apikey"
            | "authorization"
            | "credential"
            | "password"
            | "passwd"
            | "secret"
            | "signature"
            | "sig"
            | "x_amz_credential"
            | "x_amz_signature"
    ) || key.ends_with("_token")
        || key.ends_with("_credential")
        || key.ends_with("_signature")
        || key.ends_with("_password")
        || key.ends_with("_secret")
}

/// 解码 URI 供可读日志并脱敏可复用查询凭据；原始分隔符作为边界，secret 内编码 `&` 不会在整值替换前拆开。
/// Decode a URI for readable logs while preserving raw query boundaries so encoded separators cannot bypass whole-secret redaction.
fn redact_and_decode_uri(uri: &str) -> String {
    let Some((path, query)) = uri.split_once('?') else {
        return decode_component(uri);
    };

    let mut output = decode_component(path);
    output.push('?');
    for (index, field) in query.split('&').enumerate() {
        if index > 0 {
            output.push('&');
        }
        match field.split_once('=') {
            Some((raw_key, raw_value)) => {
                let key = decode_component(raw_key);
                output.push_str(&key);
                output.push('=');
                if is_sensitive_query_key(&key) {
                    output.push_str("***");
                } else {
                    output.push_str(&decode_component(raw_value));
                }
            }
            None => output.push_str(&decode_component(field)),
        }
    }
    output
}

/// 日志值转义：反斜杠和引号加转义前缀，控制字符转成 `\x..` 形式，
/// 保证一条日志永远只占一行、且无法伪造出"另一条日志"。
/// Escape slashes/quotes and render controls as hex so one value cannot forge another log line.
fn sanitize_log_value(s: &str) -> String {
    sanitize_log_value_with_limit(s, MAX_LOG_LINE_BYTES)
}

fn sanitize_log_value_with_limit(s: &str, limit: usize) -> String {
    let mut output = String::with_capacity(s.len().min(limit));
    for c in s.chars() {
        let escaped = match c {
            '\\' => "\\\\".to_string(),
            '"' => "\\\"".to_string(),
            c if c.is_control() => format!("\\x{:02x}", c as u32),
            c => c.to_string(),
        };
        if escaped.len() > limit.saturating_sub(output.len()) {
            break;
        }
        output.push_str(&escaped);
    }
    output
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_log_format(data: &[u8]) {
    if data.len() > MAX_LOG_LINE_BYTES {
        return;
    }
    let Ok(format) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(logger) = format.parse::<HttpLogger>()
        && let Some((line, _)) = logger.render_line(&HashMap::new(), Some(format))
    {
        assert!(line.len() <= MAX_LOG_LINE_BYTES);
        assert!(!line.contains(['\r', '\n']));
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HttpLogger, LOG_TRUNCATION_SUFFIX, MAX_LOG_LINE_BYTES, is_sensitive_log_header,
        redact_and_decode_uri,
    };
    use std::collections::HashMap;

    #[test]
    fn query_credentials_are_redacted_after_decoding_only_the_key() {
        assert_eq!(
            redact_and_decode_uri("/file?%74oken=first%26second%3Dstill-secret&ok=yes"),
            "/file?token=***&ok=yes"
        );
        assert_eq!(
            redact_and_decode_uri("/file?X-Amz-Credential=abc&X-Amz-Signature=def"),
            "/file?X-Amz-Credential=***&X-Amz-Signature=***"
        );
    }

    #[test]
    fn non_sensitive_components_remain_readable_without_changing_boundaries() {
        assert_eq!(
            redact_and_decode_uri("/hello%20world?name=a%26b%3Dc&mode=compact"),
            "/hello world?name=a&b=c&mode=compact"
        );
    }

    #[test]
    fn credential_like_headers_are_rejected_conservatively() {
        for name in [
            "x-api-key",
            "x-auth-token",
            "x-client-secret",
            "x-user-password",
            "x-amz-credential",
        ] {
            assert!(is_sensitive_log_header(name), "{name}");
        }
        assert!(!is_sensitive_log_header("user-agent"));
    }

    #[test]
    fn adjacent_variables_and_literal_whitespace_are_preserved() {
        let logger: HttpLogger = "  $request_method$status  ".parse().unwrap();
        let data = HashMap::from([
            ("request_method".to_string(), "GET".to_string()),
            ("status".to_string(), "200".to_string()),
        ]);
        let (line, is_error) = logger.render_line(&data, None).unwrap();
        assert_eq!(line, "  GET200  ");
        assert!(!is_error);

        let dollars: HttpLogger = "cost=$$5".parse().unwrap();
        assert_eq!(
            dollars.render_line(&HashMap::new(), None).unwrap().0,
            "cost=$$5"
        );
    }

    #[test]
    fn rendered_access_line_is_bounded_before_entering_the_async_logger() {
        let logger: HttpLogger = "$request_uri".parse().unwrap();
        let data = HashMap::from([("request_uri".to_string(), "界".repeat(MAX_LOG_LINE_BYTES))]);
        let (line, _) = logger
            .render_line(&data, Some(&"error".repeat(MAX_LOG_LINE_BYTES)))
            .unwrap();
        assert!(line.len() <= MAX_LOG_LINE_BYTES);
        assert!(line.ends_with(LOG_TRUNCATION_SUFFIX));
        assert!(std::str::from_utf8(line.as_bytes()).is_ok());
    }

    #[test]
    fn log_format_rejects_control_characters_invalid_and_sensitive_headers() {
        for format in [
            "line\nforged",
            "$http_",
            "$http_authorization",
            "$http_x_api_key",
        ] {
            assert!(format.parse::<HttpLogger>().is_err(), "accepted {format:?}");
        }
        assert!("$http_user_agent".parse::<HttpLogger>().is_ok());
        assert!(
            "x".repeat(MAX_LOG_LINE_BYTES + 1)
                .parse::<HttpLogger>()
                .is_err()
        );
    }
}
