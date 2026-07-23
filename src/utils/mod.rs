//! 通用工具函数：时间戳、URI 编解码、文件名提取与 HTTP Range 解析等。
//!
//! ## 本模块的 Rust 知识点
//! - **`Cow`（Clone on Write）**：`decode_uri` 返回 `Cow<str>`——如果输入
//!   不含百分号编码就直接借用原字符串（零拷贝），需要解码时才分配新内存。
//! - **`Option`/`Result` 组合子**：大量使用 `and_then`、`ok_or_else`、`?`
//!   把"可能失败"的步骤串成一条链。
//!
//! ## English overview
//! Shared helpers for timestamps, URI encoding/decoding, filename extraction, HTTP Range parsing,
//! and related operations.
//!
//! ## Rust concepts in this module
//! - **`Cow` (clone on write)**: `decode_uri` returns `Cow<str>`. It borrows an input with no percent
//!   escapes without allocating and allocates only when decoding is required.
//! - **`Option`/`Result` combinators**: `and_then`, `ok_or_else`, and `?` compose sequences of steps
//!   that may fail.

use anyhow::{Result, anyhow};

use std::{
    borrow::Cow,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// 此进程是否信任安全敏感文件属主：非 root 可信自身/root，root 只信 root，避免非特权属主在校验后替换。
/// Whether a sensitive owner is trusted: non-root accepts self/root, while root accepts only root.
pub(crate) fn is_trusted_file_owner(uid: u32) -> bool {
    let euid = rustix::process::geteuid().as_raw();
    is_trusted_file_owner_for(uid, euid)
}

fn is_trusted_file_owner_for(uid: u32, euid: u32) -> bool {
    uid == 0 || (euid != 0 && uid == euid)
}

/// 当前的 Unix 时间（距 1970-01-01 的时长）。系统时钟异常时返回错误，
/// 让认证调用方 fail closed，而不是由远程请求触发整个服务 panic。
/// Return Unix time fallibly so authentication fails closed on a broken clock instead of panicking.
pub fn unix_now() -> Result<Duration> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow!("System clock is before the Unix epoch"))
}

/// 百分号编码的字符集：RFC 3986 unreserved（字母数字和 `-`、`_`、`.`、`~`）
/// 之外的所有字节都编码。与之前 urlencoding crate 的行为逐字节一致，
/// 换用 percent-encoding 是为了与 `decode_uri` 用同一个 crate。
/// Percent-encode every byte outside RFC 3986 unreserved, aligned with `decode_uri`.
const ENCODE_URI_SET: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// 对路径做 URI 编码：按 `/` 分段编码再拼回，
/// 这样斜杠本身保持原样，而每段里的特殊字符（空格、中文等）被百分号编码。
/// Encode each path segment while preserving slash separators.
pub fn encode_uri(v: &str) -> String {
    let parts: Vec<_> = v
        .split('/')
        .map(|part| percent_encoding::utf8_percent_encode(part, ENCODE_URI_SET).to_string())
        .collect();
    parts.join("/")
}

/// URI 百分号解码；解码结果不是合法 UTF-8 时返回 `None`。
/// 返回 `Cow`：无需解码时直接借用输入，避免分配。
/// Percent-decode to UTF-8, borrowing unchanged input through `Cow`; invalid UTF-8 returns None.
pub fn decode_uri(v: &str) -> Option<Cow<'_, str>> {
    percent_encoding::percent_decode(v.as_bytes())
        .decode_utf8()
        .ok()
}

/// 返回 UTF-8 最末路径段，缺失/非 UTF-8 时为空。 / Return the final UTF-8 path segment or empty on absence/non-UTF-8.
pub fn get_file_name(path: &Path) -> &str {
    path.file_name()
        .and_then(|v| v.to_str())
        .unwrap_or_default()
}

/// 与 [`get_file_name`] 相同，但失败时返回带路径信息的错误，
/// 供"必须有文件名"的场景（如生成下载文件名）使用。
/// Fallible final filename with path context for callers that require one.
pub fn try_get_file_name(path: &Path) -> Result<&str> {
    path.file_name()
        .and_then(|v| v.to_str())
        .ok_or_else(|| anyhow!("Failed to get file name of `{}`", path.display()))
}

/// HTTP byte-range 解析结果。调用方必须区分“不认识的单位”、
/// “语法无效”和“语法正确但全部不可满足”；只有最后一种才是 416。
/// Byte-range parse outcome distinguishes unknown unit, invalid syntax, and valid-but-unsatisfiable (the only 416 case).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ByteRangeParse {
    UnsupportedUnit,
    Invalid,
    Unsatisfiable,
    Satisfiable(Vec<(u64, u64)>),
}

/// 与 multipart 响应层的范围成员上限保持一致。解析器必须在看到第 17
/// 个成员时立刻停止，避免先解析攻击者提供的任意长尾部。
/// Match multipart's member cap and stop immediately at member 17.
pub(crate) const MAX_HTTP_RANGE_MEMBERS: usize = 16;

/// 限制未经解析的 Range 值，避免单个超长十进制整数或空白段消耗过多 CPU。
/// 8 KiB 足以容纳正常客户端的 16 个范围，同时符合常见 HTTP 头大小预算。
/// Cap raw Range at 8 KiB before parsing to bound long integers/empty segments.
const MAX_HTTP_RANGE_HEADER_BYTES: usize = 8 * 1024;

/// 解析 HTTP `Range` 头（形如 `bytes=0-499, -200`）。
///
/// 支持三种写法（`size` 为文件总大小）：
/// - `start-end`：明确区间，超过文件末尾时截断到 `size - 1`；
/// - `start-`：从 start 到文件末尾；
/// - `-suffix`：文件末尾的 suffix 个字节。
///
/// 语法正确但不可满足的单个区间（例如起点已越过文件末尾）
/// 会被忽略；如果最后没有任何可满足的区间，返回 `Unsatisfiable`。
/// 这也避免空文件和 `bytes=-0` 产生整数下溢。
/// Parse explicit, open-ended, and suffix byte ranges; ignore individually
/// unsatisfiable members and return Unsatisfiable only when none remain.
pub fn parse_http_range(range: &str, size: u64) -> ByteRangeParse {
    if range.len() > MAX_HTTP_RANGE_HEADER_BYTES {
        return ByteRangeParse::Unsatisfiable;
    }
    // 中文：split_once 分离单位与区间列表。 / English: `split_once` separates the unit from the range list.
    let Some((unit, ranges)) = range.split_once('=') else {
        return ByteRangeParse::Invalid;
    };
    if unit != "bytes" {
        return ByteRangeParse::UnsupportedUnit;
    }
    if ranges.is_empty() {
        return ByteRangeParse::Invalid;
    }

    let mut result = Vec::new();
    for (index, range) in ranges.split(',').enumerate() {
        if index >= MAX_HTTP_RANGE_MEMBERS {
            return ByteRangeParse::Unsatisfiable;
        }
        let Some((start, end)) = range.trim().split_once('-') else {
            return ByteRangeParse::Invalid;
        };
        if start.is_empty() {
            // 中文：`-N` 取末尾 N 字节。 / English: `-N` selects the final N bytes.
            let Ok(offset) = end.parse::<u64>() else {
                return ByteRangeParse::Invalid;
            };
            if offset == 0 || size == 0 {
                continue;
            }
            let offset = offset.min(size);
            result.push((size - offset, size - 1));
        } else {
            let Ok(start) = start.parse::<u64>() else {
                return ByteRangeParse::Invalid;
            };
            if end.is_empty() {
                // 中文：`N-` 从 N 到末尾。 / English: `N-` selects from N through EOF.
                if start < size {
                    result.push((start, size - 1));
                }
            } else {
                let Ok(end) = end.parse::<u64>() else {
                    return ByteRangeParse::Invalid;
                };
                // 中文：start>end 是语法/语义错误，不能作为普通越界区间忽略。
                // English: start>end is invalid syntax/semantics, not an ignorable out-of-file range.
                if start > end {
                    return ByteRangeParse::Invalid;
                }
                if start < size {
                    result.push((start, end.min(size - 1)));
                }
            }
        }
    }

    if result.is_empty() {
        ByteRangeParse::Unsatisfiable
    } else {
        ByteRangeParse::Satisfiable(result)
    }
}

/// 通过创建 IPv6 socket 探测支持。 / Probe IPv6 support by attempting to create an IPv6 socket.
pub fn is_ipv6_available() -> bool {
    use socket2::{Domain, Protocol, Socket, Type};
    Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_file_owner_policy_is_fail_closed_for_root() {
        assert!(is_trusted_file_owner_for(0, 0));
        assert!(!is_trusted_file_owner_for(1_000, 0));
        assert!(is_trusted_file_owner_for(0, 1_000));
        assert!(is_trusted_file_owner_for(1_000, 1_000));
        assert!(!is_trusted_file_owner_for(1_001, 1_000));
    }

    #[test]
    fn range_member_limit_precedes_member_parsing() {
        let mut members = vec!["0-0"; MAX_HTTP_RANGE_MEMBERS];
        members.push("malformed");
        let value = format!("bytes={}", members.join(","));
        assert_eq!(parse_http_range(&value, 1), ByteRangeParse::Unsatisfiable);
    }

    #[test]
    fn raw_range_length_is_bounded() {
        let value = format!("bytes=0-{}", "9".repeat(MAX_HTTP_RANGE_HEADER_BYTES));
        assert_eq!(parse_http_range(&value, 1), ByteRangeParse::Unsatisfiable);
    }

    #[test]
    fn range_limits_are_inclusive() {
        let members = vec!["0-0"; MAX_HTTP_RANGE_MEMBERS].join(",");
        assert!(matches!(
            parse_http_range(&format!("bytes={members}"), 1),
            ByteRangeParse::Satisfiable(ranges) if ranges.len() == MAX_HTTP_RANGE_MEMBERS
        ));

        let padding = MAX_HTTP_RANGE_HEADER_BYTES - "bytes=".len() - members.len();
        let exact = format!("bytes={}{}", " ".repeat(padding), members);
        assert_eq!(exact.len(), MAX_HTTP_RANGE_HEADER_BYTES);
        assert!(matches!(
            parse_http_range(&exact, 1),
            ByteRangeParse::Satisfiable(ranges) if ranges.len() == MAX_HTTP_RANGE_MEMBERS
        ));
    }
}
