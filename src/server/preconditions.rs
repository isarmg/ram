//! HTTP 条件请求的单次严格解析与统一求值模型。受保护文件系统资源有意先完成认证，再调用
//! [`ParsedPreconditions::parse`]；公开内置资源在其早退路由中复用同一解析器。解析后的同一
//! 值贯穿乐观探测与最终变更事务，处理器不会重新解释原始头字节，也不会再次调用
//! `typed_try_get`。
//!
//! One strict parse and one evaluation model for HTTP conditional requests. Authentication
//! deliberately happens before [`ParsedPreconditions::parse`] for protected filesystem resources;
//! public built-in assets use this same parser in their early-return route. Once parsed, the same
//! value follows the request through optimistic probes and the final mutation transaction: handlers
//! do not reinterpret raw header bytes or call `typed_try_get` again.

use headers::{
    ETag, HeaderMapExt, IfMatch, IfModifiedSince, IfNoneMatch, IfRange, IfUnmodifiedSince,
    LastModified,
};
use hyper::{
    HeaderMap,
    header::{
        HeaderName, HeaderValue, IF_MATCH, IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_RANGE,
        IF_UNMODIFIED_SINCE,
    },
};
use std::fmt;

use crate::http::ResourceMethod;

#[derive(Clone, Debug, Default)]
pub(crate) struct ParsedPreconditions {
    pub(super) if_match: Option<IfMatch>,
    pub(super) if_unmodified_since: Option<IfUnmodifiedSince>,
    pub(super) if_none_match: Option<IfNoneMatch>,
    pub(super) if_modified_since: Option<IfModifiedSince>,
    if_range: Option<ParsedIfRange>,
}

#[derive(Clone, Debug)]
enum ParsedIfRange {
    /// If-Range 只允许强实体标签比较；保留解析标签避免 Range 求值时重读原始字节。
    /// If-Range permits only strong ETag comparison; retain the parsed tag for Range evaluation.
    StrongTag(ETag),
    /// 弱标签语法有效但永远不满足 If-Range。 / A weak tag is valid syntax but never satisfies If-Range.
    WeakTag,
    /// Ram 不把秒粒度文件时间当作字节身份；合法日期仍回退完整表示。
    /// Ram does not treat second-resolution dates as byte identity, so valid dates fall back to the full representation.
    Date,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReadPreconditionOutcome {
    Proceed,
    NotModified,
    PreconditionFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct InvalidPrecondition {
    header: &'static str,
}

impl InvalidPrecondition {
    fn new(header: &'static str) -> Self {
        Self { header }
    }
}

impl fmt::Display for InvalidPrecondition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid {} header", self.header)
    }
}

impl std::error::Error for InvalidPrecondition {}

impl ParsedPreconditions {
    /// 每个支持的条件字段严格且只解析一次。 / Strictly parse every supported conditional field exactly once.
    ///
    /// ETag 列表可跨字段行，但 wildcard 与 tag 不得混用/重复；日期与 If-Range 为单值，多行直接拒绝。
    /// ETag lists may span lines; wildcard/tag forms cannot mix. Date and If-Range are singleton fields and reject duplicates.
    pub(super) fn parse(headers: &HeaderMap<HeaderValue>) -> Result<Self, InvalidPrecondition> {
        validate_entity_tag_condition(headers, &IF_MATCH, "If-Match")?;
        validate_entity_tag_condition(headers, &IF_NONE_MATCH, "If-None-Match")?;

        let if_match = headers
            .typed_try_get::<IfMatch>()
            .map_err(|_| InvalidPrecondition::new("If-Match"))?;
        let if_none_match = headers
            .typed_try_get::<IfNoneMatch>()
            .map_err(|_| InvalidPrecondition::new("If-None-Match"))?;
        let if_unmodified_since = parse_single::<IfUnmodifiedSince>(
            headers,
            &IF_UNMODIFIED_SINCE,
            "If-Unmodified-Since",
        )?;
        let if_modified_since =
            parse_single::<IfModifiedSince>(headers, &IF_MODIFIED_SINCE, "If-Modified-Since")?;
        let if_range = parse_if_range(headers)?;

        Ok(Self {
            if_match,
            if_unmodified_since,
            if_none_match,
            if_modified_since,
            if_range,
        })
    }

    /// GET/HEAD 按 RFC 9110 §13.2.2 排序；ETag 优先于较不精确日期，同时发送仍合法。
    /// RFC 9110 §13.2.2 ordering: ETags suppress date counterparts by priority, not syntax conflict.
    pub(super) fn evaluate_read(
        &self,
        etag: &ETag,
        last_modified: Option<LastModified>,
    ) -> ReadPreconditionOutcome {
        if let Some(if_match) = &self.if_match {
            if !if_match.precondition_passes(etag) {
                return ReadPreconditionOutcome::PreconditionFailed;
            }
        } else if let (Some(if_unmodified_since), Some(last_modified)) =
            (self.if_unmodified_since, last_modified)
            && !if_unmodified_since.precondition_passes(last_modified.into())
        {
            return ReadPreconditionOutcome::PreconditionFailed;
        }

        if let Some(if_none_match) = &self.if_none_match {
            if !if_none_match.precondition_passes(etag) {
                return ReadPreconditionOutcome::NotModified;
            }
        } else if let (Some(if_modified_since), Some(last_modified)) =
            (self.if_modified_since, last_modified)
            && !if_modified_since.is_modified(last_modified.into())
        {
            return ReadPreconditionOutcome::NotModified;
        }

        ReadPreconditionOutcome::Proceed
    }

    pub(super) fn if_range_matches(&self, current_etag: &ETag, current_is_strong: bool) -> bool {
        match self.if_range.as_ref() {
            None => true,
            Some(ParsedIfRange::StrongTag(candidate)) => {
                current_is_strong && candidate == current_etag
            }
            Some(ParsedIfRange::WeakTag | ParsedIfRange::Date) => false,
        }
    }

    pub(super) fn requires_existing_representation(&self) -> bool {
        self.if_match.is_some()
    }

    /// 当所有实体标签条件均为通配符时，无需生成正文即可判定现有动态表示的 HEAD 条件。
    /// `None` 表示存在具体标签，调用方必须生成精确表示并调用 [`Self::evaluate_read`]；这些
    /// 动态视图不声明 Last-Modified，因此仅日期字段按规范忽略。
    ///
    /// Decide an existing generated representation's HEAD condition without materializing its
    /// bytes when every entity-tag condition is a wildcard. `None` means a concrete tag requires
    /// the caller to generate the exact representation and use [`Self::evaluate_read`]. Date-only
    /// fields are ignored because these generated views do not declare Last-Modified.
    pub(super) fn evaluate_generated_head_without_body(&self) -> Option<ReadPreconditionOutcome> {
        if self.if_match.as_ref().is_some_and(|value| !value.is_any()) {
            return None;
        }
        if let Some(if_none_match) = &self.if_none_match {
            if *if_none_match != IfNoneMatch::any() {
                return None;
            }
            return Some(ReadPreconditionOutcome::NotModified);
        }
        Some(ReadPreconditionOutcome::Proceed)
    }
}

/// 只为选择/修改文件系统表示的方法解析条件字段，扩展/控制方法按自身契约忽略。
/// Parse conditional fields only for methods selecting or mutating representations.
pub(super) const fn method_uses_preconditions(method: ResourceMethod) -> bool {
    method.uses_preconditions()
}

fn parse_single<H>(
    headers: &HeaderMap<HeaderValue>,
    name: &HeaderName,
    display_name: &'static str,
) -> Result<Option<H>, InvalidPrecondition>
where
    H: headers::Header,
{
    if headers.get_all(name).iter().count() > 1 {
        return Err(InvalidPrecondition::new(display_name));
    }
    headers
        .typed_try_get::<H>()
        .map_err(|_| InvalidPrecondition::new(display_name))
}

fn parse_if_range(
    headers: &HeaderMap<HeaderValue>,
) -> Result<Option<ParsedIfRange>, InvalidPrecondition> {
    let mut values = headers.get_all(IF_RANGE).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(InvalidPrecondition::new("If-Range"));
    }

    let raw = trim_http_ows(value.as_bytes());
    if raw.starts_with(b"W/") || raw.starts_with(b"\"") {
        // 中文：If-Range 的 ETag 分支只能是单标签，不是 CSV。 / English: If-Range's ETag alternative is one tag, never a CSV list.
        if entity_tag_kind(raw) != Some(false) {
            return Err(InvalidPrecondition::new("If-Range"));
        }
        let etag: ETag = std::str::from_utf8(raw)
            .map_err(|_| InvalidPrecondition::new("If-Range"))?
            .parse()
            .map_err(|_| InvalidPrecondition::new("If-Range"))?;
        if raw.starts_with(b"W/") {
            return Ok(Some(ParsedIfRange::WeakTag));
        }
        Ok(Some(ParsedIfRange::StrongTag(etag)))
    } else {
        headers
            .typed_try_get::<IfRange>()
            .map_err(|_| InvalidPrecondition::new("If-Range"))?
            .ok_or_else(|| InvalidPrecondition::new("If-Range"))?;
        Ok(Some(ParsedIfRange::Date))
    }
}

/// 解码 fuzz 二进制帧及可审阅文本种子；文本末尾换行是 framing，不属于 If-Range 值。
/// Decode binary fuzz frames and reviewable text seeds, treating terminal newline as framing.
#[cfg(any(test, feature = "fuzzing"))]
fn split_fuzz_range_frame(data: &[u8]) -> (u64, &[u8], Option<&[u8]>) {
    let textual_size = data
        .iter()
        .position(|byte| *byte == b'\n')
        .filter(|line_end| *line_end <= 20)
        .and_then(|line_end| {
            let line = std::str::from_utf8(&data[..line_end]).ok()?;
            let value = line.strip_prefix("0x").or_else(|| line.strip_prefix("0X"));
            let size = match value {
                Some(hex) if !hex.is_empty() => u64::from_str_radix(hex, 16).ok()?,
                Some(_) => return None,
                None => line.parse::<u64>().ok()?,
            };
            Some((size, line_end + 1))
        });
    let (size, fields, is_text_frame) = if let Some((size, offset)) = textual_size {
        (size, &data[offset..], true)
    } else {
        let mut size_bytes = [0u8; 8];
        let size_len = data.len().min(size_bytes.len());
        size_bytes[..size_len].copy_from_slice(&data[..size_len]);
        (
            u64::from_le_bytes(size_bytes),
            data.get(size_len..).unwrap_or_default(),
            false,
        )
    };
    // 中文：同时接受换行分隔文本种子与原生 NUL 帧。 / English: Accept newline-separated text seeds and native NUL framing.
    let split = fields.iter().position(|byte| matches!(*byte, 0 | b'\n'));
    let (range, mut if_range) = match split {
        Some(index) => (&fields[..index], Some(&fields[index + 1..])),
        None => (fields, None),
    };
    if is_text_frame
        && split.is_some_and(|index| fields[index] == b'\n')
        && let Some(value) = if_range
    {
        if_range = Some(value.strip_suffix(b"\n").unwrap_or(value));
    }
    (size, range, if_range)
}

/// 联合 fuzz Range 与 If-Range；文本种子首行为十进制/hex 大小，其他输入前 8 字节为 little-endian 大小，余部按首个 NUL/换行拆字段。
/// Fuzz Range and If-Range together using reviewable size-line seeds or an arbitrary little-endian size prefix.
#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_range_if_range(data: &[u8]) {
    const FUZZ_INPUT_MAX_BYTES: usize = 16 * 1024;
    if data.len() > FUZZ_INPUT_MAX_BYTES {
        return;
    }
    let (size, range, if_range) = split_fuzz_range_frame(data);

    if let Ok(range) = std::str::from_utf8(range)
        && let crate::utils::ByteRangeParse::Satisfiable(ranges) =
            crate::utils::parse_http_range(range, size)
    {
        assert!(!ranges.is_empty());
        assert!(ranges.len() <= crate::utils::MAX_HTTP_RANGE_MEMBERS);
        for (start, end) in ranges {
            assert!(start <= end);
            assert!(end < size);
        }
    }

    if let Some(if_range) = if_range
        && let Ok(value) = HeaderValue::from_bytes(if_range)
    {
        let mut headers = HeaderMap::new();
        headers.insert(IF_RANGE, value);
        if let Ok(parsed) = ParsedPreconditions::parse(&headers) {
            let current: ETag = "\"ram-fuzz-etag\""
                .parse()
                .expect("static fuzz ETag must remain valid");
            let _ = parsed.if_range_matches(&current, true);
            assert!(!parsed.if_range_matches(&current, false));
        }
    }
}

fn validate_entity_tag_condition(
    headers: &HeaderMap<HeaderValue>,
    name: &HeaderName,
    display_name: &'static str,
) -> Result<(), InvalidPrecondition> {
    let mut observed_kind = None;
    for value in headers.get_all(name) {
        let Some(kind) = entity_tag_kind(value.as_bytes()) else {
            return Err(InvalidPrecondition::new(display_name));
        };
        if let Some(previous) = observed_kind {
            // 中文：wildcard 必须独占完整字段，与任何其他行（含另一个 wildcard）组合均无效。
            // English: Wildcard must be the complete field and cannot combine with another line.
            if previous || kind {
                return Err(InvalidPrecondition::new(display_name));
            }
        }
        observed_kind = Some(kind);
    }
    Ok(())
}

/// true 表示 wildcard，false 表示非空严格 tag 列表。 / True is wildcard; false is a non-empty strict tag list.
fn entity_tag_kind(value: &[u8]) -> Option<bool> {
    let value = trim_http_ows(value);
    if value == b"*" {
        return Some(true);
    }
    if value.is_empty() {
        return None;
    }

    let mut index = 0usize;
    loop {
        while matches!(value.get(index), Some(b' ' | b'\t')) {
            index += 1;
        }
        if value.get(index..index.checked_add(2)?) == Some(b"W/") {
            index += 2;
        }
        if value.get(index) != Some(&b'"') {
            return None;
        }
        index += 1;
        loop {
            let byte = *value.get(index)?;
            if byte == b'"' {
                index += 1;
                break;
            }
            // 中文：headers crate 不能可靠比较非 UTF-8 列表；服务端 validator 为 ASCII，故拒绝 obs-text，不能让 decoder 静默给空列表。
            // English: Server validators are ASCII; reject obs-text rather than relying on unreliable non-UTF-8 list decoding.
            if !(byte == 0x21 || (0x23..=0x7e).contains(&byte)) {
                return None;
            }
            index += 1;
        }
        while matches!(value.get(index), Some(b' ' | b'\t')) {
            index += 1;
        }
        if index == value.len() {
            return Some(false);
        }
        if value.get(index) != Some(&b',') {
            return None;
        }
        index += 1;
        if trim_http_ows(value.get(index..)?).is_empty() {
            return None;
        }
    }
}

fn trim_http_ows(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::{IF_MATCH, IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_RANGE};

    #[test]
    fn textual_fuzz_frame_does_not_include_the_file_terminator_in_if_range() {
        let (size, range, if_range) = split_fuzz_range_frame(b"16\nbytes=0-3\n\"ram-fuzz-etag\"\n");
        assert_eq!(size, 16);
        assert_eq!(range, b"bytes=0-3");
        assert_eq!(if_range, Some(b"\"ram-fuzz-etag\"".as_slice()));

        let mut headers = HeaderMap::new();
        headers.insert(
            IF_RANGE,
            HeaderValue::from_bytes(if_range.unwrap()).unwrap(),
        );
        let parsed = ParsedPreconditions::parse(&headers).unwrap();
        let current: ETag = "\"ram-fuzz-etag\"".parse().unwrap();
        assert!(parsed.if_range_matches(&current, true));
    }

    #[test]
    fn strict_tags_accept_lists_but_reject_wildcard_mixing_and_obs_text() {
        let mut headers = HeaderMap::new();
        headers.append(IF_NONE_MATCH, HeaderValue::from_static("\"one\""));
        headers.append(IF_NONE_MATCH, HeaderValue::from_static("W/\"two,three\""));
        let parsed = ParsedPreconditions::parse(&headers).unwrap();
        let current: ETag = "\"two,three\"".parse().unwrap();
        assert_eq!(
            parsed.evaluate_read(&current, None),
            ReadPreconditionOutcome::NotModified
        );

        headers.append(IF_NONE_MATCH, HeaderValue::from_static("*"));
        assert!(ParsedPreconditions::parse(&headers).is_err());

        let mut headers = HeaderMap::new();
        headers.insert(
            IF_MATCH,
            HeaderValue::from_bytes(b"\"current\", \"\xff\"").unwrap(),
        );
        assert!(ParsedPreconditions::parse(&headers).is_err());
    }

    #[test]
    fn duplicate_single_value_fields_are_rejected() {
        let mut headers = HeaderMap::new();
        headers.append(
            IF_MODIFIED_SINCE,
            HeaderValue::from_static("Sat, 29 Oct 1994 19:43:31 GMT"),
        );
        headers.append(
            IF_MODIFIED_SINCE,
            HeaderValue::from_static("Sun, 30 Oct 1994 19:43:31 GMT"),
        );
        assert!(ParsedPreconditions::parse(&headers).is_err());

        let mut headers = HeaderMap::new();
        headers.append(IF_RANGE, HeaderValue::from_static("\"one\""));
        headers.append(IF_RANGE, HeaderValue::from_static("\"two\""));
        assert!(ParsedPreconditions::parse(&headers).is_err());
    }

    #[test]
    fn generated_head_fast_path_only_decides_wildcards_without_body_bytes() {
        let parsed = ParsedPreconditions::default();
        assert_eq!(
            parsed.evaluate_generated_head_without_body(),
            Some(ReadPreconditionOutcome::Proceed)
        );

        let mut headers = HeaderMap::new();
        headers.insert(IF_MATCH, HeaderValue::from_static("*"));
        let parsed = ParsedPreconditions::parse(&headers).unwrap();
        assert_eq!(
            parsed.evaluate_generated_head_without_body(),
            Some(ReadPreconditionOutcome::Proceed)
        );

        headers.insert(IF_NONE_MATCH, HeaderValue::from_static("*"));
        let parsed = ParsedPreconditions::parse(&headers).unwrap();
        assert_eq!(
            parsed.evaluate_generated_head_without_body(),
            Some(ReadPreconditionOutcome::NotModified)
        );

        headers.remove(IF_MATCH);
        headers.insert(IF_NONE_MATCH, HeaderValue::from_static("\"specific\""));
        let parsed = ParsedPreconditions::parse(&headers).unwrap();
        assert_eq!(parsed.evaluate_generated_head_without_body(), None);

        headers.remove(IF_NONE_MATCH);
        headers.insert(IF_MATCH, HeaderValue::from_static("\"specific\""));
        let parsed = ParsedPreconditions::parse(&headers).unwrap();
        assert_eq!(parsed.evaluate_generated_head_without_body(), None);
    }

    #[test]
    fn if_range_distinguishes_opaque_commas_csv_weak_tags_and_obs_text() {
        let current: ETag = "\"foo,bar\"".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(IF_RANGE, HeaderValue::from_static("\"foo,bar\""));
        let parsed = ParsedPreconditions::parse(&headers).unwrap();
        assert!(parsed.if_range_matches(&current, true));

        headers.insert(IF_RANGE, HeaderValue::from_static("\"one\", \"two\""));
        assert!(ParsedPreconditions::parse(&headers).is_err());

        headers.insert(IF_RANGE, HeaderValue::from_static("W/\"foo,bar\""));
        let parsed = ParsedPreconditions::parse(&headers).unwrap();
        assert!(!parsed.if_range_matches(&current, true));

        headers.insert(
            IF_RANGE,
            HeaderValue::from_bytes(b"\"opaque-\xff\"").unwrap(),
        );
        assert!(ParsedPreconditions::parse(&headers).is_err());
    }

    #[test]
    fn rfc_priority_keeps_etag_fields_authoritative() {
        let current: ETag = "\"current\"".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(IF_MATCH, HeaderValue::from_static("\"current\""));
        headers.insert(
            IF_UNMODIFIED_SINCE,
            HeaderValue::from_static("Sat, 01 Jan 2000 00:00:00 GMT"),
        );
        let parsed = ParsedPreconditions::parse(&headers).unwrap();
        assert_eq!(
            parsed.evaluate_read(
                &current,
                Some(LastModified::from(std::time::SystemTime::now()))
            ),
            ReadPreconditionOutcome::Proceed
        );
    }
}
