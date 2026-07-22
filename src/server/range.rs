//! HTTP 多区间 Range 下载（`multipart/byteranges`）的实现。
//!
//! 当客户端一次请求多个区间（如 `Range: bytes=0-99,200-299`）时，
//! 响应体是若干"分部"：每部分由边界行（boundary）、子头部、区间数据组成，
//! 最后以结束边界收尾。本模块负责：
//! - 限制区间数量与总字节数，防止恶意构造大量小区间放大响应（拒绝服务）；
//! - 精确预计算 Content-Length（分部头也算在内）；
//! - 用异步状态流边读文件边发送响应体。
//!
//! ## 本模块的 Rust 知识点
//! - **`stream::unfold`**：把文件、区间迭代器与当前阶段保存在状态中，
//!   每次异步推进只产出一个数据帧，因此不会缓存完整文件区间。
//! - **`checked_add`**：算术溢出安全。u64 加法在恶意输入下可能回绕，
//!   `checked_add` 溢出时返回 `None` 而不是错误结果。
//!
//! HTTP multipart Range download (`multipart/byteranges`) implementation.
//!
//! When a client requests multiple ranges at once (for example,
//! `Range: bytes=0-99,200-299`), the response body contains parts made of a boundary line,
//! per-part headers, and range data, followed by a closing boundary. This module:
//! - limits range count and aggregate bytes so malicious collections of tiny ranges cannot amplify
//!   a response into denial of service;
//! - precomputes the exact Content-Length, including part headers;
//! - streams file data through an asynchronous state machine.
//!
//! ## Rust concepts in this module
//! - **`stream::unfold`** stores the file, range iterator, and current phase as state, producing one
//!   frame per asynchronous step instead of buffering complete ranges.
//! - **`checked_add`** provides overflow-safe arithmetic: hostile u64 additions return `None` on
//!   overflow instead of wrapping into an incorrect result.

use anyhow::{Result, anyhow};
use bytes::Bytes;
use futures_util::Stream;
use hyper::body::Frame;
use tokio::io::{AsyncReadExt, AsyncSeekExt, SeekFrom};

use super::filesystem::GuardedBlockingFile;

const CHUNK_SIZE: usize = 8192;

/// 单请求最大区间数。 / Maximum ranges per request.
pub const MAX_MULTIPART_RANGES: usize = 16;
/// 所有区间合计最大 64 MiB。 / Maximum aggregate range bytes (64 MiB).
pub const MAX_MULTIPART_RANGE_BYTES: u64 = 64 * 1024 * 1024;

/// 多区间是否超限，超出返回 416。 / Whether a multi-range request exceeds protection limits (416).
pub fn multipart_ranges_exceed_limits(ranges: &[(u64, u64)]) -> bool {
    if ranges.len() > MAX_MULTIPART_RANGES {
        return true;
    }

    // 中文：try_fold + checked_add 使任一步溢出变为 None。 / English: `try_fold` plus `checked_add` turns any overflow into None.
    let total = ranges.iter().try_fold(0u64, |total, (start, end)| {
        total.checked_add(end - start + 1)
    });

    total
        .map(|total| total > MAX_MULTIPART_RANGE_BYTES)
        .unwrap_or(true)
}

/// 预计算整个 multipart 响应体的精确字节数：
/// 每个分部 = 分部头 + 区间数据 + 结尾 CRLF，最后再加结束边界。
/// 必须与 [`multipart_body`] 实际产出的字节严格一致，
/// 否则 Content-Length 不匹配会导致客户端截断或挂起。
/// Precompute exact multipart length including headers, CRLF, data, and final boundary; it must match the stream exactly.
pub fn multipart_content_length(
    ranges: &[(u64, u64)],
    boundary: &str,
    content_type: &str,
    size: u64,
) -> u64 {
    let parts_len = ranges.iter().fold(0u64, |total, &(start, end)| {
        total
            + part_header(boundary, content_type, start, end, size).len() as u64
            + (end - start + 1)
            + 2
    });
    parts_len + final_boundary(boundary).len() as u64
}

/// 生成流式响应体：逐区间 seek 到起点、按 8KB 块读文件并产出数据帧。
/// 参数都按值（owned）传入，因为这个流的生命周期比请求处理函数更长
/// （`'static` 约束），不能借用局部变量。
/// Stream by seeking each range and yielding 8 KiB chunks; owned inputs satisfy the body's `'static` lifetime.
pub fn multipart_body(
    file: GuardedBlockingFile,
    ranges: Vec<(u64, u64)>,
    boundary: String,
    content_type: String,
    size: u64,
) -> impl Stream<Item = Result<Frame<Bytes>>> + Send + 'static {
    enum Phase {
        Next,
        Seek { start: u64, remaining: u64 },
        Data { remaining: u64 },
        Separator,
        Done,
    }

    struct State {
        file: GuardedBlockingFile,
        ranges: std::vec::IntoIter<(u64, u64)>,
        boundary: String,
        content_type: String,
        size: u64,
        buffer: Vec<u8>,
        phase: Phase,
    }

    let state = State {
        file,
        ranges: ranges.into_iter(),
        boundary,
        content_type,
        size,
        buffer: vec![0; CHUNK_SIZE],
        phase: Phase::Next,
    };
    futures_util::stream::unfold(state, |mut state| async move {
        loop {
            let phase = std::mem::replace(&mut state.phase, Phase::Done);
            match phase {
                Phase::Next => {
                    let Some((start, end)) = state.ranges.next() else {
                        let frame = Frame::data(Bytes::from(final_boundary(&state.boundary)));
                        return Some((Ok(frame), state));
                    };
                    let header =
                        part_header(&state.boundary, &state.content_type, start, end, state.size);
                    state.phase = Phase::Seek {
                        start,
                        remaining: end - start + 1,
                    };
                    return Some((Ok(Frame::data(Bytes::from(header))), state));
                }
                Phase::Seek { start, remaining } => {
                    if let Err(error) = state.file.seek(SeekFrom::Start(start)).await {
                        return Some((Err(error.into()), state));
                    }
                    state.phase = Phase::Data { remaining };
                }
                Phase::Data { remaining } => {
                    let read_len = remaining.min(CHUNK_SIZE as u64) as usize;
                    let bytes_read = match state.file.read(&mut state.buffer[..read_len]).await {
                        Ok(0) => {
                            let error = anyhow!("file was truncated while streaming a byte range");
                            return Some((Err(error), state));
                        }
                        Ok(bytes_read) => bytes_read,
                        Err(error) => return Some((Err(error.into()), state)),
                    };
                    let remaining = remaining - bytes_read as u64;
                    state.phase = if remaining == 0 {
                        Phase::Separator
                    } else {
                        Phase::Data { remaining }
                    };
                    let frame = Frame::data(Bytes::copy_from_slice(&state.buffer[..bytes_read]));
                    return Some((Ok(frame), state));
                }
                Phase::Separator => {
                    state.phase = Phase::Next;
                    return Some((Ok(Frame::data(Bytes::from_static(b"\r\n"))), state));
                }
                Phase::Done => return None,
            }
        }
    })
}

/// 单分部头（边界、两个子头、空行）。 / One part header: boundary, two subheaders, and blank line.
fn part_header(boundary: &str, content_type: &str, start: u64, end: u64, size: u64) -> String {
    format!(
        "--{boundary}\r\nContent-Type: {content_type}\r\nContent-Range: bytes {start}-{end}/{size}\r\n\r\n",
    )
}

/// 结束边界。 / Closing `--boundary--` marker.
fn final_boundary(boundary: &str) -> String {
    format!("--{boundary}--\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multipart_count_and_byte_budgets_are_inclusive_at_the_boundary() {
        for (count, exceeds) in [(15, false), (16, false), (17, true)] {
            let ranges = vec![(0, 0); count];
            assert_eq!(multipart_ranges_exceed_limits(&ranges), exceeds, "{count}");
        }

        for (bytes, exceeds) in [
            (MAX_MULTIPART_RANGE_BYTES - 1, false),
            (MAX_MULTIPART_RANGE_BYTES, false),
            (MAX_MULTIPART_RANGE_BYTES + 1, true),
        ] {
            let ranges = [(0, bytes - 1)];
            assert_eq!(
                multipart_ranges_exceed_limits(&ranges),
                exceeds,
                "{bytes} bytes"
            );
        }
    }
}
