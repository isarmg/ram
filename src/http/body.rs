//! HTTP 请求/响应体的底层适配工具。
//!
//! hyper 1.x 中请求体是 `Incoming`（一帧一帧到达的流），而 tokio 的 IO 工具
//! 操作的是 `AsyncRead`/`Stream`。本模块提供两者之间的"转接头"：
//! - [`IncomingStream`]：把 hyper 的请求体适配成 `Stream<Item = Bytes>`，
//!   供上传处理用 `StreamReader` 按字节读取；
//! - [`LengthLimitedStream`]：只读取前 N 个字节的流，用于 Range 下载；
//! - [`body_full`]：把一段完整内存数据包装成响应体。
//!
//! 响应包装器还会保留准入 permit、观察真实传输终态，并执行响应局部进度期限。
//!
//! ## 本模块的 Rust 知识点（进阶）
//! - **手写 `Stream`/`poll` 状态机**：`async fn` 是编译器帮你生成状态机；
//!   这里因为要实现 trait（`Stream::poll_next`），只能手写"轮询"逻辑。
//!   `Poll::Pending` 表示"数据还没到，稍后再来问"，`Poll::Ready` 表示有结果。
//! - **`Pin` 与 `pin_project_lite`**：自引用的异步类型不能随意移动，
//!   `Pin` 在类型层面固定它；`pin_project!` 宏帮我们安全地访问被 Pin
//!   结构体的字段（否则需要 unsafe）。
//! - **`BytesMut`/`Bytes`**：字节缓冲区，`split`/`freeze` 可以零拷贝地
//!   把写缓冲转成只读的 `Bytes` 交给下游。
//!
//! ## English overview
//! Low-level adapters for HTTP request/response bodies.
//!
//! In Hyper 1.x, an `Incoming` request body arrives as a stream of frames, while Tokio I/O tools
//! operate on `AsyncRead`/`Stream`. This module provides adapters between them:
//! - [`IncomingStream`] adapts a Hyper request body into `Stream<Item = Bytes>` so upload handling can
//!   consume bytes through `StreamReader`;
//! - [`LengthLimitedStream`] reads only the first N bytes for Range downloads;
//! - [`body_full`] wraps one complete in-memory value as a response body.
//!
//! Response wrappers also retain admission permits, observe real delivery outcomes, and enforce
//! response-local progress deadlines.
//!
//! ## Rust concepts in this module (advanced)
//! - **Handwritten `Stream`/`poll` state machines**: `async fn` normally lets the compiler generate a
//!   state machine, but implementing `Stream::poll_next` requires polling explicitly. `Poll::Pending`
//!   means “ask again later”; `Poll::Ready` carries a result.
//! - **`Pin` and `pin_project_lite`**: self-referential asynchronous types cannot move freely. `Pin`
//!   fixes them at the type level, and `pin_project!` exposes pinned fields safely without `unsafe`.
//! - **`BytesMut`/`Bytes`**: `split`/`freeze` converts a writable byte buffer into read-only `Bytes`
//!   for downstream consumers without copying.

use bytes::{Bytes, BytesMut};
use futures_util::Stream;
use http_body_util::{BodyExt, combinators::BoxBody};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::AsyncRead;
use tokio::sync::{Notify, OwnedSemaphorePermit, watch};
use tokio::task::JoinHandle;
use tokio_util::io::poll_read_buf;

const FULL_BODY_CHUNK_SIZE: usize = 64 * 1024;
const MAX_BODY_ERROR_LENGTH: usize = 512;

/// 把 Hyper `Incoming` 适配成字节流。 / Adapt Hyper `Incoming` into `Stream<Item = Result<Bytes>>`.
#[derive(Debug)]
pub struct IncomingStream {
    inner: Incoming,
}

impl IncomingStream {
    pub fn new(inner: Incoming) -> Self {
        Self { inner }
    }
}

impl Stream for IncomingStream {
    type Item = Result<Bytes, anyhow::Error>;

    #[inline]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            // 中文：`ready!` 在内部仍 Pending 时直接向上传播。 / English: `ready!` propagates an inner Pending immediately.
            match futures_util::ready!(Pin::new(&mut self.inner).poll_frame(cx)?) {
                // 中文：只产出 HTTP 数据帧；trailers 被跳过并继续轮询。
                // English: Yield only data frames; skip trailers and keep polling.
                Some(frame) => match frame.into_data() {
                    Ok(data) => return Poll::Ready(Some(Ok(data))),
                    Err(_frame) => {}
                },
                // 中文：None 表示正文流结束。 / English: None marks request-body end of stream.
                None => return Poll::Ready(None),
            }
        }
    }
}

pin_project_lite::pin_project! {
    /// 只允许读出前 `remaining` 个字节的流。
    ///
    /// 用于单区间 Range 下载：文件先 seek 到区间起点，再用本流限制
    /// 只发送区间长度那么多字节。读够后把 `reader` 置为 `None`，
    /// 提前关闭底层文件。
    ///
    /// `remaining` 用 `u64`：区间长度来自文件大小，在 32 位平台上
    /// 用 `usize` 存会截断（Range 下载大于 4GB 的区间时限额回绕）。
    /// Stream at most `remaining` bytes after Range seek, then close the reader.
    /// `u64` avoids truncating file-derived lengths on 32-bit platforms.
    pub struct LengthLimitedStream<R> {
        #[pin]
        reader: Option<R>,
        remaining: u64,
        buf: BytesMut,
    }
}

impl<R> LengthLimitedStream<R> {
    pub fn new(reader: R, limit: u64) -> Self {
        Self {
            reader: Some(reader),
            remaining: limit,
            buf: BytesMut::new(),
        }
    }
}

impl<R: AsyncRead> Stream for LengthLimitedStream<R> {
    type Item = std::io::Result<Bytes>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // 中文：`project()` 把 Pin<Self> 安全投影为各字段引用。 / English: `project()` safely projects pinned Self into field references.
        let mut this = self.as_mut().project();

        // 中文：预算耗尽后关闭 reader 并结束。 / English: Close the reader and finish when the byte budget is exhausted.
        if *this.remaining == 0 {
            self.project().reader.set(None);
            return Poll::Ready(None);
        }

        let reader = match this.reader.as_pin_mut() {
            Some(r) => r,
            None => return Poll::Ready(None),
        };

        // 中文：上次 split 后重新预留与全文件下载一致的 64 KiB 块；旧 4 KiB 会显著压低 Range 吞吐。
        // English: Re-reserve the shared 64 KiB download chunk after split; the former 4 KiB chunk unnecessarily reduced Range throughput.
        if this.buf.capacity() == 0 {
            this.buf.reserve(crate::server::BUF_SIZE);
        }

        match poll_read_buf(reader, cx, &mut this.buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => {
                self.project().reader.set(None);
                Poll::Ready(Some(Err(err)))
            }
            // 中文：0 字节表示提前 EOF。 / English: A zero-byte read is early EOF.
            Poll::Ready(Ok(0)) => {
                self.project().reader.set(None);
                Poll::Ready(None)
            }
            Poll::Ready(Ok(_)) => {
                // 中文：split 零拷贝取走数据，截到剩余预算，再 freeze 为只读 Bytes。
                // English: Split without copying, truncate to budget, then freeze into read-only Bytes.
                let mut chunk = this.buf.split();
                // 中文：chunk.len() 为 usize，取 min 后转换安全。 / English: After min with `chunk.len()`, the value necessarily fits usize.
                let chunk_size = (*this.remaining).min(chunk.len() as u64) as usize;
                chunk.truncate(chunk_size);
                *this.remaining -= chunk_size as u64;
                Poll::Ready(Some(Ok(chunk.freeze())))
            }
        }
    }
}

/// 把一段完整的内存数据（字符串、字节等）包装成响应体。
/// `impl Into<Bytes>` 使调用方可以直接传 `String`、`&'static str`、`Vec<u8>` 等。
/// Wrap in-memory data as a response body; `Into<Bytes>` accepts strings and byte vectors.
pub fn body_full(content: impl Into<hyper::body::Bytes>) -> BoxBody<Bytes, anyhow::Error> {
    ChunkedFullBody {
        remaining: content.into(),
    }
    .boxed()
}

/// 固定帧大小的内存正文，避免协议层在流控前排队整块大分配或过早释放请求准入；切片仍零拷贝并有精确 size hint。
/// A bounded-frame in-memory body makes backpressure effective without losing zero-copy slicing or exact size hints.
struct ChunkedFullBody {
    remaining: Bytes,
}

impl Body for ChunkedFullBody {
    type Data = Bytes;
    type Error = anyhow::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.remaining.is_empty() {
            return Poll::Ready(None);
        }
        let chunk_len = self.remaining.len().min(FULL_BODY_CHUNK_SIZE);
        let chunk = self.remaining.split_to(chunk_len);
        Poll::Ready(Some(Ok(Frame::data(chunk))))
    }

    fn is_end_stream(&self) -> bool {
        self.remaining.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining.len() as u64)
    }
}

pin_project_lite::pin_project! {
    /// 在响应完整流式生命周期内持有全部请求准入 permit 的正文包装器。
    /// Response-body wrapper retaining all request-admission permits for the complete stream lifetime.
    ///
    /// handler 返回 Response 不等于文件/归档传输结束；本包装器只在 EOS/错误释放，Drop 覆盖取消/断连。
    /// Returning a response does not finish its stream; release at EOS/error, with Drop covering cancellation/teardown.
    struct RequestPermitBody<B> {
        #[pin]
        inner: B,
        permits: Vec<OwnedSemaphorePermit>,
    }
}

impl<B> RequestPermitBody<B> {
    fn new(inner: B, permits: Vec<OwnedSemaphorePermit>) -> Self {
        Self { inner, permits }
    }
}

impl<B> Body for RequestPermitBody<B>
where
    B: Body,
{
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();
        let polled = this.inner.as_mut().poll_frame(cx);
        if let Poll::Ready(result) = &polled {
            // 中文：inner 声称某帧为最后一帧时不能释放，Hyper 仍可能在 socket 背压后持有它；
            // Body 边界只以 None、错误或 Drop 为生命周期终点。
            // English: Do not release on a claimed last frame while Hyper may
            // retain it behind flow control; only None, error, or Drop is terminal here.
            let finished = result.is_none() || result.as_ref().is_some_and(Result::is_err);
            if finished {
                this.permits.clear();
            }
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// 把已取得全局请求 permit 绑定到响应正文。 / Attach an acquired global request permit to a response body.
#[cfg(test)]
pub(crate) fn body_with_request_permit(
    body: BoxBody<Bytes, anyhow::Error>,
    permit: OwnedSemaphorePermit,
) -> BoxBody<Bytes, anyhow::Error> {
    body_with_request_permits(body, vec![permit])
}

/// 把已取得的来源/全局/账号 permit 全部绑定到响应。 / Attach all acquired source/global/account permits to a response.
pub(crate) fn body_with_request_permits(
    body: BoxBody<Bytes, anyhow::Error>,
    permits: Vec<OwnedSemaphorePermit>,
) -> BoxBody<Bytes, anyhow::Error> {
    RequestPermitBody::new(body, permits).boxed()
}

/// Hyper 消费响应正文时观察到的终态。 / Terminal state observed while Hyper consumes a response body.
///
/// handler 成功只说明响应头状态；此状态记录随后正文向协议层流送的真实结果。
/// Handler success covers only the head; this records the later body-stream outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResponseBodyOutcome {
    Complete,
    BodyError,
    Truncated,
    LengthMismatch,
    DownstreamCancelled,
}

impl ResponseBodyOutcome {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::BodyError => "body_error",
            Self::Truncated => "truncated",
            Self::LengthMismatch => "length_mismatch",
            Self::DownstreamCancelled => "downstream_cancelled",
        }
    }
}

/// 被观察正文达到终态时恰好传递一次的信息。 / Information delivered exactly once at observed body termination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResponseBodyCompletion {
    pub(crate) outcome: ResponseBodyOutcome,
    /// 产给协议层的数据帧字节数，trailers 不计。 / Bytes yielded in data frames; trailers do not contribute.
    pub(crate) body_bytes: u64,
    /// 仅 BodyError 携带的有界单行错误。 / Bounded single-line error present only for `BodyError`.
    pub(crate) error: Option<String>,
}

type ResponseBodyObserver = Box<dyn FnOnce(ResponseBodyCompletion) + Send + 'static>;

/// 报告正文真实流式结果的响应包装器。 / Response-body wrapper reporting the real streaming outcome.
///
/// observer 在 poll_frame/Drop 内联运行，必须非阻塞；mutex 让正文满足 BoxBody 的 Sync，
/// 无需一次性回调本身实现 Sync。
/// The observer runs inline and must not block; a mutex preserves `Sync` without requiring the callback to be `Sync`.
struct ObservedResponseBody {
    inner: BoxBody<Bytes, anyhow::Error>,
    expected_length: Option<u64>,
    body_bytes: u64,
    observer: Mutex<Option<ResponseBodyObserver>>,
    finalized: bool,
}

impl ObservedResponseBody {
    fn new<F>(
        inner: BoxBody<Bytes, anyhow::Error>,
        expected_length: Option<u64>,
        observer: F,
    ) -> Self
    where
        F: FnOnce(ResponseBodyCompletion) + Send + 'static,
    {
        Self {
            inner,
            expected_length,
            body_bytes: 0,
            observer: Mutex::new(Some(Box::new(observer))),
            finalized: false,
        }
    }

    fn finish(&mut self, outcome: ResponseBodyOutcome, error: Option<String>) {
        if self.finalized {
            return;
        }
        self.finalized = true;

        // 中文：包装器独占访问时 get_mut 避免流式热路径加锁；回调取出后才执行，故恢复中毒 mutex 安全。
        // English: Exclusive wrapper access uses get_mut to avoid locking; poison recovery is safe because callbacks run after extraction.
        let observer = self
            .observer
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(observer) = observer {
            observer(ResponseBodyCompletion {
                outcome,
                body_bytes: self.body_bytes,
                error,
            });
        }
    }

    fn finish_at_eof(&mut self) {
        let outcome = match self.expected_length {
            Some(expected) if self.body_bytes < expected => ResponseBodyOutcome::Truncated,
            Some(expected) if self.body_bytes > expected => ResponseBodyOutcome::LengthMismatch,
            Some(_) | None => ResponseBodyOutcome::Complete,
        };
        self.finish(outcome, None);
    }

    fn outcome_on_drop(&self) -> ResponseBodyOutcome {
        match self.expected_length {
            // 中文：达到声明 wire length 后 Hyper 可停止轮询，正文可能从不返回 None，流正文也未必更新 is_end_stream；
            // 因而已知长度时精确交付量是权威完成信号。
            // English: Hyper may stop at declared length without polling None;
            // exact delivered length is therefore authoritative when known.
            Some(expected) if expected == self.body_bytes => ResponseBodyOutcome::Complete,
            // 中文：producer 表示结束后，已知 wire length 的短/长传输是表示失败，不是下游取消。
            // English: Once the producer is finished, a known short/long wire length is representation failure, not cancellation.
            Some(expected) if self.inner.is_end_stream() && self.body_bytes < expected => {
                ResponseBodyOutcome::Truncated
            }
            Some(expected) if self.body_bytes > expected => ResponseBodyOutcome::LengthMismatch,
            Some(_) => ResponseBodyOutcome::DownstreamCancelled,
            // 中文：无期望长度时只有 inner 显式结束能区分完成与下游取消。
            // English: Without expected length, only explicit inner end distinguishes completion from downstream cancellation.
            None if self.inner.is_end_stream() => ResponseBodyOutcome::Complete,
            None => ResponseBodyOutcome::DownstreamCancelled,
        }
    }
}

impl Body for ObservedResponseBody {
    type Data = Bytes;
    type Error = anyhow::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let polled = Pin::new(&mut self.inner).poll_frame(cx);
        match &polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    self.body_bytes = self.body_bytes.saturating_add(data.len() as u64);
                }
            }
            Poll::Ready(Some(Err(error))) => {
                let error = bounded_body_error(error);
                self.finish(ResponseBodyOutcome::BodyError, Some(error));
            }
            Poll::Ready(None) => self.finish_at_eof(),
            Poll::Pending => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for ObservedResponseBody {
    fn drop(&mut self) {
        if self.finalized {
            return;
        }

        let outcome = self.outcome_on_drop();
        self.finish(outcome, None);
    }
}

fn bounded_body_error(error: &anyhow::Error) -> String {
    // 中文：alternate 格式保留 anyhow 完整因果链，下方清理和字节上限仍防多行/日志放大。
    // English: Alternate formatting retains the cause chain; sanitization and byte bounds prevent multiline amplification.
    let raw = format!("{error:#}");
    let mut bounded = String::with_capacity(raw.len().min(MAX_BODY_ERROR_LENGTH));
    let mut truncated = false;

    for character in raw.chars() {
        // 中文：错误不得伪造访问日志行或注入终端控制；单字节替换也让预算可预测。
        // English: Prevent forged log lines/terminal controls; one-byte replacement keeps the bound predictable.
        let character = if character.is_control() {
            ' '
        } else {
            character
        };
        if bounded.len() + character.len_utf8() > MAX_BODY_ERROR_LENGTH {
            truncated = true;
            break;
        }
        bounded.push(character);
    }

    if truncated {
        const ELLIPSIS: &str = "…";
        while bounded.len() + ELLIPSIS.len() > MAX_BODY_ERROR_LENGTH {
            bounded.pop();
        }
        bounded.push_str(ELLIPSIS);
    }
    bounded
}

/// 给响应正文绑定一次性完成 observer。 / Attach a one-shot completion observer to a response body.
pub(crate) fn body_with_completion_observer<F>(
    body: BoxBody<Bytes, anyhow::Error>,
    expected_length: Option<u64>,
    observer: F,
) -> BoxBody<Bytes, anyhow::Error>
where
    F: FnOnce(ResponseBodyCompletion) + Send + 'static,
{
    ObservedResponseBody::new(body, expected_length, observer).boxed()
}

/// 响应局部输出进度 watchdog。 / Response-local output progress watchdog.
///
/// socket 背压后 Hyper 可能暂停轮询正文，因此 `poll_frame` 内的计时器无法可靠触发；
/// 此包装器用独立任务按响应帧刷新 deadline，超时后通知连接驱动终止 Hyper future。
/// An independent task enforces per-response progress even when socket backpressure stops body
/// polling.
struct ResponseWriteIdleBody {
    inner: BoxBody<Bytes, anyhow::Error>,
    progress: Option<watch::Sender<u64>>,
    monitor: Option<JoinHandle<()>>,
}

impl ResponseWriteIdleBody {
    fn new(
        inner: BoxBody<Bytes, anyhow::Error>,
        timeout: Duration,
        connection_timeout: Arc<Notify>,
    ) -> Self {
        let (progress, mut observed) = watch::channel(0u64);
        let monitor = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    changed = observed.changed() => {
                        if changed.is_err() {
                            return;
                        }
                    }
                    _ = tokio::time::sleep(timeout) => {
                        connection_timeout.notify_one();
                        return;
                    }
                }
            }
        });
        Self {
            inner,
            progress: Some(progress),
            monitor: Some(monitor),
        }
    }

    fn record_progress(&self) {
        if let Some(progress) = &self.progress {
            let next = progress.borrow().wrapping_add(1);
            progress.send_replace(next);
        }
    }

    fn stop_monitor(&mut self) {
        self.progress.take();
        if let Some(monitor) = self.monitor.take() {
            monitor.abort();
        }
    }
}

impl Body for ResponseWriteIdleBody {
    type Data = Bytes;
    type Error = anyhow::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let polled = Pin::new(&mut self.inner).poll_frame(cx);
        match &polled {
            Poll::Ready(Some(Ok(frame))) => {
                let data_progress = frame.data_ref().is_some_and(|data| !data.is_empty());
                if data_progress || frame.trailers_ref().is_some() {
                    self.record_progress();
                }
            }
            Poll::Ready(Some(Err(_))) | Poll::Ready(None) => self.stop_monitor(),
            Poll::Pending => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for ResponseWriteIdleBody {
    fn drop(&mut self) {
        self.stop_monitor();
    }
}

pub(crate) fn body_with_response_write_idle_timeout(
    body: BoxBody<Bytes, anyhow::Error>,
    timeout: Duration,
    connection_timeout: Arc<Notify>,
) -> BoxBody<Bytes, anyhow::Error> {
    ResponseWriteIdleBody::new(body, timeout, connection_timeout).boxed()
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::StreamBody;
    use hyper::HeaderMap;
    use hyper::body::Frame;
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    type Completions = Arc<Mutex<Vec<ResponseBodyCompletion>>>;

    fn observe(
        body: BoxBody<Bytes, anyhow::Error>,
        expected_length: Option<u64>,
    ) -> (BoxBody<Bytes, anyhow::Error>, Completions) {
        let completions = Arc::new(Mutex::new(Vec::new()));
        let captured = completions.clone();
        let body = body_with_completion_observer(body, expected_length, move |completion| {
            captured.lock().unwrap().push(completion);
        });
        (body, completions)
    }

    fn only_completion(completions: &Completions) -> ResponseBodyCompletion {
        let completions = completions.lock().unwrap();
        assert_eq!(completions.len(), 1, "observer must run exactly once");
        completions[0].clone()
    }

    struct BodyWithoutEndSignal(Option<Bytes>);

    impl Body for BodyWithoutEndSignal {
        type Data = Bytes;
        type Error = anyhow::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(self.0.take().map(|data| Ok(Frame::data(data))))
        }

        fn is_end_stream(&self) -> bool {
            false
        }
    }

    #[tokio::test]
    async fn request_permit_is_held_until_body_eos() {
        let semaphore = std::sync::Arc::new(Semaphore::new(1));
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let body = body_with_request_permit(body_full("response"), permit);

        assert_eq!(semaphore.available_permits(), 0);
        let bytes = body.collect().await.unwrap().to_bytes();
        assert_eq!(bytes, "response");
        assert_eq!(semaphore.available_permits(), 1);
    }

    #[tokio::test]
    async fn final_frame_does_not_eagerly_release_request_permit() {
        let semaphore = std::sync::Arc::new(Semaphore::new(1));
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let mut body = body_with_request_permit(body_full("response"), permit);

        assert!(body.frame().await.unwrap().unwrap().is_data());
        assert_eq!(semaphore.available_permits(), 0);
        assert!(body.frame().await.is_none());
        assert_eq!(semaphore.available_permits(), 1);
    }

    #[tokio::test]
    async fn large_memory_body_is_split_into_bounded_frames() {
        let mut body = body_full(vec![b'x'; FULL_BODY_CHUNK_SIZE + 1]);
        let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
        let second = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(first.len(), FULL_BODY_CHUNK_SIZE);
        assert_eq!(second.len(), 1);
        assert!(body.frame().await.is_none());
    }

    #[tokio::test]
    async fn dropping_unconsumed_body_releases_request_permit() {
        let semaphore = std::sync::Arc::new(Semaphore::new(1));
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let body = body_with_request_permit(body_full("response"), permit);

        assert_eq!(semaphore.available_permits(), 0);
        drop(body);
        assert_eq!(semaphore.available_permits(), 1);
    }

    #[tokio::test]
    async fn inner_body_error_releases_request_permit() {
        let semaphore = std::sync::Arc::new(Semaphore::new(1));
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let stream = futures_util::stream::iter([Err::<Frame<Bytes>, anyhow::Error>(
            anyhow::anyhow!("body failed"),
        )]);
        let body = StreamBody::new(stream).boxed();
        let mut body = body_with_request_permit(body, permit);

        assert_eq!(semaphore.available_permits(), 0);
        assert!(body.frame().await.unwrap().is_err());
        assert_eq!(semaphore.available_permits(), 1);
    }

    #[tokio::test]
    async fn observer_reports_exact_body_at_eof() {
        let (body, completions) = observe(body_full("abc"), Some(3));
        assert_eq!(body.collect().await.unwrap().to_bytes(), "abc");
        assert_eq!(
            only_completion(&completions),
            ResponseBodyCompletion {
                outcome: ResponseBodyOutcome::Complete,
                body_bytes: 3,
                error: None,
            }
        );
    }

    #[tokio::test]
    async fn observer_reports_unknown_length_body_at_eof() {
        let (body, completions) = observe(body_full("unknown"), None);
        assert_eq!(body.collect().await.unwrap().to_bytes(), "unknown");
        assert_eq!(
            only_completion(&completions).outcome,
            ResponseBodyOutcome::Complete
        );
        assert_eq!(only_completion(&completions).body_bytes, 7);
    }

    #[tokio::test]
    async fn observer_reports_truncated_body_at_eof() {
        let (body, completions) = observe(body_full("abc"), Some(4));
        assert_eq!(body.collect().await.unwrap().to_bytes(), "abc");
        assert_eq!(
            only_completion(&completions).outcome,
            ResponseBodyOutcome::Truncated
        );
        assert_eq!(only_completion(&completions).body_bytes, 3);
    }

    #[tokio::test]
    async fn observer_reports_length_mismatch_at_eof() {
        let (body, completions) = observe(body_full("abc"), Some(2));
        assert_eq!(body.collect().await.unwrap().to_bytes(), "abc");
        assert_eq!(
            only_completion(&completions).outcome,
            ResponseBodyOutcome::LengthMismatch
        );
        assert_eq!(only_completion(&completions).body_bytes, 3);
    }

    #[tokio::test]
    async fn observer_reports_bounded_body_error_once() {
        let message = format!("bad\n{}", "x".repeat(MAX_BODY_ERROR_LENGTH * 2));
        let error = anyhow::anyhow!(message).context("stream wrapper context");
        let stream = futures_util::stream::iter([
            Ok::<Frame<Bytes>, anyhow::Error>(Frame::data(Bytes::from_static(b"a"))),
            Err(error),
        ]);
        let (mut body, completions) = observe(StreamBody::new(stream).boxed(), Some(2));

        assert!(body.frame().await.unwrap().unwrap().is_data());
        assert!(body.frame().await.unwrap().is_err());
        drop(body);

        let completion = only_completion(&completions);
        assert_eq!(completion.outcome, ResponseBodyOutcome::BodyError);
        assert_eq!(completion.body_bytes, 1);
        let error = completion.error.unwrap();
        assert!(error.len() <= MAX_BODY_ERROR_LENGTH);
        assert!(!error.chars().any(char::is_control));
        assert!(error.starts_with("stream wrapper context: bad "));
    }

    #[tokio::test]
    async fn observer_reports_unread_drop_as_downstream_cancelled() {
        let (body, completions) = observe(body_full("abc"), Some(3));
        drop(body);
        assert_eq!(
            only_completion(&completions),
            ResponseBodyCompletion {
                outcome: ResponseBodyOutcome::DownstreamCancelled,
                body_bytes: 0,
                error: None,
            }
        );
    }

    #[tokio::test]
    async fn observer_reports_partially_read_drop_as_downstream_cancelled() {
        let stream = futures_util::stream::iter([
            Ok::<Frame<Bytes>, anyhow::Error>(Frame::data(Bytes::from_static(b"a"))),
            Ok(Frame::data(Bytes::from_static(b"b"))),
        ]);
        let (mut body, completions) = observe(StreamBody::new(stream).boxed(), Some(2));
        assert!(body.frame().await.unwrap().unwrap().is_data());
        drop(body);

        assert_eq!(
            only_completion(&completions).outcome,
            ResponseBodyOutcome::DownstreamCancelled
        );
        assert_eq!(only_completion(&completions).body_bytes, 1);
    }

    #[tokio::test]
    async fn observer_reports_complete_when_dropped_after_final_frame() {
        let (mut body, completions) = observe(body_full("a"), Some(1));
        assert!(body.frame().await.unwrap().unwrap().is_data());
        drop(body);

        assert_eq!(
            only_completion(&completions).outcome,
            ResponseBodyOutcome::Complete
        );
        assert_eq!(only_completion(&completions).body_bytes, 1);
    }

    #[tokio::test]
    async fn exact_declared_length_is_complete_without_inner_end_signal() {
        let inner = BodyWithoutEndSignal(Some(Bytes::from_static(b"a"))).boxed();
        let (mut body, completions) = observe(inner, Some(1));
        assert!(body.frame().await.unwrap().unwrap().is_data());
        drop(body);

        assert_eq!(
            only_completion(&completions).outcome,
            ResponseBodyOutcome::Complete
        );
        assert_eq!(only_completion(&completions).body_bytes, 1);
    }

    #[tokio::test]
    async fn unknown_length_without_inner_end_signal_remains_cancelled() {
        let inner = BodyWithoutEndSignal(Some(Bytes::from_static(b"a"))).boxed();
        let (mut body, completions) = observe(inner, None);
        assert!(body.frame().await.unwrap().unwrap().is_data());
        drop(body);

        assert_eq!(
            only_completion(&completions).outcome,
            ResponseBodyOutcome::DownstreamCancelled
        );
        assert_eq!(only_completion(&completions).body_bytes, 1);
    }

    #[tokio::test]
    async fn known_short_body_is_truncated_when_inner_ends_without_eof_poll() {
        let (mut body, completions) = observe(body_full("a"), Some(2));
        assert!(body.frame().await.unwrap().unwrap().is_data());
        drop(body);

        assert_eq!(
            only_completion(&completions).outcome,
            ResponseBodyOutcome::Truncated
        );
        assert_eq!(only_completion(&completions).body_bytes, 1);
    }

    #[tokio::test]
    async fn oversized_final_frame_is_length_mismatch_without_eof_poll() {
        let (mut body, completions) = observe(body_full("ab"), Some(1));
        assert!(body.frame().await.unwrap().unwrap().is_data());
        drop(body);

        assert_eq!(
            only_completion(&completions).outcome,
            ResponseBodyOutcome::LengthMismatch
        );
        assert_eq!(only_completion(&completions).body_bytes, 2);
    }

    #[tokio::test]
    async fn observer_does_not_count_trailer_bytes() {
        let mut trailers = HeaderMap::new();
        trailers.insert("x-finished", "yes".parse().unwrap());
        let stream = futures_util::stream::iter([
            Ok::<Frame<Bytes>, anyhow::Error>(Frame::data(Bytes::from_static(b"ab"))),
            Ok(Frame::trailers(trailers)),
        ]);
        let (body, completions) = observe(StreamBody::new(stream).boxed(), Some(2));
        body.collect().await.unwrap();

        assert_eq!(
            only_completion(&completions).outcome,
            ResponseBodyOutcome::Complete
        );
        assert_eq!(only_completion(&completions).body_bytes, 2);
    }

    #[tokio::test]
    async fn another_response_cannot_refresh_a_stalled_response_deadline() {
        let timeout_signal = Arc::new(Notify::new());
        let stalled_stream = futures_util::stream::pending::<Result<Frame<Bytes>, anyhow::Error>>();
        let stalled = body_with_response_write_idle_timeout(
            StreamBody::new(stalled_stream).boxed(),
            Duration::from_millis(60),
            timeout_signal.clone(),
        );

        let active_stream = futures_util::stream::repeat_with(|| {
            Ok::<Frame<Bytes>, anyhow::Error>(Frame::data(Bytes::from_static(b"x")))
        });
        let mut active = body_with_response_write_idle_timeout(
            StreamBody::new(active_stream).boxed(),
            Duration::from_millis(60),
            timeout_signal.clone(),
        );
        let active_task = tokio::spawn(async move {
            loop {
                let frame = active
                    .frame()
                    .await
                    .expect("active response unexpectedly reached EOS")
                    .expect("active response failed");
                assert_eq!(frame.data_ref(), Some(&Bytes::from_static(b"x")));
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });

        tokio::time::timeout(Duration::from_millis(180), timeout_signal.notified())
            .await
            .expect("activity on another response hid the stalled response");
        drop(stalled);
        active_task.abort();
    }

    #[tokio::test]
    async fn response_idle_monitor_stops_on_eos_error_and_drop() {
        async fn assert_no_timeout_after_termination(
            mut body: BoxBody<Bytes, anyhow::Error>,
            signal: Arc<Notify>,
        ) {
            while let Some(frame) = body.frame().await {
                let _ = frame;
            }
            drop(body);
            assert!(
                tokio::time::timeout(Duration::from_millis(80), signal.notified())
                    .await
                    .is_err(),
                "terminated response left its idle monitor armed"
            );
        }

        let eos_signal = Arc::new(Notify::new());
        let eos_body = body_with_response_write_idle_timeout(
            body_full("complete"),
            Duration::from_millis(30),
            eos_signal.clone(),
        );
        assert_no_timeout_after_termination(eos_body, eos_signal).await;

        let error_signal = Arc::new(Notify::new());
        let error_stream = futures_util::stream::iter([Err::<Frame<Bytes>, anyhow::Error>(
            anyhow::anyhow!("body failed"),
        )]);
        let error_body = body_with_response_write_idle_timeout(
            StreamBody::new(error_stream).boxed(),
            Duration::from_millis(30),
            error_signal.clone(),
        );
        assert_no_timeout_after_termination(error_body, error_signal).await;

        let drop_signal = Arc::new(Notify::new());
        let pending_stream = futures_util::stream::pending::<Result<Frame<Bytes>, anyhow::Error>>();
        let dropped_body = body_with_response_write_idle_timeout(
            StreamBody::new(pending_stream).boxed(),
            Duration::from_millis(30),
            drop_signal.clone(),
        );
        drop(dropped_body);
        assert!(
            tokio::time::timeout(Duration::from_millis(80), drop_signal.notified())
                .await
                .is_err(),
            "dropping a response left its idle monitor armed"
        );
    }

    #[test]
    fn response_body_outcome_names_are_stable() {
        assert_eq!(ResponseBodyOutcome::Complete.as_str(), "complete");
        assert_eq!(ResponseBodyOutcome::BodyError.as_str(), "body_error");
        assert_eq!(ResponseBodyOutcome::Truncated.as_str(), "truncated");
        assert_eq!(
            ResponseBodyOutcome::LengthMismatch.as_str(),
            "length_mismatch"
        );
        assert_eq!(
            ResponseBodyOutcome::DownstreamCancelled.as_str(),
            "downstream_cancelled"
        );
    }
}
