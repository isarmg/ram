//! 连接级 I/O 超时包装器分别执行双向空闲与 pending-write 停滞策略。读活动只更新空闲
//! deadline，不能解除已经 pending 的写；正字节写入或完成一个曾 pending 的 flush 才同时
//! 更新空闲 deadline 并解除写停滞。任一 deadline 到期后，所有后续 I/O 都永久返回
//! `TimedOut`。
//!
//! 这是两层策略中的传输层：同一 HTTP/2 连接上任意流成功写入都算 socket 进度；每个非空
//! 响应还由 `http::body` 的响应局部 watchdog 独立约束，因此其他流活跃不能掩盖单流停滞。
//! handler 活跃时仅暂停连接空闲到期，不暂停已经 pending 的写、响应局部 deadline 或外层
//! 最大连接寿命。
//!
//! Connection-level I/O timeout enforcement.
//!
//! [`IoWatchdog`] wraps an [`AsyncRead`] + [`AsyncWrite`] transport and applies
//! two independent policies:
//!
//! - the idle timeout expires when neither side has made progress;
//! - the write-stall timeout is armed only after a write, vectored write, or
//!   flush returns [`Poll::Pending`].
//!
//! Read activity resets only the connection idle deadline. Write-side progress
//! resets the idle deadline and disarms the write-stall deadline. Once either
//! deadline expires, the wrapper is terminal and every later I/O operation
//! returns [`io::ErrorKind::TimedOut`].
//!
//! This wrapper is the transport half of a two-layer policy. It deliberately
//! observes one socket rather than individual HTTP/2 streams, so any stream's
//! successful write is transport progress. Each non-empty response is also
//! wrapped by the response-local monitor in `http::body`; that monitor has an
//! independent deadline and closes the Hyper connection if its own stream
//! stops producing output, even while another H2 stream remains active.
//! Connection idle expiry is suspended while a request handler is actively
//! consuming a body or doing local work, but pending writes, response-local
//! deadlines, and maximum lifetime are not.

use std::{
    future::Future,
    io::{self, IoSlice},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Instant, Sleep},
};

/// 已锁定的终止原因；一旦写入便不再恢复为可用连接。
/// Terminal reason latched by the wrapper; once set, the connection never becomes usable again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TimeoutKind {
    Idle,
    WriteStall,
}

/// 区分 pending write 与 pending flush，避免一个从未阻塞的空 flush 伪造传输进度。
/// Distinguishes a pending write from a pending flush so a never-blocked empty flush cannot forge progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingWriteKind {
    Write,
    Flush,
}

impl TimeoutKind {
    fn error(self) -> io::Error {
        let message = match self {
            Self::Idle => "connection idle timeout",
            Self::WriteStall => "connection write stalled",
        };
        io::Error::new(io::ErrorKind::TimedOut, message)
    }
}

pin_project_lite::pin_project! {
    /// 给异步流增加真实连接空闲与 pending-write 超时。 / Adds connection-idle and pending-write timeouts.
    ///
    /// 正字节读写算进度；完成曾 pending 的 flush 也算写进度，因为缓冲字节可能已到传输层。
    /// Positive-byte I/O and completion of a previously pending flush count as progress.
    ///
    /// 写停滞 deadline 从首次 Pending 开始，不被后续 Pending 或读活动延长，防止持续发请求的对端无限保活阻塞响应。
    /// The write-stall deadline starts at first Pending and is not extended by pending polls or reads.
    #[derive(Debug)]
    pub struct IoWatchdog<T> {
        #[pin]
        inner: T,
        idle_sleep: Pin<Box<Sleep>>,
        write_stall_sleep: Pin<Box<Sleep>>,
        idle_timeout: Duration,
        write_stall_timeout: Duration,
        active_requests: Option<Arc<AtomicUsize>>,
        pending_write: Option<PendingWriteKind>,
        timed_out: Option<TimeoutKind>,
    }
}

impl<T> IoWatchdog<T> {
    /// 用给定空闲与 pending-write 超时包装 inner。 / Wrap `inner` with the supplied timeouts.
    ///
    /// 0 时长合法，并在策略适用的首次 poll 到期。 / Zero is valid and expires on the first applicable poll.
    pub fn new(inner: T, idle_timeout: Duration, write_stall_timeout: Duration) -> Self {
        let now = Instant::now();
        Self {
            inner,
            idle_sleep: Box::pin(tokio::time::sleep_until(now + idle_timeout)),
            // 中文：记录 pending 写之前计时器保持惰性。 / English: This timer remains inert until a pending write is recorded.
            write_stall_sleep: Box::pin(tokio::time::sleep_until(now + write_stall_timeout)),
            idle_timeout,
            write_stall_timeout,
            active_requests: None,
            pending_write: None,
            timed_out: None,
        }
    }

    /// 已准入 handler 执行时暂停连接空闲到期；pending 写仍独立受控，最大连接寿命由外层运行时执行。
    /// Suspend idle expiry during handler work; pending writes and outer maximum lifetime remain enforced.
    pub fn with_active_requests(
        inner: T,
        idle_timeout: Duration,
        write_stall_timeout: Duration,
        active_requests: Arc<AtomicUsize>,
    ) -> Self {
        let mut watchdog = Self::new(inner, idle_timeout, write_stall_timeout);
        watchdog.active_requests = Some(active_requests);
        watchdog
    }
}

fn reset_timer(mut timer: Pin<&mut Sleep>, timeout: Duration) {
    timer.as_mut().reset(Instant::now() + timeout);
}

/// 在接触 inner I/O 前统一检查终止状态。写停滞优先于同时到期的空闲超时；handler 活跃只会
/// 把空闲计时器向后移动一个完整周期，绝不影响已武装的写计时器。
/// Check terminal state before touching inner I/O. Write stall wins when both timers expire together;
/// an active handler moves only the idle timer by one full interval and never alters an armed write timer.
fn poll_timeouts(
    timed_out: &mut Option<TimeoutKind>,
    mut idle_sleep: Pin<&mut Sleep>,
    mut write_stall_sleep: Pin<&mut Sleep>,
    pending_write: Option<PendingWriteKind>,
    active_requests: Option<&Arc<AtomicUsize>>,
    idle_timeout: Duration,
    cx: &mut Context<'_>,
) -> Option<io::Error> {
    if let Some(kind) = *timed_out {
        return Some(kind.error());
    }

    // 中文：同一 executor 轮次两个 deadline 同时就绪时优先更具体错误。
    // English: Prefer the more specific error when both deadlines become ready together.
    if pending_write.is_some() && write_stall_sleep.as_mut().poll(cx).is_ready() {
        *timed_out = Some(TimeoutKind::WriteStall);
        return Some(TimeoutKind::WriteStall.error());
    }
    if idle_sleep.as_mut().poll(cx).is_ready() {
        if active_requests.is_some_and(|count| count.load(Ordering::Acquire) > 0) {
            reset_timer(idle_sleep.as_mut(), idle_timeout);
            // 中文：把当前任务注册到重置后的 deadline。 / English: Register the current task against the reset deadline.
            let _ = idle_sleep.as_mut().poll(cx);
            return None;
        }
        *timed_out = Some(TimeoutKind::Idle);
        return Some(TimeoutKind::Idle.error());
    }
    None
}

/// 仅在首次观察到指定写操作 `Pending` 时设置 deadline，并立即 poll 一次以注册当前 waker。
/// 后续 `Pending` 不延长期限；只有对应写进度路径显式解除它。
/// Arm on the first observed pending write operation and immediately poll once to register this waker.
/// Repeated `Pending` never extends the deadline; only an explicit write-progress path disarms it.
fn arm_write_stall(
    timed_out: &mut Option<TimeoutKind>,
    mut write_stall_sleep: Pin<&mut Sleep>,
    write_stall_timeout: Duration,
    pending_write: &mut Option<PendingWriteKind>,
    kind: PendingWriteKind,
    cx: &mut Context<'_>,
) -> Option<io::Error> {
    if pending_write.is_none() {
        reset_timer(write_stall_sleep.as_mut(), write_stall_timeout);
        *pending_write = Some(kind);
    }

    // 中文：inner 可能不再唤醒任务，新启动计时器必须在返回 Pending 前注册 waker。
    // English: Inner may never wake again, so the newly armed timer must register the waker before Pending.
    if write_stall_sleep.as_mut().poll(cx).is_ready() {
        *timed_out = Some(TimeoutKind::WriteStall);
        return Some(TimeoutKind::WriteStall.error());
    }
    None
}

impl<T: AsyncRead> AsyncRead for IoWatchdog<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut this = self.project();
        if let Some(error) = poll_timeouts(
            this.timed_out,
            this.idle_sleep.as_mut(),
            this.write_stall_sleep.as_mut(),
            *this.pending_write,
            this.active_requests.as_ref(),
            *this.idle_timeout,
            cx,
        ) {
            return Poll::Ready(Err(error));
        }

        let filled_before = buf.filled().len();
        match this.inner.as_mut().poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if buf.filled().len() > filled_before {
                    reset_timer(this.idle_sleep.as_mut(), *this.idle_timeout);
                }
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }
}

impl<T: AsyncWrite> AsyncWrite for IoWatchdog<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut this = self.project();
        if let Some(error) = poll_timeouts(
            this.timed_out,
            this.idle_sleep.as_mut(),
            this.write_stall_sleep.as_mut(),
            *this.pending_write,
            this.active_requests.as_ref(),
            *this.idle_timeout,
            cx,
        ) {
            return Poll::Ready(Err(error));
        }

        match this.inner.as_mut().poll_write(cx, buf) {
            Poll::Pending => {
                if let Some(error) = arm_write_stall(
                    this.timed_out,
                    this.write_stall_sleep.as_mut(),
                    *this.write_stall_timeout,
                    this.pending_write,
                    PendingWriteKind::Write,
                    cx,
                ) {
                    Poll::Ready(Err(error))
                } else {
                    Poll::Pending
                }
            }
            Poll::Ready(Ok(written)) => {
                if written > 0 {
                    *this.pending_write = None;
                    reset_timer(this.idle_sleep.as_mut(), *this.idle_timeout);
                }
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => {
                *this.pending_write = None;
                Poll::Ready(Err(error))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut this = self.project();
        if let Some(error) = poll_timeouts(
            this.timed_out,
            this.idle_sleep.as_mut(),
            this.write_stall_sleep.as_mut(),
            *this.pending_write,
            this.active_requests.as_ref(),
            *this.idle_timeout,
            cx,
        ) {
            return Poll::Ready(Err(error));
        }

        let pending_before = *this.pending_write;
        match this.inner.as_mut().poll_flush(cx) {
            Poll::Pending => {
                if let Some(error) = arm_write_stall(
                    this.timed_out,
                    this.write_stall_sleep.as_mut(),
                    *this.write_stall_timeout,
                    this.pending_write,
                    PendingWriteKind::Flush,
                    cx,
                ) {
                    Poll::Ready(Err(error))
                } else {
                    Poll::Pending
                }
            }
            Poll::Ready(Ok(())) => {
                // 中文：立即 ready 的 flush 可为空操作，不证明传输进度；完成曾 pending 的 flush 才算。
                // English: An immediately ready flush may be a no-op; only completion of a pending flush proves progress.
                if pending_before == Some(PendingWriteKind::Flush) {
                    *this.pending_write = None;
                    reset_timer(this.idle_sleep.as_mut(), *this.idle_timeout);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                *this.pending_write = None;
                Poll::Ready(Err(error))
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut this = self.project();
        if let Some(error) = poll_timeouts(
            this.timed_out,
            this.idle_sleep.as_mut(),
            this.write_stall_sleep.as_mut(),
            *this.pending_write,
            this.active_requests.as_ref(),
            *this.idle_timeout,
            cx,
        ) {
            return Poll::Ready(Err(error));
        }

        match this.inner.as_mut().poll_shutdown(cx) {
            Poll::Ready(result) => {
                *this.pending_write = None;
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let mut this = self.project();
        if let Some(error) = poll_timeouts(
            this.timed_out,
            this.idle_sleep.as_mut(),
            this.write_stall_sleep.as_mut(),
            *this.pending_write,
            this.active_requests.as_ref(),
            *this.idle_timeout,
            cx,
        ) {
            return Poll::Ready(Err(error));
        }

        match this.inner.as_mut().poll_write_vectored(cx, bufs) {
            Poll::Pending => {
                if let Some(error) = arm_write_stall(
                    this.timed_out,
                    this.write_stall_sleep.as_mut(),
                    *this.write_stall_timeout,
                    this.pending_write,
                    PendingWriteKind::Write,
                    cx,
                ) {
                    Poll::Ready(Err(error))
                } else {
                    Poll::Pending
                }
            }
            Poll::Ready(Ok(written)) => {
                if written > 0 {
                    *this.pending_write = None;
                    reset_timer(this.idle_sleep.as_mut(), *this.idle_timeout);
                }
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => {
                *this.pending_write = None;
                Poll::Ready(Err(error))
            }
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::poll_fn,
        io::IoSlice,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
        time::Duration,
    };

    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, duplex},
        time::{sleep, timeout},
    };

    use super::IoWatchdog;

    const TEST_TIMEOUT: Duration = Duration::from_secs(2);

    #[tokio::test]
    async fn read_and_write_activity_each_reset_idle_deadline() {
        let idle_timeout = Duration::from_millis(400);
        let activity_interval = Duration::from_millis(250);
        let (inner, mut peer) = duplex(64);
        let mut io = IoWatchdog::new(inner, idle_timeout, Duration::from_secs(1));

        peer.write_all(b"a").await.unwrap();
        let mut byte = [0_u8; 1];
        io.read_exact(&mut byte).await.unwrap();

        sleep(activity_interval).await;
        io.write_all(b"b").await.unwrap();
        peer.read_exact(&mut byte).await.unwrap();

        // 中文：此操作晚于原读 deadline，只有上方成功写重置共享空闲计时器才会成功。
        // English: This occurs after the original read deadline and succeeds only if the write reset idle time.
        sleep(activity_interval).await;
        peer.write_all(b"c").await.unwrap();
        io.read_exact(&mut byte).await.unwrap();

        // 中文：同理，此写晚于前一写 deadline，证明中间读取重置了空闲计时器。
        // English: This write occurs after the prior deadline and proves the intervening read reset idle time.
        sleep(activity_interval).await;
        timeout(TEST_TIMEOUT, io.write_all(b"d"))
            .await
            .expect("write did not complete")
            .unwrap();
    }

    #[tokio::test]
    async fn idle_connection_returns_timed_out() {
        let (inner, _peer) = duplex(8);
        let mut io = IoWatchdog::new(inner, Duration::from_millis(40), Duration::from_secs(1));
        let mut byte = [0_u8; 1];

        let error = timeout(TEST_TIMEOUT, io.read(&mut byte))
            .await
            .expect("idle timer did not wake the task")
            .expect_err("idle read unexpectedly completed");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(error.to_string(), "connection idle timeout");
    }

    #[tokio::test]
    async fn active_handler_suspends_idle_but_not_after_handler_completion() {
        let active = Arc::new(AtomicUsize::new(1));
        let (inner, _peer) = duplex(8);
        let mut io = IoWatchdog::with_active_requests(
            inner,
            Duration::from_millis(40),
            Duration::from_secs(1),
            active.clone(),
        );
        let mut byte = [0_u8; 1];

        assert!(
            timeout(Duration::from_millis(130), io.read(&mut byte))
                .await
                .is_err(),
            "connection idle fired while a request handler was active"
        );
        active.store(0, Ordering::Release);
        let error = timeout(TEST_TIMEOUT, io.read(&mut byte))
            .await
            .expect("idle timer did not wake after handler completion")
            .expect_err("inactive idle connection unexpectedly remained open");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(error.to_string(), "connection idle timeout");
    }

    #[tokio::test]
    async fn pending_write_returns_timed_out() {
        let (inner, _peer) = duplex(1);
        let mut io = IoWatchdog::new(inner, Duration::from_secs(1), Duration::from_millis(40));

        // 中文：首字节填满 duplex 缓冲；对端刻意不读使第二字节 poll_write pending。
        // English: The first byte fills the buffer; with the peer not reading, the second write remains Pending.
        let error = timeout(TEST_TIMEOUT, io.write_all(b"ab"))
            .await
            .expect("write-stall timer did not wake the task")
            .expect_err("blocked write unexpectedly completed");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(error.to_string(), "connection write stalled");
    }

    #[derive(Debug, Default)]
    struct PendingWriteReadyFlush;

    impl AsyncRead for PendingWriteReadyFlush {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for PendingWriteReadyFlush {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    async fn observe_one_pending_write(io: &mut IoWatchdog<PendingWriteReadyFlush>) {
        poll_fn(|cx| match Pin::new(&mut *io).poll_write(cx, b"x") {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(result) => panic!("write did not remain pending: {result:?}"),
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn ready_flush_cannot_disarm_a_different_pending_write() {
        let mut io = IoWatchdog::new(
            PendingWriteReadyFlush,
            Duration::from_secs(1),
            Duration::from_millis(60),
        );

        observe_one_pending_write(&mut io).await;
        sleep(Duration::from_millis(25)).await;
        io.flush().await.unwrap();
        observe_one_pending_write(&mut io).await;
        sleep(Duration::from_millis(25)).await;
        io.flush().await.unwrap();
        observe_one_pending_write(&mut io).await;
        sleep(Duration::from_millis(25)).await;

        let error = io
            .flush()
            .await
            .expect_err("Ready flushes incorrectly extended a pending write deadline");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(error.to_string(), "connection write stalled");
    }

    #[tokio::test]
    async fn elapsed_write_stall_duration_is_inert_without_pending_write() {
        let write_stall_timeout = Duration::from_millis(30);
        let (inner, mut peer) = duplex(8);
        let mut io = IoWatchdog::new(inner, Duration::from_secs(1), write_stall_timeout);

        sleep(write_stall_timeout * 3).await;
        peer.write_all(b"x").await.unwrap();
        let mut byte = [0_u8; 1];
        timeout(TEST_TIMEOUT, io.read_exact(&mut byte))
            .await
            .expect("read did not complete")
            .unwrap();
        assert_eq!(byte, *b"x");
    }

    #[derive(Debug, Default)]
    struct PendingFlush;

    impl AsyncRead for PendingFlush {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for PendingFlush {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn pending_flush_uses_write_stall_deadline() {
        let mut io = IoWatchdog::new(
            PendingFlush,
            Duration::from_secs(1),
            Duration::from_millis(40),
        );

        let error = timeout(TEST_TIMEOUT, io.flush())
            .await
            .expect("write-stall timer did not wake the task")
            .expect_err("pending flush unexpectedly completed");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(error.to_string(), "connection write stalled");
    }

    #[derive(Debug, Default)]
    struct VectoredWriter {
        vectored_calls: usize,
        output: Vec<u8>,
    }

    impl AsyncRead for VectoredWriter {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for VectoredWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.output.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<std::io::Result<usize>> {
            self.vectored_calls += 1;
            let mut written = 0;
            for buf in bufs {
                self.output.extend_from_slice(buf);
                written += buf.len();
            }
            Poll::Ready(Ok(written))
        }

        fn is_write_vectored(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn immediately_ready_empty_flushes_do_not_forge_idle_activity() {
        let idle_timeout = Duration::from_millis(80);
        let mut io = IoWatchdog::new(
            VectoredWriter::default(),
            idle_timeout,
            Duration::from_secs(1),
        );

        // 中文：每次 flush 都是立即 no-op；以短于空闲间隔重复不能移动原 deadline。
        // English: Immediate no-op flushes repeated below the interval must not move the original idle deadline.
        for _ in 0..3 {
            sleep(Duration::from_millis(20)).await;
            io.flush().await.unwrap();
        }
        sleep(Duration::from_millis(30)).await;
        let error = io
            .flush()
            .await
            .expect_err("empty Ready flushes incorrectly kept the connection alive");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(error.to_string(), "connection idle timeout");
    }

    #[tokio::test]
    async fn vectored_write_capability_and_call_are_forwarded() {
        let mut io = IoWatchdog::new(
            VectoredWriter::default(),
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        assert!(io.is_write_vectored());

        let bufs = [IoSlice::new(b"ab"), IoSlice::new(b"cd")];
        let written = poll_fn(|cx| Pin::new(&mut io).poll_write_vectored(cx, &bufs))
            .await
            .unwrap();

        assert_eq!(written, 4);
        assert_eq!(io.inner.vectored_calls, 1);
        assert_eq!(io.inner.output, b"abcd");
    }
}
