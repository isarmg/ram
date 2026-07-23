//! 目录的流式 zip 打包下载（`GET <目录>?zip`）。
//!
//! 核心思路：目录遍历和 zip 编码在后台任务里进行，通过一个有界内存通道
//! 流向 HTTP 响应——**边压缩边发送**，
//! 任意大的目录都不会在内存里缓存整个压缩包。
//!
//! ## 本模块的 Rust 知识点
//! - **生产者-消费者管道**：同步 zip writer 把固定大小的块发送到有界通道，
//!   接收端包装成响应体。通道内部有背压：
//!   客户端下载慢时写端会自然阻塞，压缩速度自动跟着放慢。
//! - **`tokio::spawn` 后台任务**：压缩在独立任务里跑，本函数立即返回
//!   响应；任务的生命周期由运行时管理，与请求处理解耦。
//! - **错误分类**：客户端中途取消下载会表现为管道写入错误
//!   （BrokenPipe 等），这属于正常现象记 debug 而非 error。
//!
//! 安全边界同时限制遍历条目、目录深度、未压缩字节数、总执行时间与取消信号；归档名称固定
//! 在单一根目录下，并按 POSIX 与 Windows 解压语义共同验证，避免跨平台 Zip Slip 或设备名。
//!
//! Streaming ZIP downloads for directories (`GET <directory>?zip`).
//!
//! The core design performs directory traversal and ZIP encoding in a background task, then sends
//! output through a bounded in-memory channel to the HTTP response. Compression and transmission
//! proceed together, so even an arbitrarily large directory never buffers the whole archive in
//! memory.
//!
//! ## Rust concepts in this module
//! - **Producer-consumer pipeline**: a synchronous ZIP writer sends fixed-size chunks through a
//!   bounded channel to the response body. Channel backpressure naturally blocks the writer when a
//!   client downloads slowly, reducing compression speed to match.
//! - **`tokio::spawn` background task**: compression runs in an independent task and the function
//!   returns the response immediately. The runtime owns the task lifetime, decoupling it from the
//!   request handler.
//! - **Error classification**: cancelling a download midway appears as a pipe-write error such as
//!   `BrokenPipe`; that normal condition is logged at debug rather than error level.
//!
//! The security boundary also limits traversal entries, directory depth, uncompressed bytes, total
//! execution time, and cancellation. Archive names remain under one fixed root and are validated
//! under both POSIX and Windows extraction semantics to prevent cross-platform Zip Slip and device
//! names.

use super::error::{
    AdmissionError, AdmissionResource, ChangedStatus, LimitKind, QueueScope, ResponseError,
};
use super::filesystem::RootFs;
use super::reply::set_content_disposition;
use super::walk::{
    CancelOnDrop, CancellationReason, CapabilityWalkAction, CapabilityWalkEntry, HiddenRules,
    RequestCancellation, spawn_supervised_blocking_with_shutdown, walk_dir_entries,
};
use super::{BUF_SIZE, RequestContext, Response, Server};
use crate::auth::AccessPaths;
use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use hyper::header::HeaderValue;
use std::io;
use std::io::Read as _;
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZIP64_BYTES_THR, ZipWriter};

/// 每个归档使用稳定、与解压器无关的根。 / Every generated archive has one stable extractor-independent root.
///
/// 不从请求路径派生，因为它可能为根、非 UTF-8、Windows 设备名或在其他平台具有分隔语义。
/// Do not derive the root from a possibly non-portable requested path.
const ZIP_TOP_LEVEL_DIRECTORY: &str = "archive";
/// ZIP 的 local/central header 都用 `u16` 编码文件名长度，因此百分号编码后的完整条目路径
/// 最多为 65,535 字节；必须按字节而非字符计数。
/// ZIP local and central headers encode filename length as `u16`, so the complete percent-encoded
/// entry path is limited to 65,535 bytes; the limit counts bytes, not characters.
const ZIP_ENTRY_NAME_MAX_BYTES: usize = u16::MAX as usize;

impl Server {
    /// `?zip` 流式打包目录。 / Stream a directory as ZIP.
    pub(super) async fn handle_zip_dir(
        &self,
        path: &Path,
        ctx: &RequestContext<'_>,
        res: &mut Response,
    ) -> Result<()> {
        // 中文：两个 chunk 既限制内存又允许编码器与 socket writer 重叠。
        // English: Two chunks bound memory while overlapping encoder and socket writer.
        let (chunk_tx, chunk_rx) = mpsc::channel(2);
        let filename = archive_download_name(path);
        if ctx.head_only {
            set_content_disposition(res, false, &filename)?;
            res.headers_mut()
                .insert("content-type", HeaderValue::from_static("application/zip"));
            return Ok(());
        }
        let permit_wait = Duration::from_secs(self.args.expensive_task_timeout);
        let deadline = tokio::time::Instant::now() + permit_wait;
        let expensive_permit = match tokio::time::timeout_at(
            deadline,
            self.expensive_task_limit.clone().acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => permit,
            Err(_) => {
                let error = ResponseError::admission(AdmissionError::queue_timeout(
                    AdmissionResource::ExpensiveTasks,
                    QueueScope::WorkerPool,
                    permit_wait,
                ));
                warn!("Archive admission failed: error={error:#}");
                error.apply(res);
                return Ok(());
            }
            Ok(Err(_)) => {
                let error = ResponseError::admission(AdmissionError::cancelled(
                    AdmissionResource::ExpensiveTasks,
                ));
                warn!("Archive admission failed: error={error:#}");
                error.apply(res);
                return Ok(());
            }
        };
        // 中文：归档任务为 'static，克隆 owned 数据。 / English: The archive task outlives this function, so clone owned data.
        let access_paths = ctx.access_paths.clone();
        let path = path.to_owned();
        let hidden = self.hidden.clone();
        let running = self.running.clone();
        let compression = self.args.compress.to_compression();
        let fs_root = self.fs_root.clone();
        let base_rel = PathBuf::from(&ctx.authorization_path);
        let max_walk_entries = self.args.max_walk_entries as usize;
        let max_walk_depth = self.args.max_walk_depth as usize;
        let max_archive_size = self.args.max_archive_size;
        let (preflight_tx, preflight_rx) = oneshot::channel();
        let (result_tx, result_rx) = oneshot::channel();
        let operation = spawn_supervised_blocking_with_shutdown(
            self.running.clone(),
            expensive_permit,
            move |cancellation| {
                // 中文：提交响应头前校验遍历与稳定 metadata；后续增长竞态仍由 producer 检测，但已知超预算必须先返回 422，而非 200 后重置/截断。
                // English: Reject known budget violations before committing 200; streaming still catches later growth races.
                let preflight_result = preflight_zip_dir(
                    base_rel.clone(),
                    access_paths.clone(),
                    hidden.clone(),
                    fs_root.clone(),
                    running.clone(),
                    cancellation.clone(),
                    max_walk_entries,
                    max_walk_depth,
                    max_archive_size,
                );
                if let Err(error) = preflight_result {
                    return match preflight_tx.send(Err(error)) {
                        Ok(()) => Ok(()),
                        Err(Err(error)) => Err(error),
                        Err(Ok(())) => unreachable!("failed preflight carried success"),
                    };
                }
                if preflight_tx.send(Ok(())).is_err() {
                    return Err(anyhow::Error::new(AdmissionError::cancelled(
                        AdmissionResource::ArchiveBytes,
                    ))
                    .context("archive request ended during budget preflight"));
                }
                // 中文：worker 全程用 supervisor 的原因感知 token，permit 留在阻塞闭包直至遍历/编码真实返回。
                // English: Use reason-aware cancellation and retain the permit in the worker until real ZIP exit.
                let writer = ArchiveChunkWriter::new(chunk_tx, cancellation.clone());
                zip_dir(
                    writer,
                    base_rel,
                    access_paths,
                    hidden,
                    compression,
                    fs_root,
                    running,
                    cancellation,
                    max_walk_entries,
                    max_walk_depth,
                    max_archive_size,
                )
            },
        );
        let cancellation = operation.cancellation();
        let cancel_on_drop = CancelOnDrop::new(cancellation.clone());
        let worker_cancellation = cancellation.clone();
        tokio::spawn(async move {
            // 中文：请求超时与 worker 真实退出不同；wait_until 可先返回，supervisor 继续等 syscall，worker permit 仍持有。
            // English: Timeout may return before real worker exit; supervision and worker-owned admission remain.
            let result = operation.wait_until(deadline).await;
            if let Err(e) = &result {
                match worker_cancellation.reason() {
                    CancellationReason::RequestDropped | CancellationReason::Shutdown => {
                        debug!("Zip download for {} was interrupted: {e:#}", path.display());
                    }
                    CancellationReason::DeadlineExceeded => {
                        warn!(
                            "Zip download for {} reached its deadline: {e:#}",
                            path.display()
                        );
                    }
                    CancellationReason::Running if is_client_disconnect(e) => {
                        debug!("Zip download for {} was interrupted: {e:#}", path.display());
                    }
                    CancellationReason::Running => {
                        error!("Failed to zip {}, {e:#}", path.display());
                    }
                }
            }
            let _ = result_tx.send(result);
        });
        match tokio::time::timeout_at(deadline, preflight_rx).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(error))) => {
                let response_error = ResponseError::from_anyhow_or_filesystem(
                    "validating archive traversal and size",
                    error,
                    ChangedStatus::Conflict,
                );
                warn!("Archive preflight rejected the request: error={response_error:#}");
                response_error.apply(res);
                return Ok(());
            }
            Ok(Err(_)) => {
                return Err(anyhow!(
                    "archive worker terminated before reporting its budget preflight"
                ));
            }
            Err(_) => {
                cancellation.cancel_for_deadline();
                let error = ResponseError::admission(AdmissionError::execution_timeout(
                    AdmissionResource::ExpensiveTasks,
                    permit_wait,
                ));
                warn!("Archive preflight reached its deadline: error={error:#}");
                error.apply(res);
                return Ok(());
            }
        }
        set_content_disposition(res, false, &filename)?;
        res.headers_mut()
            .insert("content-type", HeaderValue::from_static("application/zip"));
        let body_cancellation = cancellation.clone();
        // 中文：流首次 poll 前构造 guard；Hyper 可能仅写响应头即 reset，若 guard 在 generator 内则未初始化，Drop 无法取消 producer。
        // English: Construct cancellation guard before polling so an unpolled reset body still cancels its producer.
        struct ResponseStreamState {
            chunk_rx: mpsc::Receiver<Bytes>,
            result_rx: Option<oneshot::Receiver<Result<()>>>,
            deadline: tokio::time::Instant,
            operation_timeout: Duration,
            body_cancellation: RequestCancellation,
            _cancel_on_drop: CancelOnDrop,
            done: bool,
        }

        let state = ResponseStreamState {
            chunk_rx,
            result_rx: Some(result_rx),
            deadline,
            operation_timeout: permit_wait,
            body_cancellation,
            _cancel_on_drop: cancel_on_drop,
            done: false,
        };
        let response_stream = futures_util::stream::unfold(state, |mut state| async move {
            if state.done {
                return None;
            }

            match tokio::time::timeout_at(state.deadline, state.chunk_rx.recv()).await {
                Ok(Some(chunk)) => Some((Ok(Frame::data(chunk)), state)),
                Err(_) => {
                    state.body_cancellation.cancel();
                    state.done = true;
                    let error = archive_timeout_error(state.operation_timeout);
                    Some((Err(error), state))
                }
                Ok(None) => {
                    let Some(result_rx) = state.result_rx.take() else {
                        state.done = true;
                        return Some((
                            Err(anyhow!("zip producer terminated without a result")),
                            state,
                        ));
                    };
                    let producer_result = tokio::time::timeout_at(state.deadline, result_rx).await;
                    state.done = true;
                    match producer_result {
                        Err(_) => {
                            state.body_cancellation.cancel();
                            let error = archive_timeout_error(state.operation_timeout);
                            Some((Err(error), state))
                        }
                        Ok(Ok(Ok(()))) => None,
                        Ok(Ok(Err(err))) => Some((Err(err), state)),
                        Ok(Err(_)) => Some((
                            Err(anyhow!("zip producer terminated without a result")),
                            state,
                        )),
                    }
                }
            }
        });
        let stream_body = StreamBody::new(response_stream);
        let boxed_body = BodyExt::boxed(stream_body);
        *res.body_mut() = boxed_body;
        Ok(())
    }
}

/// 判断错误是否只是"客户端断开下载"：只接受错误链中的 typed I/O
/// cause；不得用文本片段推断错误类别。
/// Classify client disconnect only from typed I/O causes, never error-message fragments.
fn is_client_disconnect(err: &anyhow::Error) -> bool {
    err.chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|err| {
            matches!(
                err.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
            )
        })
}

/// ZipWriter 使用的同步有界适配器。 / Synchronous bounded adapter for `zip::ZipWriter`.
///
/// 不像 SyncIoBridge，它不在不可中断 async 写中等待；通道背压时周期检查取消，响应 receiver Drop 变为 BrokenPipe。
/// It polls cancellation during channel backpressure and maps a dropped receiver to BrokenPipe.
struct ArchiveChunkWriter {
    sender: mpsc::Sender<Bytes>,
    buffer: Vec<u8>,
    cancellation: RequestCancellation,
}

impl ArchiveChunkWriter {
    fn new(sender: mpsc::Sender<Bytes>, cancellation: RequestCancellation) -> Self {
        Self {
            sender,
            buffer: Vec::with_capacity(BUF_SIZE),
            cancellation,
        }
    }

    fn send_buffer(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        if self.cancellation.is_cancelled() {
            self.buffer.clear();
            return Ok(());
        }
        let mut chunk = Bytes::from(std::mem::replace(
            &mut self.buffer,
            Vec::with_capacity(BUF_SIZE),
        ));
        loop {
            if self.cancellation.is_cancelled() {
                // 中文：reader/遍历返回终态取消；writer 切到 sink，让 ZipWriter Drop 安静收尾而不重试或向 stderr 打预期错误。
                // English: On terminal cancellation switch writer to a sink so ZipWriter Drop unwinds quietly.
                return Ok(());
            }
            match self.sender.try_send(chunk) {
                Ok(()) => return Ok(()),
                Err(mpsc::error::TrySendError::Full(returned)) => {
                    chunk = returned;
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "archive response receiver closed",
                    ));
                }
            }
        }
    }
}

impl io::Write for ArchiveChunkWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if self.cancellation.is_cancelled() {
            return Ok(input.len());
        }
        if input.is_empty() {
            return Ok(0);
        }
        if self.buffer.len() == BUF_SIZE {
            self.send_buffer()?;
        }
        let written = input.len().min(BUF_SIZE - self.buffer.len());
        self.buffer.extend_from_slice(&input[..written]);
        if self.buffer.len() == BUF_SIZE {
            self.send_buffer()?;
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.send_buffer()
    }
}

/// 响应提交前执行只读预检：验证所有可见名称、稳定 metadata 与累计未压缩大小，并复用正式
/// 生产阶段的遍历/深度/取消预算。这样已知的策略错误可返回 4xx，而不是先发 200 再截断流。
/// Read-only preflight before committing the response: validate visible names, stable metadata, and
/// aggregate uncompressed size under the producer's traversal/depth/cancellation budgets. Known
/// policy failures can therefore return 4xx instead of truncating a response after 200.
// 中文：参数是移交给 `'static` 后台任务的 owned 数据，不借用请求上下文。
// English: Parameters are owned for the `'static` background task, not borrowed request context.
#[allow(clippy::too_many_arguments)]
fn preflight_zip_dir(
    base_rel: PathBuf,
    access_paths: AccessPaths,
    hidden: Arc<HiddenRules>,
    fs_root: RootFs,
    running: Arc<AtomicBool>,
    cancellation: RequestCancellation,
    max_walk_entries: usize,
    max_walk_depth: usize,
    max_archive_size: u64,
) -> Result<()> {
    let mut uncompressed_bytes = 0u64;
    let mut entry_error = None;
    let walk_result = walk_dir_entries(
        fs_root,
        access_paths,
        running,
        cancellation,
        max_walk_entries,
        max_walk_depth,
        base_rel.clone(),
        hidden,
        |entry| {
            let result = (|| {
                let relative = entry
                    .display_rel
                    .strip_prefix(&base_rel)
                    .map_err(|_| anyhow!("ZIP entry is outside the archive root"))?;
                let filename = validated_zip_entry_name(relative)?;
                if entry.metadata.is_dir() {
                    validate_zip_entry_name(&format!("{filename}/"), true)?;
                } else if entry.metadata.is_file() {
                    validate_zip_entry_name(&filename, false)?;
                    let observed = uncompressed_bytes
                        .checked_add(entry.metadata.len())
                        .ok_or_else(|| archive_size_limit_error(max_archive_size, None))?;
                    if observed > max_archive_size {
                        return Err(archive_size_limit_error(max_archive_size, Some(observed)));
                    }
                    uncompressed_bytes = observed;
                }
                Ok(())
            })();
            match result {
                Ok(()) => CapabilityWalkAction::Continue,
                Err(error) => {
                    entry_error = Some(error);
                    CapabilityWalkAction::Stop
                }
            }
        },
    );
    if let Some(error) = entry_error {
        return Err(error);
    }
    walk_result.context("archive preflight traversal failed")?;
    Ok(())
}

/// 预检成功后的第二次遍历会真正编码 ZIP 并通过有界通道施加背压。两次遍历之间仍可能发生
/// 文件增长或替换，因此打开描述符、逐项名称校验、限长 reader 与取消检查仍是最终防线。
/// The second traversal encodes ZIP bytes through a bounded backpressured channel. Files may still
/// grow or change after preflight, so opened descriptors, per-entry name checks, the bounded reader,
/// and cancellation checks remain authoritative.
#[allow(clippy::too_many_arguments)]
fn zip_dir<W: io::Write>(
    writer: W,
    base_rel: PathBuf,
    access_paths: AccessPaths,
    hidden: Arc<HiddenRules>,
    compression: (CompressionMethod, Option<i64>),
    fs_root: RootFs,
    running: Arc<AtomicBool>,
    cancellation: RequestCancellation,
    max_walk_entries: usize,
    max_walk_depth: usize,
    max_archive_size: u64,
) -> Result<()> {
    let mut zip = ZipWriter::new_stream(writer);
    let root_entry_name = format!("{ZIP_TOP_LEVEL_DIRECTORY}/");
    validate_zip_entry_name(&root_entry_name, true)?;
    let mut root_options = SimpleFileOptions::default();
    #[cfg(unix)]
    {
        root_options = root_options.unix_permissions(0o755);
    }
    root_options = root_options.compression_method(CompressionMethod::Stored);
    zip.add_directory(&root_entry_name, root_options)
        .context("failed to append the ZIP top-level directory")?;
    let mut entry_error = None;
    let mut uncompressed_bytes = 0u64;
    let visitor_cancellation = cancellation.clone();
    let walk_result = walk_dir_entries(
        fs_root,
        access_paths,
        running,
        cancellation,
        max_walk_entries,
        max_walk_depth,
        base_rel.clone(),
        hidden,
        |entry| {
            if let Err(err) = append_zip_entry(
                &mut zip,
                &base_rel,
                entry,
                compression,
                &visitor_cancellation,
                max_archive_size,
                &mut uncompressed_bytes,
            ) {
                entry_error = Some(err);
                CapabilityWalkAction::Stop
            } else {
                CapabilityWalkAction::Continue
            }
        },
    );
    if let Some(err) = entry_error {
        return Err(err);
    }
    walk_result.context("directory traversal failed")?;
    let stream_writer = zip.finish().context("failed to finalize ZIP archive")?;
    stream_writer
        .into_inner()
        .flush()
        .context("failed to flush ZIP archive")?;
    Ok(())
}

/// 把 walker 已通过能力根打开的稳定条目加入归档；文件 reader 最多读取“剩余预算 + 1”字节，
/// 其中哨兵字节用于发现预检后增长，绝不会把 pathname 重新打开为另一个对象。
/// Append the stable entry opened by the capability walker. The reader consumes at most remaining
/// budget plus one sentinel byte to detect post-preflight growth and never reopens a pathname as a
/// different object.
fn append_zip_entry<W: io::Write>(
    zip: &mut ZipWriter<zip::write::StreamWriter<W>>,
    zip_base: &Path,
    entry: &mut CapabilityWalkEntry,
    compression: (CompressionMethod, Option<i64>),
    cancellation: &RequestCancellation,
    max_archive_size: u64,
    uncompressed_bytes: &mut u64,
) -> Result<()> {
    let relative = entry
        .display_rel
        .strip_prefix(zip_base)
        .map_err(|_| anyhow!("ZIP entry is outside the archive root"))?;
    let filename = validated_zip_entry_name(relative)?;
    let meta = &entry.metadata;
    if meta.is_dir() {
        let directory_name = format!("{filename}/");
        validate_zip_entry_name(&directory_name, true)?;
        let mut options = SimpleFileOptions::default();
        #[cfg(unix)]
        {
            options = options.unix_permissions(meta.permissions().mode() & 0o7777);
        }
        options = options.compression_method(CompressionMethod::Stored);
        zip.add_directory(&directory_name, options)
            .with_context(|| format!("failed to append ZIP directory {filename:?}"))?;
    } else if meta.is_file() {
        validate_zip_entry_name(&filename, false)?;
        let remaining = max_archive_size.saturating_sub(*uncompressed_bytes);
        if meta.len() > remaining {
            return Err(archive_size_limit_error(
                max_archive_size,
                (*uncompressed_bytes).checked_add(meta.len()),
            ));
        }
        let mut options = SimpleFileOptions::default();
        #[cfg(unix)]
        {
            options = options.unix_permissions(meta.permissions().mode() & 0o7777);
        }
        options = options
            .compression_method(compression.0)
            .compression_level(compression.1)
            // 中文：流式 writer 无法在写过 4 GiB 后回头扩展 local header。文件可在读取期间
            // 增长，Deflate 还可能略微膨胀，因此同时按未压缩读取上限与压缩方法的保守输出
            // 上限预留 ZIP64；这也覆盖低于 4 GiB 的自定义归档预算。
            // English: A streaming writer cannot enlarge its local header after crossing 4 GiB.
            // Files may grow while read and Deflate can expand incompressible input, so reserve ZIP64
            // from both the read ceiling and a conservative method-specific output ceiling, including
            // custom archive budgets below 4 GiB.
            .large_file(zip64_required_for_entry(remaining, compression.0));
        zip.start_file(&filename, options)
            .with_context(|| format!("failed to start ZIP file {filename:?}"))?;
        let mut reader = CancellableReader {
            inner: &mut entry.file,
            cancellation,
        }
        .take(remaining.saturating_add(1));
        let copied = match io::copy(&mut reader, zip) {
            Ok(copied) => copied,
            Err(_) if cancellation.is_cancelled() => {
                return Err(anyhow::Error::new(AdmissionError::cancelled(
                    AdmissionResource::ArchiveBytes,
                ))
                .context("archive generation was cancelled"));
            }
            Err(error) => {
                return Err(error).with_context(|| format!("failed to copy ZIP file {filename:?}"));
            }
        };
        if copied > remaining {
            return Err(archive_size_limit_error(
                max_archive_size,
                (*uncompressed_bytes).checked_add(copied),
            ));
        }
        *uncompressed_bytes = (*uncompressed_bytes)
            .checked_add(copied)
            .ok_or_else(|| archive_size_limit_error(max_archive_size, None))?;
    }
    Ok(())
}

/// reader 最多把“剩余预算 + 1 个增长探测字节”交给 encoder。Stored 输出等长；当前
/// raw-Deflate 后端的最坏界远小于“每输入字节额外 1 bit + 64 字节”，这里采用该更宽松且
/// 饱和的证明上界，确保压缩或未压缩尺寸任一可能越过 ZIP32 时都预声明 ZIP64。
/// The reader can hand the encoder at most the remaining budget plus one growth sentinel. Stored
/// output is equal-sized. The current raw-Deflate backend's worst-case bound is dominated by one
/// extra bit per input byte plus 64 bytes; use that wider saturating bound and predeclare ZIP64 if
/// either compressed or uncompressed size can cross ZIP32.
fn zip64_required_for_entry(remaining_budget: u64, compression_method: CompressionMethod) -> bool {
    let input_ceiling = remaining_budget.saturating_add(1);
    let output_ceiling = match compression_method {
        CompressionMethod::Stored => input_ceiling,
        CompressionMethod::Deflated => deflate_output_ceiling(input_ceiling),
        // 中文：配置目前只产生 Stored/Deflated；未来方法没有已证明上界时安全地预留 ZIP64。
        // English: Configuration currently emits only Stored/Deflated; reserve ZIP64 for a future
        // method until it has a proven output bound.
        _ => u64::MAX,
    };
    input_ceiling.max(output_ceiling) > ZIP64_BYTES_THR
}

fn deflate_output_ceiling(input_bytes: u64) -> u64 {
    let extra_bits_as_bytes = input_bytes / 8 + u64::from(!input_bytes.is_multiple_of(8));
    input_bytes
        .saturating_add(extra_bits_as_bytes)
        .saturating_add(64)
}

fn archive_timeout_error(waited: Duration) -> anyhow::Error {
    anyhow::Error::new(AdmissionError::execution_timeout(
        AdmissionResource::ExpensiveTasks,
        waited,
    ))
    .context("archive operation timed out")
}

fn archive_size_limit_error(limit: u64, observed: Option<u64>) -> anyhow::Error {
    anyhow::Error::new(AdmissionError::limit_exceeded(
        AdmissionResource::ArchiveBytes,
        LimitKind::Semantic,
        limit,
        observed,
    ))
    .context("archive uncompressed-size budget exceeded")
}

fn archive_entry_name_limit_error(observed: usize) -> anyhow::Error {
    anyhow::Error::new(AdmissionError::limit_exceeded(
        AdmissionResource::ArchiveEntryNameBytes,
        LimitKind::Semantic,
        ZIP_ENTRY_NAME_MAX_BYTES as u64,
        Some(observed as u64),
    ))
    .context("ZIP entry-name byte limit exceeded")
}

fn archive_download_name(path: &Path) -> String {
    path.file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .map(|value| format!("{value}.zip"))
        .unwrap_or_else(|| "archive.zip".to_string())
}

/// ZIP 条目始终用 `/`；真实文件名中的敌意/不可移植字节（含 `%`）百分号编码以保持映射无歧义，结构性根/父组件拒绝，结果固定根下再独立校验。
/// ZIP names use `/`; non-portable filename bytes are unambiguously percent-encoded, structural components rejected, and rooted output revalidated.
fn validated_zip_entry_name(path: &Path) -> Result<String> {
    let mut encoded = vec![ZIP_TOP_LEVEL_DIRECTORY.to_owned()];
    for component in path.components() {
        let Component::Normal(component) = component else {
            return Err(anyhow!("unsafe structural ZIP entry path {path:?}"));
        };
        let bytes = component.as_bytes();
        if bytes.is_empty() || bytes.contains(&0) {
            return Err(anyhow!("unsafe ZIP entry path {path:?}"));
        }
        encoded.push(encode_zip_component(bytes));
    }
    if encoded.len() == 1 {
        return Err(anyhow!("empty ZIP entry path"));
    }
    let entry_name = encoded.join("/");
    validate_zip_entry_name(&entry_name, false)?;
    Ok(entry_name)
}

/// 按 POSIX/Windows 解压语义校验最终生成名，而不信源 Path；Linux 普通 `\`/`:` 在 Windows 可为分隔/驱动语法。
/// Validate generated ZIP names under both POSIX and Windows semantics.
fn validate_zip_entry_name(entry_name: &str, directory: bool) -> Result<()> {
    // 中文：必须在交给 zip crate 前拒绝超过 65,535 字节的最终编码名；local/central header
    // 的 `u16` 长度字段无法无损表示更长名称，绝不能让截断或两个头之间的不一致进入归档。
    // English: Reject final encoded names over 65,535 bytes before calling the ZIP crate. The local
    // and central headers' `u16` length fields cannot represent a longer name losslessly, so neither
    // truncation nor disagreement between the two headers may enter the archive.
    if entry_name.len() > ZIP_ENTRY_NAME_MAX_BYTES {
        return Err(archive_entry_name_limit_error(entry_name.len()));
    }
    if entry_name.is_empty()
        || entry_name.starts_with('/')
        || entry_name.starts_with('\\')
        || entry_name.as_bytes().contains(&0)
    {
        return Err(anyhow!("unsafe ZIP entry name {entry_name:?}"));
    }

    let logical_name = if directory {
        entry_name
            .strip_suffix('/')
            .ok_or_else(|| anyhow!("ZIP directory entry lacks its trailing slash"))?
    } else {
        if entry_name.ends_with('/') {
            return Err(anyhow!("ZIP file entry has a trailing slash"));
        }
        entry_name
    };
    if logical_name.is_empty() {
        return Err(anyhow!("unsafe ZIP entry name {entry_name:?}"));
    }

    let mut components = logical_name.split('/');
    if components.next() != Some(ZIP_TOP_LEVEL_DIRECTORY) {
        return Err(anyhow!(
            "ZIP entry is outside the fixed top-level directory"
        ));
    }
    let mut child_components = 0usize;
    for component in components {
        validate_portable_zip_component(component)?;
        child_components += 1;
    }
    if !directory && child_components == 0 {
        return Err(anyhow!(
            "ZIP file entry must be a child of the fixed top-level directory"
        ));
    }
    Ok(())
}

fn validate_portable_zip_component(component: &str) -> Result<()> {
    let bytes = component.as_bytes();
    if bytes.is_empty()
        || matches!(component, "." | "..")
        || component.ends_with(['.', ' '])
        || windows_device_name(bytes)
    {
        return Err(anyhow!("unsafe ZIP entry component {component:?}"));
    }

    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            if index + 2 >= bytes.len()
                || !is_upper_hex_digit(bytes[index + 1])
                || !is_upper_hex_digit(bytes[index + 2])
            {
                return Err(anyhow!(
                    "invalid percent encoding in ZIP entry component {component:?}"
                ));
            }
            index += 3;
            continue;
        }
        if matches!(
            byte,
            0..=0x1f | 0x7f | b'<' | b'>' | b':' | b'"' | b'/' | b'\\' | b'|' | b'?' | b'*'
        ) {
            return Err(anyhow!("unsafe ZIP entry component {component:?}"));
        }
        index += 1;
    }
    Ok(())
}

/// 保留任意 Linux 文件名字节，同时保证 POSIX/Windows 解压均不能逃出固定顶层目录。
/// Preserve arbitrary Linux filename bytes without emitting an entry that escapes under POSIX or Windows.
#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_zip_entry_name(data: &[u8]) {
    const FUZZ_INPUT_MAX_BYTES: usize = 64 * 1024;
    if data.len() > FUZZ_INPUT_MAX_BYTES {
        return;
    }
    use std::ffi::OsStr;

    let path = Path::new(OsStr::from_bytes(data));
    if let Ok(entry_name) = validated_zip_entry_name(path) {
        validate_zip_entry_name(&entry_name, false)
            .expect("validated ZIP name must pass deterministic revalidation");
        assert!(entry_name.starts_with("archive/"));
        assert!(!entry_name.starts_with('/'));
        assert!(!entry_name.starts_with('\\'));
        assert!(!entry_name.as_bytes().contains(&0));
        assert!(
            entry_name.len()
                <= ZIP_TOP_LEVEL_DIRECTORY
                    .len()
                    .saturating_add(1)
                    .saturating_add(data.len().saturating_mul(3))
        );
    }
}

fn is_upper_hex_digit(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'A'..=b'F')
}

fn encode_zip_component(bytes: &[u8]) -> String {
    let reserved_device = windows_device_name(bytes);
    let mut output = String::with_capacity(bytes.len());
    let mut offset = 0;
    while offset < bytes.len() {
        match std::str::from_utf8(&bytes[offset..]) {
            Ok(valid) => {
                encode_valid_zip_utf8(&mut output, valid, offset, bytes.len(), reserved_device);
                break;
            }
            Err(error) => {
                let valid_end = offset + error.valid_up_to();
                let valid = std::str::from_utf8(&bytes[offset..valid_end])
                    .expect("Utf8Error::valid_up_to always identifies valid UTF-8");
                encode_valid_zip_utf8(&mut output, valid, offset, bytes.len(), reserved_device);

                // 中文：保留独立有效 Unicode 子序列，仅编码畸形字节；EOF 不完整序列的全部余部逐字节编码。
                // English: Preserve valid Unicode subsequences and encode only malformed bytes, including the full incomplete EOF remainder.
                let invalid_len = error
                    .error_len()
                    .unwrap_or_else(|| bytes.len().saturating_sub(valid_end));
                for byte in &bytes[valid_end..valid_end + invalid_len] {
                    encode_zip_byte_as_percent(&mut output, *byte);
                }
                offset = valid_end + invalid_len;
            }
        }
    }
    output
}

fn encode_valid_zip_utf8(
    output: &mut String,
    valid: &str,
    offset: usize,
    component_len: usize,
    reserved_device: bool,
) {
    for (relative_index, character) in valid.char_indices() {
        let index = offset + relative_index;
        if character.is_ascii() {
            encode_zip_byte(
                output,
                character as u8,
                index,
                component_len,
                reserved_device,
            );
        } else {
            // 中文：Unicode scalar 在两种解释下都无分隔/驱动语义，故同名另有畸形字节时有效子序列仍保持可读。
            // English: Unicode scalars have no separator/drive semantics, so valid subsequences remain readable.
            output.push(character);
        }
    }
}

fn encode_zip_byte(
    output: &mut String,
    byte: u8,
    index: usize,
    component_len: usize,
    reserved_device: bool,
) {
    let trailing_dot_or_space = index + 1 == component_len && matches!(byte, b'.' | b' ');
    let forbidden = matches!(
        byte,
        0..=0x1f | 0x7f | b'%' | b'<' | b'>' | b':' | b'"' | b'/' | b'\\' | b'|' | b'?' | b'*'
    );
    let safe = byte.is_ascii() && !forbidden && !trailing_dot_or_space;
    // 中文：给 Windows 设备名首字节加前缀即可让 CON/NUL/COM1.txt 等成为普通可移植名。
    // English: Prefixing a Windows device name makes CON/NUL/COM1.txt ordinary portable names.
    if safe && !(reserved_device && index == 0) {
        output.push(char::from(byte));
    } else {
        encode_zip_byte_as_percent(output, byte);
    }
}

fn encode_zip_byte_as_percent(output: &mut String, byte: u8) {
    use std::fmt::Write as _;
    write!(output, "%{byte:02X}").expect("writing to a String cannot fail");
}

fn windows_device_name(bytes: &[u8]) -> bool {
    let stem_end = bytes
        .iter()
        .position(|byte| matches!(byte, b'.' | b':'))
        .unwrap_or(bytes.len());
    let stem = bytes[..stem_end].trim_ascii_end();
    stem.eq_ignore_ascii_case(b"CON")
        || stem.eq_ignore_ascii_case(b"PRN")
        || stem.eq_ignore_ascii_case(b"AUX")
        || stem.eq_ignore_ascii_case(b"NUL")
        || windows_numbered_device_name(stem, b"COM")
        || windows_numbered_device_name(stem, b"LPT")
}

fn windows_numbered_device_name(stem: &[u8], prefix: &[u8; 3]) -> bool {
    let Some(suffix) = stem.get(prefix.len()..) else {
        return false;
    };
    stem.get(..prefix.len())
        .is_some_and(|actual| actual.eq_ignore_ascii_case(prefix))
        && (matches!(suffix, [b'1'..=b'9']) || matches!(suffix, [0xC2, 0xB9 | 0xB2 | 0xB3]))
}

struct CancellableReader<'a, R> {
    inner: &'a mut R,
    cancellation: &'a RequestCancellation,
}

impl<R: io::Read> io::Read for CancellableReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cancellation.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "archive request cancelled",
            ));
        }
        self.inner.read(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::error::{AdmissionTimeoutKind, ChangedStatus, ResponseErrorRef};
    use hyper::StatusCode;
    use std::ffi::OsStr;

    #[test]
    fn archive_download_name_has_root_fallback() {
        assert_eq!(archive_download_name(Path::new("/")), "archive.zip");
        assert_eq!(archive_download_name(Path::new("/srv/share")), "share.zip");
    }

    #[test]
    fn disconnect_classification_uses_typed_io_causes_only() {
        for kind in [
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
        ] {
            let error = anyhow::Error::new(io::Error::new(kind, "private transport detail"))
                .context("archive producer failed");
            assert!(is_client_disconnect(&error));
        }
        assert!(!is_client_disconnect(&anyhow!(
            "broken pipe text is not a typed transport error"
        )));
        assert!(!is_client_disconnect(&anyhow!("request cancelled")));
    }

    #[test]
    fn archive_timeout_retains_typed_execution_deadline() {
        let waited = Duration::from_secs(17);
        let error = archive_timeout_error(waited);
        assert!(matches!(
            AdmissionError::in_anyhow_chain(&error),
            Some(AdmissionError::Timeout {
                resource: AdmissionResource::ExpensiveTasks,
                kind: AdmissionTimeoutKind::Execution,
                waited: actual,
            }) if *actual == waited
        ));
        let mapped = ResponseErrorRef::from_anyhow_typed(&error, ChangedStatus::Conflict)
            .expect("archive deadline remains typed under context");
        assert_eq!(mapped.status(), StatusCode::GATEWAY_TIMEOUT);
    }

    #[test]
    fn archive_size_budget_retains_limit_and_observed_bytes() {
        let error = archive_size_limit_error(1024, Some(1025));
        assert!(matches!(
            AdmissionError::in_anyhow_chain(&error),
            Some(AdmissionError::LimitExceeded {
                resource: AdmissionResource::ArchiveBytes,
                kind: LimitKind::Semantic,
                limit: 1024,
                observed: Some(1025),
            })
        ));
        let mapped = ResponseErrorRef::from_anyhow_typed(&error, ChangedStatus::Conflict)
            .expect("archive size budget remains typed under context");
        assert_eq!(mapped.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn zip64_is_selected_from_the_entry_ceiling_without_writing_four_gibibytes() {
        assert!(!zip64_required_for_entry(
            ZIP64_BYTES_THR - 1,
            CompressionMethod::Stored
        ));
        assert!(zip64_required_for_entry(
            ZIP64_BYTES_THR,
            CompressionMethod::Stored
        ));
        assert!(zip64_required_for_entry(
            ZIP64_BYTES_THR + 1,
            CompressionMethod::Stored
        ));
        assert!(zip64_required_for_entry(
            4 * 1024 * 1024 * 1024,
            CompressionMethod::Stored
        ));
        assert!(zip64_required_for_entry(
            u64::MAX,
            CompressionMethod::Stored
        ));
    }

    #[test]
    fn deflate_expansion_selects_zip64_below_the_zip32_input_boundary() {
        let custom_budget_below_zip32 = ZIP64_BYTES_THR - 1024;
        assert!(!zip64_required_for_entry(
            custom_budget_below_zip32,
            CompressionMethod::Stored
        ));
        assert!(zip64_required_for_entry(
            custom_budget_below_zip32,
            CompressionMethod::Deflated
        ));
        assert!(!zip64_required_for_entry(
            1024 * 1024,
            CompressionMethod::Deflated
        ));
        assert_eq!(deflate_output_ceiling(u64::MAX), u64::MAX);
    }

    #[test]
    fn cancellable_reader_returns_a_typed_transport_cause() {
        let cancellation = RequestCancellation::new();
        cancellation.cancel();
        let mut source = io::Cursor::new(b"payload");
        let mut reader = CancellableReader {
            inner: &mut source,
            cancellation: &cancellation,
        };
        let error = reader.read(&mut [0; 8]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    }

    #[test]
    fn zip_entry_name_accepts_portable_relative_paths() {
        assert_eq!(
            validated_zip_entry_name(Path::new("dir/file.txt")).unwrap(),
            "archive/dir/file.txt"
        );
        assert_eq!(
            validated_zip_entry_name(Path::new("目录/😀.txt")).unwrap(),
            "archive/目录/😀.txt"
        );
        assert_eq!(
            validated_zip_entry_name(Path::new("read me + (final),v1.txt")).unwrap(),
            "archive/read me + (final),v1.txt"
        );
    }

    #[test]
    fn zip_entry_name_byte_limit_is_inclusive_and_typed() {
        let child_bytes = ZIP_ENTRY_NAME_MAX_BYTES - ZIP_TOP_LEVEL_DIRECTORY.len() - 1;
        let at_limit = format!("{ZIP_TOP_LEVEL_DIRECTORY}/{}", "a".repeat(child_bytes));
        assert_eq!(at_limit.len(), ZIP_ENTRY_NAME_MAX_BYTES);
        validate_zip_entry_name(&at_limit, false).unwrap();

        let over_limit = format!("{at_limit}a");
        let error = validate_zip_entry_name(&over_limit, false).unwrap_err();
        assert!(matches!(
            AdmissionError::in_anyhow_chain(&error),
            Some(AdmissionError::LimitExceeded {
                resource: AdmissionResource::ArchiveEntryNameBytes,
                kind: LimitKind::Semantic,
                limit,
                observed: Some(observed),
            }) if *limit == ZIP_ENTRY_NAME_MAX_BYTES as u64
                && *observed == ZIP_ENTRY_NAME_MAX_BYTES as u64 + 1
        ));
        let mapped = ResponseErrorRef::from_anyhow_typed(&error, ChangedStatus::Conflict)
            .expect("ZIP entry-name limit remains typed under context");
        assert_eq!(mapped.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn percent_encoding_cannot_expand_a_deep_path_past_the_zip_header_limit() {
        let mut source = PathBuf::new();
        for _ in 0..86 {
            // 中文：每个 255 字节组件会编码为 765 字节。 / English: Each 255-byte component expands to 765 encoded bytes.
            source.push(":".repeat(255));
        }

        let error = validated_zip_entry_name(&source).unwrap_err();
        assert!(matches!(
            AdmissionError::in_anyhow_chain(&error),
            Some(AdmissionError::LimitExceeded {
                resource: AdmissionResource::ArchiveEntryNameBytes,
                kind: LimitKind::Semantic,
                limit,
                observed: Some(observed),
            }) if *limit == ZIP_ENTRY_NAME_MAX_BYTES as u64
                && *observed > ZIP_ENTRY_NAME_MAX_BYTES as u64
        ));
    }

    #[test]
    fn zip_entry_name_rejects_only_structural_traversal_forms() {
        for value in ["", ".", "..", "../escape", "dir/../escape", "/absolute"] {
            assert!(
                validated_zip_entry_name(Path::new(value)).is_err(),
                "unexpectedly accepted {value:?}"
            );
        }
    }

    #[test]
    fn zip_entry_name_encodes_cross_platform_special_names() {
        assert_eq!(
            validated_zip_entry_name(Path::new(r"dir\file:ads.txt")).unwrap(),
            "archive/dir%5Cfile%3Aads.txt"
        );
        assert_eq!(
            validated_zip_entry_name(Path::new("CON.txt")).unwrap(),
            "archive/%43ON.txt"
        );
        assert_eq!(
            validated_zip_entry_name(Path::new("literal%5C.txt")).unwrap(),
            "archive/literal%255C.txt"
        );
        assert_eq!(
            validated_zip_entry_name(Path::new(OsStr::from_bytes(b"raw-\xff.txt"))).unwrap(),
            "archive/raw-%FF.txt"
        );
        assert_eq!(
            validated_zip_entry_name(Path::new(OsStr::from_bytes(
                b"caf\xc3\xa9-\xff-\xe6\x96\x87.txt"
            )))
            .unwrap(),
            "archive/café-%FF-文.txt"
        );
    }

    #[test]
    fn zip_entry_name_encodes_the_complete_windows_device_matrix() {
        for device in ["CON", "PRN", "AUX", "NUL"] {
            let source = format!("{device}.txt");
            let encoded = validated_zip_entry_name(Path::new(&source)).unwrap();
            assert_eq!(
                encoded,
                format!("archive/%{:02X}{}.txt", device.as_bytes()[0], &device[1..])
            );
        }
        for prefix in ["COM", "LPT"] {
            for suffix in ["1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³"] {
                let device = format!("{prefix}{suffix}");
                let source = format!("{device}.log");
                let encoded = validated_zip_entry_name(Path::new(&source)).unwrap();
                assert_eq!(
                    encoded,
                    format!("archive/%{:02X}{}.log", prefix.as_bytes()[0], &device[1..]),
                    "Windows device name {source:?} was not neutralized"
                );
            }
        }
    }

    #[test]
    fn final_zip_name_validator_rejects_posix_and_windows_escape_forms() {
        for (value, directory) in [
            ("", false),
            ("/archive/file", false),
            (r"\archive\file", false),
            ("other/file", false),
            ("archive", false),
            ("archive/", false),
            ("archive", true),
            ("archive//file", false),
            ("archive/../evil", false),
            (r"archive/..\..\evil", false),
            (r"archive/C:\evil", false),
            (r"archive/\\server\share", false),
            ("archive/CON", false),
            ("archive/file.", false),
            ("archive/file ", false),
            ("archive/raw%ff", false),
            ("archive/file:stream", false),
        ] {
            assert!(
                validate_zip_entry_name(value, directory).is_err(),
                "unexpectedly accepted {value:?}"
            );
        }
        assert!(validate_zip_entry_name("archive/", true).is_ok());
        assert!(validate_zip_entry_name("archive/dir/", true).is_ok());
        assert!(validate_zip_entry_name("archive/dir/file.txt", false).is_ok());
        assert!(validate_zip_entry_name("archive/目录/😀.txt", false).is_ok());
        assert!(validate_zip_entry_name("archive/%43ON.txt", false).is_ok());
    }

    #[test]
    fn hostile_linux_filenames_remain_beneath_root_under_windows_semantics() {
        for source_name in [r"..\..\evil", r"C:\evil", r"\\server\share", r"dir\..\evil"] {
            let entry_name = validated_zip_entry_name(Path::new(source_name)).unwrap();
            validate_zip_entry_name(&entry_name, false).unwrap();
            let windows_components = windows_semantic_components(&entry_name)
                .expect("generated ZIP name must be a relative Windows path");
            assert_eq!(
                windows_components.first().map(String::as_str),
                Some(ZIP_TOP_LEVEL_DIRECTORY),
                "{source_name:?} produced {entry_name:?}"
            );
            assert_eq!(
                windows_components.len(),
                2,
                "encoded separators must remain inside one child component: {entry_name:?}"
            );
        }
    }

    /// 仅作回归 oracle 的最小独立 Windows 路径规范化：两种 slash 都分隔，`..` 弹出组件。
    /// Minimal independent Windows normalization oracle with both separators and parent popping.
    fn windows_semantic_components(value: &str) -> Option<Vec<String>> {
        let bytes = value.as_bytes();
        if value.starts_with(['/', '\\'])
            || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
        {
            return None;
        }

        let mut normalized = Vec::new();
        for component in value.split(['/', '\\']) {
            match component {
                "" | "." => {}
                ".." => {
                    normalized.pop()?;
                }
                _ if component.as_bytes().get(1) == Some(&b':')
                    && component.as_bytes()[0].is_ascii_alphabetic() =>
                {
                    return None;
                }
                _ => normalized.push(component.to_owned()),
            }
        }
        Some(normalized)
    }
}
