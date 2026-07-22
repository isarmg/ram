//! 对文件系统的**写**操作：上传（PUT/PATCH）、删除（DELETE），
//! 以及 WebDAV 的写方法 MKCOL/COPY/MOVE——包括 `Destination` 头的
//! 校验和 RFC 4918 规定的 `Overwrite` 语义。
//!
//! 写操作是安全敏感区：每个函数都要考虑"这一步会不会覆盖/删掉
//! 用户无权动的东西"，注意代码里 allow_upload / allow_delete 与
//! 目标路径越界检查的组合运用。
//!
//! ## 本模块的 Rust 知识点
//! - **流式落盘**：上传体经一个两块容量的有界通道交给同步文件 worker，
//!   网络读取和磁盘写入互相背压，超大文件也不会占用大量内存。
//! - **`take(n)` 限流**：给 reader 套上"最多读 n 字节"的适配器
//!   实现上传大小上限，多读到的第 n+1 字节用于识别超限。
//! - **两阶段发布**：请求体先进入不可公开的 `0600` 候选；取得终局变更锁后重新打开真实
//!   目标并复核 ACL、HTTP 前置条件与 inode 期望，最后由单次 rename 发布。
//! - **外部配额策略**：只执行启动时捕获的钩子描述符。单线程 helper 清空环境、安装
//!   `PDEATHSIG` 后 `exec`，超时/取消会终止其进程组并回收直系子进程。
//!
//! This module implements filesystem mutations: PUT/PATCH uploads, DELETE, and WebDAV MKCOL/COPY/MOVE,
//! including `Destination` validation and RFC 4918 `Overwrite` semantics. Every path is security
//! sensitive: upload/delete policy and containment checks must jointly prevent modification of an
//! unauthorized object. Upload bodies flow through a bounded two-chunk channel into a synchronous
//! disk worker for backpressure, and `take(n)` reads one sentinel byte beyond a configured limit.
//! Publication is two-phase: bytes first enter a private `0600` candidate, then final mutation locks
//! protect descriptor-based ACL/precondition/identity revalidation before one rename. External quota
//! policy executes only the startup-pinned hook through a clean-environment, parent-bound helper whose
//! process group is terminated and reaped on timeout or cancellation.

use super::error::{
    AdmissionError, AdmissionResource, ChangedStatus, FsError, HttpError, LimitKind,
    MutationEndpointRole, QueueScope, ResponseError, ResponseErrorRef,
};
#[cfg(test)]
use super::filesystem::RootFs;
use super::filesystem::{EntryExpectation, NodeKind, OpenedNode, TempFile};
use super::preconditions::ParsedPreconditions;
use super::reply::{status_bad_request, status_forbid, status_no_content};
use super::walk::{
    RequestCancellation, is_blocking_deadline, spawn_supervised_blocking_with_shutdown,
};
use super::{MutationGuards, Request, Response, Server, extract_cache_headers};
use crate::http::IncomingStream;
use crate::path_identity::PathIdentity;
use crate::source_identity::SourceIdentity;

use anyhow::{Context, Result, anyhow, bail};
use futures_util::StreamExt;
use headers::{HeaderMap, IfNoneMatch};
use hyper::{
    Method, StatusCode, Uri,
    header::{CONTENT_LENGTH, HOST, HeaderValue},
};
use std::ffi::OsString;
use std::fs::File;
#[cfg(test)]
use std::io;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub(super) struct StagedUpload {
    temp: TempFile,
    len: u64,
    user: Option<String>,
}

struct UploadAdmission {
    _global: tokio::sync::OwnedSemaphorePermit,
    _user: tokio::sync::OwnedSemaphorePermit,
    _source: tokio::sync::OwnedSemaphorePermit,
}

enum UploadFeedFailure {
    TooLarge,
    Deadline,
    Body(anyhow::Error),
    WorkerStopped,
}

const CANCELLED_UPLOAD_CLEANUP_GRACE: Duration = Duration::from_millis(250);

/// 一次原子上传发布所观察并重新验证的全部状态。集中保存可防止 PUT/PATCH 调用点把偏移或
/// 存在标志与另一探测的元数据错误配对。
/// All state observed/revalidated for one atomic upload publication. Keeping it together prevents
/// PUT/PATCH from pairing an offset/existence flag with metadata from another probe.
pub(super) struct UploadCommit {
    pub(super) upload_offset: Option<u64>,
    pub(super) original: Option<OpenedNode>,
    pub(super) staged: StagedUpload,
    pub(super) mutation_guards: MutationGuards,
    pub(super) changed_status: ChangedStatus,
}

/// 早期上传大小准入使用的表示状态。PATCH 会在提交工作线程中用权威描述符元数据重新评估；
/// 此乐观副本只用于在读取前拒绝明显过大的请求体。
/// Representation state for early upload-size admission. PATCH is re-evaluated from authoritative
/// descriptor metadata in the commit worker; this optimistic copy only rejects obvious oversize.
#[derive(Clone, Copy, Debug)]
pub(super) struct UploadProjection {
    current_size: u64,
    offset: Option<u64>,
}

impl UploadProjection {
    pub(super) const fn put() -> Self {
        Self {
            current_size: 0,
            offset: None,
        }
    }

    pub(super) const fn patch(current_size: u64, offset: u64) -> Self {
        Self {
            current_size,
            offset: Some(offset),
        }
    }

    fn projected(self, incoming_len: u64, limit: u64) -> Result<u64, UploadSizeExceeded> {
        projected_upload_size(self.current_size, self.offset, incoming_len, limit)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct UploadSizeExceeded;

/// 不执行变更地计算 PUT/PATCH 最终表示长度。
/// Compute the final representation length for PUT/PATCH without mutation.
///
/// `offset == None` 表示 PUT 并替换旧表示；PATCH 取现有长度与 `offset + incoming_len` 的
/// 较大值。每次加法都检查，算术溢出和超配置上限都映射为稳定 HTTP 413。零上限是有文档的
/// 显式无限模式，但绝不关闭溢出检测。
/// `offset == None` is PUT and replaces the old representation. PATCH keeps the longer of existing
/// length and `offset + incoming_len`. All addition is checked; overflow/limit violations are 413.
/// Zero explicitly means unlimited but never disables overflow detection.
pub(super) fn projected_upload_size(
    current_size: u64,
    offset: Option<u64>,
    incoming_len: u64,
    limit: u64,
) -> Result<u64, UploadSizeExceeded> {
    let projected = match offset {
        Some(offset) => {
            current_size.max(offset.checked_add(incoming_len).ok_or(UploadSizeExceeded)?)
        }
        None => incoming_len,
    };
    if limit > 0 && projected > limit {
        Err(UploadSizeExceeded)
    } else {
        Ok(projected)
    }
}

fn upload_size_error(limit: u64, observed: Option<u64>) -> anyhow::Error {
    anyhow::Error::new(AdmissionError::limit_exceeded(
        AdmissionResource::UploadBytes,
        LimitKind::Payload,
        limit,
        observed,
    ))
}

fn copy_size_error(limit: u64, observed: Option<u64>) -> anyhow::Error {
    anyhow::Error::new(AdmissionError::limit_exceeded(
        AdmissionResource::CopyBytes,
        LimitKind::Storage,
        limit,
        observed,
    ))
}

fn local_path_error(detail: &'static str) -> anyhow::Error {
    anyhow::Error::new(HttpError::bad_request(anyhow!(detail)))
}

fn upload_body_transport_error(source: anyhow::Error) -> anyhow::Error {
    anyhow::Error::new(HttpError::bad_request(source))
        .context("reading PUT/PATCH request body transport")
}

fn copy_cancellation_error(context: &'static str) -> anyhow::Error {
    anyhow::Error::new(AdmissionError::cancelled(AdmissionResource::CopyBytes)).context(context)
}

impl Server {
    /// 获取变更锁前把 PUT/PATCH 请求体接收到私有候选中。若目标父目录已存在，PUT 可直接
    /// 发布同一候选。暂存期间刻意不创建缺失祖先；回退候选位于固定服务根中，只在变更锁下
    /// 重新评估授权/前置条件后复制。
    /// Receive a PUT/PATCH body into a private candidate before mutation locking. If the parent exists,
    /// PUT can publish it directly. Staging never creates ancestors; a root fallback is copied only
    /// after authorization/preconditions are re-evaluated under the lock.
    pub(super) async fn stage_upload(
        &self,
        path: &Path,
        req: Request,
        projection: UploadProjection,
        user: Option<&str>,
        source: SourceIdentity,
        res: &mut Response,
    ) -> Result<Option<StagedUpload>> {
        let max_upload_size = self.args.max_upload_size;
        let declared_length = req
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        if let Some(length) = declared_length
            && projection.projected(length, max_upload_size).is_err()
        {
            ResponseError::admission(AdmissionError::limit_exceeded(
                AdmissionResource::UploadBytes,
                LimitKind::Payload,
                max_upload_size,
                Some(length),
            ))
            .apply(res);
            return Ok(None);
        }

        let global_permit = match self.upload_limit.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                ResponseError::admission(AdmissionError::queue_full(
                    AdmissionResource::Uploads,
                    QueueScope::Global,
                    self.args.max_concurrent_uploads,
                ))
                .apply(res);
                return Ok(None);
            }
        };
        let user_key = user.map(str::to_owned);
        let user_permit = match self.upload_user_limit.try_acquire(&user_key)? {
            Some(permit) => permit,
            None => {
                ResponseError::admission(AdmissionError::queue_full(
                    AdmissionResource::Uploads,
                    QueueScope::PerAccount,
                    self.args
                        .max_concurrent_uploads_per_user
                        .min(self.args.max_concurrent_uploads),
                ))
                .apply(res);
                return Ok(None);
            }
        };
        let source_permit = match self.upload_source_limit.try_acquire(&source)? {
            Some(permit) => permit,
            None => {
                ResponseError::admission(AdmissionError::queue_full(
                    AdmissionResource::Uploads,
                    QueueScope::PerSource,
                    self.args
                        .max_concurrent_uploads_per_source
                        .min(self.args.max_concurrent_uploads),
                ))
                .apply(res);
                return Ok(None);
            }
        };
        let admission = UploadAdmission {
            _global: global_permit,
            _user: user_permit,
            _source: source_permit,
        };

        let upload_idle_timeout = Duration::from_secs(self.args.upload_idle_timeout);
        let upload_deadline =
            tokio::time::Instant::now() + Duration::from_secs(self.args.upload_total_timeout);
        let operation_name = if req.method() == Method::PATCH {
            "PATCH"
        } else {
            "PUT"
        };
        let response_user = user.map(str::to_owned);
        let worker_path = path.to_path_buf();
        let fs_root = self.fs_root.clone();
        let upload_dir_mode = self.args.upload_dir_mode;
        let (chunk_tx, mut chunk_rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(2);
        let operation = spawn_supervised_blocking_with_shutdown(
            self.running.clone(),
            (),
            move |cancellation| {
                let mut temp =
                    match fs_root.create_blocking_temp(&worker_path, false, upload_dir_mode) {
                        Ok(temp) if temp.target_rel() == worker_path => temp,
                        Ok(_) => {
                            return Err(anyhow::Error::new(HttpError::bad_request(anyhow!(
                                "upload staging target resolved to a different capability path"
                            ))));
                        }
                        Err(error) => {
                            let error = ensure_typed_filesystem_error(
                                "creating upload staging candidate",
                                error,
                            );
                            if upload_target_parent_is_missing(&error) {
                                fs_root.create_blocking_staging_temp()?
                            } else {
                                return Err(error);
                            }
                        }
                    };
                // 准入守卫随候选经过异步暂存、发布工作线程和所有清理路径。
                // The admission guard follows this candidate through async staging, publication, and
                // every cleanup path.
                temp.attach_cleanup_guard(admission)?;
                let mut received = 0u64;
                while let Some(chunk) = chunk_rx.blocking_recv() {
                    if cancellation.is_cancelled() {
                        return Err(anyhow::Error::new(AdmissionError::cancelled(
                            AdmissionResource::Uploads,
                        ))
                        .context("upload staging request was cancelled"));
                    }
                    let next = projected_upload_size(0, Some(received), chunk.len() as u64, 0)
                        .and_then(|next| projection.projected(next, max_upload_size).map(|_| next))
                        .map_err(|_| {
                            anyhow::Error::new(AdmissionError::limit_exceeded(
                                AdmissionResource::UploadBytes,
                                LimitKind::Payload,
                                max_upload_size,
                                None,
                            ))
                        })?;
                    temp.write_all(&chunk)?;
                    received = next;
                }
                if cancellation.is_cancelled() {
                    return Err(anyhow::Error::new(AdmissionError::cancelled(
                        AdmissionResource::Uploads,
                    ))
                    .context("upload staging request was cancelled"));
                }
                temp.flush()?;
                Ok(StagedUpload {
                    temp: temp.into_async_temp()?,
                    len: received,
                    user: user_key,
                })
            },
        );
        let cancellation = operation.cancellation();
        let mut stream = IncomingStream::new(req.into_body());
        let mut queued = 0u64;
        let feed_result = loop {
            let next_deadline =
                (tokio::time::Instant::now() + upload_idle_timeout).min(upload_deadline);
            match tokio::time::timeout_at(next_deadline, stream.next()).await {
                Ok(Some(Ok(chunk))) => {
                    let Ok(next) = projected_upload_size(0, Some(queued), chunk.len() as u64, 0)
                    else {
                        break Err(UploadFeedFailure::TooLarge);
                    };
                    if projection.projected(next, max_upload_size).is_err() {
                        break Err(UploadFeedFailure::TooLarge);
                    }
                    match tokio::time::timeout_at(upload_deadline, chunk_tx.send(chunk)).await {
                        Ok(Ok(())) => queued = next,
                        Ok(Err(_)) => break Err(UploadFeedFailure::WorkerStopped),
                        Err(_) => break Err(UploadFeedFailure::Deadline),
                    }
                }
                Ok(Some(Err(error))) => break Err(UploadFeedFailure::Body(error)),
                Ok(None) => break Ok(()),
                Err(_) => break Err(UploadFeedFailure::Deadline),
            }
        };
        drop(chunk_tx);

        match feed_result {
            Ok(()) | Err(UploadFeedFailure::WorkerStopped) => {}
            Err(UploadFeedFailure::TooLarge) => {
                cancellation.cancel();
                let _ = operation
                    .wait_until(tokio::time::Instant::now() + CANCELLED_UPLOAD_CLEANUP_GRACE)
                    .await;
                ResponseError::admission(AdmissionError::limit_exceeded(
                    AdmissionResource::UploadBytes,
                    LimitKind::Payload,
                    max_upload_size,
                    None,
                ))
                .apply(res);
                return Ok(None);
            }
            Err(UploadFeedFailure::Deadline) => {
                cancellation.cancel_for_deadline();
                let _ = operation
                    .wait_until(tokio::time::Instant::now() + CANCELLED_UPLOAD_CLEANUP_GRACE)
                    .await;
                *res.status_mut() = StatusCode::REQUEST_TIMEOUT;
                return Ok(None);
            }
            Err(UploadFeedFailure::Body(error)) => {
                cancellation.cancel();
                let _ = operation
                    .wait_until(tokio::time::Instant::now() + CANCELLED_UPLOAD_CLEANUP_GRACE)
                    .await;
                return Err(upload_body_transport_error(error));
            }
        }

        match operation.wait_until(upload_deadline).await {
            Ok(staged) => Ok(Some(staged)),
            Err(error) if is_blocking_deadline(&error) => {
                warn!(
                    "Upload staging worker deadline exceeded: operation={operation_name} path={path:?} error={error:#}"
                );
                ResponseError::admission(AdmissionError::execution_timeout(
                    AdmissionResource::Uploads,
                    Duration::from_secs(self.args.upload_total_timeout),
                ))
                .apply(res);
                Ok(None)
            }
            Err(error) => {
                map_local_mutation_error(
                    operation_name,
                    path,
                    response_user.as_deref(),
                    error,
                    ChangedStatus::Conflict,
                    res,
                )?;
                Ok(None)
            }
        }
    }

    /// 上传（PUT 整文件 / PATCH 断点续传）。
    /// `upload_offset`：None = 从头新建/覆盖；Some(offset) = 从 offset 续写，
    /// offset 等于当前大小时是纯追加。
    /// Upload via full-file PUT or resumable PATCH. `None` creates/replaces from the start;
    /// `Some(offset)` resumes there, and an offset equal to current length is a pure append.
    pub(super) async fn handle_upload(
        &self,
        path: &Path,
        upload: UploadCommit,
        res: &mut Response,
    ) -> Result<()> {
        let UploadCommit {
            upload_offset,
            original,
            staged,
            mutation_guards,
            changed_status,
        } = upload;
        let expected_target = original
            .as_ref()
            .map(|opened| EntryExpectation::from_metadata(&opened.metadata))
            .unwrap_or(EntryExpectation::Missing);
        let target_exists = matches!(expected_target, EntryExpectation::Present(_));
        let observed_size = original
            .as_ref()
            .map(|opened| opened.metadata.len())
            .unwrap_or(0);
        let max_upload_size = self.args.max_upload_size;
        let StagedUpload {
            temp: staged_temp,
            len: staged_len,
            user: staged_user,
        } = staged;

        if projected_upload_size(observed_size, upload_offset, staged_len, max_upload_size).is_err()
        {
            ResponseError::admission(AdmissionError::limit_exceeded(
                AdmissionResource::UploadBytes,
                LimitKind::Payload,
                max_upload_size,
                Some(staged_len),
            ))
            .apply(res);
            return Ok(());
        }

        // 发布、fsync、PATCH 基础复制和可选配额钩子均在一个拥有所有权的阻塞任务中执行。上传
        // 准入附着于 staged_temp 并随它进入工作线程；昂贵任务 permit 是显式工作守卫。因此
        // 丢弃/超时请求不会在内核 I/O 或候选清理仍继续时把容量显示为空闲。
        // Publication, fsync, PATCH base copy, and optional quota hook run in one owned blocking job.
        // Admission follows staged_temp; the expensive permit guards the worker, so cancellation cannot
        // make capacity appear free while kernel I/O or cleanup continues.
        let expensive_permit = match self.expensive_task_limit.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                ResponseError::admission(AdmissionError::queue_full(
                    AdmissionResource::ExpensiveTasks,
                    QueueScope::WorkerPool,
                    self.args.max_expensive_tasks,
                ))
                .apply(res);
                return Ok(());
            }
        };

        if let Some(opened) = original
            .as_ref()
            .filter(|opened| opened.real_rel != path || !opened.metadata.is_file())
        {
            let error = anyhow::Error::new(FsError::changed(
                MutationEndpointRole::Target,
                path.display().to_string(),
                format!("{expected_target:?}"),
                format!(
                    "opened path={:?}, kind_mode={:o}",
                    opened.real_rel,
                    opened.metadata.mode() & 0o170000
                ),
            ));
            return map_local_mutation_error(
                if upload_offset.is_some() {
                    "PATCH"
                } else {
                    "PUT"
                },
                path,
                staged_user.as_deref(),
                error,
                changed_status,
                res,
            );
        }
        let old_permissions = original.as_ref().map(|opened| {
            std::fs::Permissions::from_mode(opened.metadata.permissions().mode() & 0o777)
        });
        let direct_put = upload_offset.is_none() && staged_temp.target_rel() == path;
        let staged_temp = staged_temp.into_blocking()?;
        let mut source = match upload_offset {
            Some(_) => Some(
                original
                    .ok_or_else(|| {
                        anyhow::Error::new(FsError::changed(
                            MutationEndpointRole::Target,
                            path.display().to_string(),
                            format!("{expected_target:?}"),
                            "PATCH source disappeared before publication",
                        ))
                    })?
                    .file
                    .into_std()
                    .context("converting the guarded PATCH source")?,
            ),
            None => None,
        };
        let fs_root = self.fs_root.clone();
        let path = path.to_path_buf();
        let worker_path = path.clone();
        let allow_delete = self.args.allow_delete;
        let upload_file_mode = self.args.upload_file_mode;
        let upload_dir_mode = self.args.upload_dir_mode;
        let storage_space_check = self.args.storage_space_check;
        let storage_reserve = self.args.storage_reserve;
        let quota_hook = self
            .args
            .startup_paths
            .as_ref()
            .and_then(|paths| paths.storage_quota_hook())
            .cloned();
        let quota_hook_timeout = Duration::from_secs(self.args.storage_quota_hook_timeout);
        let operation_name = if upload_offset.is_some() {
            "PATCH"
        } else {
            "PUT"
        };
        let response_user = staged_user.clone();

        let operation = spawn_supervised_blocking_with_shutdown(
            self.running.clone(),
            expensive_permit,
            move |cancellation| {
                // 在所有候选局部变量前声明，使逆序 Drop 在释放命名空间变更锁前清理每个临时名称。
                // Declared before candidate locals so reverse drop order cleans every temporary name
                // before releasing namespace mutation locks.
                let _mutation_guards = mutation_guards;
                let mut staged_temp = Some(staged_temp);
                let mut target = if direct_put {
                    staged_temp
                        .take()
                        .ok_or_else(|| anyhow!("direct PUT candidate is missing"))?
                } else {
                    let candidate =
                        fs_root.create_blocking_temp(&worker_path, true, upload_dir_mode)?;
                    if candidate.target_rel() != worker_path {
                        return Err(local_path_error(
                            "upload candidate resolved to a different capability path",
                        ));
                    }
                    candidate
                };

                let actual_base_size = if let (Some(offset), Some(source)) =
                    (upload_offset, source.as_mut())
                {
                    let source_metadata = source.metadata()?;
                    if !expected_target.matches_metadata(&source_metadata) {
                        return Err(anyhow::Error::new(super::error::FsError::changed(
                            MutationEndpointRole::Target,
                            worker_path.display().to_string(),
                            format!("{expected_target:?}"),
                            format!("{:?}", EntryExpectation::from_metadata(&source_metadata)),
                        )));
                    }
                    let actual_size = source_metadata.len();
                    if projected_upload_size(actual_size, Some(offset), staged_len, max_upload_size)
                        .is_err()
                    {
                        return Err(upload_size_error(max_upload_size, Some(staged_len)));
                    }
                    if offset > actual_size {
                        return Err(anyhow::Error::new(FsError::conflict(
                            "validating PATCH offset",
                            anyhow!("PATCH offset exceeds the current representation length"),
                        )));
                    }
                    if offset < actual_size && !allow_delete {
                        return Err(anyhow::Error::new(HttpError::forbidden(anyhow!(
                            "PATCH would overwrite existing representation bytes"
                        ))));
                    }
                    actual_size
                } else {
                    0
                };
                let final_size = projected_upload_size(
                    actual_base_size,
                    upload_offset,
                    staged_len,
                    max_upload_size,
                )
                .map_err(|_| upload_size_error(max_upload_size, None))?;

                run_storage_quota_hook(
                    quota_hook.as_ref(),
                    quota_hook_timeout,
                    staged_user.as_deref(),
                    operation_name,
                    &worker_path,
                    observed_size,
                    final_size,
                    &cancellation,
                )?;
                if storage_space_check {
                    // 直接 PUT 候选已包含请求体；PATCH/回退 PUT 会在旧表示仍可达时分配第二个
                    // 完整候选。
                    // A direct PUT candidate already contains its body. PATCH/fallback PUT allocates a
                    // second complete candidate while the old representation remains reachable.
                    let additional_bytes = if direct_put { 0 } else { final_size };
                    enforce_storage_preflight(&target, additional_bytes, storage_reserve)?;
                }

                if let (Some(offset), Some(source)) = (upload_offset, source.as_mut()) {
                    let outcome = copy_regular_file_cooperatively(
                        source,
                        target.file_mut(),
                        (max_upload_size > 0).then_some(max_upload_size),
                        &cancellation,
                    )?;
                    if max_upload_size > 0 && outcome.bytes > max_upload_size {
                        return Err(upload_size_error(max_upload_size, Some(outcome.bytes)));
                    }
                    if outcome.bytes != actual_base_size {
                        return Err(anyhow::Error::new(FsError::changed(
                            MutationEndpointRole::Target,
                            worker_path.display().to_string(),
                            format!("{actual_base_size} bytes"),
                            format!("{} bytes copied", outcome.bytes),
                        )));
                    }
                    let source_metadata = source.metadata()?;
                    if !expected_target.matches_metadata(&source_metadata) {
                        return Err(anyhow::Error::new(super::error::FsError::changed(
                            MutationEndpointRole::Target,
                            worker_path.display().to_string(),
                            format!("{expected_target:?}"),
                            format!("{:?}", EntryExpectation::from_metadata(&source_metadata)),
                        )));
                    }
                    if offset > outcome.bytes {
                        return Err(anyhow::Error::new(FsError::conflict(
                            "validating PATCH offset after source copy",
                            anyhow!("PATCH offset exceeds copied representation length"),
                        )));
                    }
                    target.file_mut().seek(SeekFrom::Start(offset))?;
                }
                if !direct_put {
                    let staged_temp = staged_temp
                        .as_mut()
                        .ok_or_else(|| anyhow!("staged upload candidate is missing"))?;
                    staged_temp.file_mut().seek(SeekFrom::Start(0))?;
                    copy_exact_at_current(
                        staged_temp.file_mut(),
                        target.file_mut(),
                        staged_len,
                        &cancellation,
                    )?;
                }
                let final_mode = old_permissions
                    .as_ref()
                    .map(std::fs::Permissions::mode)
                    .unwrap_or(upload_file_mode)
                    & 0o777;
                let actual_final_size = target.file_mut().metadata()?.len();
                if actual_final_size != final_size {
                    bail!(
                        "upload candidate length changed: expected {final_size}, got {actual_final_size}"
                    );
                }
                target.commit(expected_target, final_mode, &cancellation)
            },
        );
        let deadline = tokio::time::Instant::now() + Duration::from_secs(self.args.copy_timeout);
        if let Err(err) = operation.wait_until(deadline).await {
            return map_local_mutation_error(
                operation_name,
                &path,
                response_user.as_deref(),
                err,
                changed_status,
                res,
            );
        }

        *res.status_mut() = if upload_offset.is_some() || target_exists {
            StatusCode::NO_CONTENT
        } else {
            StatusCode::CREATED
        };

        Ok(())
    }

    /// DELETE：文件用 remove_file，目录用 remove_dir_all 整树删除。
    /// DELETE: remove a file directly or remove a directory tree recursively.
    pub(super) async fn handle_delete(
        &self,
        path: &Path,
        original: OpenedNode,
        mutation_guards: MutationGuards,
        changed_status: ChangedStatus,
        res: &mut Response,
    ) -> Result<()> {
        if original.real_rel != path {
            ResponseError::filesystem(
                FsError::changed(
                    MutationEndpointRole::Target,
                    path.display().to_string(),
                    format!("opened {:?}", original.real_rel),
                    "mutation aliases through a symlink are not supported",
                ),
                changed_status,
            )
            .apply(res);
            return Ok(());
        }
        let is_dir = original.metadata.is_dir();
        let expected_target = EntryExpectation::from_metadata(&original.metadata);
        let expensive_permit = match self.expensive_task_limit.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                ResponseError::admission(AdmissionError::queue_full(
                    AdmissionResource::ExpensiveTasks,
                    QueueScope::WorkerPool,
                    self.args.max_expensive_tasks,
                ))
                .apply(res);
                return Ok(());
            }
        };
        let fs_root = self.fs_root.clone();
        let worker_path = path.to_path_buf();
        let max_entries = self.args.max_walk_entries as usize;
        let max_depth = self.args.max_walk_depth as usize;
        let operation = spawn_supervised_blocking_with_shutdown(
            self.running.clone(),
            expensive_permit,
            move |cancellation| {
                let _mutation_guards = mutation_guards;
                fs_root.remove_sync(
                    &worker_path,
                    is_dir,
                    expected_target,
                    max_entries,
                    max_depth,
                    &cancellation,
                )
            },
        );
        let deadline = tokio::time::Instant::now() + Duration::from_secs(self.args.copy_timeout);
        if let Err(error) = operation.wait_until(deadline).await {
            return map_local_mutation_error("DELETE", path, None, error, changed_status, res);
        }

        status_no_content(res);
        Ok(())
    }

    /// MKCOL（WebDAV 建目录，Web 界面的"新建文件夹"也走这里）。
    /// MKCOL creates a WebDAV collection and also backs the web UI's “new folder” action.
    pub(super) async fn handle_mkcol(
        &self,
        path: &Path,
        mutation_guards: MutationGuards,
        changed_status: ChangedStatus,
        res: &mut Response,
    ) -> Result<()> {
        // RFC 4918：MKCOL 不得创建缺失祖先。`mkdir` 通过 openat2 安全打开父目录，再以单个
        // 名称调用 mkdirat。
        // RFC 4918: MKCOL may not create missing ancestors. `mkdir` securely opens the parent through
        // openat2 and calls mkdirat with one name.
        if let Err(error) = self.fs_root.open_parent(path, false).await {
            return map_required_parent_error("MKCOL", path, None, error, changed_status, res);
        }
        match self
            .fs_root
            .mkdir(path, self.args.upload_dir_mode, mutation_guards)
            .await
        {
            Ok(_) => *res.status_mut() = StatusCode::CREATED,
            Err(err) => {
                return map_local_mutation_error("MKCOL", path, None, err, changed_status, res);
            }
        }
        Ok(())
    }

    /// COPY：把源文件复制到 `Destination` 头指定的目标路径。
    /// 目录复制未实现（返回 403），与上游 dufs 保持一致。
    /// COPY a source file to the `Destination` path. Directory copy is not implemented and returns
    /// 403, matching upstream dufs behavior.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn handle_copy(
        &self,
        source: OpenedNode,
        dest: &Path,
        headers: &HeaderMap<HeaderValue>,
        user: Option<&str>,
        mutation_guards: MutationGuards,
        changed_status: ChangedStatus,
        res: &mut Response,
    ) -> Result<()> {
        let overwrite = match overwrite_allowed(headers) {
            Ok(overwrite) => overwrite,
            Err(err) => {
                warn!("Rejected invalid COPY Overwrite header: {err:#}");
                status_bad_request(res, "Invalid Overwrite header");
                return Ok(());
            }
        };

        if source.metadata.is_dir() {
            status_forbid(res);
            return Ok(());
        }
        if !source.metadata.is_file() {
            status_forbid(res);
            return Ok(());
        }
        if source.metadata.len() > self.args.max_copy_size {
            return map_local_mutation_error(
                "COPY",
                dest,
                user,
                copy_size_error(self.args.max_copy_size, Some(source.metadata.len())),
                changed_status,
                res,
            );
        }

        // RFC 4918 要求目标父集合存在；COPY 不得替客户端制造祖先层级。
        // RFC 4918 requires the destination parent collection to exist; COPY must not manufacture an
        // ancestor hierarchy for the client.
        if let Err(error) = self.fs_root.open_parent(dest, false).await {
            return map_required_parent_error("COPY", dest, user, error, changed_status, res);
        }

        let expected_destination = match self.fs_root.entry_expectation(dest).await {
            Ok(expectation) => expectation,
            Err(error) => {
                return map_entry_expectation_error("COPY", dest, user, error, changed_status, res);
            }
        };
        let dest_exists = matches!(expected_destination, EntryExpectation::Present(_));
        if dest_exists {
            if !overwrite {
                *res.status_mut() = StatusCode::PRECONDITION_FAILED;
                return Ok(());
            }
            // 路由层对 COPY 只检查了 allow_upload；但覆盖已存在的目标
            // 等于删掉它原来的内容，所以还必须尊重 allow_delete——
            // 与 PUT 覆盖非空文件的规则一致。
            // Routing checks only allow_upload for COPY, but overwriting an existing target deletes its
            // old contents and must also honor allow_delete, like PUT over a non-empty file.
            if !self.args.allow_delete {
                status_forbid(res);
                return Ok(());
            }
            // 此有限 COPY 子集能替换普通文件，不能把集合/特殊节点变成文件。在复制工作线程
            // 创建候选前拒绝资源形状冲突，否则最终 rename 失败会错误表现为 500。
            // This finite COPY subset replaces regular files, not collections/special nodes. Reject
            // shape conflicts before candidate creation so rename failure is not misreported as 500.
            match self.fs_root.open(dest.to_path_buf(), NodeKind::Any).await {
                Ok(opened) if opened.metadata.is_file() => {}
                Ok(opened) => {
                    let error = anyhow::Error::new(FsError::conflict(
                        "validating existing COPY destination",
                        anyhow!(
                            "destination is not a regular file (mode={:o})",
                            opened.metadata.mode() & 0o170000
                        ),
                    ));
                    return map_existing_destination_error(
                        "COPY",
                        dest,
                        user,
                        error,
                        overwrite,
                        changed_status,
                        res,
                    );
                }
                Err(error) => {
                    return map_existing_destination_error(
                        "COPY",
                        dest,
                        user,
                        error,
                        overwrite,
                        changed_status,
                        res,
                    );
                }
            }
        }

        let dest_acl = dest
            .to_str()
            .and_then(|dest| user.and_then(|user| self.args.auth.guard_dest_for_user(user, dest)));
        if dest_acl.is_none() {
            status_forbid(res);
            return Ok(());
        }
        let expected_source = EntryExpectation::from_metadata(&source.metadata);
        let source_path = source.real_rel.clone();
        let source_mode = source.metadata.permissions().mode() & 0o777;
        let mut source_file = source
            .file
            .into_std()
            .context("converting the guarded COPY source")?;
        let expensive_permit = match self.expensive_task_limit.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                ResponseError::admission(AdmissionError::queue_full(
                    AdmissionResource::ExpensiveTasks,
                    QueueScope::WorkerPool,
                    self.args.max_expensive_tasks,
                ))
                .apply(res);
                return Ok(());
            }
        };
        let fs_root = self.fs_root.clone();
        let destination = dest.to_path_buf();
        let worker_destination = destination.clone();
        let copy_limit = self.args.max_copy_size;
        let upload_dir_mode = self.args.upload_dir_mode;
        let storage_space_check = self.args.storage_space_check;
        let storage_reserve = self.args.storage_reserve;
        let quota_hook = self
            .args
            .startup_paths
            .as_ref()
            .and_then(|paths| paths.storage_quota_hook())
            .cloned();
        let quota_hook_timeout = Duration::from_secs(self.args.storage_quota_hook_timeout);
        let quota_user = user.map(str::to_owned);
        let response_user = quota_user.clone();

        let operation = spawn_supervised_blocking_with_shutdown(
            self.running.clone(),
            expensive_permit,
            move |cancellation| {
                let _mutation_guards = mutation_guards;
                let source_metadata = fs_root.verify_opened_entry_sync(
                    &source_path,
                    &source_file,
                    expected_source,
                    MutationEndpointRole::Source,
                )?;
                let source_size = source_metadata.len();
                if source_size > copy_limit {
                    return Err(copy_size_error(copy_limit, Some(source_size)));
                }
                let current_size = fs_root
                    .entry_size_nofollow(&worker_destination)?
                    .unwrap_or(0);
                run_storage_quota_hook(
                    quota_hook.as_ref(),
                    quota_hook_timeout,
                    quota_user.as_deref(),
                    "COPY",
                    &worker_destination,
                    current_size,
                    source_size,
                    &cancellation,
                )?;

                // 父解析和 O_EXCL 候选创建包含在工作线程生命周期内，不由可取消请求 future
                // 执行，以免过早释放昂贵操作 permit。
                // Parent resolution and O_EXCL creation belong to the worker lifetime, not a cancellable
                // request future that could prematurely release the expensive permit.
                let mut target =
                    fs_root.create_blocking_temp(&worker_destination, false, upload_dir_mode)?;
                if target.target_rel() != worker_destination {
                    return Err(local_path_error(
                        "COPY destination resolved to a different capability path",
                    ));
                }
                if storage_space_check {
                    enforce_storage_preflight(&target, source_size, storage_reserve)?;
                }
                let outcome = copy_regular_file_cooperatively(
                    &mut source_file,
                    target.file_mut(),
                    Some(copy_limit),
                    &cancellation,
                )?;
                if outcome.bytes > copy_limit {
                    return Err(copy_size_error(copy_limit, Some(outcome.bytes)));
                }
                if outcome.bytes != source_size {
                    return Err(anyhow::Error::new(FsError::changed(
                        MutationEndpointRole::Source,
                        source_path.display().to_string(),
                        format!("{source_size} bytes"),
                        format!("{} bytes copied", outcome.bytes),
                    )));
                }
                fs_root.verify_opened_entry_sync(
                    &source_path,
                    &source_file,
                    expected_source,
                    MutationEndpointRole::Source,
                )?;
                target.commit(expected_destination, source_mode, &cancellation)?;
                Ok(outcome)
            },
        );
        let deadline = tokio::time::Instant::now() + Duration::from_secs(self.args.copy_timeout);
        let outcome = match operation.wait_until(deadline).await {
            Ok(outcome) => outcome,
            Err(err) => {
                let endpoint_status = copy_move_changed_status(&err, changed_status, overwrite);
                return map_local_mutation_error(
                    "COPY",
                    &destination,
                    response_user.as_deref(),
                    err,
                    endpoint_status,
                    res,
                );
            }
        };
        debug!(
            "Completed local COPY: destination={destination:?} bytes={} strategy={:?}",
            outcome.bytes, outcome.strategy
        );

        if dest_exists {
            status_no_content(res);
        } else {
            *res.status_mut() = StatusCode::CREATED;
        }
        Ok(())
    }

    /// MOVE：重命名/移动到 `Destination` 指定的目标（文件和目录都支持，
    /// 底层是一次 rename 系统调用）。
    /// MOVE renames/moves a file or directory to `Destination` through one rename syscall.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn handle_move(
        &self,
        path: &Path,
        source: OpenedNode,
        dest: &Path,
        headers: &HeaderMap<HeaderValue>,
        user: Option<&str>,
        mutation_guards: MutationGuards,
        changed_status: ChangedStatus,
        res: &mut Response,
    ) -> Result<()> {
        let overwrite = match overwrite_allowed(headers) {
            Ok(overwrite) => overwrite,
            Err(err) => {
                warn!("Rejected invalid MOVE Overwrite header: {err:#}");
                status_bad_request(res, "Invalid Overwrite header");
                return Ok(());
            }
        };

        if source.real_rel != path {
            ResponseError::filesystem(
                FsError::changed(
                    MutationEndpointRole::Source,
                    path.display().to_string(),
                    format!("opened {:?}", source.real_rel),
                    "MOVE source aliases through a symlink are not supported",
                ),
                changed_status,
            )
            .apply(res);
            return Ok(());
        }
        // rename(2) 在目录被移动到自身后代时返回 EINVAL；这是客户端命名空间冲突而非基础设施
        // 故障。系统调用前拒绝可稳定返回 409，并避免误分类为 500。
        // rename(2) reports EINVAL when a directory is moved below itself. That errno is a client
        // namespace conflict, not an infrastructure failure; reject it before any syscall so it is
        // always a stable 409 and cannot be misclassified as 500.
        if source.metadata.is_dir() && dest != path && dest.starts_with(path) {
            ResponseError::filesystem(
                FsError::conflict(
                    "validating MOVE destination",
                    anyhow!("a collection cannot be moved into its own descendant"),
                ),
                ChangedStatus::Conflict,
            )
            .apply(res);
            return Ok(());
        }

        // MOVE 与 COPY 有相同父集合要求。能力查找保持不创建，使缺失父目录报告 409 而非
        // 悄然出现。
        // MOVE has COPY's parent-collection requirement. Keep capability lookup non-creating so a
        // missing parent is 409 rather than silently created.
        if let Err(error) = self.fs_root.open_parent(dest, false).await {
            return map_required_parent_error("MOVE", dest, user, error, changed_status, res);
        }
        let expected_source = EntryExpectation::from_metadata(&source.metadata);
        let expected_destination = match self.fs_root.entry_expectation(dest).await {
            Ok(expectation) => expectation,
            Err(error) => {
                return map_entry_expectation_error("MOVE", dest, user, error, changed_status, res);
            }
        };
        let dest_exists = matches!(expected_destination, EntryExpectation::Present(_));
        if dest_exists && !overwrite {
            *res.status_mut() = StatusCode::PRECONDITION_FAILED;
            return Ok(());
        }

        // 在能力层将提交的确切根相对身份上重新检查目标写 ACL。
        // Re-check destination write ACL at the exact root-relative identity the capability layer commits.
        let authorized = dest
            .to_str()
            .and_then(|dest| user.and_then(|user| self.args.auth.guard_dest_for_user(user, dest)));
        if authorized.is_none() {
            status_forbid(res);
            return Ok(());
        }
        if let Err(error) = self
            .fs_root
            .rename(
                path,
                dest,
                false,
                expected_source,
                expected_destination,
                mutation_guards,
            )
            .await
        {
            let endpoint_status = copy_move_changed_status(&error, changed_status, overwrite);
            return map_local_mutation_error("MOVE", dest, user, error, endpoint_status, res);
        }

        if dest_exists {
            status_no_content(res);
        } else {
            *res.status_mut() = StatusCode::CREATED;
        }
        Ok(())
    }

    /// 解析并校验 COPY/MOVE 的目标路径：
    /// Destination 头 → 路径规范化（拒绝 `..`）→ 目标权限鉴权 → 拼绝对路径。
    /// 请求语义/权限失败把状态写进 `res` 并返回 `Ok(None)`；解析器或
    /// 文件系统基础设施失败保留 typed cause 向上传播。
    /// Parse and validate COPY/MOVE destination: normalize the header path, reject `..`, authorize the
    /// target, and build its path. Semantic/permission failures write `res` and return `Ok(None)`;
    /// parser/filesystem failures preserve typed causes.
    pub(super) async fn prepare_destination(
        &self,
        req: &Request,
        user: Option<&str>,
        res: &mut Response,
    ) -> Result<Option<PathBuf>> {
        let dest_path = match self
            .extract_destination_header(req)
            .and_then(|dest| self.resolve_path(&dest))
        {
            Some(dest) => dest,
            None => {
                status_bad_request(res, "Invalid Destination");
                return Ok(None);
            }
        };
        // 服务根在文件系统能力内没有父目录槽位，因此不能成为 COPY/MOVE 发布目标；在此拒绝，
        // 避免 open_parent 把请求语义误报为内部错误。
        // The served root has no parent slot in the filesystem capability and therefore cannot be a
        // COPY/MOVE publication destination. Reject it here instead of letting open_parent turn this
        // request semantic into an internal error.
        if dest_path.is_empty() {
            status_forbid(res);
            return Ok(None);
        }

        // 走到这里时，请求的 Authorization 头已针对"真实请求目标（源路径）"
        // 验证过一次；这里直接复用已认证的 `user` 去检查目标路径的权限，
        // 而不是对目标路径重跑一遍认证（Digest 签名绑定的是源路径的 URI，
        // 重跑必然失败）。目标路径一律要求读写权限（见 guard_dest_for_user）。
        // The Authorization header was verified for the real source request target. Reuse the authenticated
        // user for destination ACL instead of rerunning authentication: Digest binds the source URI and
        // would necessarily fail. Destinations always require read-write permission.
        let authorization_path = match self.canonical_authorization_path(&dest_path).await {
            Ok(path) => path,
            Err(error)
                if matches!(
                    FsError::in_anyhow_chain(&error),
                    Some(FsError::OutsideRoot { .. })
                ) =>
            {
                warn!(
                    "Rejected COPY/MOVE Destination outside the filesystem capability: error={error:#}"
                );
                ResponseError::bad_request(error).apply(res);
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let authorized = user
            .and_then(|user| {
                self.args
                    .auth
                    .guard_dest_for_user(user, &authorization_path)
            })
            .is_some();
        if !authorized {
            status_forbid(res);
            return Ok(None);
        }

        Ok(Some(PathBuf::from(authorization_path)))
    }

    /// 从 `Destination` 头提取目标路径。
    /// Extract the target path from the `Destination` header.
    fn extract_destination_header(&self, req: &Request) -> Option<String> {
        let headers = req.headers();
        // Destination 是单值请求指令。若从多个字段行中只取第一个，中间代理与源站可能对
        // 变更目标产生分歧；因此即使重复值完全相同也一律拒绝。
        // Destination is a singleton request directive. Picking the first of multiple field lines
        // lets intermediaries and the origin disagree about the mutation target, so reject any
        // repetition even when all values happen to be equal.
        let mut destinations = headers.get_all("Destination").iter();
        let dest = destinations.next()?.to_str().ok()?;
        if destinations.next().is_some() {
            return None;
        }
        // HTTP/2 通过 `:authority` 携带有效 authority；Hyper 不会为其合成 HTTP/1 `Host`。
        // 回退到请求 URI 使同源 Destination 校验跨协议一致，避免把所有绝对 H2 COPY/MOVE
        // 目标误判为畸形。
        // HTTP/2 carries effective authority in `:authority`; Hyper does not synthesize `Host`.
        // Falling back to the URI keeps same-origin checks identical across protocols.
        let mut host_values = headers.get_all(HOST).iter();
        let header_host = match host_values.next() {
            Some(value) => Some(value.to_str().ok()?),
            None => None,
        };
        if host_values.next().is_some() {
            return None;
        }
        let uri_host = req.uri().authority().map(|authority| {
            authority
                .as_str()
                .rsplit_once('@')
                .map(|(_, host)| host)
                .unwrap_or_else(|| authority.as_str())
        });
        if let (Some(header_host), Some(uri_host)) = (header_host, uri_host)
            && !header_host.eq_ignore_ascii_case(uri_host)
        {
            return None;
        }
        let request_host = header_host.or(uri_host);
        parse_destination_uri(dest, request_host)
    }
}

const LOCAL_COPY_CHUNK_SIZE: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LocalCopyStrategy {
    Reflink,
    CopyFileRange,
    Buffered,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LocalCopyOutcome {
    bytes: u64,
    strategy: LocalCopyStrategy,
}

fn copy_move_changed_status(
    error: &anyhow::Error,
    source_status: ChangedStatus,
    overwrite: bool,
) -> ChangedStatus {
    match FsError::in_anyhow_chain(error).and_then(FsError::changed_details) {
        Some((MutationEndpointRole::Source, _, _, _)) => source_status,
        Some((MutationEndpointRole::Destination | MutationEndpointRole::Target, _, _, _))
            if !overwrite =>
        {
            ChangedStatus::PreconditionFailed
        }
        Some(_) | None => ChangedStatus::Conflict,
    }
}

fn ensure_typed_filesystem_error(operation: &'static str, error: anyhow::Error) -> anyhow::Error {
    if ResponseErrorRef::from_anyhow_typed(&error, ChangedStatus::Conflict).is_some() {
        error
    } else {
        anyhow::Error::new(FsError::from_anyhow(operation, error))
    }
}

fn upload_target_parent_is_missing(error: &anyhow::Error) -> bool {
    matches!(
        FsError::in_anyhow_chain(error),
        Some(FsError::NotFound { .. })
    )
}

fn map_required_parent_error(
    operation: &'static str,
    path: &Path,
    user: Option<&str>,
    error: anyhow::Error,
    changed_status: ChangedStatus,
    res: &mut Response,
) -> Result<()> {
    let error = ensure_typed_filesystem_error("opening required mutation parent", error);
    let parent_missing = matches!(
        FsError::in_anyhow_chain(&error),
        Some(FsError::NotFound { .. })
    );
    let error = if parent_missing {
        anyhow::Error::new(FsError::conflict("opening required mutation parent", error))
    } else {
        error
    };
    map_local_mutation_error(operation, path, user, error, changed_status, res)
}

fn map_entry_expectation_error(
    operation: &'static str,
    path: &Path,
    user: Option<&str>,
    error: anyhow::Error,
    changed_status: ChangedStatus,
    res: &mut Response,
) -> Result<()> {
    let error = ensure_typed_filesystem_error("capturing mutation destination state", error);
    map_local_mutation_error(operation, path, user, error, changed_status, res)
}

#[allow(clippy::too_many_arguments)]
fn map_existing_destination_error(
    operation: &'static str,
    path: &Path,
    user: Option<&str>,
    error: anyhow::Error,
    overwrite: bool,
    source_status: ChangedStatus,
    res: &mut Response,
) -> Result<()> {
    let error = ensure_typed_filesystem_error("opening existing mutation destination", error);
    let destination_missing = matches!(
        FsError::in_anyhow_chain(&error),
        Some(FsError::NotFound { .. })
    );
    let error = if destination_missing {
        debug!(
            "Mutation destination disappeared before validation: operation={operation} path={path:?} error={error:#}"
        );
        anyhow::Error::new(FsError::changed(
            MutationEndpointRole::Destination,
            path.display().to_string(),
            "destination existed before shape validation",
            "destination disappeared before shape validation",
        ))
    } else {
        error
    };
    let changed_status = copy_move_changed_status(&error, source_status, overwrite);
    map_local_mutation_error(operation, path, user, error, changed_status, res)
}

fn map_local_mutation_error(
    operation: &'static str,
    path: &Path,
    user: Option<&str>,
    error: anyhow::Error,
    changed_status: ChangedStatus,
    res: &mut Response,
) -> Result<()> {
    if is_blocking_deadline(&error) {
        warn!(
            "Local filesystem operation deadline exceeded; worker cancellation requested: operation={operation} path={path:?} error={error:#}"
        );
    }
    let error = ensure_typed_filesystem_error(operation, error);
    let response_error = ResponseErrorRef::from_anyhow_typed(&error, changed_status)
        .expect("filesystem boundary always produces a typed service error");
    if response_error.status().is_server_error() {
        error!(
            "Typed filesystem/admission failure: operation={operation} path={path:?} user={user:?} error={error:#}"
        );
    } else {
        debug!(
            "Rejected filesystem mutation: operation={operation} path={path:?} user={user:?} error={error:#}"
        );
    }
    response_error.apply(res);
    Ok(())
}

#[derive(Debug)]
struct StoragePreflightDenied {
    required: u64,
    available: u64,
    inode_exhausted: bool,
}

impl std::fmt::Display for StoragePreflightDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "storage preflight denied: required={} available={} inode_exhausted={}",
            self.required, self.available, self.inode_exhausted
        )
    }
}

impl std::error::Error for StoragePreflightDenied {}

#[derive(Debug)]
struct StorageQuotaDenied {
    status: Option<i32>,
}

impl std::fmt::Display for StorageQuotaDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "storage quota hook denied the mutation: status={:?}",
            self.status
        )
    }
}

impl std::error::Error for StorageQuotaDenied {}

fn enforce_storage_preflight(
    temp: &super::filesystem::BlockingTempFile,
    final_size: u64,
    reserve: u64,
) -> Result<()> {
    let (available, total_inodes, available_inodes) = temp.available_space()?;
    let required = final_size.saturating_add(reserve);
    let inode_exhausted = total_inodes > 0 && available_inodes == 0;
    debug!(
        "Storage statvfs preflight: target={:?} required_bytes={required} available_bytes={available} total_inodes={total_inodes} available_inodes={available_inodes}",
        temp.target_rel()
    );
    if available < required || inode_exhausted {
        return Err(anyhow::Error::new(FsError::no_space(
            "enforcing storage preflight",
            StoragePreflightDenied {
                required,
                available,
                inode_exhausted,
            },
        )));
    }
    Ok(())
}

pub(crate) const STORAGE_QUOTA_HOOK_HELPER_ARG: &str = "--internal-storage-quota-hook-exec";
pub(crate) const STORAGE_QUOTA_HOOK_HELPER_FAILURE_EXIT_CODE: i32 = 125;

/// 用 stdin 收到的钩子替换单线程内部辅助进程。服务器通过 `Stdio` 把重新打开且固定的描述符
/// 映射到辅助进程 stdin，因此多线程服务器进程中绝不暴露可继承描述符。只有此辅助进程创建
/// 一个非 CLOEXEC 副本，随后立即以固定 ELF/shebang 目标替换自身并恢复钩子的标准流策略。
/// Replace the single-threaded helper with the hook received on stdin. The server maps a freshly
/// reopened pinned descriptor through `Stdio`, exposing no inheritable descriptor in its multithreaded
/// process. Only the helper creates one non-CLOEXEC duplicate before immediately execing the target.
pub(crate) fn run_storage_quota_hook_helper(
    args: impl IntoIterator<Item = OsString>,
) -> Result<()> {
    let mut args = args.into_iter();
    let expected_parent = args
        .next()
        .and_then(|value| value.into_string().ok())
        .and_then(|value| value.parse::<i32>().ok())
        .and_then(rustix::process::Pid::from_raw)
        .context("storage quota hook helper has an invalid expected parent pid")?;
    // 中文：服务器若被 SIGKILL、测试失败或异常退出，钩子不能成为永久孤儿。
    // 先设置父进程死亡信号，再核对父 PID，封闭父进程在 exec 与 prctl 之间退出的竞态。
    // English: A hook must not become a permanent orphan when the server is
    // SIGKILLed, a test fails, or the process exits unexpectedly. Arm the
    // parent-death signal before checking the PID to close the exec/prctl race.
    rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::KILL))
        .context("failed to arm storage quota hook parent-death signal")?;
    if rustix::process::getppid() != Some(expected_parent) {
        bail!("storage quota hook parent exited before helper initialization");
    }
    let hook_fd = rustix::io::dup(std::io::stdin())
        .context("failed to duplicate storage quota hook helper stdin")?;
    if hook_fd.as_raw_fd() <= 2 {
        bail!("storage quota hook helper failed to reserve a private descriptor");
    }
    let executable = PathBuf::from(format!("/proc/self/fd/{}", hook_fd.as_raw_fd()));
    let mut command = Command::new(&executable);
    command
        .env_clear()
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let error = command.exec();
    Err(error).with_context(|| {
        format!(
            "failed to replace storage quota hook helper with `{}`",
            executable.display()
        )
    })
}

fn storage_quota_hook_helper_command(args: &[OsString]) -> Command {
    let mut command = Command::new("/proc/self/exe");
    // 中间辅助进程不得短暂继承服务器配置秘密；它唯一的权限是 stdin 上固定钩子和下方显式
    // 策略参数。
    // The intermediate helper must not briefly inherit server configuration secrets. Its only authority
    // is the pinned stdin hook plus explicit policy arguments below.
    command.env_clear();
    let expected_parent = OsString::from(std::process::id().to_string());
    #[cfg(not(test))]
    {
        command
            .arg(STORAGE_QUOTA_HOOK_HELPER_ARG)
            .arg(&expected_parent)
            .args(args);
    }
    #[cfg(test)]
    {
        // 单元测试进程是 libtest harness 而非 ram 二进制。进入一个确切辅助测试，再以仅子进程
        // 环境变量携带的参数执行同一生产 exec 辅助路径。
        // A unit-test process is libtest rather than ram. Enter one exact helper test, which exercises
        // the same production exec helper using child-only environment variables.
        command
            .arg("--exact")
            .arg("server::write::storage_tests::quota_hook_subprocess_helper")
            .arg("--nocapture")
            .env("RAM_QUOTA_HOOK_TEST_HELPER", "1")
            .env(
                "RAM_QUOTA_HOOK_TEST_ARG_COUNT",
                (args.len() + 1).to_string(),
            )
            .env("RAM_QUOTA_HOOK_TEST_ARG_0", expected_parent);
        for (index, value) in args.iter().enumerate() {
            command.env(format!("RAM_QUOTA_HOOK_TEST_ARG_{}", index + 1), value);
        }
    }
    command
}

fn quota_hook_infrastructure_error(
    operation: &'static str,
    source: impl Into<anyhow::Error>,
) -> anyhow::Error {
    anyhow::Error::new(FsError::io(operation, source))
}

fn quota_hook_policy_denial(
    user: Option<&str>,
    operation: &str,
    path: &Path,
    status: Option<i32>,
) -> anyhow::Error {
    warn!(
        "Storage quota policy denied mutation: reason=quota_hook operation={operation} path={path:?} user={user:?} status={status:?}"
    );
    anyhow::Error::new(FsError::no_space(
        "enforcing storage quota policy",
        StorageQuotaDenied { status },
    ))
}

/// 在同步写入 worker 中执行已固定的配额策略。钩子 fd 经 stdin 交给清空环境的内部 helper；
/// helper 安装父进程死亡信号并从 `/proc/self/fd` exec，运行期间由独立进程组监督。
/// exit 0 允许变更，helper 专用 125 表示 exec 基础设施失败，其他非零状态表示策略拒绝；取消或
/// deadline 到期会杀死进程组并始终 wait 直系子进程。钩子不得 daemonize、double-fork 或
/// `setsid` 逃离监督边界。
/// Execute the pinned quota policy inside the synchronous write worker. The hook fd travels via stdin
/// to a clean-environment helper, which arms a parent-death signal and execs `/proc/self/fd` under a
/// separate process group. Exit 0 allows, helper-reserved 125 is infrastructure failure, and any other
/// nonzero status is policy denial. Cancellation/deadline kills the group and always waits for the
/// direct child; hooks must not daemonize, double-fork, or `setsid` out of supervision.
#[allow(clippy::too_many_arguments)]
fn run_storage_quota_hook(
    hook: Option<&PathIdentity>,
    timeout: Duration,
    user: Option<&str>,
    operation: &str,
    path: &Path,
    current_size: u64,
    final_size: u64,
    cancellation: &RequestCancellation,
) -> Result<()> {
    let Some(hook) = hook else {
        return Ok(());
    };
    let Some(user) = user else {
        return Err(quota_hook_policy_denial(None, operation, path, None));
    };
    let hook_file = hook.open_regular_file_pinned().map_err(|error| {
        quota_hook_infrastructure_error("opening the pinned storage quota hook", error).context(
            format!(
                "failed to open pinned storage quota hook `{}`",
                hook.canonical().display()
            ),
        )
    })?;
    let hook_args = [
        OsString::from("--user"),
        OsString::from(user),
        OsString::from("--operation"),
        OsString::from(operation),
        OsString::from("--path"),
        path.as_os_str().to_os_string(),
        OsString::from("--current-bytes"),
        OsString::from(current_size.to_string()),
        OsString::from("--final-bytes"),
        OsString::from(final_size.to_string()),
    ];
    let mut command = storage_quota_hook_helper_command(&hook_args);
    command
        .stdin(Stdio::from(hook_file))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        // 隔离后代，使超时/取消可杀死整棵钩子进程树，而非遗留 shell 子进程。
        // Isolate descendants so timeout/cancellation kills the whole hook tree instead of orphaning a
        // shell child. Hooks must not daemonize or deliberately escape this process group.
        .process_group(0);
    let mut child = command.spawn().map_err(|error| {
        quota_hook_infrastructure_error("starting the storage quota hook helper", error).context(
            format!(
                "failed to start helper for pinned storage quota hook `{}`",
                hook.canonical().display(),
            ),
        )
    })?;
    let deadline = Instant::now() + timeout;
    loop {
        if cancellation.is_cancelled() {
            terminate_quota_hook(&mut child);
            return Err(anyhow::Error::new(AdmissionError::cancelled(
                AdmissionResource::ExpensiveTasks,
            ))
            .context("request was cancelled while the storage quota hook was running"));
        }
        let status = child.try_wait().map_err(|error| {
            quota_hook_infrastructure_error("waiting for the storage quota hook helper", error)
        })?;
        if let Some(status) = status {
            return if status.success() {
                Ok(())
            } else if status.code() == Some(STORAGE_QUOTA_HOOK_HELPER_FAILURE_EXIT_CODE) {
                Err(quota_hook_infrastructure_error(
                    "executing the pinned storage quota hook",
                    anyhow!(
                        "storage quota hook helper failed before executing pinned hook `{}`",
                        hook.canonical().display()
                    ),
                ))
            } else {
                Err(quota_hook_policy_denial(
                    Some(user),
                    operation,
                    path,
                    status.code(),
                ))
            };
        }
        if Instant::now() >= deadline {
            terminate_quota_hook(&mut child);
            return Err(anyhow::Error::new(AdmissionError::execution_timeout(
                AdmissionResource::ExpensiveTasks,
                timeout,
            ))
            .context("storage quota hook execution timed out"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// 先向整个进程组发送 SIGKILL，以覆盖 shell/解释器后代；再对直系子进程执行 kill 回退并
/// `wait`，同时处理组信号与启动之间的竞态并避免僵尸进程。
/// Send SIGKILL to the process group first to cover shell/interpreter descendants, then kill the
/// direct child as a startup-race fallback and always `wait` it to prevent zombies.
fn terminate_quota_hook(child: &mut Child) {
    if let Some(pid) = rustix::process::Pid::from_raw(child.id() as i32) {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
    // 对组信号与进程启动发生竞态的平台/文件系统保留直系子进程回退，随后始终回收子进程。
    // Retain direct-child fallback where the group signal races startup, then always reap the child.
    let _ = child.kill();
    let _ = child.wait();
}

fn copy_regular_file_cooperatively(
    source: &mut File,
    destination: &mut File,
    max_bytes: Option<u64>,
    cancellation: &RequestCancellation,
) -> Result<LocalCopyOutcome> {
    let source_metadata = source.metadata()?;
    let destination_metadata = destination.metadata()?;
    let same_filesystem = source_metadata.dev() == destination_metadata.dev();
    let limit = max_bytes
        .map(|value| value.saturating_add(1))
        .unwrap_or(u64::MAX);

    if same_filesystem {
        #[cfg(not(any(target_arch = "sparc", target_arch = "sparc64")))]
        loop {
            if cancellation.is_cancelled() {
                return Err(copy_cancellation_error(
                    "request was cancelled before reflink",
                ));
            }
            match rustix::fs::ioctl_ficlone(&*destination, &*source) {
                Ok(()) => {
                    if cancellation.is_cancelled() {
                        return Err(copy_cancellation_error(
                            "request was cancelled after reflink",
                        ));
                    }
                    let bytes = destination.metadata()?.len();
                    return Ok(LocalCopyOutcome {
                        bytes,
                        strategy: LocalCopyStrategy::Reflink,
                    });
                }
                Err(rustix::io::Errno::INTR) => continue,
                Err(err) if reflink_fallback_error(err) => {
                    destination.set_len(0)?;
                    source.seek(SeekFrom::Start(0))?;
                    destination.seek(SeekFrom::Start(0))?;
                    break;
                }
                Err(err) => return Err(err.into()),
            }
        }

        let mut source_offset = 0u64;
        let mut destination_offset = 0u64;
        loop {
            if cancellation.is_cancelled() {
                return Err(copy_cancellation_error(
                    "request was cancelled during copy_file_range",
                ));
            }
            if destination_offset >= limit {
                destination.set_len(destination_offset)?;
                return Ok(LocalCopyOutcome {
                    bytes: destination_offset,
                    strategy: LocalCopyStrategy::CopyFileRange,
                });
            }
            let chunk = (limit - destination_offset).min(LOCAL_COPY_CHUNK_SIZE as u64) as usize;
            match rustix::fs::copy_file_range(
                &*source,
                Some(&mut source_offset),
                &*destination,
                Some(&mut destination_offset),
                chunk,
            ) {
                Ok(0) => {
                    destination.set_len(destination_offset)?;
                    return Ok(LocalCopyOutcome {
                        bytes: destination_offset,
                        strategy: LocalCopyStrategy::CopyFileRange,
                    });
                }
                Ok(_) => {}
                Err(rustix::io::Errno::INTR) => continue,
                Err(err) if copy_file_range_fallback_error(err, destination_offset == 0) => {
                    source.seek(SeekFrom::Start(0))?;
                    destination.set_len(0)?;
                    destination.seek(SeekFrom::Start(0))?;
                    break;
                }
                Err(err) => return Err(err.into()),
            }
        }
    }

    source.seek(SeekFrom::Start(0))?;
    destination.set_len(0)?;
    destination.seek(SeekFrom::Start(0))?;
    let bytes = copy_buffered_bounded(source, destination, limit, cancellation)?;
    Ok(LocalCopyOutcome {
        bytes,
        strategy: LocalCopyStrategy::Buffered,
    })
}

fn copy_buffered_bounded(
    source: &mut File,
    destination: &mut File,
    limit: u64,
    cancellation: &RequestCancellation,
) -> Result<u64> {
    let mut buffer = vec![0u8; 64 * 1024];
    let mut copied = 0u64;
    while copied < limit {
        if cancellation.is_cancelled() {
            return Err(copy_cancellation_error(
                "request was cancelled during buffered copy",
            ));
        }
        let requested = (limit - copied).min(buffer.len() as u64) as usize;
        let read = source.read(&mut buffer[..requested])?;
        if read == 0 {
            break;
        }
        destination.write_all(&buffer[..read])?;
        copied = copied.saturating_add(read as u64);
    }
    Ok(copied)
}

fn copy_exact_at_current(
    source: &mut File,
    destination: &mut File,
    expected: u64,
    cancellation: &RequestCancellation,
) -> Result<()> {
    if source.metadata()?.len() != expected {
        bail!("staged upload length changed before local copy");
    }
    let copied = copy_buffered_bounded(source, destination, expected, cancellation)?;
    if copied != expected {
        bail!("staged upload ended before its recorded length");
    }
    Ok(())
}

fn reflink_fallback_error(error: rustix::io::Errno) -> bool {
    matches!(
        error,
        rustix::io::Errno::XDEV
            | rustix::io::Errno::OPNOTSUPP
            | rustix::io::Errno::NOTTY
            | rustix::io::Errno::INVAL
    )
}

fn copy_file_range_fallback_error(error: rustix::io::Errno, zero_progress: bool) -> bool {
    matches!(
        error,
        rustix::io::Errno::XDEV | rustix::io::Errno::OPNOTSUPP | rustix::io::Errno::NOSYS
    ) || (zero_progress && error == rustix::io::Errno::INVAL)
}

/// 独立于请求/认证状态解析 WebDAV Destination。仅当绝对 URI 的有效 `host[:port]` 与请求
/// Host 匹配时才接受；相对路径不要求 Host。
/// Parse WebDAV Destination independently of request/auth state. Absolute URIs require effective
/// `host[:port]` to match request Host; relative paths need no Host.
fn parse_destination_uri(destination: &str, request_host: Option<&str>) -> Option<String> {
    // Ram 只把 Destination 映射为一个文件系统路径，不提供 query/fragment 资源映射；
    // 静默丢弃任一部分都会变更一个不同于客户端所提交 URI 的资源。
    // Ram maps Destination to one filesystem path and has no query/fragment resource mapping.
    // Silently discarding either would mutate a different URI than the client supplied.
    if destination.is_empty() || destination.contains(['?', '#']) {
        return None;
    }
    let first_segment = destination.split('/').next().unwrap_or_default();
    if !first_segment.contains(':') {
        // 网络路径引用具有 authority 而没有 scheme，本站不接受。裸相对路径会被 `http::Uri`
        // 误解释为 authority-form，因此临时添加 `/` 只做 path 字符语法验证。
        // A network-path reference has authority without scheme and is rejected. `http::Uri`
        // interprets a bare relative path as authority-form, so prefix `/` solely to validate path
        // character syntax and restore the original relative form afterward.
        if destination.starts_with("//") {
            return None;
        }
        let relative = !destination.starts_with('/');
        let normalized;
        let parseable = if relative {
            normalized = format!("/{destination}");
            normalized.as_str()
        } else {
            destination
        };
        let uri: Uri = parseable.parse().ok()?;
        if uri.scheme().is_some() || uri.authority().is_some() || uri.query().is_some() {
            return None;
        }
        return if relative {
            uri.path().strip_prefix('/').map(str::to_owned)
        } else {
            Some(uri.path().to_owned())
        };
    }

    let uri: Uri = destination.parse().ok()?;
    match (uri.scheme(), uri.authority()) {
        (Some(scheme), Some(authority))
            if scheme.as_str().eq_ignore_ascii_case("http")
                || scheme.as_str().eq_ignore_ascii_case("https") =>
        {
            // `Authority::as_str()` 会保留 URI userinfo，而 HTTP Host 从不包含它。只比较最终
            // host[:port] 组件。
            // `Authority::as_str()` retains URI userinfo while Host never does. Compare only final
            // host[:port].
            let destination_host = authority
                .as_str()
                .rsplit_once('@')
                .map(|(_, host)| host)
                .unwrap_or_else(|| authority.as_str());
            if !request_host.is_some_and(|host| host.eq_ignore_ascii_case(destination_host)) {
                return None;
            }
        }
        // `http:/path`、`urn:...` 与 `ftp://...` 都不代表本站支持的一个
        // HTTP(S) 文件资源。接受后只取 path 会把客户端指定的另一 URI 误变更为本地路径。
        // A scheme without authority or a non-HTTP scheme does not identify one supported local
        // HTTP(S) resource. Taking only its path would mutate a different URI from the one supplied.
        _ => return None,
    }
    Some(uri.path().to_string())
}

/// 联合配置 URI 前缀和请求路径能力规范器测试 WebDAV Destination/Host 同源检查。
/// Exercise WebDAV Destination/Host same-origin checks with the configured URI prefix and request-path
/// capability normalizer.
#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_destination_host_prefix(data: &[u8]) {
    const FUZZ_INPUT_MAX_BYTES: usize = 64 * 1024;
    if data.len() > FUZZ_INPUT_MAX_BYTES {
        return;
    }
    // 换行分帧使种子语料可按文本审查；fuzz 生成的 NUL 仍覆盖 harness 使用的二进制分帧。
    // Newline framing keeps the seed corpus text-reviewable; fuzz-generated NULs still exercise binary framing.
    let mut fields = data.splitn(3, |byte| matches!(*byte, 0 | b'\n'));
    let Some(destination) = fields
        .next()
        .and_then(|value| std::str::from_utf8(value).ok())
    else {
        return;
    };
    let Some(host) = fields
        .next()
        .and_then(|value| std::str::from_utf8(value).ok())
    else {
        return;
    };
    let Some(prefix) = fields
        .next()
        .and_then(|value| std::str::from_utf8(value).ok())
    else {
        return;
    };
    let request_host = (!host.is_empty()).then_some(host);
    let Ok(prefix) = crate::config::normalize_path_prefix(prefix) else {
        return;
    };

    if let Some(destination_path) = parse_destination_uri(destination, request_host) {
        assert!(!destination.contains(['?', '#']));
        let first_segment = destination.split('/').next().unwrap_or_default();
        if first_segment.contains(':') {
            let parsed: Uri = destination
                .parse()
                .expect("accepted absolute Destination must parse deterministically");
            match (parsed.scheme(), parsed.authority()) {
                (Some(scheme), Some(authority)) => {
                    assert!(
                        scheme.as_str().eq_ignore_ascii_case("http")
                            || scheme.as_str().eq_ignore_ascii_case("https")
                    );
                    let effective = authority
                        .as_str()
                        .rsplit_once('@')
                        .map(|(_, host)| host)
                        .unwrap_or_else(|| authority.as_str());
                    assert!(request_host.is_some_and(|host| host.eq_ignore_ascii_case(effective)));
                }
                _ => panic!("accepted Destination paired scheme and authority incorrectly"),
            }
        } else {
            assert!(!destination.starts_with("//"));
        }
        if let Some(relative) = super::normalize_request_path(&destination_path, &prefix) {
            assert!(!relative.starts_with('/'));
            assert!(!relative.contains('\0'));
            assert!(
                std::path::Path::new(&relative)
                    .components()
                    .all(|component| matches!(component, std::path::Component::Normal(_)))
            );
        }
    }
}

/// PUT 覆盖已有文件前评估条件写入头（`If-Match`、`If-None-Match: *`、
/// `If-Unmodified-Since`）。
/// 前置条件不满足时返回 `Ok(false)` 并把响应设为 412——
/// 这正是编辑器"乐观并发控制"的实现：A、B 两人同时编辑，后保存的
/// 那位带着旧 ETag，会被 412 拒绝而不是悄悄覆盖对方的修改。
/// Evaluate conditional-write headers before overwriting with PUT. Failure returns `Ok(false)` and
/// 412, implementing optimistic concurrency: the later editor's stale ETag is rejected instead of
/// silently overwriting another user's change.
async fn write_cache_validators(
    opened: &mut OpenedNode,
    res: &mut Response,
) -> Result<Option<super::CacheValidators>> {
    let expected_len = opened.metadata.len();
    match extract_cache_headers(&mut opened.file, &opened.metadata).await {
        Ok(validators) => Ok(Some(validators)),
        Err(error) => {
            // 若保留描述符当前长度不同于已验证快照，短读不是一般哈希失败，而是乐观并发竞态，
            // 因此在写前置条件边界稳定映射为 412。
            // A short read after descriptor length changes is not generic hashing failure; it is an
            // optimistic-concurrency race and a stable 412 at this boundary.
            if let Ok(actual) = opened.file.metadata().await
                && actual.len() != expected_len
            {
                let changed = ResponseError::filesystem(
                    FsError::changed(
                        MutationEndpointRole::Target,
                        opened.real_rel.display().to_string(),
                        format!("{expected_len} bytes"),
                        format!("{} bytes", actual.len()),
                    ),
                    ChangedStatus::PreconditionFailed,
                );
                debug!(
                    "Write precondition target changed while computing validators: path={:?} error={error:#}",
                    opened.real_rel
                );
                changed.apply(res);
                return Ok(None);
            }
            Err(error.context("computing validators for a write precondition"))
        }
    }
}

pub(super) async fn write_precondition_passes(
    opened: Option<&mut OpenedNode>,
    preconditions: &ParsedPreconditions,
    res: &mut Response,
) -> Result<bool> {
    if preconditions.if_match.is_none()
        && preconditions.if_unmodified_since.is_none()
        && preconditions.if_none_match.is_none()
    {
        return Ok(true);
    }
    let Some(opened) = opened else {
        // If-Match 要求当前表示存在；具体标签和 `*` 都不能匹配缺失资源。
        // If-Match requires a current representation. Neither a concrete tag nor `*` matches absence.
        if preconditions.if_match.is_some() {
            *res.status_mut() = StatusCode::PRECONDITION_FAILED;
            return Ok(false);
        }
        return Ok(true);
    };

    // RFC 9110 §13.2.2：If-Match 存在时必须忽略 If-Unmodified-Since
    // （ETag 比秒级时间戳精确，同时出现时只看 ETag）。
    // RFC 9110 §13.2.2: when If-Match exists, ignore If-Unmodified-Since; ETags are more precise than
    // second-resolution timestamps, so only the tag applies when both appear.
    if let Some(if_match) = &preconditions.if_match {
        // `*` 只询问表示是否存在，`opened` 已提供答案；构造实体标签没有价值。
        // `*` only asks whether a representation exists, already known from `opened`; no tag is needed.
        if !if_match.is_any() {
            if !opened.metadata.is_file() {
                *res.status_mut() = StatusCode::PRECONDITION_FAILED;
                return Ok(false);
            }
            let Some(validators) = write_cache_validators(opened, res).await? else {
                return Ok(false);
            };
            if !if_match.precondition_passes(&validators.etag) {
                *res.status_mut() = StatusCode::PRECONDITION_FAILED;
                return Ok(false);
            }
        }
    } else if let Some(if_unmodified_since) = preconditions.if_unmodified_since {
        // 纯日期前置条件只需要描述符元数据。
        // A pure date precondition needs only descriptor metadata.
        if let Some(last_modified) = opened
            .metadata
            .modified()
            .ok()
            .or_else(|| opened.metadata.created().ok())
            && !if_unmodified_since.precondition_passes(last_modified)
        {
            *res.status_mut() = StatusCode::PRECONDITION_FAILED;
            return Ok(false);
        }
    }

    if let Some(if_none_match) = &preconditions.if_none_match {
        // 对非安全方法，`If-None-Match: *` 是仅创建守卫；具体标签使用普通弱 If-None-Match 比较。
        // For unsafe methods, `If-None-Match: *` is the create-only guard; concrete tags use normal weak comparison.
        let failed = if *if_none_match == IfNoneMatch::any() {
            true
        } else if !opened.metadata.is_file() {
            // 目录响应不声明实体标签，因此具体客户端标签无法匹配；上方通配符仍对每个现有表示失败。
            // Directory responses advertise no entity-tag, so concrete tags cannot match; wildcard still
            // fails for every existing representation.
            false
        } else {
            let Some(validators) = write_cache_validators(opened, res).await? else {
                return Ok(false);
            };
            !if_none_match.precondition_passes(&validators.etag)
        };
        if failed {
            *res.status_mut() = StatusCode::PRECONDITION_FAILED;
            return Ok(false);
        }
    }
    Ok(true)
}

/// COPY/MOVE 的 RFC 4918 `Overwrite` 头。缺省和精确的 `T` 允许覆盖，
/// 精确的 `F` 禁止覆盖；其他值（包括非 UTF-8）都是无效请求。
/// RFC 4918 `Overwrite` for COPY/MOVE: absent or exact `T` permits replacement; exact `F` forbids it;
/// every other value, including non-UTF-8, is invalid.
fn overwrite_allowed(headers: &HeaderMap<HeaderValue>) -> Result<bool> {
    let mut values = headers.get_all("overwrite").iter();
    let value = values.next().map(HeaderValue::as_bytes);
    if values.next().is_some() {
        bail!("Invalid duplicate Overwrite header");
    }
    match value {
        None | Some(b"T") => Ok(true),
        Some(b"F") => Ok(false),
        Some(_) => bail!("Invalid Overwrite header"),
    }
}

/// 解析 PATCH 的 `X-Update-Range` 头，得到写入偏移：
/// `append` = 从当前文件末尾追加；`bytes=N-` 等 Range 语法 = 从 N 开始写。
/// 没带该头返回 `Ok(None)`（路由层回 405）。
/// Parse PATCH `X-Update-Range`: `append` starts at EOF and `bytes=N-` starts at N. Absence returns
/// `Ok(None)` for the routing layer to map according to method semantics.
pub(super) fn parse_upload_offset(
    headers: &HeaderMap<HeaderValue>,
    size: u64,
) -> Result<Option<u64>> {
    let mut values = headers.get_all("x-update-range").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        bail!("Invalid X-Update-Range Header");
    }
    let err = || anyhow!("Invalid X-Update-Range Header");
    let value = value.to_str().map_err(|_| err())?;
    if value == "append" {
        return Ok(Some(size));
    }
    // PATCH 只接受一个开放结尾字节偏移，而非完整 GET Range 语法。拒绝后缀、多重和闭合范围，
    // 使提交偏移不依赖当前表示大小。
    // PATCH accepts one open-ended byte offset, not full GET Range grammar. Rejecting suffix/multiple/
    // closed ranges keeps commit offset independent of current representation size.
    let offset = value
        .strip_prefix("bytes=")
        .and_then(|value| value.strip_suffix('-'))
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(err)?;
    Ok(Some(offset))
}

#[cfg(test)]
mod storage_tests {
    use super::*;
    use assert_fs::TempDir;
    use hyper::header::RETRY_AFTER;
    use std::fs::OpenOptions;

    #[test]
    fn destination_accepts_only_relative_or_same_host_http_family_uris() {
        for (destination, host, expected) in [
            ("dir/child.txt", None, Some("dir/child.txt")),
            ("/dir/child.txt", None, Some("/dir/child.txt")),
            (
                "http://example.test/child.txt",
                Some("example.test"),
                Some("/child.txt"),
            ),
            (
                "https://example.test:8443/child.txt",
                Some("example.test:8443"),
                Some("/child.txt"),
            ),
        ] {
            assert_eq!(
                parse_destination_uri(destination, host).as_deref(),
                expected
            );
        }

        for destination in [
            "http:/child.txt",
            "urn:example:child",
            "ftp://example.test/child.txt",
            "//example.test/child.txt",
            "https://other.test/child.txt",
            "https://example.test/child.txt?download",
            "https://example.test/child.txt#section",
        ] {
            assert_eq!(
                parse_destination_uri(destination, Some("example.test")),
                None,
                "{destination}"
            );
        }
    }

    #[test]
    fn quota_hook_subprocess_helper() {
        if std::env::var_os("RAM_QUOTA_HOOK_TEST_HELPER").is_none() {
            return;
        }
        let count = std::env::var("RAM_QUOTA_HOOK_TEST_ARG_COUNT")
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let args = (0..count)
            .map(|index| {
                std::env::var_os(format!("RAM_QUOTA_HOOK_TEST_ARG_{index}"))
                    .expect("quota-hook helper argument is missing")
            })
            .collect::<Vec<_>>();
        if run_storage_quota_hook_helper(args).is_err() {
            std::process::exit(STORAGE_QUOTA_HOOK_HELPER_FAILURE_EXIT_CODE);
        }
    }

    #[test]
    fn projected_upload_size_covers_limit_boundaries_for_put_and_patch() {
        for (incoming, expected) in [(7, Ok(7)), (8, Ok(8)), (9, Err(UploadSizeExceeded))] {
            assert_eq!(projected_upload_size(99, None, incoming, 8), expected);
        }

        for (incoming, expected) in [(2, Ok(7)), (3, Ok(8)), (4, Err(UploadSizeExceeded))] {
            assert_eq!(projected_upload_size(5, Some(5), incoming, 8), expected);
        }
        assert_eq!(projected_upload_size(8, Some(8), 0, 8), Ok(8));
        assert_eq!(
            projected_upload_size(9, Some(9), 0, 8),
            Err(UploadSizeExceeded)
        );
    }

    #[test]
    fn projected_upload_size_rejects_overflow_even_when_unlimited() {
        assert_eq!(
            projected_upload_size(0, Some(u64::MAX), 1, 0),
            Err(UploadSizeExceeded)
        );
        assert_eq!(
            projected_upload_size(u64::MAX, Some(u64::MAX - 1), 1, 0),
            Ok(u64::MAX)
        );
    }

    #[test]
    fn upload_body_transport_failure_has_a_stable_typed_400() {
        let error = upload_body_transport_error(anyhow::Error::new(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "private transport detail",
        )));
        assert!(matches!(
            HttpError::in_anyhow_chain(&error),
            Some(HttpError::BadRequest { .. })
        ));
        let response = ResponseErrorRef::from_anyhow_typed(&error, ChangedStatus::Conflict)
            .expect("upload transport failure remains typed under context");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn staging_fallback_accepts_only_a_typed_missing_parent() {
        let missing = anyhow::Error::new(FsError::from_anyhow(
            "opening upload parent",
            anyhow::Error::new(io::Error::from(io::ErrorKind::NotFound)),
        ))
        .context("resolving initial upload candidate");
        let missing = ensure_typed_filesystem_error("creating upload staging candidate", missing);
        assert!(upload_target_parent_is_missing(&missing));

        // 内部 ENOENT 是刻意误导项：封闭 OutsideRoot 标记必须穿过附加上下文，绝不能触发根暂存回退。
        // The inner ENOENT is deliberately misleading: the closed OutsideRoot marker must survive
        // added context and never trigger root-staging fallback.
        let outside = anyhow::Error::new(FsError::outside_root(
            "resolving upload parent",
            io::Error::from(io::ErrorKind::NotFound),
        ))
        .context("resolving initial upload candidate");
        let outside = ensure_typed_filesystem_error("creating upload staging candidate", outside);
        assert!(!upload_target_parent_is_missing(&outside));
        assert!(matches!(
            FsError::in_anyhow_chain(&outside),
            Some(FsError::OutsideRoot { .. })
        ));

        let cancelled = anyhow::Error::new(AdmissionError::cancelled(AdmissionResource::Uploads))
            .context("resolving initial upload candidate");
        let cancelled =
            ensure_typed_filesystem_error("creating upload staging candidate", cancelled);
        assert!(!upload_target_parent_is_missing(&cancelled));
        assert!(matches!(
            AdmissionError::in_anyhow_chain(&cancelled),
            Some(AdmissionError::Cancelled {
                resource: AdmissionResource::Uploads
            })
        ));
    }

    #[test]
    fn quota_hook_infrastructure_is_500_but_policy_denial_is_507() {
        let infrastructure = quota_hook_infrastructure_error(
            "opening quota hook",
            io::Error::from(io::ErrorKind::PermissionDenied),
        );
        assert!(matches!(
            FsError::in_anyhow_chain(&infrastructure),
            Some(FsError::Io { .. })
        ));
        let infrastructure =
            ResponseErrorRef::from_anyhow_typed(&infrastructure, ChangedStatus::Conflict)
                .expect("quota infrastructure error is typed");
        assert_eq!(infrastructure.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let denial =
            quota_hook_policy_denial(Some("alice"), "COPY", Path::new("dest.bin"), Some(23));
        assert!(matches!(
            FsError::in_anyhow_chain(&denial),
            Some(FsError::NoSpace { .. })
        ));
        let denial = ResponseErrorRef::from_anyhow_typed(&denial, ChangedStatus::Conflict)
            .expect("quota policy denial is typed");
        assert_eq!(denial.status(), StatusCode::INSUFFICIENT_STORAGE);
    }

    #[tokio::test]
    async fn validator_truncation_maps_to_changed_precondition_412() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("target.bin");
        std::fs::write(&path, b"original bytes").unwrap();
        let root = RootFs::new(dir.path(), false, false).unwrap();
        let mut opened = root.open("target.bin", NodeKind::File).await.unwrap();
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        let mut response = Response::default();

        let validators = write_cache_validators(&mut opened, &mut response)
            .await
            .unwrap();
        assert!(validators.is_none());
        assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    }

    fn open_pair(source: &Path, destination: &Path) -> (File, File) {
        let source = OpenOptions::new().read(true).open(source).unwrap();
        let destination = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(destination)
            .unwrap();
        (source, destination)
    }

    fn executable_script(dir: &TempDir, body: &str) -> PathBuf {
        let path = dir.path().join("quota-hook.sh");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn storage_errno_classification_survives_anyhow_context() {
        for errno in [rustix::io::Errno::NOSPC, rustix::io::Errno::DQUOT] {
            let error = anyhow::Error::new(io::Error::from_raw_os_error(errno.raw_os_error()))
                .context("candidate sync failed");
            assert!(matches!(
                FsError::from_anyhow("writing candidate", error),
                FsError::NoSpace { .. }
            ));
        }
        assert!(matches!(
            FsError::from_anyhow("writing candidate", anyhow!("unrelated internal failure")),
            FsError::Io { .. }
        ));
    }

    #[test]
    fn actual_dev_full_enospc_is_classified_when_available() {
        let Ok(mut full) = OpenOptions::new().write(true).open("/dev/full") else {
            return;
        };
        let error = full.write_all(b"x").unwrap_err();
        let error = anyhow::Error::new(error).context("fault-injected candidate write");
        assert!(matches!(
            FsError::from_anyhow("writing candidate", error),
            FsError::NoSpace { .. }
        ));
    }

    #[test]
    fn copy_acceleration_keeps_safe_fallback_boundaries() {
        for errno in [
            rustix::io::Errno::XDEV,
            rustix::io::Errno::OPNOTSUPP,
            rustix::io::Errno::NOTTY,
            rustix::io::Errno::INVAL,
        ] {
            assert!(reflink_fallback_error(errno));
        }
        for errno in [
            rustix::io::Errno::NOSPC,
            rustix::io::Errno::DQUOT,
            rustix::io::Errno::IO,
        ] {
            assert!(!reflink_fallback_error(errno));
            assert!(!copy_file_range_fallback_error(errno, true));
        }
        assert!(copy_file_range_fallback_error(
            rustix::io::Errno::INVAL,
            true
        ));
        assert!(!copy_file_range_fallback_error(
            rustix::io::Errno::INVAL,
            false
        ));
    }

    #[test]
    fn cooperative_copy_preserves_content_and_reports_policy_overrun() {
        let dir = TempDir::new().unwrap();
        let source_path = dir.path().join("source");
        std::fs::write(&source_path, b"abcdef").unwrap();

        let (mut source, mut destination) = open_pair(&source_path, &dir.path().join("copy"));
        let outcome = copy_regular_file_cooperatively(
            &mut source,
            &mut destination,
            None,
            &RequestCancellation::new(),
        )
        .unwrap();
        assert_eq!(outcome.bytes, 6);
        assert_eq!(std::fs::read(dir.path().join("copy")).unwrap(), b"abcdef");

        let (mut source, mut destination) =
            open_pair(&source_path, &dir.path().join("limited-copy"));
        let outcome = copy_regular_file_cooperatively(
            &mut source,
            &mut destination,
            Some(3),
            &RequestCancellation::new(),
        )
        .unwrap();
        assert!(
            outcome.bytes > 3,
            "caller must observe limit + 1/full reflink"
        );
    }

    #[test]
    fn cooperative_copy_observes_preexisting_cancellation() {
        let dir = TempDir::new().unwrap();
        let source_path = dir.path().join("source");
        std::fs::write(&source_path, b"abcdef").unwrap();
        let (mut source, mut destination) =
            open_pair(&source_path, &dir.path().join("cancelled-copy"));
        let cancellation = RequestCancellation::new();
        cancellation.cancel();
        let error =
            copy_regular_file_cooperatively(&mut source, &mut destination, None, &cancellation)
                .unwrap_err();
        assert!(matches!(
            AdmissionError::in_anyhow_chain(&error),
            Some(AdmissionError::Cancelled {
                resource: AdmissionResource::CopyBytes,
            })
        ));
        let response = ResponseErrorRef::from_anyhow_typed(&error, ChangedStatus::Conflict)
            .expect("copy cancellation remains typed under context");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(destination.metadata().unwrap().len(), 0);
    }

    #[test]
    fn quota_hook_receives_identity_and_sizes_and_denies_fail_closed() {
        let dir = TempDir::new().unwrap();
        let allow_path = executable_script(
            &dir,
            r#"test "$1" = "--user" && test "$2" = "alice" &&
test "$3" = "--operation" && test "$4" = "COPY" &&
test "$5" = "--path" && test "$6" = "dest.bin" &&
test "$7" = "--current-bytes" && test "$8" = "12" &&
test "$9" = "--final-bytes" && test "${10}" = "34""#,
        );
        let allow = PathIdentity::capture(&allow_path).unwrap();
        run_storage_quota_hook(
            Some(&allow),
            Duration::from_secs(1),
            Some("alice"),
            "COPY",
            Path::new("dest.bin"),
            12,
            34,
            &RequestCancellation::new(),
        )
        .unwrap();

        let deny_path = executable_script(&dir, "exit 17");
        let deny = PathIdentity::capture(&deny_path).unwrap();
        let error = run_storage_quota_hook(
            Some(&deny),
            Duration::from_secs(1),
            Some("alice"),
            "COPY",
            Path::new("dest.bin"),
            0,
            1,
            &RequestCancellation::new(),
        )
        .unwrap_err();
        assert!(matches!(
            FsError::in_anyhow_chain(&error),
            Some(FsError::NoSpace { .. })
        ));

        let error = run_storage_quota_hook(
            Some(&allow),
            Duration::from_secs(1),
            None,
            "COPY",
            Path::new("dest.bin"),
            0,
            1,
            &RequestCancellation::new(),
        )
        .unwrap_err();
        assert!(matches!(
            FsError::in_anyhow_chain(&error),
            Some(FsError::NoSpace { .. })
        ));
    }

    #[test]
    fn quota_hook_timeout_kills_descendants_and_is_distinct_from_quota_denial() {
        let dir = TempDir::new().unwrap();
        let child_pid = dir.path().join("child.pid");
        let hook_path = executable_script(
            &dir,
            &format!(
                r#"
/bin/sleep 30 &
echo $! > "{}"
wait"#,
                child_pid.display()
            ),
        );
        let hook = PathIdentity::capture(&hook_path).unwrap();
        let error = run_storage_quota_hook(
            Some(&hook),
            Duration::from_millis(200),
            Some("alice"),
            "PATCH",
            Path::new("dest.bin"),
            1,
            2,
            &RequestCancellation::new(),
        )
        .unwrap_err();
        assert!(matches!(
            AdmissionError::in_anyhow_chain(&error),
            Some(AdmissionError::Timeout {
                kind: super::super::error::AdmissionTimeoutKind::Execution,
                ..
            })
        ));
        assert!(FsError::in_anyhow_chain(&error).is_none());

        let pid: u32 = std::fs::read_to_string(&child_pid)
            .expect("quota hook did not start its descendant")
            .trim()
            .parse()
            .unwrap();
        let descendant_is_running = || {
            let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
                return false;
            };
            stat.rsplit_once(") ")
                .is_some_and(|(_, fields)| !fields.starts_with("Z "))
        };
        let deadline = Instant::now() + Duration::from_secs(1);
        while descendant_is_running() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !descendant_is_running(),
            "quota-hook timeout left descendant pid {pid} running"
        );
    }

    #[test]
    fn quota_hook_executes_pinned_shebang_after_parent_namespace_replacement() {
        let dir = TempDir::new().unwrap();
        let trusted_parent = dir.path().join("trusted");
        std::fs::create_dir(&trusted_parent).unwrap();
        let marker = dir.path().join("marker");
        let trusted_hook = trusted_parent.join("quota-hook.sh");
        std::fs::write(
            &trusted_hook,
            format!("#!/bin/sh\nprintf trusted > \"{}\"\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&trusted_hook, std::fs::Permissions::from_mode(0o700)).unwrap();
        let identity = PathIdentity::capture(&trusted_hook).unwrap();

        let moved_parent = dir.path().join("trusted-before-replacement");
        std::fs::rename(&trusted_parent, &moved_parent).unwrap();
        std::fs::create_dir(&trusted_parent).unwrap();
        let decoy_hook = trusted_parent.join("quota-hook.sh");
        std::fs::write(
            &decoy_hook,
            format!(
                "#!/bin/sh\nprintf decoy > \"{}\"\nexit 23\n",
                marker.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&decoy_hook, std::fs::Permissions::from_mode(0o700)).unwrap();

        run_storage_quota_hook(
            Some(&identity),
            Duration::from_secs(1),
            Some("alice"),
            "PUT",
            Path::new("dest.bin"),
            0,
            1,
            &RequestCancellation::new(),
        )
        .unwrap();
        assert_eq!(std::fs::read_to_string(marker).unwrap(), "trusted");
    }

    #[test]
    fn quota_hook_helper_exec_failure_is_not_a_policy_denial() {
        let dir = TempDir::new().unwrap();
        let invalid_hook = dir.path().join("invalid-hook");
        std::fs::write(
            &invalid_hook,
            b"#!/definitely/missing/ram-quota-hook-interpreter\n",
        )
        .unwrap();
        std::fs::set_permissions(&invalid_hook, std::fs::Permissions::from_mode(0o700)).unwrap();
        let identity = PathIdentity::capture(&invalid_hook).unwrap();

        let error = run_storage_quota_hook(
            Some(&identity),
            // cargo-llvm-cov 下辅助进程是插桩 libtest 可执行文件；即使无效 shebang 立即失败，
            // 进程启动和 profile 刷新也可能超过一秒。此分类测试应独立于工具开销。
            // Under cargo-llvm-cov the helper is instrumented libtest; startup/profile flushing may
            // exceed one second although invalid shebang fails immediately. Keep classification independent.
            Duration::from_secs(10),
            Some("alice"),
            "PUT",
            Path::new("dest.bin"),
            0,
            1,
            &RequestCancellation::new(),
        )
        .unwrap_err();
        assert!(!matches!(
            FsError::in_anyhow_chain(&error),
            Some(FsError::NoSpace { .. })
        ));
        assert!(
            error
                .to_string()
                .contains("failed before executing pinned hook"),
            "unexpected quota-hook infrastructure error: {error:#}"
        );
    }

    #[test]
    fn storage_denials_map_to_507_but_internal_errors_do_not() {
        let mut response = Response::default();
        map_local_mutation_error(
            "COPY",
            Path::new("dest.bin"),
            Some("alice"),
            anyhow::Error::new(io::Error::from_raw_os_error(
                rustix::io::Errno::DQUOT.raw_os_error(),
            )),
            ChangedStatus::Conflict,
            &mut response,
        )
        .unwrap();
        assert_eq!(response.status(), StatusCode::INSUFFICIENT_STORAGE);

        let mut response = Response::default();
        map_local_mutation_error(
            "COPY",
            Path::new("dest.bin"),
            Some("alice"),
            anyhow!("internal invariant failed"),
            ChangedStatus::Conflict,
            &mut response,
        )
        .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn raced_endpoint_roles_select_412_or_409_without_path_inference() {
        let cases = [
            (
                MutationEndpointRole::Source,
                ChangedStatus::PreconditionFailed,
                true,
                StatusCode::PRECONDITION_FAILED,
            ),
            (
                MutationEndpointRole::Source,
                ChangedStatus::Conflict,
                false,
                StatusCode::CONFLICT,
            ),
            (
                MutationEndpointRole::Destination,
                ChangedStatus::PreconditionFailed,
                true,
                StatusCode::CONFLICT,
            ),
            (
                MutationEndpointRole::Destination,
                ChangedStatus::Conflict,
                false,
                StatusCode::PRECONDITION_FAILED,
            ),
        ];
        for (role, source_status, overwrite, expected_status) in cases {
            let error = anyhow::Error::new(FsError::changed(role, "diagnostic/path", "A", "B"));
            let changed_status = copy_move_changed_status(&error, source_status, overwrite);
            let mut response = Response::default();
            map_local_mutation_error(
                "COPY/MOVE",
                Path::new("unrelated/display/path"),
                Some("alice"),
                error,
                changed_status,
                &mut response,
            )
            .unwrap();
            assert_eq!(response.status(), expected_status);
        }
    }

    #[test]
    fn upload_and_mkcol_target_races_keep_conditional_statuses() {
        for operation in ["PUT", "MKCOL"] {
            for (changed_status, expected_status) in [
                (
                    ChangedStatus::PreconditionFailed,
                    StatusCode::PRECONDITION_FAILED,
                ),
                (ChangedStatus::Conflict, StatusCode::CONFLICT),
            ] {
                let error = anyhow::Error::new(FsError::changed(
                    MutationEndpointRole::Target,
                    "target",
                    "Missing",
                    "appeared",
                ));
                let mut response = Response::default();
                map_local_mutation_error(
                    operation,
                    Path::new("target"),
                    Some("alice"),
                    error,
                    changed_status,
                    &mut response,
                )
                .unwrap();
                assert_eq!(response.status(), expected_status);
            }
        }
    }

    #[test]
    fn recursive_delete_budget_cancel_and_deadline_have_stable_http_statuses() {
        for (error, expected) in [
            (
                AdmissionError::limit_exceeded(
                    AdmissionResource::WalkEntries,
                    super::super::error::LimitKind::Semantic,
                    3,
                    Some(4),
                ),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                AdmissionError::cancelled(AdmissionResource::WalkEntries),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                AdmissionError::execution_timeout(
                    AdmissionResource::ExpensiveTasks,
                    Duration::from_secs(5),
                ),
                StatusCode::GATEWAY_TIMEOUT,
            ),
        ] {
            let mut response = Response::default();
            map_local_mutation_error(
                "DELETE",
                Path::new("tree"),
                Some("alice"),
                anyhow::Error::new(error),
                ChangedStatus::Conflict,
                &mut response,
            )
            .unwrap();
            assert_eq!(response.status(), expected);
        }
    }

    #[test]
    fn candidate_and_post_publish_durability_failures_are_stable_500() {
        for errno in [rustix::io::Errno::NOSPC, rustix::io::Errno::DQUOT] {
            for published in [false, true] {
                let stage = if published {
                    super::super::error::DurabilityStage::DestinationParent
                } else {
                    super::super::error::DurabilityStage::CandidateFile
                };
                let error = anyhow::Error::new(FsError::durability(
                    stage,
                    published,
                    std::io::Error::from_raw_os_error(errno.raw_os_error()),
                ));
                assert_eq!(
                    FsError::in_anyhow_chain(&error)
                        .is_some_and(FsError::is_published_durability_failure),
                    published,
                    "published marker"
                );
                let mut response = Response::default();
                map_local_mutation_error(
                    "PUT",
                    Path::new("dest.bin"),
                    Some("alice"),
                    error,
                    ChangedStatus::Conflict,
                    &mut response,
                )
                .unwrap();
                assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
                assert!(!response.headers().contains_key(RETRY_AFTER));
            }
        }
    }
}
