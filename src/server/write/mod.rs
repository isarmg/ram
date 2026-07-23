//! 对文件系统的**写**操作：上传（PUT）、删除（DELETE）、新建目录（MKCOL）
//! 和移动（MOVE）。
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
//!
//! This module implements filesystem mutations: PUT uploads, DELETE, MKCOL, and MOVE.
//! Every path is security
//! sensitive: upload/delete policy and containment checks must jointly prevent modification of an
//! unauthorized object. Upload bodies flow through a bounded two-chunk channel into a synchronous
//! disk worker for backpressure, and `take(n)` reads one sentinel byte beyond a configured limit.
//! Publication is two-phase: bytes first enter a private `0600` candidate, then final mutation locks
//! protect descriptor-based ACL/precondition/identity revalidation before one rename.

use super::error::{
    AdmissionError, AdmissionResource, ChangedStatus, FsError, HttpError, LimitKind,
    MutationEndpointRole, QueueScope, ResponseError, ResponseErrorRef,
};
#[cfg(test)]
use super::filesystem::NodeKind;
#[cfg(test)]
use super::filesystem::RootFs;
use super::filesystem::{EntryExpectation, OpenedNode, TempFile};
use super::preconditions::ParsedPreconditions;
use super::reply::{status_bad_request, status_forbid, status_no_content};
use super::walk::{
    RequestCancellation, is_blocking_deadline, spawn_supervised_blocking_with_shutdown,
};
use super::{MutationGuards, Request, Response, Server, extract_cache_headers};
use crate::http::IncomingStream;
use crate::identity::SourceIdentity;

use anyhow::{Result, anyhow, bail};
use futures_util::StreamExt;
use headers::{HeaderMap, IfNoneMatch};
use hyper::{
    StatusCode, Uri,
    header::{CONTENT_LENGTH, HOST, HeaderValue},
};
use std::fs::File;
#[cfg(test)]
use std::io;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

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

/// 一次原子上传发布所观察并重新验证的全部状态。
/// All state observed/revalidated for one atomic upload publication. Keeping it together prevents
/// callers from pairing existence state with metadata from another probe.
pub(super) struct UploadCommit {
    pub(super) original: Option<OpenedNode>,
    pub(super) staged: StagedUpload,
    pub(super) mutation_guards: MutationGuards,
    pub(super) changed_status: ChangedStatus,
}

fn upload_size_allowed(size: u64, limit: u64) -> bool {
    size <= limit
}

fn local_path_error(detail: &'static str) -> anyhow::Error {
    anyhow::Error::new(HttpError::bad_request(anyhow!(detail)))
}

fn upload_body_transport_error(source: anyhow::Error) -> anyhow::Error {
    anyhow::Error::new(HttpError::bad_request(source)).context("reading PUT request body transport")
}

impl Server {
    /// 获取变更锁前把 PUT 请求体接收到私有候选中。若目标父目录已存在，PUT 可直接
    /// 发布同一候选。暂存期间刻意不创建缺失祖先；回退候选位于固定服务根中，只在变更锁下
    /// 重新评估授权/前置条件后复制。
    /// Receive a PUT body into a private candidate before mutation locking. If the parent exists,
    /// PUT can publish it directly. Staging never creates ancestors; a root fallback is copied only
    /// after authorization/preconditions are re-evaluated under the lock.
    pub(super) async fn stage_upload(
        &self,
        path: &Path,
        req: Request,
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
            && !upload_size_allowed(length, max_upload_size)
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
        let operation_name = "PUT";
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
                    let next = received
                        .checked_add(chunk.len() as u64)
                        .filter(|next| upload_size_allowed(*next, max_upload_size))
                        .ok_or_else(|| {
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
                    let Some(next) = queued
                        .checked_add(chunk.len() as u64)
                        .filter(|next| upload_size_allowed(*next, max_upload_size))
                    else {
                        break Err(UploadFeedFailure::TooLarge);
                    };
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

    /// 以 PUT 原子新建或替换一个完整文件。
    /// Atomically create or replace one complete file with PUT.
    pub(super) async fn handle_upload(
        &self,
        path: &Path,
        upload: UploadCommit,
        res: &mut Response,
    ) -> Result<()> {
        let UploadCommit {
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
        let max_upload_size = self.args.max_upload_size;
        let StagedUpload {
            temp: staged_temp,
            len: staged_len,
            user: staged_user,
        } = staged;

        if !upload_size_allowed(staged_len, max_upload_size) {
            ResponseError::admission(AdmissionError::limit_exceeded(
                AdmissionResource::UploadBytes,
                LimitKind::Payload,
                max_upload_size,
                Some(staged_len),
            ))
            .apply(res);
            return Ok(());
        }

        // 发布和 fsync 在拥有全部资源的阻塞任务中执行。上传准入附着于 staged_temp 并随它
        // 进入工作线程；昂贵任务 permit 是显式工作守卫。
        // Publication and fsync run in one owned blocking job. Admission follows staged_temp and the
        // expensive permit guards the worker until all kernel I/O and cleanup have completed.
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
                "PUT",
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
        let direct_put = staged_temp.target_rel() == path;
        let staged_temp = staged_temp.into_blocking()?;
        drop(original);
        let fs_root = self.fs_root.clone();
        let path = path.to_path_buf();
        let worker_path = path.clone();
        let upload_file_mode = self.args.upload_file_mode;
        let upload_dir_mode = self.args.upload_dir_mode;
        let storage_space_check = self.args.storage_space_check;
        let storage_reserve = self.args.storage_reserve;
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

                if storage_space_check {
                    // 直接 PUT 候选已包含请求体；回退 PUT 会在旧表示仍可达时分配第二个候选。
                    // A direct candidate already contains the body; a fallback PUT allocates a second
                    // candidate while the old representation remains reachable.
                    let additional_bytes = if direct_put { 0 } else { staged_len };
                    enforce_storage_preflight(&target, additional_bytes, storage_reserve)?;
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
                if actual_final_size != staged_len {
                    bail!(
                        "upload candidate length changed: expected {staged_len}, got {actual_final_size}"
                    );
                }
                target.commit(expected_target, final_mode, &cancellation)
            },
        );
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(self.args.expensive_task_timeout);
        if let Err(err) = operation.wait_until(deadline).await {
            return map_local_mutation_error(
                "PUT",
                &path,
                response_user.as_deref(),
                err,
                changed_status,
                res,
            );
        }

        *res.status_mut() = if target_exists {
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
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(self.args.expensive_task_timeout);
        if let Err(error) = operation.wait_until(deadline).await {
            return map_local_mutation_error("DELETE", path, None, error, changed_status, res);
        }

        status_no_content(res);
        Ok(())
    }

    /// MKCOL 新建目录，Web 界面的“新建文件夹”也走这里。
    /// MKCOL creates a directory and also backs the web UI's “new folder” action.
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

        // MOVE 要求目标父目录已经存在。能力查找保持不创建，使缺失父目录报告 409 而非
        // 悄然出现。
        // MOVE requires an existing destination parent. Keep capability lookup non-creating so a
        // missing parent is 409 rather than silently creating it.
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
            let endpoint_status = move_changed_status(&error, changed_status, overwrite);
            return map_local_mutation_error("MOVE", dest, user, error, endpoint_status, res);
        }

        if dest_exists {
            status_no_content(res);
        } else {
            *res.status_mut() = StatusCode::CREATED;
        }
        Ok(())
    }

    /// 解析并校验 MOVE 的目标路径：
    /// Destination 头 → 路径规范化（拒绝 `..`）→ 目标权限鉴权 → 拼绝对路径。
    /// 请求语义/权限失败把状态写进 `res` 并返回 `Ok(None)`；解析器或
    /// 文件系统基础设施失败保留 typed cause 向上传播。
    /// Parse and validate a MOVE destination: normalize the header path, reject `..`, authorize the
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
        // 服务根在文件系统能力内没有父目录槽位，因此不能成为 MOVE 发布目标；在此拒绝，
        // 避免 open_parent 把请求语义误报为内部错误。
        // The served root has no parent slot in the filesystem capability and therefore cannot be a
        // MOVE publication destination. Reject it here instead of letting open_parent turn this
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
                    "Rejected MOVE Destination outside the filesystem capability: error={error:#}"
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
        // 对 absolute-form HTTP/1 请求，authority 位于请求 URI；普通 origin-form 请求则
        // 使用 Host。两者同时存在时必须一致。
        // Absolute-form HTTP/1 requests carry authority in the request URI; ordinary origin-form
        // requests use Host. When both are present they must agree.
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

fn move_changed_status(
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

/// 将已经记录长度的 PUT 暂存文件复制到目标父目录中的发布候选。
/// Copy a recorded PUT staging file into a publication candidate in the target parent.
fn copy_exact_at_current(
    source: &mut File,
    destination: &mut File,
    expected: u64,
    cancellation: &RequestCancellation,
) -> Result<()> {
    if source.metadata()?.len() != expected {
        bail!("staged upload length changed before local copy");
    }
    let mut buffer = vec![0u8; 64 * 1024];
    let mut copied = 0u64;
    while copied < expected {
        if cancellation.is_cancelled() {
            return Err(
                anyhow::Error::new(AdmissionError::cancelled(AdmissionResource::Uploads))
                    .context("request was cancelled during PUT fallback copy"),
            );
        }
        let requested = (expected - copied).min(buffer.len() as u64) as usize;
        let read = source.read(&mut buffer[..requested])?;
        if read == 0 {
            break;
        }
        destination.write_all(&buffer[..read])?;
        copied = copied.saturating_add(read as u64);
    }
    if copied != expected {
        bail!("staged upload ended before its recorded length");
    }
    Ok(())
}

/// 独立于请求/认证状态解析 MOVE Destination。仅当绝对 URI 的有效 `host[:port]` 与请求
/// Host 匹配时才接受；相对路径不要求 Host。
/// Parse a MOVE Destination independently of request/auth state. Absolute URIs require effective
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

/// 联合配置 URI 前缀和请求路径能力规范器测试 MOVE Destination/Host 同源检查。
/// Exercise MOVE Destination/Host same-origin checks with the configured URI prefix and request-path
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
/// `If-Unmodified-Since`）。前置条件不满足时返回 `Ok(false)` 并把响应设为 412，
/// 避免携带旧 ETag 的客户端悄悄覆盖已经变化的内容。
/// Evaluate conditional-write headers before overwriting with PUT. Failure returns `Ok(false)` and
/// 412, so a client carrying a stale ETag cannot silently overwrite changed content.
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

/// MOVE 的 RFC 4918 `Overwrite` 头。缺省和精确的 `T` 允许覆盖，
/// 精确的 `F` 禁止覆盖；其他值（包括非 UTF-8）都是无效请求。
/// RFC 4918 `Overwrite` for MOVE: absent or exact `T` permits replacement; exact `F` forbids it;
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

#[cfg(test)]
mod storage_tests;
