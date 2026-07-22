//! 基于 Linux dirfd 的文件系统能力层。
//! Linux dirfd-based filesystem capability layer.
//!
//! 每条完整相对路径都由 `openat2(2)` 解析。若某个 `*at` 系统调用没有解析标志，操作会
//! 先固定父目录，再只向系统调用传递一个基名。由此请求处理绑定到文件系统对象，而非可能
//! 发生竞态的绝对路径字符串。
//! Every full relative path is resolved by `openat2(2)`. Operations whose `*at` syscall has no
//! resolve flags first pin the parent and pass only one basename, keeping request handling tied to
//! filesystem objects rather than raceable absolute path strings.

use super::error::{
    AdmissionError, AdmissionResource, DurabilityStage, FsError, LimitKind, MutationEndpointRole,
};
use super::{
    MutationGuards, MutationIntent, MutationLockKey, MutationLockMode, MutationLockRequest,
};
use crate::path_identity::ServedPathIdentity;
use crate::utils::is_trusted_file_owner;
use anyhow::{Context, Result, anyhow, bail};
use rustix::fs::{
    self, AtFlags, Dir, FileType, FlockOperation, Mode, OFlags, RenameFlags, ResolveFlags, flock,
};
use rustix::io::Errno;
use std::collections::{BTreeMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs::{File, Metadata};
use std::future::Future;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::task::{Context as TaskContext, Poll};
use std::thread;
use std::time::{Duration, Instant, SystemTime};
use std::{io, pin::Pin};
use tokio::io::{AsyncRead, AsyncSeek, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const VERIFY_RETRIES: usize = 3;
const STALE_CLEANUP_DIAGNOSTIC_LIMIT: usize = 4;
const STALE_CLEANUP_DIAGNOSTIC_PATH_MAX_BYTES: usize = 512;
const STALE_CLEANUP_DIAGNOSTIC_CAUSE_MAX_BYTES: usize = 1024;

#[derive(Clone)]
pub(super) struct RootFs {
    inner: Arc<RootFsInner>,
}

/// 所有短文件系统阻塞任务共享的进程内准入。许可必须在调用 `spawn_blocking` **之前**
/// 获得，并由真实阻塞闭包持有；否则 HTTP future 被取消会分离 JoinHandle、提前释放请求
/// 准入，并允许已取消任务无限堆入 Tokio 的无界 blocking queue。
///
/// Process-wide admission shared by short filesystem blocking tasks. A permit is acquired
/// **before** `spawn_blocking` and owned by the real closure. Dropping an HTTP future therefore
/// cannot detach work, release all capacity, and accumulate cancelled jobs in Tokio's unbounded
/// blocking queue.
#[derive(Clone)]
pub(super) struct FilesystemBlockingAdmission {
    semaphore: Arc<Semaphore>,
    queue_timeout: Duration,
}

/// 每个已准入任务的真实 worker 所拥有的许可。响应体 Drop 时，正在内核调用中的闭包仍持有
/// 此值，直至 syscall 真正返回才释放容量；空闲响应体不会长期占用许可。
/// The permit owned by each admitted real worker. If a response body is dropped, an in-kernel
/// closure retains this value until the syscall actually returns; an idle body holds no permit.
struct FilesystemBlockingLease {
    _permit: OwnedSemaphorePermit,
}

/// Tokio 的 `JoinHandle::drop` 只会分离任务；本封装在请求 future Drop 时额外 abort，防止
/// 尚未启动的已取消变更稍后执行。准入许可仍在排队 task 的闭包中，因此即使 Tokio 直到
/// dequeue 才销毁已 abort task，队列长度也始终受 semaphore 上限约束。
/// Tokio detaches a task when its `JoinHandle` is dropped. This wrapper additionally aborts on
/// request-future drop so a queued cancelled mutation cannot execute later. The queued task still
/// owns its admission lease, keeping queue cardinality bounded until Tokio dequeues it.
struct AbortOnDropBlocking<T> {
    task: tokio::task::JoinHandle<T>,
}

impl<T> AbortOnDropBlocking<T> {
    fn new(task: tokio::task::JoinHandle<T>) -> Self {
        Self { task }
    }
}

impl<T> Future for AbortOnDropBlocking<T> {
    type Output = std::result::Result<T, tokio::task::JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.task).poll(cx)
    }
}

impl<T> Drop for AbortOnDropBlocking<T> {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FilesystemBlockingAdmission {
    pub(super) fn new(limit: usize, queue_timeout: Duration) -> Self {
        debug_assert!(limit > 0);
        Self {
            semaphore: Arc::new(Semaphore::new(limit.max(1))),
            queue_timeout,
        }
    }

    async fn acquire(&self) -> Result<Arc<FilesystemBlockingLease>> {
        let permit =
            match tokio::time::timeout(self.queue_timeout, self.semaphore.clone().acquire_owned())
                .await
            {
                Ok(Ok(permit)) => permit,
                Ok(Err(_)) => {
                    return Err(anyhow::Error::new(AdmissionError::cancelled(
                        AdmissionResource::FilesystemTasks,
                    )));
                }
                Err(_) => {
                    return Err(anyhow::Error::new(AdmissionError::queue_timeout(
                        AdmissionResource::FilesystemTasks,
                        super::error::QueueScope::WorkerPool,
                        self.queue_timeout,
                    )));
                }
            };
        Ok(Arc::new(FilesystemBlockingLease { _permit: permit }))
    }

    fn acquire_future(&self) -> FilesystemLeaseFuture {
        let admission = self.clone();
        Box::pin(async move { admission.acquire().await })
    }

    fn spawn_with_lease<T, F>(
        &self,
        lease: Arc<FilesystemBlockingLease>,
        work: F,
    ) -> AbortOnDropBlocking<T>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        AbortOnDropBlocking::new(tokio::task::spawn_blocking(move || {
            let _lease = lease;
            work()
        }))
    }

    async fn run<T, F>(&self, work: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T> + Send + 'static,
    {
        let lease = self.acquire().await?;
        self.spawn_with_lease(lease, work)
            .await
            .map_err(anyhow::Error::new)
            .context("filesystem blocking worker failed")?
    }

    #[cfg(test)]
    pub(super) fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }
}

type FilesystemLeaseFuture =
    Pin<Box<dyn Future<Output = Result<Arc<FilesystemBlockingLease>>> + Send + Sync + 'static>>;

struct RootFsInner {
    root: File,
    blocking_admission: FilesystemBlockingAdmission,
    allow_symlink: bool,
    allow_cross_filesystems: bool,
    candidate_cleanup_max_depth: usize,
    /// 粘性恢复准入状态。若有界清理扫描无法证明已访问完整能力树，此 RootFs 生命周期内将
    /// 禁止创建新私有候选。现有读取仍可用，只读部署可自行决定不完整启动报告是否致命。
    /// Sticky recovery admission state. If a bounded cleanup scan cannot prove it visited the whole
    /// capability tree, new private candidates remain disabled for this RootFs lifetime. Reads stay
    /// available, and read-only deployments decide separately whether an incomplete report is fatal.
    candidate_recovery_healthy: AtomicBool,
    /// 单文件模式保留经过校验的确切文件描述符；之后重命名或替换配置基名不得改变所服务 inode。
    /// Single-file mode retains the exact validated descriptor. Later rename/replacement of the
    /// configured basename must never change which inode is served.
    single_file: Option<SingleFileCapability>,
}

struct SingleFileCapability {
    name: OsString,
    file: File,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NodeKind {
    Any,
    File,
    Directory,
}

pub(super) struct OpenedNode {
    pub(super) file: GuardedBlockingFile,
    pub(super) metadata: Metadata,
    pub(super) real_rel: PathBuf,
}

/// 使用显式 `spawn_blocking` 的已打开文件。与 `tokio::fs::File` 不同，每次真实
/// metadata/read/seek 闭包都会捕获共享 FS lease；因此下载响应体被客户端取消时，在途 syscall
/// 不会脱离准入。操作之间不保留 lease，避免网络背压让慢客户端长期占用 worker 容量。
///
/// An opened file whose real metadata/read/seek closures explicitly retain the shared filesystem
/// lease. Unlike `tokio::fs::File`, body cancellation cannot detach an in-flight syscall from
/// admission accounting. No lease is retained between operations, so network backpressure does not
/// let a slow client monopolize worker capacity.
pub(super) struct GuardedBlockingFile {
    state: GuardedBlockingFileState,
    admission: FilesystemBlockingAdmission,
    position: u64,
}

enum GuardedBlockingFileState {
    Idle(File),
    AcquiringRead {
        file: Option<File>,
        read_len: usize,
        acquire: FilesystemLeaseFuture,
    },
    Reading(AbortOnDropBlocking<BlockingReadOutcome>),
    AcquiringSeek {
        file: Option<File>,
        position: SeekFrom,
        acquire: FilesystemLeaseFuture,
    },
    Seeking(AbortOnDropBlocking<BlockingSeekOutcome>),
    /// 仅在安全移出 enum payload 的同一同步临界区短暂存在。 / Transient only while moving an enum payload synchronously.
    Vacant,
}

struct BlockingReadOutcome {
    file: File,
    buffer: Vec<u8>,
    result: io::Result<usize>,
}

struct BlockingSeekOutcome {
    file: File,
    result: io::Result<u64>,
}

impl GuardedBlockingFile {
    fn new(file: File, admission: FilesystemBlockingAdmission) -> Self {
        Self {
            state: GuardedBlockingFileState::Idle(file),
            admission,
            position: 0,
        }
    }

    /// 元数据查询使用描述符克隆并让真实 worker 捕获 lease；取消查询不会遗留免费任务。
    /// Query metadata through a descriptor clone whose real worker owns the lease; cancellation
    /// cannot leave an unaccounted task behind.
    pub(super) async fn metadata(&self) -> io::Result<Metadata> {
        let file = match &self.state {
            GuardedBlockingFileState::Idle(file) => file.try_clone()?,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "another guarded file operation is in flight",
                ));
            }
        };
        let lease = self
            .admission
            .acquire()
            .await
            .map_err(Self::admission_error)?;
        let task = self
            .admission
            .spawn_with_lease(lease, move || file.metadata());
        task.await
            .map_err(|error| io::Error::other(format!("metadata worker failed: {error}")))?
    }

    /// 仅在没有在途操作时交出同步描述符；所有生产调用都在已 await 的边界使用此转换。
    /// Yield the synchronous descriptor only while idle; production callers convert after awaited boundaries.
    pub(super) fn into_std(self) -> io::Result<File> {
        match self.state {
            GuardedBlockingFileState::Idle(file) => Ok(file),
            _ => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "cannot convert a guarded file while an operation is in flight",
            )),
        }
    }

    fn join_error(error: tokio::task::JoinError) -> io::Error {
        io::Error::other(format!("guarded filesystem worker failed: {error}"))
    }

    fn admission_error(error: anyhow::Error) -> io::Error {
        let kind = if matches!(
            AdmissionError::in_anyhow_chain(&error),
            Some(AdmissionError::Timeout { .. })
        ) {
            io::ErrorKind::TimedOut
        } else {
            io::ErrorKind::Other
        };
        io::Error::new(kind, format!("filesystem admission failed: {error:#}"))
    }
}

impl AsyncRead for GuardedBlockingFile {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        destination: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &mut this.state {
                GuardedBlockingFileState::Idle(_) if destination.remaining() == 0 => {
                    return Poll::Ready(Ok(()));
                }
                GuardedBlockingFileState::Idle(_) => {
                    let GuardedBlockingFileState::Idle(file) =
                        std::mem::replace(&mut this.state, GuardedBlockingFileState::Vacant)
                    else {
                        unreachable!();
                    };
                    this.state = GuardedBlockingFileState::AcquiringRead {
                        file: Some(file),
                        read_len: destination.remaining().min(super::BUF_SIZE),
                        acquire: this.admission.acquire_future(),
                    };
                }
                GuardedBlockingFileState::AcquiringRead {
                    file,
                    read_len,
                    acquire,
                } => {
                    let lease = match acquire.as_mut().poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(lease)) => lease,
                        Poll::Ready(Err(error)) => {
                            let file = file.take().expect("acquiring read always retains its file");
                            this.state = GuardedBlockingFileState::Idle(file);
                            return Poll::Ready(Err(Self::admission_error(error)));
                        }
                    };
                    let mut file = file.take().expect("admitted read always retains its file");
                    let read_len = *read_len;
                    let task = this.admission.spawn_with_lease(lease, move || {
                        let mut buffer = vec![0_u8; read_len];
                        let result = file.read(&mut buffer);
                        BlockingReadOutcome {
                            file,
                            buffer,
                            result,
                        }
                    });
                    this.state = GuardedBlockingFileState::Reading(task);
                }
                GuardedBlockingFileState::Reading(task) => {
                    let outcome = match Pin::new(task).poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(outcome)) => outcome,
                        Poll::Ready(Err(error)) => {
                            this.state = GuardedBlockingFileState::Vacant;
                            return Poll::Ready(Err(Self::join_error(error)));
                        }
                    };
                    let BlockingReadOutcome {
                        file,
                        buffer,
                        result,
                    } = outcome;
                    this.state = GuardedBlockingFileState::Idle(file);
                    match result {
                        Ok(read) => {
                            destination.put_slice(&buffer[..read]);
                            this.position = this.position.saturating_add(read as u64);
                            return Poll::Ready(Ok(()));
                        }
                        Err(error) => return Poll::Ready(Err(error)),
                    }
                }
                GuardedBlockingFileState::AcquiringSeek { .. }
                | GuardedBlockingFileState::Seeking(_) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "a guarded seek is still in flight",
                    )));
                }
                GuardedBlockingFileState::Vacant => {
                    return Poll::Ready(Err(io::Error::other(
                        "guarded file entered an invalid vacant state",
                    )));
                }
            }
        }
    }
}

impl AsyncSeek for GuardedBlockingFile {
    fn start_seek(self: Pin<&mut Self>, position: SeekFrom) -> io::Result<()> {
        let this = self.get_mut();
        let state = std::mem::replace(&mut this.state, GuardedBlockingFileState::Vacant);
        let GuardedBlockingFileState::Idle(file) = state else {
            this.state = state;
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "another guarded file operation is in flight",
            ));
        };
        this.state = GuardedBlockingFileState::AcquiringSeek {
            file: Some(file),
            position,
            acquire: this.admission.acquire_future(),
        };
        Ok(())
    }

    fn poll_complete(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<u64>> {
        let this = self.get_mut();
        loop {
            match &mut this.state {
                GuardedBlockingFileState::Idle(_) => {
                    return Poll::Ready(Ok(this.position));
                }
                GuardedBlockingFileState::AcquiringRead { .. }
                | GuardedBlockingFileState::Reading(_) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "a guarded read is still in flight",
                    )));
                }
                GuardedBlockingFileState::AcquiringSeek {
                    file,
                    position,
                    acquire,
                } => {
                    let lease = match acquire.as_mut().poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(lease)) => lease,
                        Poll::Ready(Err(error)) => {
                            let file = file.take().expect("acquiring seek always retains its file");
                            this.state = GuardedBlockingFileState::Idle(file);
                            return Poll::Ready(Err(Self::admission_error(error)));
                        }
                    };
                    let mut file = file.take().expect("admitted seek always retains its file");
                    let position = *position;
                    let task = this.admission.spawn_with_lease(lease, move || {
                        let result = file.seek(position);
                        BlockingSeekOutcome { file, result }
                    });
                    this.state = GuardedBlockingFileState::Seeking(task);
                }
                GuardedBlockingFileState::Seeking(task) => {
                    let outcome = match Pin::new(task).poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(outcome)) => outcome,
                        Poll::Ready(Err(error)) => {
                            this.state = GuardedBlockingFileState::Vacant;
                            return Poll::Ready(Err(Self::join_error(error)));
                        }
                    };
                    let BlockingSeekOutcome { file, result } = outcome;
                    this.state = GuardedBlockingFileState::Idle(file);
                    match result {
                        Ok(position) => {
                            this.position = position;
                            return Poll::Ready(Ok(position));
                        }
                        Err(error) => return Poll::Ready(Err(error)),
                    }
                }
                GuardedBlockingFileState::Vacant => {
                    return Poll::Ready(Err(io::Error::other(
                        "guarded file entered an invalid vacant state",
                    )));
                }
            }
        }
    }
}

/// 变更事务持有进程内锁时捕获的命名空间状态。最终组件始终使用 `AT_SYMLINK_NOFOLLOW`
/// 观察；提交路径在发出破坏性 `*at` 调用前，通过已固定父目录再次比较此值。
/// Namespace state captured while a mutation transaction owns its in-process lock. The final
/// component is observed with `AT_SYMLINK_NOFOLLOW`; commit paths compare it again through the
/// pinned parent before issuing a destructive `*at` syscall.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum EntryExpectation {
    Missing,
    Present(EntryVersion),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct EntryVersion {
    dev: u64,
    ino: u64,
    ctime_sec: i64,
    ctime_nsec: i64,
    kind: u32,
}

impl EntryExpectation {
    pub(super) fn from_metadata(metadata: &Metadata) -> Self {
        Self::Present(EntryVersion::from_metadata(metadata))
    }

    fn from_stat(stat: &fs::Stat) -> Self {
        Self::Present(EntryVersion {
            dev: stat.st_dev,
            ino: stat.st_ino,
            ctime_sec: stat.st_ctime,
            ctime_nsec: stat.st_ctime_nsec as i64,
            kind: stat.st_mode & 0o170000,
        })
    }

    pub(super) fn matches_metadata(self, metadata: &Metadata) -> bool {
        self == Self::from_metadata(metadata)
    }

    fn same_object(self, other: Self) -> bool {
        match (self, other) {
            (Self::Missing, Self::Missing) => true,
            (Self::Present(left), Self::Present(right)) => {
                left.dev == right.dev && left.ino == right.ino && left.kind == right.kind
            }
            _ => false,
        }
    }
}

impl EntryVersion {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            ctime_sec: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
            kind: metadata.mode() & 0o170000,
        }
    }
}

pub(super) struct DirectoryEntry {
    pub(super) name: OsString,
    pub(super) metadata: Metadata,
    pub(super) real_rel: PathBuf,
    pub(super) is_symlink: bool,
}

pub(super) struct WalkEntry {
    pub(super) name: OsString,
    pub(super) display_rel: PathBuf,
    /// 解析符号链接并由 capability root 约束后的真实相对路径。
    /// 列表类接口必须同时确认显示路径和真实路径都能以 UTF-8 表示，
    /// 避免通过 UTF-8 别名泄露不可表示的目标。
    /// Real relative path after symlink resolution, constrained by the capability root. Listing APIs
    /// require both display and real paths to be UTF-8 so no alias leaks an unrepresentable target.
    pub(super) real_rel: PathBuf,
    pub(super) metadata: Metadata,
    pub(super) file: File,
    pub(super) is_symlink: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WalkAction {
    Continue,
    SkipDirectory,
    Stop,
}

pub(super) struct ParentDir {
    fd: File,
    real_rel: PathBuf,
    target_name: OsString,
    created_ancestors: Vec<CreatedAncestor>,
}

impl ParentDir {
    pub(super) fn target_rel(&self) -> PathBuf {
        self.real_rel.join(&self.target_name)
    }

    fn transfer_clone(&mut self) -> Result<Self> {
        Ok(Self {
            fd: self.fd.try_clone()?,
            real_rel: self.real_rel.clone(),
            target_name: self.target_name.clone(),
            created_ancestors: std::mem::take(&mut self.created_ancestors),
        })
    }

    fn current_expectation(&self) -> Result<EntryExpectation> {
        match fs::statat(&self.fd, &self.target_name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => Ok(EntryExpectation::from_stat(&stat)),
            Err(Errno::NOENT) => Ok(EntryExpectation::Missing),
            Err(err) => Err(err.into()),
        }
    }

    fn verify_entry(&self, expected: EntryExpectation) -> Result<()> {
        self.verify_entry_with_role(expected, MutationEndpointRole::Target)
    }

    fn verify_entry_with_role(
        &self,
        expected: EntryExpectation,
        role: MutationEndpointRole,
    ) -> Result<()> {
        let actual = self.current_expectation()?;
        if actual != expected {
            return Err(anyhow::Error::new(FsError::changed(
                role,
                self.target_rel().display().to_string(),
                format!("{expected:?}"),
                format!("{actual:?}"),
            )));
        }
        Ok(())
    }

    fn verify_entry_identity(&self, expected: EntryExpectation) -> Result<()> {
        let actual = self.current_expectation()?;
        if !expected.same_object(actual) {
            return Err(anyhow::Error::new(FsError::changed(
                MutationEndpointRole::Target,
                self.target_rel().display().to_string(),
                format!("{expected:?}"),
                format!("{actual:?}"),
            )));
        }
        Ok(())
    }

    fn verify_candidate_identity(&self, name: &OsStr, expected: EntryExpectation) -> Result<()> {
        let actual = match fs::statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => EntryExpectation::from_stat(&stat),
            Err(Errno::NOENT) => EntryExpectation::Missing,
            Err(error) => return Err(error.into()),
        };
        if !expected.same_object(actual) {
            return Err(anyhow::Error::new(FsError::changed(
                MutationEndpointRole::Target,
                self.target_rel().display().to_string(),
                format!("private candidate {expected:?}"),
                format!("private candidate {actual:?}"),
            )));
        }
        Ok(())
    }

    /// 当仅创建 mkdir 或 `RENAME_NOREPLACE` 观察到目标在刚完成的命名空间检查后出现时，
    /// 保留语义化竞态分类。EEXIST 本身就是权威观察；后续 stat 可能再与删除发生竞态。
    /// Preserve semantic race classification when create-only mkdir or `RENAME_NOREPLACE` sees a
    /// target appear after the preceding namespace check. EEXIST is authoritative; a later stat
    /// could race with another removal.
    fn create_only_error(
        &self,
        expected: EntryExpectation,
        role: MutationEndpointRole,
        error: Errno,
    ) -> anyhow::Error {
        if error == Errno::EXIST {
            anyhow::Error::new(FsError::changed(
                role,
                self.target_rel().display().to_string(),
                format!("{expected:?}"),
                "entry appeared before atomic no-replace publication",
            ))
        } else {
            error.into()
        }
    }
}

struct CreatedAncestor {
    parent: File,
    name: OsString,
    expectation: EntryExpectation,
    parent_sync_pending: bool,
}

/// 在目标所在同一固定目录中新建的临时文件；丢弃未提交值会移除私有候选名称。
/// A create-new temporary file in the same pinned directory as its target. Dropping an uncommitted
/// value removes the private candidate name.
pub(super) struct TempFile {
    root: RootFs,
    parent: ParentDir,
    temp_name: OsString,
    file: Option<File>,
    candidate_lock: Option<File>,
    candidate_expectation: EntryExpectation,
    cleanup_guard: Option<Box<dyn Send + 'static>>,
    committed: bool,
}

/// 与 `openat(O_EXCL)` 在同一个阻塞闭包内建立的候选所有权。若请求 future 在观察
/// JoinHandle 结果前取消，丢弃此值仍会安排 unlink 新建目录项。
/// Candidate ownership established in the same blocking closure as `openat(O_EXCL)`. If the request
/// future is cancelled before observing the JoinHandle, dropping this value still schedules unlink.
struct CreatedTempCandidate {
    cleanup_parent: Option<File>,
    temp_name: OsString,
    file: Option<File>,
    candidate_lock: Option<File>,
    expectation: EntryExpectation,
    created_ancestors: Vec<CreatedAncestor>,
}

/// COPY/PATCH 所拥有阻塞任务使用的同步形式。其 Drop 在该工作线程中执行 unlink，因此在
/// 候选清理真正返回前，不会释放工作线程拥有的准入 permit。
/// Synchronous form used by COPY/PATCH owned blocking jobs. Its Drop unlinks in that worker, so the
/// worker-owned admission permit cannot be released before cleanup actually returns.
pub(super) struct BlockingTempFile {
    root: RootFs,
    parent: ParentDir,
    temp_name: OsString,
    file: Option<File>,
    candidate_lock: Option<File>,
    candidate_expectation: EntryExpectation,
    cleanup_guard: Option<Box<dyn Send + 'static>>,
    committed: bool,
}

struct CandidateCleanup {
    parent: Option<File>,
    name: OsString,
    state: CandidateCleanupState,
    expectation: Option<EntryExpectation>,
    /// 自动创建的父目录属于同一变更事务。只有明确确认候选已 unlink 后才能回滚；清理器
    /// 失败会保留完整身份记录供下次尝试。
    /// Auto-created parents belong to the same transaction and may be rolled back only after candidate
    /// unlink is confirmed; a failed reaper attempt retains the full identity record.
    created_ancestors: Vec<CreatedAncestor>,
    /// 目录项真正移除前保留 advisory flock。降级清理器在进程剩余生命周期内保留该描述符，
    /// 避免另一进程的启动清理把未解决活跃候选误认为遗留项。
    /// Retain the advisory flock until the entry is removed. A degraded reaper keeps the descriptor
    /// for the process lifetime so another process cannot mistake an unresolved candidate as abandoned.
    _candidate_lock: Option<File>,
    /// 异步候选可附带准入所有权。将其保留在排队清理记录中，避免已取消上传在 unlink 真正
    /// 返回前释放容量。
    /// Admission ownership may be attached to an async candidate. Retaining it in the queued cleanup
    /// record prevents a cancelled upload freeing capacity before unlink returns.
    _guard: Option<Box<dyn Send + 'static>>,
    ticket: Option<CleanupTicket>,
}

/// 私有候选清理的单向状态机：
/// `Present` 先验证名称仍指向预期 inode，再 unlink（或观察 `ENOENT`）；
/// `ParentSyncPending` 表示名称已不可见但父目录尚未持久化；`Absent` 仅在父目录 fsync 后进入，
/// 此时才允许回滚事务自动创建的祖先；仅含祖先的清理任务因没有候选名而直接从 `Absent`
/// 开始。重试只可向前，不能提前释放锁或准入守卫。
/// Monotonic private-candidate cleanup state: `Present` verifies the exact inode before unlinking;
/// `ParentSyncPending` means the name is gone but its parent is not durable; only post-fsync `Absent`
/// may roll back transaction-created ancestors. An ancestor-only job starts at `Absent` because it
/// has no candidate name. Retries never move backward or release guards early.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CandidateCleanupState {
    Present,
    ParentSyncPending,
    Absent,
}

const CANDIDATE_REAPER_QUEUE_CAPACITY: usize = 64;
const CANDIDATE_REAPER_RETRY_INTERVAL: Duration = Duration::from_millis(250);

/// 记录排队、运行和降级保留的全部清理责任；只有最后一个 ticket 释放时 shutdown 才可认为
/// 候选清理已排空。
/// Tracks queued, running, and degraded-retained cleanup responsibility; shutdown is drained only
/// when the final ticket is released.
#[derive(Default)]
struct CleanupTracker {
    pending: Mutex<usize>,
    drained: Condvar,
}

struct CleanupTicket(Arc<CleanupTracker>);

impl CleanupTicket {
    fn new(tracker: Arc<CleanupTracker>) -> Self {
        if let Ok(mut pending) = tracker.pending.lock() {
            *pending = pending.saturating_add(1);
        }
        Self(tracker)
    }
}

impl Drop for CleanupTicket {
    fn drop(&mut self) {
        if let Ok(mut pending) = self.0.pending.lock() {
            *pending = pending.saturating_sub(1);
            if *pending == 0 {
                self.0.drained.notify_all();
            }
        }
    }
}

/// 异步 [`TempFile`] Drop 的有界进程级清理执行器。工作线程失败或队列饱和会永久降级实例：
/// 现有候选留给能力根启动扫描，之后所有候选创建关闭失败。绝不在 Tokio 运行时线程回退
/// `unlinkat`，因为异常挂载点可能无限阻塞异步工作线程。
/// Bounded process-wide cleanup executor for async [`TempFile`] drops. A failed worker or saturated
/// queue permanently degrades the instance: existing candidates await startup sweep and future
/// creation fails closed. It never falls back to `unlinkat` on a Tokio runtime thread.
struct CandidateReaper {
    sender: SyncSender<CandidateCleanup>,
    healthy: Arc<AtomicBool>,
    /// 关闭失败墓碑。向量收到首条记录后立即停止候选创建，因此总大小仅受降级前已准入候选
    /// 加有界队列限制，而不受之后请求量影响。
    /// Fail-closed tombstones. Candidate creation stops on the first record, bounding total size by
    /// candidates admitted before degradation plus the bounded queue, never later request volume.
    retained: Arc<Mutex<Vec<CandidateCleanup>>>,
    tracker: Arc<CleanupTracker>,
}

static CANDIDATE_REAPER: OnceLock<CandidateReaper> = OnceLock::new();

fn candidate_reaper_unavailable() -> anyhow::Error {
    anyhow::Error::new(AdmissionError::cancelled(AdmissionResource::Uploads))
        .context("private-candidate cleanup service is unavailable")
}

fn candidate_recovery_unavailable() -> anyhow::Error {
    anyhow::Error::new(AdmissionError::cancelled(AdmissionResource::Uploads))
        .context("private-candidate creation is disabled because a recovery scan was incomplete")
}

#[derive(Clone, Copy, Debug)]
pub(super) struct StaleUploadCleanupLimits {
    pub(super) min_age: Duration,
    pub(super) max_entries: usize,
    pub(super) max_depth: usize,
    pub(super) max_deletions: usize,
    pub(super) timeout: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum StaleUploadCleanupStage {
    ReadDirectory,
    ReadDirectoryEntry,
    InspectEntry,
    OpenDirectory,
    ReadDirectoryMetadata,
    OpenCandidate,
    ReadCandidateMetadata,
    LockCandidate,
    RecheckCandidate,
    UnlinkCandidate,
    SyncParent(DurabilityStage),
}

impl std::fmt::Display for StaleUploadCleanupStage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadDirectory => formatter.write_str("read-directory"),
            Self::ReadDirectoryEntry => formatter.write_str("read-directory-entry"),
            Self::InspectEntry => formatter.write_str("inspect-entry"),
            Self::OpenDirectory => formatter.write_str("open-directory"),
            Self::ReadDirectoryMetadata => formatter.write_str("read-directory-metadata"),
            Self::OpenCandidate => formatter.write_str("open-candidate"),
            Self::ReadCandidateMetadata => formatter.write_str("read-candidate-metadata"),
            Self::LockCandidate => formatter.write_str("lock-candidate"),
            Self::RecheckCandidate => formatter.write_str("recheck-candidate"),
            Self::UnlinkCandidate => formatter.write_str("unlink-candidate"),
            Self::SyncParent(stage) => write!(formatter, "sync-parent({stage})"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StaleUploadCleanupFailure {
    pub(super) stage: StaleUploadCleanupStage,
    /// 已净化、有界且相对能力根的路径，绝非绝对路径。
    /// Sanitized, bounded, capability-root-relative path. Never absolute.
    pub(super) relative_path: String,
    /// 有界的替代格式原因链。
    /// Bounded alternate-form cause chain.
    pub(super) cause: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct StaleUploadCleanupReport {
    pub(super) scanned_entries: usize,
    pub(super) deleted: usize,
    pub(super) skipped_active: usize,
    pub(super) skipped_young: usize,
    pub(super) skipped_unsafe: usize,
    pub(super) failures: usize,
    pub(super) failure_diagnostics: Vec<StaleUploadCleanupFailure>,
    pub(super) suppressed_failures: usize,
    pub(super) entry_limit_reached: bool,
    pub(super) depth_limit_reached: bool,
    pub(super) deletion_limit_reached: bool,
    pub(super) deadline_reached: bool,
}

impl StaleUploadCleanupReport {
    /// 本次扫描是否证明范围内每个目录项均已检查，且没有歧义候选或 I/O/持久化故障。
    /// Whether this scan proved that every in-scope entry was inspected without an ambiguous
    /// candidate or I/O/durability failure.
    ///
    /// 较新候选和 advisory lock 正被持有的候选会有意延期，但不使遍历不完整，周期维护会
    /// 重访。具有不安全保留名称的条目存在歧义，因此新候选准入关闭失败。
    /// Young or advisory-locked candidates are intentionally deferred and revisited periodically,
    /// without making traversal incomplete. Unsafe reserved-name entries are ambiguous and fail closed.
    pub(super) fn is_complete(&self) -> bool {
        self.failures == 0
            && self.skipped_unsafe == 0
            && !self.entry_limit_reached
            && !self.depth_limit_reached
            && !self.deletion_limit_reached
            && !self.deadline_reached
    }
}

struct StaleUploadCleanupState {
    limits: StaleUploadCleanupLimits,
    deadline: Instant,
    now: SystemTime,
    service_uid: u32,
    resolve_flags: ResolveFlags,
    visited_directories: HashSet<(u64, u64)>,
    report: StaleUploadCleanupReport,
}

impl StaleUploadCleanupState {
    fn record_failure(
        &mut self,
        stage: StaleUploadCleanupStage,
        relative_path: &Path,
        error: impl Into<anyhow::Error>,
    ) {
        self.report.failures = self.report.failures.saturating_add(1);
        if self.report.failure_diagnostics.len() >= STALE_CLEANUP_DIAGNOSTIC_LIMIT {
            self.report.suppressed_failures = self.report.suppressed_failures.saturating_add(1);
            return;
        }
        let error = error.into();
        self.report
            .failure_diagnostics
            .push(StaleUploadCleanupFailure {
                stage,
                relative_path: bounded_relative_cleanup_path(relative_path),
                cause: bounded_cleanup_diagnostic(
                    &format!("{error:#}"),
                    STALE_CLEANUP_DIAGNOSTIC_CAUSE_MAX_BYTES,
                ),
            });
    }
}

fn bounded_relative_cleanup_path(path: &Path) -> String {
    if path.components().any(|component| {
        matches!(
            component,
            Component::Prefix(_) | Component::RootDir | Component::ParentDir
        )
    }) {
        return "<invalid-capability-relative-path>".to_string();
    }
    bounded_cleanup_diagnostic(
        &path.to_string_lossy(),
        STALE_CLEANUP_DIAGNOSTIC_PATH_MAX_BYTES,
    )
}

fn bounded_cleanup_diagnostic(value: &str, max_bytes: usize) -> String {
    let mut output = String::with_capacity(value.len().min(max_bytes));
    let mut truncated = false;
    for character in value.chars() {
        let character = if character.is_control() {
            ' '
        } else {
            character
        };
        if output.len() + character.len_utf8() > max_bytes {
            truncated = true;
            break;
        }
        output.push(character);
    }
    if truncated {
        const ELLIPSIS: &str = "…";
        while output.len() + ELLIPSIS.len() > max_bytes {
            output.pop();
        }
        output.push_str(ELLIPSIS);
    }
    output
}

struct PlannedRemoval {
    rel: PathBuf,
    expected: EntryExpectation,
    directory: bool,
    parent_dev: u64,
    parent_ino: u64,
}

fn durability_error(
    stage: DurabilityStage,
    published: bool,
    source: impl Into<anyhow::Error>,
) -> anyhow::Error {
    anyhow::Error::new(FsError::durability(stage, published, source))
}

fn typed_filesystem_error(
    operation: &'static str,
    source: impl Into<anyhow::Error>,
) -> anyhow::Error {
    let source = source.into();
    if FsError::in_anyhow_chain(&source).is_some()
        || AdmissionError::in_anyhow_chain(&source).is_some()
    {
        source
    } else {
        anyhow::Error::new(FsError::from_anyhow(operation, source))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectorySyncPoint {
    CreatedDirectory,
    CreatedDirectoryParent,
    DestinationParent,
    SourceParent,
    RemovedEntryParent,
}

impl DirectorySyncPoint {
    fn durability_stage(self) -> DurabilityStage {
        match self {
            Self::CreatedDirectory | Self::CreatedDirectoryParent => {
                DurabilityStage::CreatedDirectory
            }
            Self::DestinationParent => DurabilityStage::DestinationParent,
            Self::SourceParent => DurabilityStage::SourceParent,
            Self::RemovedEntryParent => DurabilityStage::RemovedEntryParent,
        }
    }
}

/// 编译期变更接缝。生产入口始终实例化 [`RealMutationOps`]；测试实现记录顺序，把成功步骤
/// 转发到相同的能力相对系统调用，并可在任何变更或同步前令一个确切步骤失败。
/// Compile-time mutation seam. Production always instantiates [`RealMutationOps`]; tests record
/// ordering, forward successful steps to the same capability-relative syscalls, and can fail one
/// exact step before it mutates or syncs anything.
trait MutationOps {
    fn write_candidate(&mut self, file: &mut File, data: &[u8]) -> std::io::Result<()>;
    fn flush_candidate(&mut self, file: &mut File) -> std::io::Result<()>;
    fn sync_candidate_data(&mut self, file: &File) -> std::io::Result<()>;
    fn mkdir(&mut self, parent: &File, name: &OsStr, mode: Mode) -> std::result::Result<(), Errno>;
    fn unlink(
        &mut self,
        parent: &File,
        name: &OsStr,
        flags: AtFlags,
    ) -> std::result::Result<(), Errno>;
    fn rename(
        &mut self,
        source_parent: &File,
        source_name: &OsStr,
        destination_parent: &File,
        destination_name: &OsStr,
        no_replace: bool,
    ) -> std::result::Result<(), Errno>;
    fn chmod_published(&mut self, file: &File, mode: Mode) -> std::result::Result<(), Errno>;
    fn sync_published_file(&mut self, file: &File) -> std::io::Result<()>;
    fn sync_directory(
        &mut self,
        directory: &File,
        point: DirectorySyncPoint,
    ) -> std::result::Result<(), Errno>;
}

struct RealMutationOps;

impl MutationOps for RealMutationOps {
    fn write_candidate(&mut self, file: &mut File, data: &[u8]) -> std::io::Result<()> {
        file.write_all(data)
    }

    fn flush_candidate(&mut self, file: &mut File) -> std::io::Result<()> {
        std::io::Write::flush(file)
    }

    fn sync_candidate_data(&mut self, file: &File) -> std::io::Result<()> {
        file.sync_data()
    }

    fn mkdir(&mut self, parent: &File, name: &OsStr, mode: Mode) -> std::result::Result<(), Errno> {
        fs::mkdirat(parent, name, mode)
    }

    fn unlink(
        &mut self,
        parent: &File,
        name: &OsStr,
        flags: AtFlags,
    ) -> std::result::Result<(), Errno> {
        fs::unlinkat(parent, name, flags)
    }

    fn rename(
        &mut self,
        source_parent: &File,
        source_name: &OsStr,
        destination_parent: &File,
        destination_name: &OsStr,
        no_replace: bool,
    ) -> std::result::Result<(), Errno> {
        if no_replace {
            fs::renameat_with(
                source_parent,
                source_name,
                destination_parent,
                destination_name,
                RenameFlags::NOREPLACE,
            )
        } else {
            fs::renameat(
                source_parent,
                source_name,
                destination_parent,
                destination_name,
            )
        }
    }

    fn chmod_published(&mut self, file: &File, mode: Mode) -> std::result::Result<(), Errno> {
        fs::fchmod(file, mode)
    }

    fn sync_published_file(&mut self, file: &File) -> std::io::Result<()> {
        file.sync_all()
    }

    fn sync_directory(
        &mut self,
        directory: &File,
        _point: DirectorySyncPoint,
    ) -> std::result::Result<(), Errno> {
        fs::fsync(directory)
    }
}

fn capability_open_error(rel: &Path, error: Errno) -> anyhow::Error {
    let source =
        anyhow::Error::new(error).context(format!("openat2 failed for capability path {rel:?}"));
    if matches!(error, Errno::XDEV | Errno::LOOP) {
        anyhow::Error::new(FsError::outside_root(
            "resolving a filesystem capability path",
            source,
        ))
    } else {
        typed_filesystem_error("opening a filesystem capability path", source)
    }
}

fn walk_cancelled(context: &'static str) -> anyhow::Error {
    anyhow::Error::new(AdmissionError::cancelled(AdmissionResource::WalkEntries)).context(context)
}

fn walk_limit_exceeded(
    resource: AdmissionResource,
    limit: usize,
    observed: Option<usize>,
) -> anyhow::Error {
    anyhow::Error::new(AdmissionError::limit_exceeded(
        resource,
        LimitKind::Semantic,
        limit as u64,
        observed.map(|value| value as u64),
    ))
}

fn unavailable_capability_entry(error: &anyhow::Error) -> bool {
    matches!(
        FsError::in_anyhow_chain(error),
        Some(FsError::NotFound { .. } | FsError::OutsideRoot { .. })
    )
}

fn post_publish_directory_lookup_error(
    rel: &Path,
    expected: impl Into<Box<str>>,
    operation: &'static str,
    error: Errno,
) -> anyhow::Error {
    // mkdirat 成功后，缺失、非目录、符号链接或跨挂载名称表明已发布命名空间条目被并发删除
    // 或替换。其他查找失败是歧义基础设施错误；发布后不得降级为公开 403/404。
    // Once mkdirat succeeds, missing/non-directory/symlink/cross-mount proves concurrent removal or
    // replacement. Other lookup failures are ambiguous infrastructure errors, never public 403/404.
    if matches!(
        error,
        Errno::NOENT | Errno::NOTDIR | Errno::LOOP | Errno::XDEV
    ) {
        anyhow::Error::new(FsError::changed(
            MutationEndpointRole::Target,
            rel.display().to_string(),
            expected,
            format!("{operation} failed after publication: {error}"),
        ))
    } else {
        durability_error(
            DurabilityStage::CreatedDirectory,
            true,
            anyhow::Error::from(error).context(operation),
        )
    }
}

fn post_publish_directory_io_error(
    operation: &'static str,
    error: impl Into<anyhow::Error>,
) -> anyhow::Error {
    durability_error(
        DurabilityStage::CreatedDirectory,
        true,
        error.into().context(operation),
    )
}

fn sync_renamed_parents_with<F>(
    destination: &File,
    source: &File,
    same_parent: bool,
    mut sync: F,
) -> Result<()>
where
    F: FnMut(&File, DurabilityStage) -> std::result::Result<(), Errno>,
{
    let destination_sync = sync(destination, DurabilityStage::DestinationParent);
    let source_sync = if same_parent {
        Ok(())
    } else {
        sync(source, DurabilityStage::SourceParent)
    };
    match (destination_sync, source_sync) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(destination), Ok(())) => Err(durability_error(
            DurabilityStage::DestinationParent,
            true,
            destination,
        )),
        (Ok(()), Err(source)) => Err(durability_error(
            DurabilityStage::SourceParent,
            true,
            source,
        )),
        (Err(destination), Err(source)) => Err(durability_error(
            DurabilityStage::DestinationParent,
            true,
            anyhow!(
                "destination parent sync failed: {destination}; source parent sync also failed: {source}"
            ),
        )),
    }
}

impl CreatedTempCandidate {
    fn new(
        parent: File,
        temp_name: OsString,
        file: File,
        candidate_lock: File,
        expectation: EntryExpectation,
        created_ancestors: Vec<CreatedAncestor>,
    ) -> Self {
        Self {
            cleanup_parent: Some(parent),
            temp_name,
            file: Some(file),
            candidate_lock: Some(candidate_lock),
            expectation,
            created_ancestors,
        }
    }

    fn into_parts(
        mut self,
    ) -> Result<(OsString, File, File, EntryExpectation, Vec<CreatedAncestor>)> {
        let file = self
            .file
            .take()
            .ok_or_else(|| anyhow!("new temporary candidate file is missing"))?;
        let candidate_lock = self
            .candidate_lock
            .take()
            .ok_or_else(|| anyhow!("new temporary candidate lock is missing"))?;
        self.cleanup_parent.take();
        Ok((
            self.temp_name.clone(),
            file,
            candidate_lock,
            self.expectation,
            std::mem::take(&mut self.created_ancestors),
        ))
    }

    fn into_cleanup(mut self) -> CandidateCleanup {
        // 清理不需要可写描述符。保留拥有 advisory flock 的克隆描述符，直到确切目录项完成
        // 验证、unlink 且父目录同步。
        // Cleanup does not need the writable descriptor. Keep the cloned flock owner until the exact
        // entry is verified, unlinked, and its parent synced.
        self.file.take();
        CandidateCleanup::candidate(
            self.cleanup_parent.take(),
            self.temp_name.clone(),
            self.expectation,
            std::mem::take(&mut self.created_ancestors),
            self.candidate_lock.take(),
            None,
        )
    }
}

impl Drop for CreatedTempCandidate {
    fn drop(&mut self) {
        if let Some(parent) = self.cleanup_parent.take() {
            schedule_candidate_cleanup(CandidateCleanup::candidate(
                Some(parent),
                self.temp_name.clone(),
                self.expectation,
                std::mem::take(&mut self.created_ancestors),
                self.candidate_lock.take(),
                None,
            ));
        }
    }
}

impl CandidateCleanup {
    fn candidate(
        parent: Option<File>,
        name: OsString,
        expectation: EntryExpectation,
        created_ancestors: Vec<CreatedAncestor>,
        candidate_lock: Option<File>,
        guard: Option<Box<dyn Send + 'static>>,
    ) -> Self {
        Self {
            parent,
            name,
            state: CandidateCleanupState::Present,
            expectation: Some(expectation),
            created_ancestors,
            _candidate_lock: candidate_lock,
            _guard: guard,
            ticket: None,
        }
    }

    fn unverified_candidate(
        parent: Option<File>,
        name: OsString,
        created_ancestors: Vec<CreatedAncestor>,
        candidate_lock: Option<File>,
    ) -> Self {
        Self {
            parent,
            name,
            state: CandidateCleanupState::Present,
            expectation: None,
            created_ancestors,
            _candidate_lock: candidate_lock,
            _guard: None,
            ticket: None,
        }
    }

    fn ancestors(created_ancestors: Vec<CreatedAncestor>) -> Self {
        Self {
            parent: None,
            name: OsString::new(),
            state: CandidateCleanupState::Absent,
            expectation: None,
            created_ancestors,
            _candidate_lock: None,
            _guard: None,
            ticket: None,
        }
    }

    /// `None` 表示已确认 unlink（包括名称已不存在）。失败时返回完整所有权记录，使候选未
    /// 解决期间不会释放其锁/准入守卫。
    /// `None` means unlink was confirmed, including an already-absent name. On failure, return the
    /// complete ownership record so lock/admission guards remain held while unresolved.
    fn run(self) -> Option<Self> {
        self.run_with_ops(
            |parent, name| fs::unlinkat(parent, name, AtFlags::empty()),
            |parent| fs::fsync(parent),
        )
    }

    fn run_with<F>(self, unlink: F) -> Option<Self>
    where
        F: FnOnce(&File, &OsStr) -> std::result::Result<(), Errno>,
    {
        self.run_with_ops(unlink, |parent| fs::fsync(parent))
    }

    /// 执行一个可重试状态转移。成功返回 `None` 表示候选删除、父目录持久化和祖先回滚均完成；
    /// 任一步失败都返回携带完整 fd、inode 期望、锁、准入守卫和 ticket 的 `Self`，供清理器重试。
    /// Execute one retryable transition. `None` means unlink, parent durability, and ancestor rollback
    /// all completed; failure returns `Self` with every fd, identity expectation, lock, admission
    /// guard, and ticket intact for the reaper.
    fn run_with_ops<F, S>(mut self, unlink: F, sync_parent: S) -> Option<Self>
    where
        F: FnOnce(&File, &OsStr) -> std::result::Result<(), Errno>,
        S: FnOnce(&File) -> std::result::Result<(), Errno>,
    {
        if self.state == CandidateCleanupState::Present {
            let Some(parent) = self.parent.as_ref() else {
                return Some(self);
            };
            let Some(expected) = self.expectation else {
                warn!(
                    "Private upload candidate {:?} has no verified inode identity; refusing name-based unlink",
                    self.name
                );
                return Some(self);
            };
            match fs::statat(parent, &self.name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) if expected.same_object(EntryExpectation::from_stat(&stat)) => {}
                Ok(stat) => {
                    warn!(
                        "Private upload candidate {:?} changed identity (expected {:?}, found {:?}); refusing to unlink a replacement",
                        self.name,
                        expected,
                        EntryExpectation::from_stat(&stat),
                    );
                    return Some(self);
                }
                // 缺失只是命名空间观察，尚非持久化证明。释放锁、守卫或自动创建祖先责任前，
                // 先同步固定父目录。
                // Absence is a namespace observation, not durability proof. Sync the pinned parent
                // before releasing locks, guards, or auto-created-ancestor responsibility.
                Err(Errno::NOENT) => self.state = CandidateCleanupState::ParentSyncPending,
                Err(error) => {
                    warn!(
                        "Failed to verify private upload candidate {:?}: {error}; retaining cleanup responsibility",
                        self.name
                    );
                    return Some(self);
                }
            }
            if self.state == CandidateCleanupState::Present {
                match unlink(parent, &self.name) {
                    Ok(()) => self.state = CandidateCleanupState::ParentSyncPending,
                    Err(Errno::NOENT) => self.state = CandidateCleanupState::ParentSyncPending,
                    Err(err) => {
                        warn!(
                            "Failed to remove private upload candidate {:?}: {err}; refusing new write candidates until cleanup succeeds",
                            self.name
                        );
                        return Some(self);
                    }
                }
            }
        }
        if self.state == CandidateCleanupState::ParentSyncPending {
            let Some(parent) = self.parent.as_ref() else {
                return Some(self);
            };
            if let Err(error) = sync_parent(parent) {
                warn!(
                    "Failed to sync candidate parent after removing {:?}: {error}; retaining cleanup responsibility",
                    self.name
                );
                return Some(self);
            }
            self.state = CandidateCleanupState::Absent;
        }
        if rollback_created_ancestors(&mut self.created_ancestors) {
            None
        } else {
            Some(self)
        }
    }
}

fn retain_degraded_cleanup(
    healthy: &AtomicBool,
    retained: &Mutex<Vec<CandidateCleanup>>,
    cleanup: CandidateCleanup,
) {
    // 保留所有权记录前先发布关闭失败状态。竞态创建者会在 O_EXCL 后复查该标志，并在其阻塞
    // 工作线程内同步移除自己的新候选。
    // Publish fail-closed state before retaining ownership. A racing creator rechecks after O_EXCL
    // and synchronously removes its own new candidate inside its blocking worker.
    healthy.store(false, Ordering::Release);
    match retained.lock() {
        Ok(mut retained) => retained.push(cleanup),
        Err(_) => {
            // 中毒的墓碑存储仍绝不能释放守卫。候选创建已禁用，因此该泄漏受首次降级前获准
            // 的有限集合约束。
            // A poisoned tombstone store must still never release the guard. Creation is disabled,
            // so the leak is bounded by the finite set admitted before degradation.
            std::mem::forget(cleanup);
        }
    }
}

fn track_cleanup(reaper: &CandidateReaper, cleanup: &mut CandidateCleanup) {
    if cleanup.ticket.is_none() {
        cleanup.ticket = Some(CleanupTicket::new(reaper.tracker.clone()));
    }
}

fn retain_with_reaper(reaper: &CandidateReaper, mut cleanup: CandidateCleanup) {
    track_cleanup(reaper, &mut cleanup);
    retain_degraded_cleanup(&reaper.healthy, &reaper.retained, cleanup);
}

fn retry_retained_cleanups(retained: &Mutex<Vec<CandidateCleanup>>) {
    let pending = match retained.lock() {
        Ok(mut retained) => std::mem::take(&mut *retained),
        Err(_) => return,
    };
    if pending.is_empty() {
        return;
    }
    let mut still_pending = Vec::new();
    for cleanup in pending {
        if let Some(cleanup) = cleanup.run() {
            still_pending.push(cleanup);
        }
    }
    if !still_pending.is_empty() {
        match retained.lock() {
            Ok(mut retained) => retained.extend(still_pending),
            Err(_) => {
                for cleanup in still_pending {
                    std::mem::forget(cleanup);
                }
            }
        }
    }
}

fn cleanup_created_candidate_after_failure(reaper: &CandidateReaper, cleanup: CandidateCleanup) {
    cleanup_created_candidate_after_failure_with(reaper, cleanup, |parent, name| {
        fs::unlinkat(parent, name, AtFlags::empty())
    });
}

fn cleanup_created_candidate_after_failure_with<F>(
    reaper: &CandidateReaper,
    cleanup: CandidateCleanup,
    unlink: F,
) where
    F: FnOnce(&File, &OsStr) -> std::result::Result<(), Errno>,
{
    // 此辅助函数只在候选创建阻塞工作线程中运行。它可同步尝试 unlink，但除非明确确认移除，
    // 否则绝不丢弃所有权。
    // This helper runs only in the candidate-creation blocking worker. It may unlink synchronously,
    // but never drops ownership unless removal is positively confirmed.
    if let Some(cleanup) = cleanup.run_with(unlink) {
        retain_with_reaper(reaper, cleanup);
    }
}

fn candidate_reaper() -> &'static CandidateReaper {
    CANDIDATE_REAPER.get_or_init(|| {
        let (sender, receiver) = sync_channel::<CandidateCleanup>(CANDIDATE_REAPER_QUEUE_CAPACITY);
        let healthy = Arc::new(AtomicBool::new(true));
        let retained = Arc::new(Mutex::new(Vec::new()));
        let tracker = Arc::new(CleanupTracker::default());
        let worker_health = healthy.clone();
        let worker_retained = retained.clone();
        if let Err(err) = thread::Builder::new()
            .name("ram-candidate-reaper".to_string())
            .spawn(move || {
                struct MarkReaperStopped(Arc<AtomicBool>);
                impl Drop for MarkReaperStopped {
                    fn drop(&mut self) {
                        self.0.store(false, Ordering::Release);
                    }
                }
                let _mark_stopped = MarkReaperStopped(worker_health.clone());
                loop {
                    match receiver.recv_timeout(CANDIDATE_REAPER_RETRY_INTERVAL) {
                        Ok(cleanup) => {
                            if let Some(cleanup) = cleanup.run() {
                                retain_degraded_cleanup(
                                    &worker_health,
                                    &worker_retained,
                                    cleanup,
                                );
                            }
                        }
                        Err(RecvTimeoutError::Timeout) => {}
                        Err(RecvTimeoutError::Disconnected) => break,
                    }

                    // 瞬时 unlink/stat/fsync 失败保留确切 inode/祖先责任，并按有界节奏重试。
                    // 首次降级后准入继续关闭失败，即使之后清理成功。
                    // A transient unlink/stat/fsync failure retains exact inode/ancestor responsibility
                    // and retries with bounded cadence. Admission stays fail-closed after degradation.
                    retry_retained_cleanups(&worker_retained);
                }
            })
        {
            healthy.store(false, Ordering::Release);
            warn!(
                "Failed to start private-candidate reaper: {err}; write candidate creation is disabled"
            );
        }
        CandidateReaper {
            sender,
            healthy,
            retained,
            tracker,
        }
    })
}

pub(super) fn drain_candidate_cleanup(timeout: Duration) -> bool {
    let Some(reaper) = CANDIDATE_REAPER.get() else {
        return true;
    };
    let deadline = Instant::now() + timeout;
    let Ok(mut pending) = reaper.tracker.pending.lock() else {
        return false;
    };
    while *pending > 0 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        let Ok((next, wait)) = reaper.tracker.drained.wait_timeout(pending, remaining) else {
            return false;
        };
        pending = next;
        if wait.timed_out() && *pending > 0 {
            return false;
        }
    }
    true
}

fn schedule_candidate_cleanup(cleanup: CandidateCleanup) {
    enqueue_candidate_cleanup(candidate_reaper(), cleanup);
}

fn enqueue_candidate_cleanup(reaper: &CandidateReaper, mut cleanup: CandidateCleanup) {
    track_cleanup(reaper, &mut cleanup);
    if !reaper.healthy.load(Ordering::Acquire) {
        retain_with_reaper(reaper, cleanup);
        return;
    }
    match reaper.sender.try_send(cleanup) {
        Ok(()) => {}
        Err(TrySendError::Full(cleanup)) => {
            retain_with_reaper(reaper, cleanup);
            warn!(
                "Private-candidate cleanup queue is full; refusing new write candidates until restart"
            );
        }
        Err(TrySendError::Disconnected(cleanup)) => {
            retain_with_reaper(reaper, cleanup);
            warn!(
                "Private-candidate cleanup worker stopped; refusing new write candidates until restart"
            );
        }
    }
}

impl TempFile {
    pub(super) fn target_rel(&self) -> PathBuf {
        self.parent.target_rel()
    }

    pub(super) fn into_blocking(mut self) -> Result<BlockingTempFile> {
        if self.file.is_none() {
            bail!("temporary file is already closed");
        }
        if self.candidate_lock.is_none() {
            bail!("temporary file candidate lock is missing");
        }
        let temp_name = self.temp_name.clone();
        let file = self
            .file
            .take()
            .expect("temporary file presence was checked");
        // 此描述符克隆后其余所有权移动均不失败。若克隆失败，`self` 仍拥有候选锁/守卫和原始
        // 祖先回滚责任。
        // All remaining ownership moves are infallible after this descriptor clone. If it fails,
        // `self` retains the candidate lock/guard and original ancestor rollback responsibility.
        let parent = self.parent.transfer_clone()?;
        let candidate_lock = self
            .candidate_lock
            .take()
            .expect("candidate lock presence was checked");
        let cleanup_guard = self.cleanup_guard.take();
        self.committed = true;
        Ok(BlockingTempFile {
            root: self.root.clone(),
            parent,
            temp_name,
            file: Some(file),
            candidate_lock: Some(candidate_lock),
            candidate_expectation: self.candidate_expectation,
            cleanup_guard,
            committed: false,
        })
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if !self.committed {
            match self.parent.fd.try_clone() {
                Ok(parent) => {
                    schedule_candidate_cleanup(CandidateCleanup::candidate(
                        Some(parent),
                        self.temp_name.clone(),
                        self.candidate_expectation,
                        std::mem::take(&mut self.parent.created_ancestors),
                        self.candidate_lock.take(),
                        self.cleanup_guard.take(),
                    ));
                }
                Err(err) => {
                    let reaper = candidate_reaper();
                    retain_with_reaper(
                        reaper,
                        CandidateCleanup::candidate(
                            None,
                            self.temp_name.clone(),
                            self.candidate_expectation,
                            std::mem::take(&mut self.parent.created_ancestors),
                            self.candidate_lock.take(),
                            self.cleanup_guard.take(),
                        ),
                    );
                    warn!(
                        "Failed to clone candidate parent for asynchronous cleanup: {err}; refusing new write candidates until restart"
                    );
                }
            }
        }
    }
}

impl BlockingTempFile {
    pub(super) fn attach_cleanup_guard<G>(&mut self, guard: G) -> Result<()>
    where
        G: Send + 'static,
    {
        if self.cleanup_guard.is_some() {
            bail!("temporary file cleanup guard is already attached");
        }
        self.cleanup_guard = Some(Box::new(guard));
        Ok(())
    }

    /// 把同步创建的候选交给异步上传接收器。返回的 TempFile 不会在 Drop 中同步 unlink；若
    /// 请求在发布前消失，其清理和所附准入守卫移交有界清理器。
    /// Hand a synchronously-created candidate to the async upload receiver. Returned TempFile never
    /// synchronously unlinks in Drop; pre-publication cancellation moves cleanup/admission to reaper.
    pub(super) fn into_async_temp(mut self) -> Result<TempFile> {
        if !self.parent.created_ancestors.is_empty() {
            bail!("a candidate with auto-created ancestors cannot move to asynchronous cleanup");
        }
        if self.file.is_none() {
            bail!("blocking temporary file is already closed");
        }
        if self.candidate_lock.is_none() {
            bail!("temporary file candidate lock is missing");
        }
        let parent = self.parent.transfer_clone()?;
        let file = self
            .file
            .take()
            .expect("blocking temporary file presence was checked");
        let candidate_lock = self
            .candidate_lock
            .take()
            .expect("candidate lock presence was checked");
        let cleanup_guard = self.cleanup_guard.take();
        self.committed = true;
        Ok(TempFile {
            root: self.root.clone(),
            parent,
            temp_name: self.temp_name.clone(),
            file: Some(file),
            candidate_lock: Some(candidate_lock),
            candidate_expectation: self.candidate_expectation,
            cleanup_guard,
            committed: false,
        })
    }

    pub(super) fn file_mut(&mut self) -> &mut File {
        self.file.as_mut().expect("blocking temporary file is open")
    }

    /// 通过确定性故障注入测试使用的同一编译期操作接缝追加上传块。生产始终提供
    /// `RealMutationOps`，不存在运行时故障点。
    /// Append an upload chunk through the same compile-time seam used by deterministic fault tests.
    /// Production always supplies `RealMutationOps`; no runtime failpoint exists.
    pub(super) fn write_all(&mut self, data: &[u8]) -> Result<()> {
        self.write_all_with_ops(data, &mut RealMutationOps)
    }

    fn write_all_with_ops<O: MutationOps>(&mut self, data: &[u8], ops: &mut O) -> Result<()> {
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| anyhow!("blocking temporary file is already closed"))?;
        ops.write_candidate(file, data)
            .map_err(|err| durability_error(DurabilityStage::CandidateFile, false, err))
    }

    pub(super) fn flush(&mut self) -> Result<()> {
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| anyhow!("blocking temporary file is already closed"))?;
        RealMutationOps
            .flush_candidate(file)
            .map_err(|err| durability_error(DurabilityStage::CandidateFile, false, err))
    }

    pub(super) fn target_rel(&self) -> PathBuf {
        self.parent.target_rel()
    }

    pub(super) fn available_space(&self) -> Result<(u64, u64, u64)> {
        let stat = fs::fstatvfs(&self.parent.fd)?;
        Ok((
            stat.f_bavail.saturating_mul(stat.f_frsize),
            stat.f_files,
            stat.f_favail,
        ))
    }

    /// 原子发布同步候选：先 flush/fsync 私有 inode 并重验父目录、候选及目标身份，再 rename。
    /// rename 是提交点，随后立即把 `committed` 置位，因此发布后的 chmod、文件 fsync 或目录
    /// fsync 失败会以 `published=true` 报告，Drop 不得删除已经可见的目标；发布前失败则仍由
    /// 候选状态机清理并回滚自动创建的祖先。
    /// Atomically publish the synchronous candidate: flush/fsync its private inode, revalidate parent,
    /// candidate, and target identities, then rename. Rename is the commit point and immediately sets
    /// `committed`; later chmod/file-fsync/directory-fsync errors report `published=true`, and Drop must
    /// not unlink the visible target. Pre-publication failures remain owned by candidate cleanup.
    pub(super) fn commit(
        self,
        expected_target: EntryExpectation,
        final_mode: u32,
        cancellation: &super::walk::RequestCancellation,
    ) -> Result<()> {
        let mut ops = RealMutationOps;
        self.commit_with_ops(expected_target, final_mode, cancellation, &mut ops)
    }

    fn commit_with_ops<O: MutationOps>(
        mut self,
        expected_target: EntryExpectation,
        final_mode: u32,
        cancellation: &super::walk::RequestCancellation,
        ops: &mut O,
    ) -> Result<()> {
        if cancellation.is_cancelled() {
            return Err(anyhow::Error::new(AdmissionError::cancelled(
                AdmissionResource::ExpensiveTasks,
            ))
            .context("request was cancelled before temporary file commit"));
        }
        let mut file = self
            .file
            .take()
            .ok_or_else(|| anyhow!("blocking temporary file is already closed"))?;
        ops.flush_candidate(&mut file)
            .map_err(|err| durability_error(DurabilityStage::CandidateFile, false, err))?;
        ops.sync_candidate_data(&file)
            .map_err(|err| durability_error(DurabilityStage::CandidateFile, false, err))?;
        if cancellation.is_cancelled() {
            return Err(anyhow::Error::new(AdmissionError::cancelled(
                AdmissionResource::ExpensiveTasks,
            ))
            .context("request was cancelled before temporary file publication"));
        }
        if self.candidate_lock.is_none() {
            bail!("temporary file candidate lock is missing");
        }
        self.root.verify_parent(&self.parent)?;
        self.parent
            .verify_candidate_identity(&self.temp_name, self.candidate_expectation)?;
        self.parent.verify_entry(expected_target)?;
        if matches!(expected_target, EntryExpectation::Present(_)) {
            ops.rename(
                &self.parent.fd,
                &self.temp_name,
                &self.parent.fd,
                &self.parent.target_name,
                false,
            )
            .context("failed to atomically commit temporary file")?;
        } else {
            ops.rename(
                &self.parent.fd,
                &self.temp_name,
                &self.parent.fd,
                &self.parent.target_name,
                true,
            )
            .map_err(|error| {
                self.parent
                    .create_only_error(expected_target, MutationEndpointRole::Target, error)
            })
            .context("failed to atomically commit temporary file without overwrite")?;
        }
        self.parent.created_ancestors.clear();
        self.committed = true;
        // 私有候选严格保持 0600，使崩溃清理能安全识别。只在发布后应用最终策略；狭窄窗口中
        // 崩溃只会让可见 inode 权限更严格而非更宽松，随后通过持有 fd 持久化模式元数据。
        // Keep candidates exactly 0600 for safe crash recognition. Apply final policy only after
        // publication; a crash leaves a stricter visible inode, never a looser one, then fsync mode.
        ops.chmod_published(&file, Mode::from_raw_mode(final_mode & 0o777))
            .map_err(|err| durability_error(DurabilityStage::PublishedFile, true, err))?;
        ops.sync_published_file(&file)
            .map_err(|err| durability_error(DurabilityStage::PublishedFile, true, err))?;
        drop(file);
        ops.sync_directory(&self.parent.fd, DirectorySyncPoint::DestinationParent)
            .map_err(|err| {
                durability_error(
                    DirectorySyncPoint::DestinationParent.durability_stage(),
                    true,
                    err,
                )
            })?;
        Ok(())
    }
}

impl Drop for BlockingTempFile {
    fn drop(&mut self) {
        if !self.committed {
            let cleanup = CandidateCleanup::candidate(
                self.parent.fd.try_clone().ok(),
                self.temp_name.clone(),
                self.candidate_expectation,
                std::mem::take(&mut self.parent.created_ancestors),
                self.candidate_lock.take(),
                self.cleanup_guard.take(),
            );
            if let Some(cleanup) = cleanup.run() {
                retain_with_reaper(candidate_reaper(), cleanup);
                warn!(
                    "Worker-owned upload candidate {:?} still needs cleanup; refusing new write candidates until restart",
                    self.temp_name
                );
            }
        }
    }
}

impl RootFs {
    /// 以默认策略捕获并打开配置服务根，该策略拒绝跨越能力下方挂载点。配置启动改用
    /// [`Self::from_verified_identity`]，以保留隔离校验时捕获的身份。
    /// Capture and open the service root with the default policy, refusing mount crossings below the
    /// capability. Startup uses [`Self::from_verified_identity`] to retain the isolation-validated identity.
    #[cfg(test)]
    pub(super) fn new(path: &Path, path_is_file: bool, allow_symlink: bool) -> Result<Self> {
        let expected = ServedPathIdentity::capture(path, path_is_file)?;
        Self::from_verified_identity(&expected, allow_symlink, false)
    }

    /// 直接从配置期身份保留的描述符建立 RootFs；之后同名命名空间替换无法重定向该能力。
    /// Establish RootFs from descriptors retained by the configuration-time identity. A later
    /// same-spelled namespace replacement cannot redirect this capability.
    pub(super) fn from_verified_identity(
        expected: &ServedPathIdentity,
        allow_symlink: bool,
        allow_cross_filesystems: bool,
    ) -> Result<Self> {
        Self::from_verified_identity_with_candidate_cleanup_and_admission(
            expected,
            allow_symlink,
            allow_cross_filesystems,
            usize::MAX,
            FilesystemBlockingAdmission::new(32, Duration::from_secs(5)),
        )
    }

    #[cfg(test)]
    pub(super) fn from_verified_identity_with_candidate_cleanup(
        expected: &ServedPathIdentity,
        allow_symlink: bool,
        allow_cross_filesystems: bool,
        candidate_cleanup_max_depth: usize,
    ) -> Result<Self> {
        Self::from_verified_identity_with_candidate_cleanup_and_admission(
            expected,
            allow_symlink,
            allow_cross_filesystems,
            candidate_cleanup_max_depth,
            FilesystemBlockingAdmission::new(32, Duration::from_secs(5)),
        )
    }

    /// 生产服务根与自定义资源根通过此入口共享同一阻塞准入，而测试/静态启动校验仍可使用
    /// 上方自含默认值的便捷构造器。
    /// Production served/assets roots share one blocking admission through this constructor, while
    /// tests and synchronous startup validation may use the self-contained convenience constructors.
    pub(super) fn from_verified_identity_with_candidate_cleanup_and_admission(
        expected: &ServedPathIdentity,
        allow_symlink: bool,
        allow_cross_filesystems: bool,
        candidate_cleanup_max_depth: usize,
        blocking_admission: FilesystemBlockingAdmission,
    ) -> Result<Self> {
        let opened = expected.open_root_verified()?;
        let single_file = opened.single_file.map(|single| SingleFileCapability {
            name: single.name,
            file: single.file,
        });
        let this = Self {
            inner: Arc::new(RootFsInner {
                root: opened.root,
                blocking_admission,
                allow_symlink,
                allow_cross_filesystems,
                candidate_cleanup_max_depth,
                candidate_recovery_healthy: AtomicBool::new(true),
                single_file,
            }),
        };
        // 对无法实施所需 openat2 解析策略的内核/seccomp 配置在启动时失败；刻意不提供不安全
        // 的 canonicalize/open 回退。
        // Fail at startup on kernels/seccomp profiles unable to enforce required openat2 policy.
        // There is deliberately no insecure canonicalize/open fallback.
        let probe = this.open_raw(Path::new(""), NodeKind::Directory)?;
        drop(probe);
        Ok(this)
    }

    #[cfg(test)]
    pub(super) fn blocking_admission(&self) -> FilesystemBlockingAdmission {
        self.inner.blocking_admission.clone()
    }

    /// 在共享准入下运行一次不返回文件句柄的短同步文件系统操作。
    /// Run one short synchronous filesystem operation under shared admission.
    pub(super) async fn run_short_blocking<T, F>(&self, work: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T> + Send + 'static,
    {
        self.inner.blocking_admission.run(work).await
    }

    pub(super) fn single_file_rel(&self) -> Option<PathBuf> {
        self.inner
            .single_file
            .as_ref()
            .map(|single| PathBuf::from(&single.name))
    }

    pub(super) fn read_to_string_limited(
        &self,
        rel: impl Into<PathBuf>,
        max_bytes: usize,
    ) -> Result<String> {
        let rel = rel.into();
        self.check_public_rel(&rel)?;
        let mut file = self.open_with_symlink_policy(&rel, NodeKind::File)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            bail!("resource is not a regular file");
        }
        if metadata.len() > max_bytes as u64 {
            bail!("resource exceeds the {max_bytes}-byte limit");
        }
        self.real_relative_verified(&file)?;
        let mut output = String::new();
        Read::by_ref(&mut file)
            .take(max_bytes.saturating_add(1) as u64)
            .read_to_string(&mut output)?;
        if output.len() > max_bytes {
            bail!("resource exceeds the {max_bytes}-byte limit");
        }
        Ok(output)
    }

    /// 启动时验证完整自定义资源能力。运行时在同一已打开描述符上重复普通文件检查，避免之后
    /// 路径替换绕过信任判定。
    /// Validate the complete custom-assets capability at startup. Runtime serving repeats the
    /// regular-file check on the same descriptor so later path replacement cannot bypass trust.
    pub(super) fn validate_trusted_asset_tree(
        &self,
        max_entries: usize,
        max_depth: usize,
    ) -> Result<()> {
        validate_trusted_asset_metadata(&self.inner.root.metadata()?, true, Path::new("."))?;
        let running = AtomicBool::new(true);
        let cancelled = AtomicBool::new(false);
        self.walk_fail_closed(
            vec![PathBuf::new()],
            &running,
            &cancelled,
            max_entries,
            max_depth,
            |entry| {
                validate_trusted_asset_metadata(
                    &entry.metadata,
                    entry.metadata.is_dir(),
                    &entry.display_rel,
                )?;
                Ok(WalkAction::Continue)
            },
        )
    }

    pub(super) async fn open(&self, rel: impl Into<PathBuf>, kind: NodeKind) -> Result<OpenedNode> {
        let rel = rel.into();
        let root = self.clone();
        // 中文：只为本次 open 获取许可；返回的文件会在每次 metadata/read/seek 前重新准入，
        // 避免慢客户端在网络等待期间占住 worker 容量。
        // English: Admit only this open. The returned file re-enters admission before each
        // metadata/read/seek, so a slow client cannot retain worker capacity while awaiting network I/O.
        let admission = self.inner.blocking_admission.clone();
        let lease = admission.acquire().await?;
        let (file, metadata, real_rel) = self
            .inner
            .blocking_admission
            .spawn_with_lease(lease, move || {
                root.check_public_rel(&rel)?;
                let file = root.open_with_symlink_policy(&rel, kind)?;
                let metadata = file.metadata().map_err(|error| {
                    typed_filesystem_error("reading opened filesystem metadata", error)
                })?;
                match kind {
                    NodeKind::File if !metadata.is_file() => {
                        return Err(anyhow::Error::new(FsError::conflict(
                            "opening a regular file",
                            anyhow!("resource is not a regular file"),
                        )));
                    }
                    NodeKind::Directory if !metadata.is_dir() => {
                        return Err(anyhow::Error::new(FsError::conflict(
                            "opening a directory",
                            anyhow!("resource is not a directory"),
                        )));
                    }
                    _ => {}
                }
                let real_rel = root.real_relative_verified(&file)?;
                Ok::<_, anyhow::Error>((file, metadata, real_rel))
            })
            .await
            .map_err(|error| {
                anyhow::Error::new(FsError::io("joining the filesystem open worker", error))
            })??;
        Ok(OpenedNode {
            file: GuardedBlockingFile::new(file, admission),
            metadata,
            real_rel,
        })
    }

    /// 访问直接子项而不先物化无界 `Vec`。调用方决定保留哪些可见条目并可提前停止；
    /// `max_entries` 单独限制原始目录扫描工作。
    /// Visit direct children without first materializing an unbounded `Vec`. The caller chooses
    /// visible entries and may stop early; `max_entries` separately bounds raw scanning.
    pub(super) fn visit_dir<F>(
        &self,
        rel: &Path,
        running: &AtomicBool,
        cancelled: &AtomicBool,
        max_entries: usize,
        mut visitor: F,
    ) -> Result<(PathBuf, bool)>
    where
        F: FnMut(DirectoryEntry) -> Result<bool>,
    {
        self.check_public_rel(rel)?;
        let dir = self.open_with_symlink_policy(rel, NodeKind::Directory)?;
        let dir_real_rel = self.real_relative_verified(&dir)?;
        let entries = Dir::read_from(&dir)
            .map_err(|error| typed_filesystem_error("opening a directory listing", error))?;
        let mut visited_entries = 0usize;
        let mut truncated = false;
        for entry in entries {
            if !running.load(Ordering::Acquire) {
                return Err(walk_cancelled(
                    "directory listing stopped during server shutdown",
                ));
            }
            if cancelled.load(Ordering::Acquire) {
                return Err(walk_cancelled("directory listing was cancelled"));
            }
            let entry = entry
                .map_err(|error| typed_filesystem_error("reading a directory entry", error))?;
            let bytes = entry.file_name().to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            visited_entries = visited_entries.saturating_add(1);
            if visited_entries > max_entries {
                truncated = true;
                break;
            }
            let name = OsString::from_vec(bytes.to_vec());
            if validate_basename(&name).is_err() {
                truncated = true;
                continue;
            }
            let requested = dir_real_rel.join(&name);
            let child = match self.open_with_symlink_policy(&requested, NodeKind::Any) {
                Ok(child) => child,
                Err(error) => {
                    let error = typed_filesystem_error("opening a directory entry", error);
                    if unavailable_capability_entry(&error) {
                        truncated = true;
                        continue;
                    }
                    return Err(error);
                }
            };
            let metadata = child.metadata().map_err(|error| {
                typed_filesystem_error("reading directory-entry metadata", error)
            })?;
            let real_rel = match self.real_relative_verified(&child) {
                Ok(real_rel) => real_rel,
                Err(error) if unavailable_capability_entry(&error) => {
                    truncated = true;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let is_symlink = match fs::statat(&dir, &name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => FileType::from_raw_mode(stat.st_mode) == FileType::Symlink,
                Err(Errno::NOENT) => {
                    truncated = true;
                    real_rel != requested
                }
                Err(error) => {
                    return Err(typed_filesystem_error(
                        "inspecting a directory entry without following symlinks",
                        error,
                    ));
                }
            } || real_rel != requested;
            if !visitor(DirectoryEntry {
                name,
                metadata,
                real_rel,
                is_symlink,
            })? {
                truncated = true;
                break;
            }
        }
        Ok((dir_real_rel, truncated))
    }

    /// 用于 `spawn_blocking` 的同步 fd 递归遍历。访问器看到的正是识别条目的同一已打开描述符；
    /// 目录递归绝不跟随链接越出安全打开的遍历根。
    /// Synchronous fd-based recursive traversal for `spawn_blocking`. Each visitor sees the same
    /// descriptor that identified the entry; recursion never follows a link outside the secure root.
    #[cfg(test)]
    pub(super) fn walk<F>(
        &self,
        roots: Vec<PathBuf>,
        running: &AtomicBool,
        cancelled: &AtomicBool,
        max_entries: usize,
        max_depth: usize,
        mut visitor: F,
    ) -> Result<()>
    where
        F: FnMut(&mut WalkEntry) -> Result<WalkAction>,
    {
        self.walk_with_unavailable_policy(
            roots,
            running,
            cancelled,
            max_entries,
            max_depth,
            false,
            &mut |_, _, _| Ok(true),
            &mut visitor,
        )
    }

    /// 对每个遍历根使用描述符派生的授权判定进行遍历。`AccessPaths::entry_paths` 可指向目录
    /// 或一个显式授权文件，获准符号链接也可能解析成不同的根相对身份。向普通访问器暴露
    /// 子项或文件前，过滤器先观察该固定身份。
    /// Walk with descriptor-derived authorization for every root. Entry paths may name a directory or
    /// explicit file, and allowed symlinks may resolve differently. Filter pinned identity before exposure.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn walk_with_root_filter<R, F>(
        &self,
        roots: Vec<PathBuf>,
        running: &AtomicBool,
        cancelled: &AtomicBool,
        max_entries: usize,
        max_depth: usize,
        mut root_filter: R,
        mut visitor: F,
    ) -> Result<()>
    where
        R: FnMut(&Path, &Path, &Metadata) -> Result<bool>,
        F: FnMut(&mut WalkEntry) -> Result<WalkAction>,
    {
        self.walk_with_unavailable_policy(
            roots,
            running,
            cancelled,
            max_entries,
            max_depth,
            false,
            &mut root_filter,
            &mut visitor,
        )
    }

    fn walk_fail_closed<F>(
        &self,
        roots: Vec<PathBuf>,
        running: &AtomicBool,
        cancelled: &AtomicBool,
        max_entries: usize,
        max_depth: usize,
        mut visitor: F,
    ) -> Result<()>
    where
        F: FnMut(&mut WalkEntry) -> Result<WalkAction>,
    {
        self.walk_with_unavailable_policy(
            roots,
            running,
            cancelled,
            max_entries,
            max_depth,
            true,
            &mut |_, _, _| Ok(true),
            &mut visitor,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_with_unavailable_policy<R, F>(
        &self,
        roots: Vec<PathBuf>,
        running: &AtomicBool,
        cancelled: &AtomicBool,
        max_entries: usize,
        max_depth: usize,
        fail_on_unavailable: bool,
        root_filter: &mut R,
        visitor: &mut F,
    ) -> Result<()>
    where
        R: FnMut(&Path, &Path, &Metadata) -> Result<bool>,
        F: FnMut(&mut WalkEntry) -> Result<WalkAction>,
    {
        let mut visited_dirs = HashSet::new();
        let mut visited_entries = 0usize;
        for display_root in roots {
            if !running.load(Ordering::Acquire) || cancelled.load(Ordering::Acquire) {
                return Err(walk_cancelled("directory traversal was cancelled"));
            }
            self.check_public_rel(&display_root)?;
            let root = self
                .open_with_symlink_policy(&display_root, NodeKind::Any)
                .map_err(|error| typed_filesystem_error("opening a traversal root", error))?;
            let real_root = self.real_relative_verified(&root)?;
            let metadata = root.metadata().map_err(|error| {
                typed_filesystem_error("reading traversal-root metadata", error)
            })?;
            if !root_filter(&display_root, &real_root, &metadata)? {
                continue;
            }
            if metadata.is_file() {
                visited_entries = visited_entries.checked_add(1).ok_or_else(|| {
                    walk_limit_exceeded(AdmissionResource::WalkEntries, max_entries, None)
                })?;
                if visited_entries > max_entries {
                    return Err(walk_limit_exceeded(
                        AdmissionResource::WalkEntries,
                        max_entries,
                        Some(visited_entries),
                    ));
                }
                let name = display_root.file_name().ok_or_else(|| {
                    anyhow::Error::new(FsError::conflict(
                        "validating a file traversal root",
                        anyhow!("file traversal root has no basename"),
                    ))
                })?;
                validate_basename(name).map_err(|error| {
                    anyhow::Error::new(FsError::conflict(
                        "validating a file traversal-root basename",
                        error,
                    ))
                })?;
                let mut entry = WalkEntry {
                    name: name.to_os_string(),
                    display_rel: display_root.clone(),
                    real_rel: real_root.clone(),
                    metadata,
                    file: root,
                    is_symlink: display_root != real_root,
                };
                if visitor(&mut entry)? == WalkAction::Stop {
                    return Ok(());
                }
                continue;
            }
            if !metadata.is_dir() {
                return Err(anyhow::Error::new(FsError::conflict(
                    "validating a traversal root",
                    anyhow!("traversal root is neither a regular file nor a directory"),
                )));
            }
            visited_dirs.insert((metadata.dev(), metadata.ino()));
            if !self.walk_dir_sync(
                root,
                &display_root,
                &real_root,
                &real_root,
                running,
                cancelled,
                max_entries,
                max_depth,
                0,
                fail_on_unavailable,
                &mut visited_entries,
                &mut visited_dirs,
                visitor,
            )? {
                return Ok(());
            }
        }
        Ok(())
    }

    pub(super) async fn open_parent(
        &self,
        rel: impl Into<PathBuf>,
        create_ancestors: bool,
    ) -> Result<ParentDir> {
        let rel = rel.into();
        let root = self.clone();
        let lease = self.inner.blocking_admission.acquire().await?;
        self.inner
            .blocking_admission
            .spawn_with_lease(lease, move || root.open_parent_sync(&rel, create_ancestors))
            .await
            .map_err(|error| {
                anyhow::Error::new(FsError::io("joining the mutation-parent resolver", error))
            })?
    }

    /// 从能力支持的文件系统身份解析进程内变更锁。命名空间路径键使缺失祖先转换稳定；已打开
    /// 目录和父槽身份使同一根内目录的别名汇聚到一把锁。
    /// Resolve process-local mutation locks from capability-backed identities. Path keys stabilize
    /// missing-ancestor transitions; directory and parent-slot identities converge aliases on one lock.
    pub(super) async fn resolve_mutation_locks(
        &self,
        intents: &[MutationIntent],
    ) -> Result<Vec<MutationLockRequest>> {
        let intents = intents.to_vec();
        let root = self.clone();
        let lease = self.inner.blocking_admission.acquire().await?;
        self.inner
            .blocking_admission
            .spawn_with_lease(lease, move || root.resolve_mutation_locks_sync(&intents))
            .await
            .map_err(|error| {
                anyhow::Error::new(FsError::io("joining the mutation-lock resolver", error))
            })?
    }

    /// 完全在调用方阻塞工作线程内创建发布候选。COPY/PATCH 使用此入口，使工作线程拥有的昂贵
    /// 操作 permit 以不可分割生命周期覆盖父解析、`openat(O_EXCL)`、传输、提交和同步清理。
    /// Create a publication candidate entirely in the caller's blocking worker. COPY/PATCH use it so
    /// one worker-owned expensive permit covers resolution, O_EXCL, transfer, commit, and cleanup.
    pub(super) fn create_blocking_temp(
        &self,
        rel: impl Into<PathBuf>,
        create_ancestors: bool,
        directory_mode: u32,
    ) -> Result<BlockingTempFile> {
        self.create_blocking_temp_with_kind(
            rel.into(),
            create_ancestors,
            directory_mode,
            TempCandidateKind::Upload,
        )
    }

    pub(super) fn create_blocking_staging_temp(&self) -> Result<BlockingTempFile> {
        self.create_blocking_temp_with_kind(
            PathBuf::from(".ram-staging"),
            false,
            0o700,
            TempCandidateKind::Staging,
        )
    }

    fn create_blocking_temp_with_kind(
        &self,
        rel: PathBuf,
        create_ancestors: bool,
        directory_mode: u32,
        kind: TempCandidateKind,
    ) -> Result<BlockingTempFile> {
        self.ensure_candidate_recovery_healthy()?;
        let parent_depth = rel
            .parent()
            .map(|parent| parent.components().count())
            .unwrap_or(0);
        if parent_depth > self.inner.candidate_cleanup_max_depth {
            return Err(anyhow::Error::new(AdmissionError::limit_exceeded(
                AdmissionResource::WalkDepth,
                LimitKind::Semantic,
                self.inner.candidate_cleanup_max_depth as u64,
                Some(parent_depth as u64),
            )))
            .context(
                "upload target parent is deeper than the configured crash-recovery cleanup scan",
            );
        }
        let mut parent = self.open_parent_sync_with_mode(&rel, create_ancestors, directory_mode)?;
        if parent.target_rel() != rel {
            rollback_or_schedule_created_ancestors(&mut parent.created_ancestors);
            bail!("mutation target resolved to a different capability path");
        }
        let candidate = match create_temp_in(&parent.fd, kind, &mut parent.created_ancestors) {
            Ok(candidate) => candidate,
            Err(error) => {
                rollback_or_schedule_created_ancestors(&mut parent.created_ancestors);
                return Err(error);
            }
        };
        // 封闭扫描/准入竞态。若首次检查后周期恢复变得不完整，在同一阻塞工作线程内移除刚创建
        // 的私有名称，再以关闭失败返回。
        // Close the scan/admission race. If recovery becomes incomplete after the first check, remove
        // this just-created private name in the same blocking worker before failing closed.
        if let Err(error) = self.ensure_candidate_recovery_healthy() {
            cleanup_created_candidate_after_failure(candidate_reaper(), candidate.into_cleanup());
            return Err(error);
        }
        let (temp_name, file, candidate_lock, candidate_expectation, created_ancestors) =
            match candidate.into_parts() {
                Ok(parts) => parts,
                Err(error) => {
                    rollback_or_schedule_created_ancestors(&mut parent.created_ancestors);
                    return Err(error);
                }
            };
        parent.created_ancestors = created_ancestors;
        Ok(BlockingTempFile {
            root: self.clone(),
            parent,
            temp_name,
            file: Some(file),
            candidate_lock: Some(candidate_lock),
            candidate_expectation,
            cleanup_guard: None,
            committed: false,
        })
    }

    /// 不信任路径字符串地移除崩溃遗留私有候选。遍历不跟随符号链接；每次 unlink 和父目录
    /// fsync 都使用产生候选名称的已打开目录描述符。
    /// Remove crash-left candidates without trusting path strings. Traversal never follows symlinks;
    /// every unlink and parent fsync uses the descriptor that yielded the name.
    pub(super) fn cleanup_stale_uploads(
        &self,
        limits: StaleUploadCleanupLimits,
    ) -> Result<StaleUploadCleanupReport> {
        let result = (|| {
            let root = self.inner.root.try_clone()?;
            let root_metadata = root.metadata()?;
            let mut state = StaleUploadCleanupState {
                limits,
                deadline: Instant::now() + limits.timeout,
                now: SystemTime::now(),
                service_uid: rustix::process::geteuid().as_raw(),
                resolve_flags: strict_component_resolve_flags(self.inner.allow_cross_filesystems),
                visited_directories: HashSet::from([(root_metadata.dev(), root_metadata.ino())]),
                report: StaleUploadCleanupReport::default(),
            };
            cleanup_stale_uploads_in_dir(&root, Path::new(""), 0, &mut state)?;
            Ok::<_, anyhow::Error>(state.report)
        })();
        self.record_stale_upload_cleanup_result(result)
    }

    fn record_stale_upload_cleanup_result(
        &self,
        result: Result<StaleUploadCleanupReport>,
    ) -> Result<StaleUploadCleanupReport> {
        match result {
            Ok(report) => {
                if !report.is_complete() {
                    self.inner
                        .candidate_recovery_healthy
                        .store(false, Ordering::Release);
                }
                Ok(report)
            }
            Err(error) => {
                self.inner
                    .candidate_recovery_healthy
                    .store(false, Ordering::Release);
                Err(error)
            }
        }
    }

    fn ensure_candidate_recovery_healthy(&self) -> Result<()> {
        if !self
            .inner
            .candidate_recovery_healthy
            .load(Ordering::Acquire)
        {
            return Err(candidate_recovery_unavailable());
        }
        Ok(())
    }

    /// 捕获固定父目录下最终组件的确切命名空间版本。对于仅创建发布，缺失父目录也表示条目
    /// 缺失；要求父目录存在的调用方按其 HTTP 方法语义另行验证。
    /// Capture the exact final-component namespace version beneath a pinned parent. A missing parent
    /// is also a missing entry for create-only publication; other callers validate separately.
    pub(super) async fn entry_expectation(
        &self,
        rel: impl Into<PathBuf>,
    ) -> Result<EntryExpectation> {
        let rel = rel.into();
        let root = self.clone();
        let lease = self.inner.blocking_admission.acquire().await?;
        self.inner
            .blocking_admission
            .spawn_with_lease(lease, move || root.entry_expectation_sync(&rel))
            .await
            .map_err(|error| {
                anyhow::Error::new(FsError::io(
                    "joining the mutation expectation worker",
                    error,
                ))
            })?
    }

    pub(super) fn entry_expectation_sync(&self, rel: &Path) -> Result<EntryExpectation> {
        let parent = match self.open_parent_sync(rel, false) {
            Ok(parent) => parent,
            Err(error) => {
                let error = typed_filesystem_error("opening mutation target parent", error);
                if matches!(
                    FsError::in_anyhow_chain(&error),
                    Some(FsError::NotFound { .. })
                ) {
                    return Ok(EntryExpectation::Missing);
                }
                return Err(error);
            }
        };
        if parent.target_rel() != rel {
            return Err(anyhow::Error::new(FsError::outside_root(
                "capturing a mutation target expectation",
                anyhow!(
                    "target resolved to {:?} instead of {rel:?}",
                    parent.target_rel()
                ),
            )));
        }
        parent.current_expectation().map_err(|error| {
            typed_filesystem_error("capturing a mutation target expectation", error)
        })
    }

    /// 同时重新验证保留描述符和预期指向它的命名空间条目。COPY 在传输前后都执行，避免外部
    /// 替换悄然改变所选源。
    /// Revalidate both a retained descriptor and the namespace entry expected to name it. COPY does
    /// this before and after transfer so external replacement cannot silently change the source.
    pub(super) fn verify_opened_entry_sync(
        &self,
        rel: &Path,
        opened: &File,
        expected: EntryExpectation,
        role: MutationEndpointRole,
    ) -> Result<Metadata> {
        let metadata = opened.metadata().map_err(|error| {
            typed_filesystem_error("reading a retained mutation endpoint", error)
        })?;
        let namespace = self.entry_expectation_sync(rel)?;
        if !expected.matches_metadata(&metadata) || namespace != expected {
            return Err(anyhow::Error::new(FsError::changed(
                role,
                rel.display().to_string(),
                format!("{expected:?}"),
                format!(
                    "descriptor={:?}, namespace={namespace:?}",
                    EntryExpectation::from_metadata(&metadata)
                ),
            )));
        }
        Ok(metadata)
    }

    /// 不跟随最终组件地返回当前目标条目的逻辑大小。该同步形式在拥有所有权的 COPY 工作线程
    /// 内使用，使配额钩子核算与发布处于相同变更守卫和昂贵操作 permit 下。
    /// Return the destination entry's logical size without following its final component. The owned
    /// COPY worker uses this so quota accounting and publication share guards and expensive permit.
    pub(super) fn entry_size_nofollow(&self, rel: &Path) -> Result<Option<u64>> {
        let parent = match self.open_parent_sync(rel, false) {
            Ok(parent) => parent,
            Err(error) => {
                let error = typed_filesystem_error("opening destination parent", error);
                if matches!(
                    FsError::in_anyhow_chain(&error),
                    Some(FsError::NotFound { .. })
                ) {
                    return Ok(None);
                }
                return Err(error);
            }
        };
        if parent.target_rel() != rel {
            return Err(anyhow::Error::new(FsError::outside_root(
                "reading a mutation target size",
                anyhow!(
                    "target resolved to {:?} instead of {rel:?}",
                    parent.target_rel()
                ),
            )));
        }
        match fs::statat(&parent.fd, &parent.target_name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => Ok(Some(u64::try_from(stat.st_size).unwrap_or(0))),
            Err(Errno::NOENT) => Ok(None),
            Err(err) => Err(typed_filesystem_error(
                "reading a mutation target size",
                err,
            )),
        }
    }

    pub(super) async fn mkdir(
        &self,
        rel: impl Into<PathBuf>,
        mode: u32,
        mutation_guards: MutationGuards,
    ) -> Result<PathBuf> {
        let rel = rel.into();
        let root = self.clone();
        let lease = self.inner.blocking_admission.acquire().await?;
        self.inner
            .blocking_admission
            .spawn_with_lease(lease, move || {
                // 中文：变更锁/active 纪元和 FS admission 均由真实 worker 持有；请求取消不能
                // 提前释放任一资源，排队且尚未启动的任务则由 AbortOnDrop 阻止执行。
                // English: The real worker owns mutation locks/active epoch and FS admission;
                // cancellation releases neither early, while AbortOnDrop prevents queued execution.
                let _mutation_guards = mutation_guards;
                root.mkdir_sync_with_ops(&rel, mode, &mut RealMutationOps)
            })
            .await?
    }

    fn mkdir_sync_with_ops<O: MutationOps>(
        &self,
        rel: &Path,
        mode: u32,
        ops: &mut O,
    ) -> Result<PathBuf> {
        let parent = self.open_parent_sync(rel, false)?;
        if parent.target_rel() != rel {
            bail!("mutation target resolved to a different capability path");
        }
        self.verify_parent(&parent)?;
        parent.verify_entry(EntryExpectation::Missing)?;
        let rollback_parent = parent.fd.try_clone()?;
        ops.mkdir(
            &parent.fd,
            &parent.target_name,
            Mode::from_raw_mode(mode & 0o777),
        )
        .map_err(|error| {
            parent.create_only_error(
                EntryExpectation::Missing,
                MutationEndpointRole::Target,
                error,
            )
        })?;
        let stat = fs::statat(&parent.fd, &parent.target_name, AtFlags::SYMLINK_NOFOLLOW).map_err(
            |error| {
                post_publish_directory_lookup_error(
                    &parent.target_rel(),
                    "newly-created directory",
                    "versioning newly-created directory",
                    error,
                )
            },
        )?;
        let mut rollback = vec![CreatedAncestor {
            parent: rollback_parent,
            name: parent.target_name.clone(),
            expectation: EntryExpectation::from_stat(&stat),
            parent_sync_pending: false,
        }];
        let result = (|| -> Result<PathBuf> {
            let (created, finalized) = self.finalize_created_directory(
                &parent.fd,
                &parent.target_name,
                &parent.target_rel(),
                rollback[0].expectation,
                mode,
            )?;
            rollback[0].expectation = finalized;
            ops.sync_directory(&created, DirectorySyncPoint::CreatedDirectory)
                .map_err(|error| {
                    durability_error(
                        DirectorySyncPoint::CreatedDirectory.durability_stage(),
                        true,
                        error,
                    )
                })?;
            ops.sync_directory(&parent.fd, DirectorySyncPoint::CreatedDirectoryParent)
                .map_err(|error| {
                    durability_error(
                        DirectorySyncPoint::CreatedDirectoryParent.durability_stage(),
                        true,
                        error,
                    )
                })?;
            Ok(parent.target_rel())
        })();
        match result {
            Ok(path) => {
                rollback.clear();
                Ok(path)
            }
            Err(error) => {
                rollback_or_schedule_created_ancestors(&mut rollback);
                Err(error)
            }
        }
    }

    pub(super) fn remove_sync(
        &self,
        rel: &Path,
        recursive: bool,
        expected_target: EntryExpectation,
        max_entries: usize,
        max_depth: usize,
        cancellation: &super::walk::RequestCancellation,
    ) -> Result<PathBuf> {
        self.remove_sync_with_ops(
            rel,
            recursive,
            expected_target,
            max_entries,
            max_depth,
            cancellation,
            &mut RealMutationOps,
            |_| {},
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn remove_sync_with_observer<F>(
        &self,
        rel: &Path,
        recursive: bool,
        expected_target: EntryExpectation,
        max_entries: usize,
        max_depth: usize,
        cancellation: &super::walk::RequestCancellation,
        after_remove: F,
    ) -> Result<PathBuf>
    where
        F: FnMut(usize),
    {
        self.remove_sync_with_ops(
            rel,
            recursive,
            expected_target,
            max_entries,
            max_depth,
            cancellation,
            &mut RealMutationOps,
            after_remove,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn remove_sync_with_ops<O, F>(
        &self,
        rel: &Path,
        recursive: bool,
        expected_target: EntryExpectation,
        max_entries: usize,
        max_depth: usize,
        cancellation: &super::walk::RequestCancellation,
        ops: &mut O,
        mut after_remove: F,
    ) -> Result<PathBuf>
    where
        O: MutationOps,
        F: FnMut(usize),
    {
        let parent = self.open_parent_sync(rel, false)?;
        if parent.target_rel() != rel {
            bail!("mutation target resolved to a different capability path");
        }
        self.verify_parent(&parent)?;
        parent.verify_entry(expected_target)?;
        let actual = parent.target_rel();
        let stat = fs::statat(&parent.fd, &parent.target_name, AtFlags::SYMLINK_NOFOLLOW)?;
        let kind = FileType::from_raw_mode(stat.st_mode);
        if kind != FileType::Directory {
            if cancellation.is_cancelled() {
                return Err(anyhow::Error::new(AdmissionError::cancelled(
                    AdmissionResource::WalkEntries,
                )));
            }
            parent.verify_entry(expected_target)?;
            ops.unlink(&parent.fd, &parent.target_name, AtFlags::empty())?;
            ops.sync_directory(&parent.fd, DirectorySyncPoint::RemovedEntryParent)
                .map_err(|err| {
                    durability_error(
                        DirectorySyncPoint::RemovedEntryParent.durability_stage(),
                        true,
                        err,
                    )
                })?;
            return Ok(actual);
        }

        if !recursive {
            parent.verify_entry(expected_target)?;
            ops.unlink(&parent.fd, &parent.target_name, AtFlags::REMOVEDIR)?;
            ops.sync_directory(&parent.fd, DirectorySyncPoint::RemovedEntryParent)
                .map_err(|err| {
                    durability_error(
                        DirectorySyncPoint::RemovedEntryParent.durability_stage(),
                        true,
                        err,
                    )
                })?;
            return Ok(actual);
        }

        // 第一阶段只读且有界。在确切命名空间检查后立即打开目录，并在遍历前证明其 fd 与 HTTP
        // 前置条件所选表示相同。
        // Phase one is read-only and bounded. Open immediately after the exact namespace check and
        // prove its fd is the representation selected by HTTP preconditions before walking.
        let directory: File = fs::openat2(
            &parent.fd,
            &parent.target_name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
            strict_component_resolve_flags(self.inner.allow_cross_filesystems),
        )?
        .into();
        if !expected_target.matches_metadata(&directory.metadata()?) {
            return Err(anyhow::Error::new(FsError::changed(
                MutationEndpointRole::Target,
                actual.display().to_string(),
                format!("{expected_target:?}"),
                "directory fd opened a different version",
            )));
        }
        let mut plan = Vec::new();
        let mut visited = HashSet::new();
        let metadata = directory.metadata()?;
        visited.insert((metadata.dev(), metadata.ino()));
        let mut entry_count = 0usize;
        self.plan_recursive_delete(
            &directory,
            &actual,
            0,
            max_entries,
            max_depth,
            cancellation,
            &mut entry_count,
            &mut visited,
            &mut plan,
        )?;
        if cancellation.is_cancelled() {
            return Err(anyhow::Error::new(AdmissionError::cancelled(
                AdmissionResource::WalkEntries,
            )));
        }
        // 尚未发生变更。扫描期间根被替换会令事务失败，整棵树保持原样。
        // No mutation has happened yet. A root replacement during scanning fails with the tree intact.
        parent.verify_entry(expected_target)?;

        // 第二阶段消费后序计划。每次 unlink 前检查固定父身份，随后立即 fsync 父目录。此后取消
        // 可能留下已有文档说明且持久的部分删除，但绝不会悄然超过预算。
        // Phase two consumes the post-order plan. Every unlink follows pinned-parent identity checking
        // and precedes parent fsync. Cancellation may leave documented durable partial deletion, never
        // silently exceed the budget.
        let mut removed = 0usize;
        for entry in plan {
            if cancellation.is_cancelled() {
                return Err(anyhow::Error::new(AdmissionError::cancelled(
                    AdmissionResource::WalkEntries,
                )))
                .with_context(|| {
                    format!("recursive DELETE cancelled after removing {removed} entries")
                });
            }
            let entry_parent = self.open_parent_sync(&entry.rel, false)?;
            self.verify_parent(&entry_parent)?;
            let parent_metadata = entry_parent.fd.metadata()?;
            if parent_metadata.dev() != entry.parent_dev
                || parent_metadata.ino() != entry.parent_ino
            {
                return Err(anyhow::Error::new(FsError::changed(
                    MutationEndpointRole::Target,
                    entry.rel.display().to_string(),
                    format!("parent {}:{}", entry.parent_dev, entry.parent_ino),
                    format!("parent {}:{}", parent_metadata.dev(), parent_metadata.ino()),
                )));
            }
            if entry.directory {
                // 移除子项会改变父目录 ctime。保留 inode/类型证明，同时允许扫描后由自身造成的
                // ctime 转换。
                // Removing children changes parent ctime. Preserve inode/kind proof while allowing
                // our own post-scan ctime transitions.
                entry_parent.verify_entry_identity(entry.expected)?;
            } else {
                entry_parent.verify_entry(entry.expected)?;
            }
            ops.unlink(
                &entry_parent.fd,
                &entry_parent.target_name,
                if entry.directory {
                    AtFlags::REMOVEDIR
                } else {
                    AtFlags::empty()
                },
            )?;
            ops.sync_directory(&entry_parent.fd, DirectorySyncPoint::RemovedEntryParent)
                .map_err(|err| {
                    durability_error(
                        DirectorySyncPoint::RemovedEntryParent.durability_stage(),
                        true,
                        err,
                    )
                })?;
            removed = removed.saturating_add(1);
            after_remove(removed);
        }

        if cancellation.is_cancelled() {
            return Err(anyhow::Error::new(AdmissionError::cancelled(
                AdmissionResource::WalkEntries,
            )))
            .context("recursive DELETE cancelled after removing all children");
        }
        parent.verify_entry_identity(expected_target)?;
        ops.unlink(&parent.fd, &parent.target_name, AtFlags::REMOVEDIR)?;
        ops.sync_directory(&parent.fd, DirectorySyncPoint::RemovedEntryParent)
            .map_err(|err| {
                durability_error(
                    DirectorySyncPoint::RemovedEntryParent.durability_stage(),
                    true,
                    err,
                )
            })?;
        Ok(actual)
    }

    pub(super) async fn rename(
        &self,
        source: impl Into<PathBuf>,
        destination: impl Into<PathBuf>,
        create_destination_ancestors: bool,
        expected_source: EntryExpectation,
        expected_destination: EntryExpectation,
        mutation_guards: MutationGuards,
    ) -> Result<(PathBuf, PathBuf)> {
        let source = source.into();
        let destination = destination.into();
        let root = self.clone();
        let lease = self.inner.blocking_admission.acquire().await?;
        self.inner
            .blocking_admission
            .spawn_with_lease(lease, move || {
                let _mutation_guards = mutation_guards;
                root.rename_sync_with_ops(
                    &source,
                    &destination,
                    create_destination_ancestors,
                    expected_source,
                    expected_destination,
                    &mut RealMutationOps,
                )
            })
            .await?
    }

    fn rename_sync_with_ops<O: MutationOps>(
        &self,
        source: &Path,
        destination: &Path,
        create_destination_ancestors: bool,
        expected_source: EntryExpectation,
        expected_destination: EntryExpectation,
        ops: &mut O,
    ) -> Result<(PathBuf, PathBuf)> {
        let src = self.open_parent_sync(source, false)?;
        let mut dst = self.open_parent_sync(destination, create_destination_ancestors)?;
        let result = (|| {
            if src.target_rel() != source || dst.target_rel() != destination {
                bail!("rename endpoint resolved to a different capability path");
            }
            self.verify_parent_with_role(&src, MutationEndpointRole::Source)?;
            self.verify_parent_with_role(&dst, MutationEndpointRole::Destination)?;
            src.verify_entry_with_role(expected_source, MutationEndpointRole::Source)?;
            dst.verify_entry_with_role(expected_destination, MutationEndpointRole::Destination)?;
            let same_parent = same_object(&src.fd, &dst.fd)?;
            ops.rename(
                &src.fd,
                &src.target_name,
                &dst.fd,
                &dst.target_name,
                matches!(expected_destination, EntryExpectation::Missing),
            )
            .map_err(|error| {
                if matches!(expected_destination, EntryExpectation::Missing) {
                    dst.create_only_error(
                        expected_destination,
                        MutationEndpointRole::Destination,
                        error,
                    )
                } else {
                    error.into()
                }
            })?;
            // 发布使每个自动创建的目标祖先可达且非空。任何发布后 fsync 可能失败之前，把其所有权
            // 转移给已提交命名空间；所有更早退出都保留回滚责任。
            // Publication makes auto-created ancestors reachable and non-empty. Transfer ownership to
            // committed namespace before post-publication fsync can fail; earlier exits retain rollback.
            dst.created_ancestors.clear();
            sync_renamed_parents_with(&dst.fd, &src.fd, same_parent, |parent, stage| {
                let point = match stage {
                    DurabilityStage::DestinationParent => DirectorySyncPoint::DestinationParent,
                    DurabilityStage::SourceParent => DirectorySyncPoint::SourceParent,
                    _ => unreachable!("rename parent sync received an unrelated stage"),
                };
                ops.sync_directory(parent, point)
            })?;
            Ok((src.target_rel(), dst.target_rel()))
        })();
        if result.is_err() {
            rollback_or_schedule_created_ancestors(&mut dst.created_ancestors);
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn plan_recursive_delete(
        &self,
        directory: &File,
        directory_rel: &Path,
        depth: usize,
        max_entries: usize,
        max_depth: usize,
        cancellation: &super::walk::RequestCancellation,
        entry_count: &mut usize,
        visited: &mut HashSet<(u64, u64)>,
        plan: &mut Vec<PlannedRemoval>,
    ) -> Result<()> {
        if cancellation.is_cancelled() {
            return Err(anyhow::Error::new(AdmissionError::cancelled(
                AdmissionResource::WalkEntries,
            )));
        }
        let parent_metadata = directory.metadata()?;
        for entry in Dir::read_from(directory)? {
            if cancellation.is_cancelled() {
                return Err(anyhow::Error::new(AdmissionError::cancelled(
                    AdmissionResource::WalkEntries,
                )));
            }
            let entry = entry?;
            let bytes = entry.file_name().to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            let name = OsString::from_vec(bytes.to_vec());
            validate_basename(&name)?;
            *entry_count = entry_count.saturating_add(1);
            if *entry_count > max_entries {
                return Err(anyhow::Error::new(AdmissionError::limit_exceeded(
                    AdmissionResource::WalkEntries,
                    LimitKind::Semantic,
                    max_entries as u64,
                    Some(*entry_count as u64),
                )));
            }
            let stat = match fs::statat(directory, &name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => stat,
                Err(Errno::NOENT) => {
                    return Err(anyhow::Error::new(FsError::changed(
                        MutationEndpointRole::Target,
                        directory_rel.join(&name).display().to_string(),
                        "entry observed by directory scan",
                        "entry disappeared before it could be versioned",
                    )));
                }
                Err(error) => return Err(error.into()),
            };
            let expected = EntryExpectation::from_stat(&stat);
            let is_directory = FileType::from_raw_mode(stat.st_mode) == FileType::Directory;
            let rel = directory_rel.join(&name);
            if is_directory {
                if depth >= max_depth {
                    return Err(anyhow::Error::new(AdmissionError::limit_exceeded(
                        AdmissionResource::WalkDepth,
                        LimitKind::Semantic,
                        max_depth as u64,
                        Some(depth.saturating_add(1) as u64),
                    )));
                }
                let child: File = fs::openat2(
                    directory,
                    &name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NONBLOCK,
                    Mode::empty(),
                    strict_component_resolve_flags(self.inner.allow_cross_filesystems),
                )?
                .into();
                let metadata = child.metadata()?;
                if !expected.matches_metadata(&metadata) {
                    return Err(anyhow::Error::new(FsError::changed(
                        MutationEndpointRole::Target,
                        rel.display().to_string(),
                        format!("{expected:?}"),
                        format!("{:?}", EntryExpectation::from_metadata(&metadata)),
                    )));
                }
                if !visited.insert((metadata.dev(), metadata.ino())) {
                    return Err(anyhow::Error::new(FsError::conflict(
                        "planning recursive DELETE",
                        anyhow!("directory graph contains a repeated inode at {rel:?}"),
                    )));
                }
                self.plan_recursive_delete(
                    &child,
                    &rel,
                    depth + 1,
                    max_entries,
                    max_depth,
                    cancellation,
                    entry_count,
                    visited,
                    plan,
                )?;
            }
            plan.push(PlannedRemoval {
                rel,
                expected,
                directory: is_directory,
                parent_dev: parent_metadata.dev(),
                parent_ino: parent_metadata.ino(),
            });
        }
        Ok(())
    }

    fn check_public_rel(&self, rel: &Path) -> Result<()> {
        validate_rel(rel)?;
        if let Some(only) = self.inner.single_file.as_ref() {
            let mut components = rel.components();
            let valid = matches!(components.next(), Some(Component::Normal(name)) if name == only.name)
                && components.next().is_none();
            if !valid {
                bail!("path is outside the single-file capability");
            }
        }
        Ok(())
    }

    fn resolve_mutation_locks_sync(
        &self,
        intents: &[MutationIntent],
    ) -> Result<Vec<MutationLockRequest>> {
        let mut requests = BTreeMap::<MutationLockKey, MutationLockMode>::new();
        let root_metadata = self.inner.root.metadata()?;
        let root_key = MutationLockKey::Directory {
            device: root_metadata.dev(),
            inode: root_metadata.ino(),
        };

        for intent in intents {
            self.check_public_rel(&intent.path)?;
            let components = intent
                .path
                .components()
                .map(|component| match component {
                    Component::Normal(name) => Ok(name.to_os_string()),
                    _ => bail!("path is not a normalized relative path"),
                })
                .collect::<Result<Vec<_>>>()?;

            if components.is_empty() {
                merge_mutation_lock(&mut requests, root_key.clone(), intent.mode);
                continue;
            }

            merge_mutation_lock(&mut requests, root_key.clone(), MutationLockMode::Read);
            let mut prefix = PathBuf::new();
            let mut parent_identity = Some((root_metadata.dev(), root_metadata.ino()));
            let last = components.len() - 1;

            for (index, name) in components.iter().enumerate() {
                prefix.push(name);
                let leaf = index == last;
                let path_mode = if leaf {
                    intent.mode
                } else {
                    MutationLockMode::Read
                };
                merge_mutation_lock(
                    &mut requests,
                    MutationLockKey::Path(prefix.clone()),
                    path_mode,
                );

                if let Some((parent_device, parent_inode)) = parent_identity {
                    let slot_key = MutationLockKey::Slot {
                        parent_device,
                        parent_inode,
                        name: name.as_bytes().to_vec(),
                    };
                    merge_mutation_lock(
                        &mut requests,
                        slot_key.clone(),
                        if leaf {
                            intent.mode
                        } else {
                            MutationLockMode::Read
                        },
                    );

                    if leaf {
                        match self.open_with_symlink_policy(&prefix, NodeKind::Any) {
                            Ok(file) => {
                                let metadata = file.metadata().map_err(|error| {
                                    typed_filesystem_error(
                                        "reading a mutation-lock endpoint",
                                        error,
                                    )
                                })?;
                                if metadata.is_dir() {
                                    merge_mutation_lock(
                                        &mut requests,
                                        MutationLockKey::Directory {
                                            device: metadata.dev(),
                                            inode: metadata.ino(),
                                        },
                                        intent.mode,
                                    );
                                }
                            }
                            Err(error) => {
                                let error = typed_filesystem_error(
                                    "opening a mutation-lock endpoint",
                                    error,
                                );
                                if !matches!(
                                    FsError::in_anyhow_chain(&error),
                                    Some(FsError::NotFound { .. })
                                ) {
                                    return Err(error);
                                }
                            }
                        }
                        continue;
                    }

                    match self.open_with_symlink_policy(&prefix, NodeKind::Directory) {
                        Ok(directory) => {
                            let metadata = directory.metadata().map_err(|error| {
                                typed_filesystem_error("reading a mutation-lock path prefix", error)
                            })?;
                            let identity = (metadata.dev(), metadata.ino());
                            merge_mutation_lock(
                                &mut requests,
                                MutationLockKey::Directory {
                                    device: identity.0,
                                    inode: identity.1,
                                },
                                MutationLockMode::Read,
                            );
                            parent_identity = Some(identity);
                        }
                        Err(error) => {
                            let error = typed_filesystem_error(
                                "opening a mutation-lock path prefix",
                                error,
                            );
                            if !matches!(
                                FsError::in_anyhow_chain(&error),
                                Some(FsError::NotFound { .. })
                            ) {
                                return Err(error);
                            }
                            // 写入者可能创建此缺失祖先。独占其最后一个能力支持槽，使创建后解析的
                            // 请求必须等待同一转换键；其余缺失后缀由规范 Path 键保护。
                            // A writer may create this missing ancestor. Exclusively hold its last
                            // capability-backed slot so later resolution waits on the same transition key;
                            // normalized Path keys protect remaining missing suffixes.
                            if intent.mode == MutationLockMode::Write {
                                merge_mutation_lock(
                                    &mut requests,
                                    slot_key,
                                    MutationLockMode::Write,
                                );
                                merge_mutation_lock(
                                    &mut requests,
                                    MutationLockKey::Path(prefix.clone()),
                                    MutationLockMode::Write,
                                );
                            }
                            parent_identity = None;
                        }
                    }
                }
            }
        }

        Ok(requests
            .into_iter()
            .map(|(key, mode)| MutationLockRequest::new(key, mode))
            .collect())
    }

    fn resolve_flags(&self) -> ResolveFlags {
        let mut base = ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS;
        if !self.inner.allow_cross_filesystems {
            base |= ResolveFlags::NO_XDEV;
        }
        if self.inner.allow_symlink {
            base
        } else {
            base | ResolveFlags::NO_SYMLINKS
        }
    }

    pub(super) fn open_raw(&self, rel: &Path, kind: NodeKind) -> Result<File> {
        validate_rel(rel)?;
        if let Some(single) = self.inner.single_file.as_ref()
            && rel == Path::new(&single.name)
        {
            if kind == NodeKind::Directory {
                return Err(anyhow::Error::new(FsError::conflict(
                    "opening the single-file capability as a directory",
                    anyhow!("single-file capability is not a directory"),
                )));
            }
            return reopen_pinned_file(&single.file).map_err(|error| {
                typed_filesystem_error("reopening the pinned single-file capability", error)
            });
        }
        self.open_namespace_raw(rel, kind)
    }

    /// 打开所保留根描述符下的当前命名空间条目。
    /// Open the current namespace entry below the retained root descriptor.
    fn open_namespace_raw(&self, rel: &Path, kind: NodeKind) -> Result<File> {
        validate_rel(rel)?;
        let path = if rel.as_os_str().is_empty() {
            Path::new(".")
        } else {
            rel
        };
        let flags = match kind {
            // RDONLY 同时打开普通文件和目录；NONBLOCK 避免路由探测阻塞在 FIFO。调用方在暴露
            // 内容前会拒绝普通文件/目录之外的所有类型。
            // RDONLY opens regular files and directories. NONBLOCK prevents FIFO hangs; callers reject
            // every type other than regular file/directory before exposing content.
            NodeKind::Any => OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            NodeKind::File => OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            NodeKind::Directory => {
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NONBLOCK
            }
        };
        let fd: OwnedFd = fs::openat2(
            &self.inner.root,
            path,
            flags,
            Mode::empty(),
            self.resolve_flags(),
        )
        .map_err(|error| capability_open_error(rel, error))?;
        Ok(fd.into())
    }

    /// `RESOLVE_BENEATH` 有意拒绝绝对符号链接。启用符号链接能力时，先把已有绝对链接解析为
    /// 根相对候选，再执行权威 openat2；规范化字符串本身绝不授予访问权。
    /// `RESOLVE_BENEATH` intentionally rejects absolute symlinks. When enabled, resolve an existing
    /// absolute link to a root-relative candidate, then perform authoritative openat2. Text grants nothing.
    fn open_with_symlink_policy(&self, rel: &Path, kind: NodeKind) -> Result<File> {
        match self.open_raw(rel, kind) {
            Ok(file) => Ok(file),
            Err(_original) if self.inner.allow_symlink => {
                let canonical_rel = self
                    .canonical_existing_rel(rel)
                    .context("resolving an allowed filesystem symlink")?;
                self.open_raw(&canonical_rel, kind)
            }
            Err(err) => Err(err),
        }
    }

    fn canonical_existing_rel(&self, rel: &Path) -> Result<PathBuf> {
        validate_rel(rel)?;
        for _ in 0..VERIFY_RETRIES {
            let root_before = proc_fd_target(&self.inner.root).map_err(|error| {
                typed_filesystem_error("reading the filesystem capability root", error)
            })?;
            let resolved = std::fs::canonicalize(root_before.join(rel)).map_err(|error| {
                typed_filesystem_error("canonicalizing an allowed filesystem symlink", error)
            })?;
            let root_after = proc_fd_target(&self.inner.root).map_err(|error| {
                typed_filesystem_error("re-reading the filesystem capability root", error)
            })?;
            if root_before != root_after || deleted_proc_target(&root_before) {
                continue;
            }
            let relative = resolved
                .strip_prefix(&root_before)
                .map(Path::to_path_buf)
                .map_err(|error| {
                    anyhow::Error::new(FsError::outside_root(
                        "canonicalizing an allowed filesystem symlink",
                        error,
                    ))
                })?;
            validate_rel(&relative)?;
            return Ok(relative);
        }
        Err(anyhow::Error::new(FsError::conflict(
            "canonicalizing an allowed filesystem symlink",
            anyhow!("filesystem root changed while resolving the symlink"),
        )))
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_dir_sync<F>(
        &self,
        directory: File,
        display_dir: &Path,
        real_dir: &Path,
        real_root: &Path,
        running: &AtomicBool,
        cancelled: &AtomicBool,
        max_entries: usize,
        max_depth: usize,
        depth: usize,
        fail_on_unavailable: bool,
        visited_entries: &mut usize,
        visited_dirs: &mut HashSet<(u64, u64)>,
        visitor: &mut F,
    ) -> Result<bool>
    where
        F: FnMut(&mut WalkEntry) -> Result<WalkAction>,
    {
        let entries = Dir::read_from(&directory)
            .map_err(|error| typed_filesystem_error("opening a traversed directory", error))?;
        for entry in entries {
            if !running.load(Ordering::Acquire) || cancelled.load(Ordering::Acquire) {
                return Err(walk_cancelled("directory traversal was cancelled"));
            }
            let entry = entry.map_err(|error| {
                typed_filesystem_error("reading a traversed directory entry", error)
            })?;
            let bytes = entry.file_name().to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            let name = OsString::from_vec(bytes.to_vec());
            validate_basename(&name).map_err(|error| {
                anyhow::Error::new(FsError::conflict(
                    "validating a traversed directory entry",
                    error,
                ))
            })?;
            *visited_entries = visited_entries.checked_add(1).ok_or_else(|| {
                walk_limit_exceeded(AdmissionResource::WalkEntries, max_entries, None)
            })?;
            if *visited_entries > max_entries {
                return Err(walk_limit_exceeded(
                    AdmissionResource::WalkEntries,
                    max_entries,
                    Some(*visited_entries),
                ));
            }

            let requested_real = real_dir.join(&name);
            let file = match self.open_with_symlink_policy(&requested_real, NodeKind::Any) {
                Ok(file) => file,
                Err(error) => {
                    let error =
                        typed_filesystem_error("opening a traversed directory entry", error);
                    if !fail_on_unavailable && unavailable_capability_entry(&error) {
                        continue;
                    }
                    return Err(error);
                }
            };
            let metadata = file.metadata().map_err(|error| {
                typed_filesystem_error("reading traversed-entry metadata", error)
            })?;
            let real_rel = match self.real_relative_verified(&file) {
                Ok(real_rel) => real_rel,
                Err(error) if !fail_on_unavailable && unavailable_capability_entry(&error) => {
                    continue;
                }
                Err(error) => return Err(error),
            };
            if !real_rel.starts_with(real_root) {
                // 这是显式允许的能力内符号链接，但目标位于调用方已授权遍历根之外。跳过链接是
                // 安全策略而非 I/O 恢复路径；真正的元数据/读取故障仍会中止。
                // This is an allowed in-capability symlink whose target lies outside the caller's
                // traversal root. Skipping is policy, not I/O recovery; genuine failures still abort.
                if fail_on_unavailable {
                    return Err(anyhow::Error::new(FsError::outside_root(
                        "validating a strict directory traversal entry",
                        anyhow!("resolved entry is outside the traversal root"),
                    )));
                }
                continue;
            }
            let is_symlink = match fs::statat(&directory, &name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => FileType::from_raw_mode(stat.st_mode) == FileType::Symlink,
                Err(Errno::NOENT) if !fail_on_unavailable => continue,
                Err(Errno::NOENT) => {
                    return Err(typed_filesystem_error(
                        "rechecking a strict traversed directory entry",
                        std::io::Error::from(std::io::ErrorKind::NotFound),
                    ));
                }
                Err(error) => {
                    return Err(typed_filesystem_error(
                        "inspecting a traversed entry without following symlinks",
                        error,
                    ));
                }
            } || real_rel != requested_real;
            let display_rel = display_dir.join(&name);
            let recurse = metadata.is_dir();
            let directory_identity = recurse.then(|| (metadata.dev(), metadata.ino()));
            let recurse_fd = if recurse {
                Some(file.try_clone().map_err(|error| {
                    typed_filesystem_error("cloning a traversed directory descriptor", error)
                })?)
            } else {
                None
            };
            let mut entry = WalkEntry {
                name,
                display_rel: display_rel.clone(),
                real_rel: real_rel.clone(),
                metadata,
                file,
                is_symlink,
            };
            match visitor(&mut entry)? {
                WalkAction::Stop => return Ok(false),
                WalkAction::SkipDirectory => continue,
                WalkAction::Continue => {}
            }
            if let (Some(identity), Some(recurse_fd)) = (directory_identity, recurse_fd) {
                if depth >= max_depth {
                    return Err(walk_limit_exceeded(
                        AdmissionResource::WalkDepth,
                        max_depth,
                        depth.checked_add(1),
                    ));
                }
                if visited_dirs.insert(identity)
                    && !self.walk_dir_sync(
                        recurse_fd,
                        &display_rel,
                        &real_rel,
                        real_root,
                        running,
                        cancelled,
                        max_entries,
                        max_depth,
                        depth + 1,
                        fail_on_unavailable,
                        visited_entries,
                        visited_dirs,
                        visitor,
                    )?
                {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    fn open_dir_raw(&self, rel: &Path) -> Result<File> {
        self.open_raw(rel, NodeKind::Directory)
    }

    /// 进程继承极端 umask 时，新目录最初可能没有可用访问位。使用无需读/搜索权限的 `O_PATH`
    /// 固定它，对 mkdir 后命名空间快照验证固定对象，再通过 procfs chmod 确切 inode，最后
    /// 重新打开用于遍历和 fsync。
    /// A new directory may have no usable bits under an extreme umask. Pin with `O_PATH`, verify
    /// against the post-mkdir snapshot, chmod that inode through procfs, then reopen for traversal/fsync.
    fn finalize_created_directory(
        &self,
        parent: &File,
        name: &OsStr,
        rel: &Path,
        expected: EntryExpectation,
        mode: u32,
    ) -> Result<(File, EntryExpectation)> {
        let pinned: File = fs::openat2(
            parent,
            name,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            strict_component_resolve_flags(self.inner.allow_cross_filesystems),
        )
        .map_err(|error| {
            post_publish_directory_lookup_error(
                rel,
                format!("{expected:?}"),
                "pinning newly-created directory",
                error,
            )
        })?
        .into();
        let pinned_before =
            EntryExpectation::from_metadata(&pinned.metadata().map_err(|error| {
                post_publish_directory_io_error("reading pinned new-directory metadata", error)
            })?);
        if pinned_before != expected {
            return Err(anyhow::Error::new(FsError::changed(
                MutationEndpointRole::Target,
                rel.display().to_string(),
                format!("{expected:?}"),
                format!("{pinned_before:?}"),
            )));
        }

        let proc_path = PathBuf::from(format!("/proc/self/fd/{}", pinned.as_raw_fd()));
        fs::chmod(&proc_path, Mode::from_raw_mode(mode & 0o777))
            .map_err(|error| durability_error(DurabilityStage::CreatedDirectory, true, error))?;
        let pinned_metadata = pinned.metadata().map_err(|error| {
            post_publish_directory_io_error("verifying new-directory metadata", error)
        })?;
        let actual_mode = pinned_metadata.mode() & 0o7777;
        if actual_mode != mode & 0o777 {
            return Err(durability_error(
                DurabilityStage::CreatedDirectory,
                true,
                anyhow!(
                    "new directory mode verification failed: expected {:04o}, found {actual_mode:04o}",
                    mode & 0o777
                ),
            ));
        }
        let finalized = EntryExpectation::from_metadata(&pinned_metadata);

        let opened: File = fs::openat2(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            strict_component_resolve_flags(self.inner.allow_cross_filesystems),
        )
        .map_err(|error| {
            post_publish_directory_lookup_error(
                rel,
                format!("{finalized:?}"),
                "reopening newly-created directory",
                error,
            )
        })?
        .into();
        let reopened = EntryExpectation::from_metadata(&opened.metadata().map_err(|error| {
            post_publish_directory_io_error("reading reopened new-directory metadata", error)
        })?);
        if !finalized.same_object(reopened) {
            return Err(anyhow::Error::new(FsError::changed(
                MutationEndpointRole::Target,
                rel.display().to_string(),
                format!("{finalized:?}"),
                format!("{reopened:?}"),
            )));
        }
        Ok((opened, finalized))
    }

    fn open_parent_sync(&self, rel: &Path, create_ancestors: bool) -> Result<ParentDir> {
        self.open_parent_sync_with_mode(rel, create_ancestors, 0o700)
    }

    fn open_parent_sync_with_mode(
        &self,
        rel: &Path,
        create_ancestors: bool,
        directory_mode: u32,
    ) -> Result<ParentDir> {
        self.check_public_rel(rel)?;
        let target_name = rel
            .file_name()
            .ok_or_else(|| anyhow!("filesystem root cannot be used as a mutation target"))?
            .to_os_string();
        validate_basename(&target_name)?;
        let parent_rel = rel.parent().unwrap_or_else(|| Path::new(""));
        let (fd, mut created_ancestors) = if create_ancestors {
            self.ensure_dir_sync(parent_rel, directory_mode)?
        } else {
            (self.open_dir_raw(parent_rel)?, Vec::new())
        };
        let real_rel = match self.real_relative_verified(&fd) {
            Ok(real_rel) => real_rel,
            Err(error) => {
                rollback_or_schedule_created_ancestors(&mut created_ancestors);
                return Err(error);
            }
        };
        Ok(ParentDir {
            fd,
            real_rel,
            target_name,
            created_ancestors,
        })
    }

    fn ensure_dir_sync(
        &self,
        rel: &Path,
        directory_mode: u32,
    ) -> Result<(File, Vec<CreatedAncestor>)> {
        validate_rel(rel)?;
        if rel.as_os_str().is_empty() {
            return Ok((self.open_dir_raw(rel)?, Vec::new()));
        }
        let mut created_ancestors = Vec::new();
        let mut prefix = PathBuf::new();
        let mut current = self.open_dir_raw(Path::new(""))?;
        let result = (|| -> Result<File> {
            for component in rel.components() {
                let Component::Normal(name) = component else {
                    bail!("invalid relative path component");
                };
                prefix.push(name);
                match self.open_dir_raw(&prefix) {
                    Ok(fd) => {
                        if self.real_relative_verified(&fd)? != prefix {
                            bail!("directory ancestor resolved to a different capability path");
                        }
                        current = fd;
                    }
                    Err(error)
                        if matches!(
                            FsError::in_anyhow_chain(&error),
                            Some(FsError::NotFound { .. })
                        ) =>
                    {
                        // `current` 是该单一组件已安全打开的父目录；mkdirat 在此无法解析攻击者
                        // 控制的祖先。
                        // `current` is the securely opened parent of this one component; mkdirat cannot
                        // resolve an attacker-controlled ancestor here.
                        let created_parent = current.try_clone()?;
                        let created = match fs::mkdirat(
                            &current,
                            name,
                            Mode::from_raw_mode(directory_mode & 0o777),
                        ) {
                            Ok(()) => true,
                            Err(Errno::EXIST) => false,
                            Err(err) => return Err(err.into()),
                        };
                        let opened = if created {
                            // 捕获 mkdir 后 inode 身份前绝不 unlink 名称：若检查失败含糊，该名称
                            // 可能已是外部写入者的替换物。
                            // Never unlink before capturing post-mkdir inode identity: after ambiguous
                            // inspection failure the name could already be an external replacement.
                            let stat = fs::statat(&current, name, AtFlags::SYMLINK_NOFOLLOW)
                                .map_err(|error| {
                                    post_publish_directory_lookup_error(
                                        &prefix,
                                        "newly auto-created upload directory",
                                        "versioning auto-created upload directory",
                                        error,
                                    )
                                })?;
                            created_ancestors.push(CreatedAncestor {
                                parent: created_parent,
                                name: name.to_os_string(),
                                expectation: EntryExpectation::from_stat(&stat),
                                parent_sync_pending: false,
                            });
                            let (opened, finalized) = self.finalize_created_directory(
                                &current,
                                name,
                                &prefix,
                                created_ancestors
                                    .last()
                                    .expect("created ancestor was just recorded")
                                    .expectation,
                                directory_mode,
                            )?;
                            created_ancestors
                                .last_mut()
                                .expect("created ancestor was just recorded")
                                .expectation = finalized;
                            fs::fsync(&opened).map_err(|error| {
                                durability_error(DurabilityStage::CreatedDirectory, true, error)
                            })?;
                            fs::fsync(&current).map_err(|error| {
                                durability_error(DurabilityStage::CreatedDirectory, true, error)
                            })?;
                            opened
                        } else {
                            self.open_dir_raw(&prefix)?
                        };
                        if self.real_relative_verified(&opened)? != prefix {
                            bail!("created ancestor resolved to a different capability path");
                        }
                        current = opened;
                    }
                    Err(error) => {
                        return Err(typed_filesystem_error(
                            "opening upload directory ancestor",
                            error,
                        ));
                    }
                }
            }
            Ok(current)
        })();
        match result {
            Ok(current) => Ok((current, created_ancestors)),
            Err(error) => {
                rollback_or_schedule_created_ancestors(&mut created_ancestors);
                Err(error)
            }
        }
    }

    fn verify_parent(&self, parent: &ParentDir) -> Result<()> {
        self.verify_parent_with_role(parent, MutationEndpointRole::Target)
    }

    fn verify_parent_with_role(
        &self,
        parent: &ParentDir,
        role: MutationEndpointRole,
    ) -> Result<()> {
        let expected = parent.fd.metadata().map_err(|error| {
            anyhow::Error::new(FsError::io("reading pinned mutation parent", error))
        })?;
        let expected_description = format!("parent {}:{}", expected.dev(), expected.ino());
        let reopened = match self.open_dir_raw(&parent.real_rel) {
            Ok(reopened) => reopened,
            Err(error) => {
                let error = typed_filesystem_error("reopening mutation parent", error);
                if matches!(
                    FsError::in_anyhow_chain(&error),
                    Some(
                        FsError::NotFound { .. }
                            | FsError::Conflict { .. }
                            | FsError::OutsideRoot { .. }
                    )
                ) {
                    return Err(anyhow::Error::new(FsError::changed(
                        role,
                        parent.real_rel.display().to_string(),
                        expected_description,
                        format!("parent namespace is unavailable: {error:#}"),
                    )));
                }
                return Err(error);
            }
        };
        let actual = reopened.metadata().map_err(|error| {
            anyhow::Error::new(FsError::io("reading reopened mutation parent", error))
        })?;
        if expected.dev() != actual.dev()
            || expected.ino() != actual.ino()
            || expected.file_type() != actual.file_type()
        {
            return Err(anyhow::Error::new(FsError::changed(
                role,
                parent.real_rel.display().to_string(),
                expected_description,
                format!("parent {}:{}", actual.dev(), actual.ino()),
            )));
        }
        Ok(())
    }

    /// 把 `fd` 背后的实际对象解析回此能力根，用 openat2 重新打开并比较 inode 身份。只有对象
    /// 身份往返成功后才信任路径文本。
    /// Resolve the object behind `fd` into this capability root, reopen with openat2, and compare inode
    /// identity. Path text is untrusted until this object-identity round trip succeeds.
    pub(super) fn real_relative_verified(&self, file: &File) -> Result<PathBuf> {
        if let Some(single) = self.inner.single_file.as_ref()
            && same_object(file, &single.file).map_err(|error| {
                typed_filesystem_error("verifying the pinned single-file identity", error)
            })?
        {
            return Ok(PathBuf::from(&single.name));
        }
        let mut last_detail = String::new();
        for _ in 0..VERIFY_RETRIES {
            let root_before = proc_fd_target(&self.inner.root).map_err(|error| {
                typed_filesystem_error("reading the filesystem capability root", error)
            })?;
            let target = proc_fd_target(file)
                .map_err(|error| typed_filesystem_error("reading an opened object path", error))?;
            let root_after = proc_fd_target(&self.inner.root).map_err(|error| {
                typed_filesystem_error("re-reading the filesystem capability root", error)
            })?;
            if root_before != root_after || deleted_proc_target(&root_before) {
                last_detail = format!("root changed: {root_before:?} -> {root_after:?}");
                continue;
            }
            let rel = target
                .strip_prefix(&root_before)
                .map(Path::to_path_buf)
                .map_err(|error| {
                    anyhow::Error::new(FsError::outside_root(
                        "verifying an opened filesystem object",
                        error,
                    ))
                })?;
            validate_rel(&rel)?;
            let reopened = match self.open_raw(&rel, NodeKind::Any) {
                Ok(file) => file,
                Err(err) => {
                    last_detail = format!("reopen {rel:?} failed: {err:#}");
                    continue;
                }
            };
            if same_object(file, &reopened).map_err(|error| {
                typed_filesystem_error("comparing reopened filesystem identities", error)
            })? {
                return Ok(rel);
            }
            let original = file.metadata().map_err(|error| {
                typed_filesystem_error("reading opened filesystem metadata", error)
            })?;
            let reopened_meta = reopened.metadata().map_err(|error| {
                typed_filesystem_error("reading reopened filesystem metadata", error)
            })?;
            last_detail = format!(
                "identity mismatch for {rel:?}: original {}:{}, reopened {}:{}",
                original.dev(),
                original.ino(),
                reopened_meta.dev(),
                reopened_meta.ino()
            );
        }
        Err(anyhow::Error::new(FsError::conflict(
            "verifying an opened filesystem object",
            anyhow!("opened object changed during verification: {last_detail}"),
        )))
    }
}

pub(super) fn validate_opened_trusted_asset(metadata: &Metadata, path: &Path) -> Result<()> {
    validate_trusted_asset_metadata(metadata, false, path)
}

fn validate_trusted_asset_metadata(
    metadata: &Metadata,
    directory: bool,
    path: &Path,
) -> Result<()> {
    if directory {
        if !metadata.is_dir() {
            bail!("trusted asset is not a directory: {:?}", path);
        }
    } else {
        if !metadata.is_file() {
            bail!("trusted asset is not a regular file: {:?}", path);
        }
        if metadata.nlink() != 1 {
            bail!("trusted asset has hard-link aliases: {:?}", path);
        }
    }
    if metadata.mode() & 0o022 != 0 {
        bail!("trusted asset is group/world writable: {:?}", path);
    }
    if !is_trusted_file_owner(metadata.uid()) {
        bail!("trusted asset has an untrusted owner: {:?}", path);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum TempCandidateKind {
    Upload,
    Staging,
}

fn cleanup_stale_uploads_in_dir(
    directory: &File,
    directory_rel: &Path,
    depth: usize,
    state: &mut StaleUploadCleanupState,
) -> Result<bool> {
    let entries = match Dir::read_from(directory) {
        Ok(entries) => entries,
        Err(error) => {
            state.record_failure(StaleUploadCleanupStage::ReadDirectory, directory_rel, error);
            return Ok(false);
        }
    };
    for entry in entries {
        if Instant::now() >= state.deadline {
            state.report.deadline_reached = true;
            return Ok(false);
        }
        if state.report.scanned_entries >= state.limits.max_entries {
            state.report.entry_limit_reached = true;
            return Ok(false);
        }
        if state.report.deleted >= state.limits.max_deletions {
            state.report.deletion_limit_reached = true;
            return Ok(false);
        }

        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                state.record_failure(
                    StaleUploadCleanupStage::ReadDirectoryEntry,
                    directory_rel,
                    error,
                );
                return Ok(false);
            }
        };
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        state.report.scanned_entries = state.report.scanned_entries.saturating_add(1);
        let name = OsString::from_vec(bytes.to_vec());
        let relative_path = directory_rel.join(&name);
        if validate_basename(&name).is_err() {
            state.report.skipped_unsafe = state.report.skipped_unsafe.saturating_add(1);
            continue;
        }
        let stat = match fs::statat(directory, &name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => continue,
            Err(error) => {
                state.record_failure(StaleUploadCleanupStage::InspectEntry, &relative_path, error);
                continue;
            }
        };
        let file_type = FileType::from_raw_mode(stat.st_mode);
        let is_candidate = name.to_str().is_some_and(super::is_internal_temp_name);

        if is_candidate {
            if file_type == FileType::RegularFile {
                try_cleanup_stale_candidate(directory, &name, &relative_path, state);
            } else {
                state.report.skipped_unsafe = state.report.skipped_unsafe.saturating_add(1);
            }
        }

        if file_type != FileType::Directory {
            continue;
        }
        if depth >= state.limits.max_depth {
            state.report.depth_limit_reached = true;
            continue;
        }
        let child: File = match fs::openat2(
            directory,
            &name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
            state.resolve_flags,
        ) {
            Ok(fd) => fd.into(),
            Err(error) => {
                state.record_failure(
                    StaleUploadCleanupStage::OpenDirectory,
                    &relative_path,
                    error,
                );
                continue;
            }
        };
        let metadata = match child.metadata() {
            Ok(metadata) => metadata,
            Err(error) => {
                state.record_failure(
                    StaleUploadCleanupStage::ReadDirectoryMetadata,
                    &relative_path,
                    error,
                );
                continue;
            }
        };
        if !state
            .visited_directories
            .insert((metadata.dev(), metadata.ino()))
        {
            continue;
        }
        if !cleanup_stale_uploads_in_dir(&child, &relative_path, depth + 1, state)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn try_cleanup_stale_candidate(
    parent: &File,
    name: &OsStr,
    relative_path: &Path,
    state: &mut StaleUploadCleanupState,
) {
    try_cleanup_stale_candidate_with(
        parent,
        name,
        relative_path,
        state,
        |parent, name| fs::unlinkat(parent, name, AtFlags::empty()),
        |parent| fs::fsync(parent),
    );
}

fn try_cleanup_stale_candidate_with<U, S>(
    parent: &File,
    name: &OsStr,
    relative_path: &Path,
    state: &mut StaleUploadCleanupState,
    mut unlink: U,
    mut sync_parent: S,
) where
    U: FnMut(&File, &OsStr) -> std::result::Result<(), Errno>,
    S: FnMut(&File) -> std::result::Result<(), Errno>,
{
    let candidate: File = match fs::openat(
        parent,
        name,
        OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => fd.into(),
        Err(Errno::NOENT) => return,
        Err(error) => {
            state.record_failure(StaleUploadCleanupStage::OpenCandidate, relative_path, error);
            return;
        }
    };
    let metadata = match candidate.metadata() {
        Ok(metadata) => metadata,
        Err(error) => {
            state.record_failure(
                StaleUploadCleanupStage::ReadCandidateMetadata,
                relative_path,
                error,
            );
            return;
        }
    };
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
        || metadata.uid() != state.service_uid
    {
        state.report.skipped_unsafe = state.report.skipped_unsafe.saturating_add(1);
        return;
    }
    let Some(age) = metadata
        .modified()
        .ok()
        .and_then(|modified| state.now.duration_since(modified).ok())
    else {
        state.report.skipped_unsafe = state.report.skipped_unsafe.saturating_add(1);
        return;
    };
    if age < state.limits.min_age {
        state.report.skipped_young = state.report.skipped_young.saturating_add(1);
        return;
    }
    match flock(&candidate, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {}
        Err(Errno::WOULDBLOCK) => {
            state.report.skipped_active = state.report.skipped_active.saturating_add(1);
            return;
        }
        Err(error) => {
            state.record_failure(StaleUploadCleanupStage::LockCandidate, relative_path, error);
            return;
        }
    }

    // 按基名 unlink 前重新确认目录项仍指向已打开 inode。Linux 没有 unlink-by-fd；在所有查找
    // 都处于已固定父能力下的前提下，这是最紧密的抗竞态序列。
    // Re-check that the entry still names the opened inode before unlinking by basename. Linux has no
    // unlink-by-fd; this is the tightest race-resistant sequence beneath a pinned parent capability.
    let current = match fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(current) => current,
        Err(Errno::NOENT) => return,
        Err(error) => {
            state.record_failure(
                StaleUploadCleanupStage::RecheckCandidate,
                relative_path,
                error,
            );
            return;
        }
    };
    if current.st_dev != metadata.dev()
        || current.st_ino != metadata.ino()
        || FileType::from_raw_mode(current.st_mode) != FileType::RegularFile
    {
        state.report.skipped_unsafe = state.report.skipped_unsafe.saturating_add(1);
        return;
    }
    match unlink(parent, name) {
        Ok(()) => {
            state.report.deleted = state.report.deleted.saturating_add(1);
            if let Err(error) = sync_parent(parent) {
                state.record_failure(
                    StaleUploadCleanupStage::SyncParent(DurabilityStage::RemovedEntryParent),
                    relative_path,
                    durability_error(DurabilityStage::RemovedEntryParent, true, error),
                );
            }
        }
        Err(Errno::NOENT) => {}
        Err(error) => state.record_failure(
            StaleUploadCleanupStage::UnlinkCandidate,
            relative_path,
            typed_filesystem_error("unlinking a stale private candidate", error),
        ),
    }
}

impl TempCandidateKind {
    fn name(self) -> String {
        let prefix = match self {
            Self::Upload => ".ram-upload-",
            Self::Staging => ".ram-staging-",
        };
        format!("{prefix}{}.tmp", uuid::Uuid::new_v4())
    }
}

fn create_temp_in(
    parent: &File,
    kind: TempCandidateKind,
    created_ancestors: &mut Vec<CreatedAncestor>,
) -> Result<CreatedTempCandidate> {
    create_temp_in_with_reaper(parent, kind, candidate_reaper(), created_ancestors)
}

fn create_temp_in_with_reaper(
    parent: &File,
    kind: TempCandidateKind,
    reaper: &CandidateReaper,
    created_ancestors: &mut Vec<CreatedAncestor>,
) -> Result<CreatedTempCandidate> {
    if !reaper.healthy.load(Ordering::Acquire) {
        return Err(candidate_reaper_unavailable());
    }
    for _ in 0..16 {
        let name = OsString::from(kind.name());
        let cleanup_parent = parent.try_clone()?;
        match fs::openat(
            parent,
            &name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(fd) => {
                let file = File::from(fd);
                let owned_ancestors = std::mem::take(created_ancestors);
                let expectation = match file.metadata() {
                    Ok(metadata) => EntryExpectation::from_metadata(&metadata),
                    Err(error) => {
                        cleanup_created_candidate_after_failure(
                            reaper,
                            CandidateCleanup::unverified_candidate(
                                Some(cleanup_parent),
                                name,
                                owned_ancestors,
                                Some(file),
                            ),
                        );
                        return Err(error.into());
                    }
                };
                match secure_private_candidate(file) {
                    Ok((file, candidate_lock)) => {
                        // 封闭初始化/队列失败竞态。此代码始终在阻塞工作线程运行，因此可在返回
                        // 关闭失败错误前安全地同步移除刚创建候选。
                        // Close the initialization/queue-failure race. This always runs on a blocking
                        // worker, so synchronously remove the new candidate before failing closed.
                        if !reaper.healthy.load(Ordering::Acquire) {
                            drop(file);
                            cleanup_created_candidate_after_failure(
                                reaper,
                                CandidateCleanup::candidate(
                                    Some(cleanup_parent),
                                    name,
                                    expectation,
                                    owned_ancestors,
                                    Some(candidate_lock),
                                    None,
                                ),
                            );
                            return Err(candidate_reaper_unavailable());
                        }
                        return Ok(CreatedTempCandidate::new(
                            cleanup_parent,
                            name,
                            file,
                            candidate_lock,
                            expectation,
                            owned_ancestors,
                        ));
                    }
                    Err((err, file)) => {
                        cleanup_created_candidate_after_failure(
                            reaper,
                            CandidateCleanup::candidate(
                                Some(cleanup_parent),
                                name,
                                expectation,
                                owned_ancestors,
                                // 若初始化在之后克隆失败前已到达 flock，该描述符仍拥有锁；更早
                                // 的失败至少保留已打开 fd。
                                // If initialization reached flock before a later clone failed, this
                                // descriptor still owns it; earlier failures at least retain the fd.
                                Some(file),
                                None,
                            ),
                        );
                        return Err(err);
                    }
                }
            }
            Err(Errno::EXIST) => continue,
            Err(err) => return Err(err.into()),
        }
    }
    bail!("unable to allocate a unique temporary file")
}

fn secure_private_candidate(
    file: File,
) -> std::result::Result<(File, File), (anyhow::Error, File)> {
    // 检查或修复元数据前先取得所有权，防止最小年龄为零的周期扫描在候选初始化窗口锁定并
    // unlink 该 O_EXCL 名称。
    // Take ownership before inspecting or repairing metadata. This prevents a zero-min-age sweep from
    // locking and unlinking the O_EXCL name during candidate initialization.
    if let Err(err) = flock(&file, FlockOperation::NonBlockingLockExclusive) {
        return Err((
            anyhow!("failed to lock private upload candidate against startup cleanup: {err}"),
            file,
        ));
    }
    // openat 创建模式受进程 umask 过滤。使用前修复描述符本身，使极端 0777 umask 也不会
    // 产生被清理永久拒绝的崩溃候选。
    // openat creation mode is filtered by umask. Repair the descriptor before use so even 0777 cannot
    // produce a crash candidate cleanup permanently rejects.
    if let Err(err) = fs::fchmod(&file, Mode::from_raw_mode(0o600)) {
        return Err((err.into(), file));
    }
    let metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(error) => return Err((error.into(), file)),
    };
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err((
            anyhow!(
                "private upload candidate metadata is unsafe: mode={:04o}, uid={}, links={}, regular={}",
                metadata.mode() & 0o7777,
                metadata.uid(),
                metadata.nlink(),
                metadata.is_file(),
            ),
            file,
        ));
    }
    // 把候选交给请求代码前持久化其识别用私有模式。之后数据传输中崩溃会留下可被有界启动/
    // 周期恢复扫描器识别的文件。
    // Persist the identifying private mode before handing the candidate to request code, so a later
    // transfer crash leaves a file the bounded recovery scanner recognizes.
    if let Err(error) = file.sync_all() {
        return Err((
            durability_error(DurabilityStage::CandidateFile, false, error),
            file,
        ));
    }
    let candidate_lock = match file.try_clone() {
        Ok(lock) => lock,
        Err(err) => return Err((err.into(), file)),
    };
    Ok((file, candidate_lock))
}

fn merge_mutation_lock(
    requests: &mut BTreeMap<MutationLockKey, MutationLockMode>,
    key: MutationLockKey,
    mode: MutationLockMode,
) {
    requests
        .entry(key)
        .and_modify(|existing| *existing = (*existing).max(mode))
        .or_insert(mode);
}

fn strict_component_resolve_flags(allow_cross_filesystems: bool) -> ResolveFlags {
    let mut flags = ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS;
    if !allow_cross_filesystems {
        flags |= ResolveFlags::NO_XDEV;
    }
    flags
}

/// 只按逆序回滚本操作创建的目录。仅当固定父目录仍指向同一 inode 且目录为空时才删除；任何
/// 歧义都保留目录，避免误删外部写入者的替换物。
/// Roll back only directories created by this operation, in reverse order. Remove one only if the
/// pinned parent still names the same empty inode; ambiguity leaves it in place.
fn rollback_created_ancestors(created: &mut Vec<CreatedAncestor>) -> bool {
    while let Some(mut ancestor) = created.pop() {
        if ancestor.parent_sync_pending {
            if let Err(error) = fs::fsync(&ancestor.parent) {
                warn!(
                    "Failed to retry parent sync after rolling back ancestor {:?}: {error}",
                    ancestor.name
                );
                created.push(ancestor);
                return false;
            }
            continue;
        }
        let actual = match fs::statat(&ancestor.parent, &ancestor.name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => EntryExpectation::from_stat(&stat),
            Err(Errno::NOENT) => continue,
            Err(error) => {
                warn!(
                    "Failed to inspect auto-created ancestor {:?} during rollback: {error}",
                    ancestor.name
                );
                created.push(ancestor);
                return false;
            }
        };
        if !ancestor.expectation.same_object(actual) {
            warn!(
                "Auto-created ancestor {:?} changed identity; leaving it in place",
                ancestor.name
            );
            continue;
        }
        match fs::unlinkat(&ancestor.parent, &ancestor.name, AtFlags::REMOVEDIR) {
            Ok(()) => {
                ancestor.parent_sync_pending = true;
                if let Err(error) = fs::fsync(&ancestor.parent) {
                    warn!(
                        "Failed to sync parent after rolling back ancestor {:?}: {error}; retaining cleanup responsibility",
                        ancestor.name
                    );
                    created.push(ancestor);
                    return false;
                }
            }
            Err(Errno::NOENT) => {}
            Err(Errno::NOTEMPTY | Errno::EXIST) => {
                warn!(
                    "Auto-created ancestor {:?} is no longer empty; leaving it in place",
                    ancestor.name
                );
            }
            Err(error) => {
                warn!(
                    "Failed to roll back auto-created ancestor {:?}: {error}",
                    ancestor.name
                );
                created.push(ancestor);
                return false;
            }
        }
    }
    true
}

fn rollback_or_schedule_created_ancestors(created: &mut Vec<CreatedAncestor>) {
    if !rollback_created_ancestors(created) && !created.is_empty() {
        schedule_candidate_cleanup(CandidateCleanup::ancestors(std::mem::take(created)));
    }
}

fn validate_rel(path: &Path) -> Result<()> {
    for component in path.components() {
        let Component::Normal(name) = component else {
            bail!("path is not a normalized relative path");
        };
        validate_basename(name)?;
    }
    Ok(())
}

fn validate_basename(name: &OsStr) -> Result<()> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&0) {
        bail!("invalid path component");
    }
    if bytes.contains(&b'/') {
        bail!("basename contains a path separator");
    }
    Ok(())
}

fn proc_fd_target(file: &File) -> Result<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .context("failed to inspect an opened filesystem descriptor")
}

/// 以独立文件偏移重新打开保留的单文件描述符。`File::try_clone` 会共享 open-file description，
/// 让并发响应在游标上竞态；即使原基名被重命名或 unlink，`/proc/self/fd/N` 仍指向所持 inode。
/// Reopen a retained single-file descriptor with an independent offset. `File::try_clone` shares an
/// open-file description and cursor; `/proc/self/fd/N` names the held inode after rename/unlink.
fn reopen_pinned_file(pinned: &File) -> Result<File> {
    let path = PathBuf::from(format!("/proc/self/fd/{}", pinned.as_raw_fd()));
    let reopened: File = fs::open(
        &path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?
    .into();
    if !same_object(pinned, &reopened)? {
        bail!("reopened single-file descriptor changed object identity");
    }
    Ok(reopened)
}

fn deleted_proc_target(path: &Path) -> bool {
    path.as_os_str().as_bytes().ends_with(b" (deleted)")
}

fn same_object(left: &File, right: &File) -> Result<bool> {
    let left = left.metadata()?;
    let right = right.metadata()?;
    Ok(left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.file_type() == right.file_type())
}

#[cfg(test)]
mod stale_upload_cleanup_tests {
    use super::{
        CandidateCleanup, CandidateReaper, CleanupTracker, EntryExpectation, RootFs,
        STALE_CLEANUP_DIAGNOSTIC_CAUSE_MAX_BYTES, STALE_CLEANUP_DIAGNOSTIC_LIMIT,
        STALE_CLEANUP_DIAGNOSTIC_PATH_MAX_BYTES, StaleUploadCleanupLimits,
        StaleUploadCleanupReport, StaleUploadCleanupStage, StaleUploadCleanupState,
        TempCandidateKind, cleanup_created_candidate_after_failure_with, create_temp_in,
        create_temp_in_with_reaper, drain_candidate_cleanup, enqueue_candidate_cleanup,
        retain_degraded_cleanup, retry_retained_cleanups, secure_private_candidate,
        try_cleanup_stale_candidate_with,
    };
    use crate::server::error::{AdmissionError, AdmissionResource, DurabilityStage};
    use crate::server::walk::spawn_supervised_blocking;
    use anyhow::Result;
    use assert_fs::TempDir;
    use rustix::fs::{AtFlags, FlockOperation, ResolveFlags, flock};
    use rustix::io::Errno;
    use std::collections::HashSet;
    use std::ffi::OsStr;
    use std::fs::{File, FileTimes, OpenOptions};
    use std::os::unix::fs::{PermissionsExt, chown, symlink};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Condvar, Mutex, mpsc};
    use std::time::{Duration, Instant, SystemTime};
    use tokio::sync::Semaphore;

    const UPLOAD: &str = ".ram-upload-00000000-0000-4000-8000-000000000001.tmp";
    const STAGING: &str = ".ram-staging-00000000-0000-4000-8000-000000000002.tmp";

    struct DropProbe(Arc<AtomicBool>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    fn old_private_file(path: &Path) -> Result<File> {
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        file.set_times(
            FileTimes::new().set_modified(SystemTime::now() - Duration::from_secs(2 * 60 * 60)),
        )?;
        Ok(file)
    }

    fn limits() -> StaleUploadCleanupLimits {
        StaleUploadCleanupLimits {
            min_age: Duration::from_secs(60 * 60),
            max_entries: 1_000,
            max_depth: 16,
            max_deletions: 100,
            timeout: Duration::from_secs(2),
        }
    }

    fn cleanup_state() -> StaleUploadCleanupState {
        let limits = limits();
        StaleUploadCleanupState {
            limits,
            deadline: Instant::now() + limits.timeout,
            now: SystemTime::now(),
            service_uid: rustix::process::geteuid().as_raw(),
            resolve_flags: ResolveFlags::empty(),
            visited_directories: HashSet::new(),
            report: StaleUploadCleanupReport::default(),
        }
    }

    #[test]
    fn candidate_creation_repairs_permissions_removed_by_extreme_umask() -> Result<()> {
        let directory = TempDir::new()?;
        let path = directory.path().join(UPLOAD);
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o000))?;
        let (file, lock_clone) = secure_private_candidate(file).map_err(|(err, _file)| err)?;
        assert_eq!(file.metadata()?.permissions().mode() & 0o7777, 0o600);
        let competing = OpenOptions::new().read(true).write(true).open(&path)?;
        assert!(
            flock(&competing, FlockOperation::NonBlockingLockExclusive).is_err(),
            "candidate lock was not retained"
        );
        drop(lock_clone);
        drop(file);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_create_worker_drops_and_unlinks_its_owned_candidate() -> Result<()> {
        let directory = TempDir::new()?;
        let parent = File::open(directory.path())?;
        let (created_tx, created_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let request = tokio::spawn(async move {
            let _ = tokio::task::spawn_blocking(move || -> Result<_> {
                let candidate =
                    create_temp_in(&parent, TempCandidateKind::Upload, &mut Vec::new())?;
                created_tx.send(candidate.temp_name.clone())?;
                release_rx.recv()?;
                Ok(candidate)
            })
            .await;
        });
        let name = created_rx.recv_timeout(Duration::from_secs(1))?;
        assert!(directory.path().join(&name).exists());
        request.abort();
        release_tx.send(())?;
        let _ = request.await;

        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while directory.path().join(&name).exists() && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            !directory.path().join(&name).exists(),
            "cancelled create worker leaked a named private candidate"
        );
        Ok(())
    }

    #[test]
    fn global_reaper_drain_waits_until_queued_candidate_is_durable_absent() -> Result<()> {
        let directory = TempDir::new()?;
        let root = RootFs::new(directory.path(), false, false)?;
        let candidate = root.create_blocking_temp("target.bin", false, 0o700)?;
        let private_path = directory.path().join(&candidate.temp_name);
        let async_candidate = candidate.into_async_temp()?;
        assert!(private_path.exists());
        drop(async_candidate);

        assert!(
            drain_candidate_cleanup(Duration::from_secs(2)),
            "cleanup tracker did not drain before its deadline"
        );
        assert!(
            !private_path.exists(),
            "drain returned before candidate unlink and parent fsync completed"
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn saturated_reaper_never_unlinks_on_tokio_and_fails_future_creation_closed() -> Result<()>
    {
        let directory = TempDir::new()?;
        let name = std::ffi::OsString::from(UPLOAD);
        let path = directory.path().join(&name);
        std::fs::write(&path, b"private candidate")?;
        let (sender, receiver) = mpsc::sync_channel(0);
        let retained = Arc::new(Mutex::new(Vec::new()));
        let reaper = CandidateReaper {
            sender,
            healthy: Arc::new(AtomicBool::new(true)),
            retained: retained.clone(),
            tracker: Arc::new(CleanupTracker::default()),
        };
        let guard_dropped = Arc::new(AtomicBool::new(false));

        let started = std::time::Instant::now();
        enqueue_candidate_cleanup(
            &reaper,
            CandidateCleanup::candidate(
                Some(File::open(directory.path())?),
                name,
                EntryExpectation::from_metadata(&std::fs::metadata(&path)?),
                Vec::new(),
                None,
                Some(Box::new(DropProbe(guard_dropped.clone()))),
            ),
        );
        assert!(started.elapsed() < Duration::from_millis(100));
        assert!(
            path.exists(),
            "queue saturation performed a synchronous unlink"
        );
        assert!(!reaper.healthy.load(Ordering::Acquire));
        assert!(
            !guard_dropped.load(Ordering::Acquire),
            "queue saturation released admission before cleanup"
        );
        assert_eq!(retained.lock().unwrap().len(), 1);

        let parent = File::open(directory.path())?;
        let result = create_temp_in_with_reaper(
            &parent,
            TempCandidateKind::Upload,
            &reaper,
            &mut Vec::new(),
        );
        let error = match result {
            Ok(_) => panic!("degraded reaper allowed a new private candidate"),
            Err(error) => error,
        };
        assert!(matches!(
            AdmissionError::in_anyhow_chain(&error),
            Some(AdmissionError::Cancelled {
                resource: AdmissionResource::Uploads
            })
        ));
        assert_eq!(std::fs::read_dir(directory.path())?.count(), 1);
        drop(receiver);
        Ok(())
    }

    #[test]
    fn unlink_failure_and_missing_parent_retain_cleanup_guards_fail_closed() -> Result<()> {
        let directory = TempDir::new()?;
        // 不带 REMOVEDIR 的 unlinkat 对目录必然失败。
        // unlinkat without REMOVEDIR deterministically fails for a directory.
        std::fs::create_dir(directory.path().join(UPLOAD))?;
        let healthy = AtomicBool::new(true);
        let retained = Mutex::new(Vec::new());
        let unlink_guard_dropped = Arc::new(AtomicBool::new(false));
        let cleanup = CandidateCleanup::candidate(
            Some(File::open(directory.path())?),
            UPLOAD.into(),
            EntryExpectation::from_metadata(&std::fs::symlink_metadata(
                directory.path().join(UPLOAD),
            )?),
            Vec::new(),
            None,
            Some(Box::new(DropProbe(unlink_guard_dropped.clone()))),
        )
        .run()
        .expect("directory candidate must fail plain unlink");
        retain_degraded_cleanup(&healthy, &retained, cleanup);

        let clone_guard_dropped = Arc::new(AtomicBool::new(false));
        let cleanup = CandidateCleanup::candidate(
            None,
            STAGING.into(),
            EntryExpectation::Missing,
            Vec::new(),
            None,
            Some(Box::new(DropProbe(clone_guard_dropped.clone()))),
        )
        .run()
        .expect("a missing cleanup parent cannot confirm unlink");
        retain_degraded_cleanup(&healthy, &retained, cleanup);

        assert!(!healthy.load(Ordering::Acquire));
        assert_eq!(retained.lock().unwrap().len(), 2);
        assert!(!unlink_guard_dropped.load(Ordering::Acquire));
        assert!(!clone_guard_dropped.load(Ordering::Acquire));
        Ok(())
    }

    #[test]
    fn o_excl_candidate_failure_path_retains_full_record_when_unlink_fails() -> Result<()> {
        let directory = TempDir::new()?;
        let (sender, receiver) = mpsc::sync_channel(1);
        let retained = Arc::new(Mutex::new(Vec::new()));
        let reaper = CandidateReaper {
            sender,
            healthy: Arc::new(AtomicBool::new(true)),
            retained: retained.clone(),
            tracker: Arc::new(CleanupTracker::default()),
        };
        let parent = File::open(directory.path())?;
        let candidate = create_temp_in_with_reaper(
            &parent,
            TempCandidateKind::Upload,
            &reaper,
            &mut Vec::new(),
        )?;
        let (name, file, candidate_lock, expectation, _ancestors) = candidate.into_parts()?;
        drop(file);
        let path = directory.path().join(&name);
        assert!(path.exists(), "O_EXCL candidate was not created");
        let guard_dropped = Arc::new(AtomicBool::new(false));

        cleanup_created_candidate_after_failure_with(
            &reaper,
            CandidateCleanup::candidate(
                Some(File::open(directory.path())?),
                name,
                expectation,
                Vec::new(),
                Some(candidate_lock),
                Some(Box::new(DropProbe(guard_dropped.clone()))),
            ),
            |_parent, _name| Err(Errno::IO),
        );

        assert!(
            path.exists(),
            "injected unlink failure removed the candidate"
        );
        assert!(!reaper.healthy.load(Ordering::Acquire));
        assert_eq!(retained.lock().unwrap().len(), 1);
        assert!(
            !guard_dropped.load(Ordering::Acquire),
            "failed O_EXCL cleanup released its admission guard"
        );
        let error = match create_temp_in_with_reaper(
            &parent,
            TempCandidateKind::Upload,
            &reaper,
            &mut Vec::new(),
        ) {
            Ok(_) => panic!("degraded reaper allowed another O_EXCL candidate"),
            Err(error) => error,
        };
        assert!(matches!(
            AdmissionError::in_anyhow_chain(&error),
            Some(AdmissionError::Cancelled {
                resource: AdmissionResource::Uploads
            })
        ));
        drop(receiver);
        Ok(())
    }

    #[test]
    fn executor_retry_path_releases_cleanup_only_after_real_success() -> Result<()> {
        let directory = TempDir::new()?;
        let parent = File::open(directory.path())?;
        let candidate = create_temp_in(&parent, TempCandidateKind::Upload, &mut Vec::new())?;
        let (name, file, candidate_lock, expectation, ancestors) = candidate.into_parts()?;
        drop(file);
        let path = directory.path().join(&name);
        let cleanup = CandidateCleanup::candidate(
            Some(parent),
            name,
            expectation,
            ancestors,
            Some(candidate_lock),
            None,
        )
        .run_with(|_, _| Err(Errno::IO))
        .expect("first injected unlink failure must retain responsibility");
        let retained = Mutex::new(vec![cleanup]);

        retry_retained_cleanups(&retained);
        assert!(retained.lock().unwrap().is_empty());
        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn noent_cleanup_requires_parent_sync_before_releasing_responsibility() -> Result<()> {
        let directory = TempDir::new()?;
        let missing_path = directory.path().join(UPLOAD);
        std::fs::write(&missing_path, b"candidate")?;
        let expectation = EntryExpectation::from_metadata(&std::fs::metadata(&missing_path)?);
        std::fs::remove_file(&missing_path)?;
        let guard_dropped = Arc::new(AtomicBool::new(false));
        let mut sync_attempts = 0;
        let cleanup = CandidateCleanup::candidate(
            Some(File::open(directory.path())?),
            UPLOAD.into(),
            expectation,
            Vec::new(),
            None,
            Some(Box::new(DropProbe(guard_dropped.clone()))),
        )
        .run_with_ops(
            |_, _| panic!("statat NOENT must not attempt unlink"),
            |_| {
                sync_attempts += 1;
                Err(Errno::IO)
            },
        )
        .expect("failed parent sync must retain a missing-name cleanup record");
        assert_eq!(sync_attempts, 1);
        assert!(!guard_dropped.load(Ordering::Acquire));

        let mut retry_syncs = 0;
        assert!(
            cleanup
                .run_with_ops(
                    |_, _| panic!("parent-sync retry must not attempt unlink"),
                    |_| {
                        retry_syncs += 1;
                        Ok(())
                    },
                )
                .is_none()
        );
        assert_eq!(retry_syncs, 1);
        assert!(guard_dropped.load(Ordering::Acquire));

        let raced_path = directory.path().join(STAGING);
        std::fs::write(&raced_path, b"candidate")?;
        let expectation = EntryExpectation::from_metadata(&std::fs::metadata(&raced_path)?);
        let mut raced_syncs = 0;
        assert!(
            CandidateCleanup::candidate(
                Some(File::open(directory.path())?),
                STAGING.into(),
                expectation,
                Vec::new(),
                None,
                None,
            )
            .run_with_ops(
                |_, _| {
                    std::fs::remove_file(&raced_path).unwrap();
                    Err(Errno::NOENT)
                },
                |_| {
                    raced_syncs += 1;
                    Ok(())
                },
            )
            .is_none()
        );
        assert_eq!(raced_syncs, 1);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn timed_out_worker_owns_candidate_and_permit_until_cleanup_finishes() -> Result<()> {
        let directory = TempDir::new()?;
        let root = RootFs::new(directory.path(), false, false)?;
        let limiter = Arc::new(Semaphore::new(1));
        let permit = limiter.clone().acquire_owned().await?;
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let worker_release = release.clone();
        let (started_tx, started_rx) = mpsc::channel();

        let operation = spawn_supervised_blocking(permit, move |_cancellation| {
            let candidate = root.create_blocking_temp("target.bin", false, 0o700)?;
            started_tx.send(())?;
            let (lock, wake) = &*worker_release;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = wake
                    .wait_timeout(released, Duration::from_millis(10))
                    .unwrap()
                    .0;
            }
            drop(candidate);
            Ok(())
        });
        let state = operation.cancellation();
        started_rx.recv_timeout(Duration::from_secs(1))?;

        assert!(
            operation
                .wait_until(tokio::time::Instant::now() + Duration::from_millis(20))
                .await
                .is_err()
        );
        assert!(!state.worker_exited());
        assert!(limiter.clone().try_acquire_owned().is_err());
        assert_eq!(
            std::fs::read_dir(directory.path())?
                .filter_map(std::result::Result::ok)
                .filter(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".ram-upload-"))
                .count(),
            1
        );

        *release.0.lock().unwrap() = true;
        release.1.notify_all();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !state.worker_exited() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        assert!(limiter.try_acquire_owned().is_ok());
        assert_eq!(std::fs::read_dir(directory.path())?.count(), 0);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn panicked_worker_cleans_real_candidate_ancestors_and_guard() -> Result<()> {
        let directory = TempDir::new()?;
        let root = RootFs::new(directory.path(), false, false)?;
        let worker_root = root.clone();
        let guard_dropped = Arc::new(AtomicBool::new(false));
        let worker_guard_dropped = guard_dropped.clone();
        let (candidate_tx, candidate_rx) = mpsc::channel();

        let worker = tokio::task::spawn_blocking(move || -> Result<()> {
            let mut candidate =
                worker_root.create_blocking_temp("one/two/target.bin", true, 0o700)?;
            candidate_tx.send(candidate.temp_name.clone())?;
            candidate.attach_cleanup_guard(DropProbe(worker_guard_dropped))?;
            panic!("injected worker panic after candidate ownership");
        });
        let join_error = worker
            .await
            .expect_err("worker panic unexpectedly returned");
        assert!(join_error.is_panic());
        let candidate_name = candidate_rx.recv_timeout(Duration::from_secs(1))?;

        assert!(
            drain_candidate_cleanup(Duration::from_secs(2)),
            "candidate cleanup did not drain after worker panic"
        );
        assert!(
            guard_dropped.load(Ordering::Acquire),
            "worker panic released neither the candidate nor its attached guard"
        );
        assert!(
            !directory
                .path()
                .join("one/two")
                .join(candidate_name)
                .exists(),
            "worker panic leaked its private candidate"
        );
        assert!(
            !directory.path().join("one").exists(),
            "worker panic leaked auto-created candidate ancestors"
        );
        Ok(())
    }

    #[test]
    fn cleanup_removes_only_old_private_unlocked_regular_candidates() -> Result<()> {
        let directory = TempDir::new()?;
        drop(old_private_file(&directory.path().join(UPLOAD))?);
        drop(old_private_file(&directory.path().join(STAGING))?);

        let young = directory
            .path()
            .join(".ram-upload-00000000-0000-4000-8000-000000000003.tmp");
        std::fs::write(&young, b"young")?;
        std::fs::set_permissions(&young, std::fs::Permissions::from_mode(0o600))?;

        let public_mode = directory
            .path()
            .join(".ram-upload-00000000-0000-4000-8000-000000000004.tmp");
        drop(old_private_file(&public_mode)?);
        std::fs::set_permissions(&public_mode, std::fs::Permissions::from_mode(0o640))?;

        let hard_link = directory
            .path()
            .join(".ram-upload-00000000-0000-4000-8000-000000000005.tmp");
        drop(old_private_file(&hard_link)?);
        std::fs::hard_link(&hard_link, directory.path().join("hard-link-alias"))?;

        let symlink_target = directory.path().join("symlink-target");
        std::fs::write(&symlink_target, b"must survive")?;
        let candidate_symlink = directory
            .path()
            .join(".ram-upload-00000000-0000-4000-8000-000000000006.tmp");
        symlink(&symlink_target, &candidate_symlink)?;

        let candidate_directory = directory
            .path()
            .join(".ram-upload-00000000-0000-4000-8000-000000000007.tmp");
        std::fs::create_dir(&candidate_directory)?;

        let active = directory
            .path()
            .join(".ram-upload-00000000-0000-4000-8000-000000000008.tmp");
        let active_file = old_private_file(&active)?;
        flock(&active_file, FlockOperation::NonBlockingLockExclusive)?;

        let malformed_names = [
            ".ram-upload-not-a-uuid.tmp",
            ".ram-upload-00000000000040008000000000000000.tmp",
            ".ram-upload-00000000-0000-4000-8000-00000000000A.tmp",
            ".ram-upload-urn:uuid:00000000-0000-4000-8000-00000000000a.tmp",
            ".ram-upload-{00000000-0000-4000-8000-00000000000a}.tmp",
            ".ram-upload-00000000-0000-4000-8000-00000000000a-extra.tmp",
        ];
        let malformed = malformed_names
            .into_iter()
            .map(|name| directory.path().join(name))
            .collect::<Vec<_>>();
        for path in &malformed {
            drop(old_private_file(path)?);
        }
        let ordinary = directory.path().join("ordinary.txt");
        drop(old_private_file(&ordinary)?);

        let foreign = if rustix::process::geteuid().is_root() {
            let foreign = directory
                .path()
                .join(".ram-upload-00000000-0000-4000-8000-000000000009.tmp");
            drop(old_private_file(&foreign)?);
            match chown(&foreign, Some(65_534), None) {
                Ok(()) => Some(foreign),
                // 非特权用户命名空间内的 root 可能没有传统 nobody uid 映射。此时只是该环境
                // 无法测试所有权分支，并非清理失败。
                // Root in an unprivileged user namespace may lack a conventional nobody-uid mapping.
                // The ownership branch is untestable there, not a cleanup failure.
                Err(err)
                    if matches!(
                        err.raw_os_error(),
                        Some(code)
                            if code == Errno::INVAL.raw_os_error()
                                || code == Errno::PERM.raw_os_error()
                    ) =>
                {
                    std::fs::remove_file(foreign)?;
                    None
                }
                Err(err) => return Err(err.into()),
            }
        } else {
            None
        };

        let root = RootFs::new(directory.path(), false, false)?;
        let report = root.cleanup_stale_uploads(limits())?;
        assert_eq!(report.deleted, 2);
        assert_eq!(report.skipped_active, 1);
        assert_eq!(report.skipped_young, 1);
        assert!(
            !report.is_complete(),
            "unsafe reserved-name entries must make admission fail closed"
        );
        assert!(!directory.path().join(UPLOAD).exists());
        assert!(!directory.path().join(STAGING).exists());
        for path in [
            &young,
            &public_mode,
            &hard_link,
            &candidate_symlink,
            &candidate_directory,
            &active,
            &ordinary,
        ] {
            assert!(
                path.symlink_metadata().is_ok(),
                "cleanup removed an ineligible path: {path:?}"
            );
        }
        for path in malformed.iter().chain(foreign.iter()) {
            assert!(
                path.symlink_metadata().is_ok(),
                "cleanup removed an ineligible strict-name/owner path: {path:?}"
            );
        }
        assert_eq!(std::fs::read(&symlink_target)?, b"must survive");
        drop(active_file);
        Ok(())
    }

    #[test]
    fn young_candidate_is_revisited_after_aging_without_closing_admission() -> Result<()> {
        let directory = TempDir::new()?;
        let candidate = directory.path().join(UPLOAD);
        std::fs::write(&candidate, b"young candidate")?;
        std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o600))?;
        let root = RootFs::new(directory.path(), false, false)?;
        let mut scan_limits = limits();
        scan_limits.min_age = Duration::from_millis(100);

        let young_report = root.cleanup_stale_uploads(scan_limits)?;
        assert_eq!(young_report.deleted, 0);
        assert_eq!(young_report.skipped_young, 1);
        assert!(young_report.is_complete());
        root.ensure_candidate_recovery_healthy()?;
        assert!(candidate.exists());

        std::thread::sleep(Duration::from_millis(150));
        let mature_report = root.cleanup_stale_uploads(scan_limits)?;
        assert_eq!(mature_report.deleted, 1);
        assert_eq!(mature_report.skipped_young, 0);
        assert!(mature_report.is_complete());
        root.ensure_candidate_recovery_healthy()?;
        assert!(!candidate.exists());
        Ok(())
    }

    #[test]
    fn entry_budget_starvation_stickily_closes_candidate_admission() -> Result<()> {
        let directory = TempDir::new()?;
        let root = RootFs::new(directory.path(), false, false)?;
        assert!(root.cleanup_stale_uploads(limits())?.is_complete());

        // 普通目录本身消耗唯一条目预算。递归时上限已耗尽，因此无论 getdents 顺序如何，其
        // 子候选都确定不可达。
        // The ordinary directory consumes the sole entry budget. Recursion is already exhausted, so
        // its child candidate is unreachable regardless of getdents ordering.
        std::fs::create_dir(directory.path().join("ordinary-directory"))?;
        let candidate = directory.path().join("ordinary-directory").join(UPLOAD);
        drop(old_private_file(&candidate)?);

        let mut starved_limits = limits();
        starved_limits.max_entries = 1;
        let report = root.cleanup_stale_uploads(starved_limits)?;
        assert!(report.entry_limit_reached);
        assert_eq!(report.deleted, 0);
        assert!(!report.is_complete());
        assert!(candidate.exists());

        let error = match root.create_blocking_temp("new-upload.bin", false, 0o700) {
            Ok(_) => panic!("an incomplete recovery scan admitted a new candidate"),
            Err(error) => error,
        };
        assert!(matches!(
            AdmissionError::in_anyhow_chain(&error),
            Some(AdmissionError::Cancelled {
                resource: AdmissionResource::Uploads
            })
        ));

        // 之后完整扫描可能回收旧候选，但进程级闸门有意保持粘性：修正恢复预算或文件系统
        // 故障后，运维人员必须重启。
        // A later complete pass may reclaim the old candidate, but the process gate is deliberately
        // sticky: operators must restart after correcting recovery-budget/filesystem failure.
        let complete_report = root.cleanup_stale_uploads(limits())?;
        assert_eq!(complete_report.deleted, 1);
        assert!(complete_report.is_complete());
        assert!(root.ensure_candidate_recovery_healthy().is_err());
        Ok(())
    }

    #[test]
    fn cleanup_io_error_closes_candidate_admission_before_returning() -> Result<()> {
        let directory = TempDir::new()?;
        let root = RootFs::new(directory.path(), false, false)?;
        let injected = root.record_stale_upload_cleanup_result(Err(anyhow::anyhow!(
            "injected directory iteration failure"
        )));
        assert!(injected.is_err());

        let error = match root.create_blocking_temp("new-upload.bin", false, 0o700) {
            Ok(_) => panic!("a failed recovery scan admitted a new candidate"),
            Err(error) => error,
        };
        assert!(matches!(
            AdmissionError::in_anyhow_chain(&error),
            Some(AdmissionError::Cancelled {
                resource: AdmissionResource::Uploads
            })
        ));
        assert_eq!(std::fs::read_dir(directory.path())?.count(), 0);
        Ok(())
    }

    #[test]
    fn cleanup_failure_diagnostics_distinguish_unlink_and_parent_sync() -> Result<()> {
        let unlink_root = TempDir::new()?;
        let unlink_path = unlink_root.path().join(UPLOAD);
        drop(old_private_file(&unlink_path)?);
        let unlink_parent = File::open(unlink_root.path())?;
        let mut unlink_state = cleanup_state();
        try_cleanup_stale_candidate_with(
            &unlink_parent,
            OsStr::new(UPLOAD),
            Path::new(UPLOAD),
            &mut unlink_state,
            |_parent, _name| Err(Errno::IO),
            |_parent| panic!("an unlink failure must not attempt parent fsync"),
        );
        assert!(unlink_path.exists());
        assert_eq!(unlink_state.report.deleted, 0);
        assert_eq!(unlink_state.report.failures, 1);
        assert_eq!(unlink_state.report.failure_diagnostics.len(), 1);
        assert_eq!(
            unlink_state.report.failure_diagnostics[0].stage,
            StaleUploadCleanupStage::UnlinkCandidate
        );
        assert_eq!(
            unlink_state.report.failure_diagnostics[0].relative_path,
            UPLOAD
        );
        assert!(
            unlink_state.report.failure_diagnostics[0]
                .cause
                .contains("unlinking a stale private candidate")
        );
        assert!(!unlink_state.report.is_complete());

        let sync_root = TempDir::new()?;
        let sync_path = sync_root.path().join(STAGING);
        drop(old_private_file(&sync_path)?);
        let sync_parent = File::open(sync_root.path())?;
        let mut sync_state = cleanup_state();
        try_cleanup_stale_candidate_with(
            &sync_parent,
            OsStr::new(STAGING),
            Path::new(STAGING),
            &mut sync_state,
            |parent, name| rustix::fs::unlinkat(parent, name, AtFlags::empty()),
            |_parent| Err(Errno::IO),
        );
        assert!(!sync_path.exists());
        assert_eq!(sync_state.report.deleted, 1);
        assert_eq!(sync_state.report.failures, 1);
        assert_eq!(sync_state.report.failure_diagnostics.len(), 1);
        assert_eq!(
            sync_state.report.failure_diagnostics[0].stage,
            StaleUploadCleanupStage::SyncParent(DurabilityStage::RemovedEntryParent)
        );
        assert!(
            sync_state.report.failure_diagnostics[0]
                .cause
                .contains("durability")
        );
        assert!(!sync_state.report.is_complete());
        Ok(())
    }

    #[test]
    fn cleanup_failure_diagnostics_are_bounded_relative_and_suppress_the_rest() {
        let mut state = cleanup_state();
        let long_relative = PathBuf::from("x".repeat(STALE_CLEANUP_DIAGNOSTIC_PATH_MAX_BYTES * 2));
        for index in 0..(STALE_CLEANUP_DIAGNOSTIC_LIMIT + 2) {
            state.record_failure(
                StaleUploadCleanupStage::InspectEntry,
                &long_relative,
                anyhow::anyhow!(
                    "injected cause {index}\n{}",
                    "y".repeat(STALE_CLEANUP_DIAGNOSTIC_CAUSE_MAX_BYTES * 2)
                ),
            );
        }
        assert_eq!(state.report.failures, STALE_CLEANUP_DIAGNOSTIC_LIMIT + 2);
        assert_eq!(
            state.report.failure_diagnostics.len(),
            STALE_CLEANUP_DIAGNOSTIC_LIMIT
        );
        assert_eq!(state.report.suppressed_failures, 2);
        for diagnostic in &state.report.failure_diagnostics {
            assert!(diagnostic.relative_path.len() <= STALE_CLEANUP_DIAGNOSTIC_PATH_MAX_BYTES);
            assert!(diagnostic.cause.len() <= STALE_CLEANUP_DIAGNOSTIC_CAUSE_MAX_BYTES);
            assert!(!diagnostic.relative_path.starts_with('/'));
            assert!(!diagnostic.relative_path.chars().any(char::is_control));
            assert!(!diagnostic.cause.chars().any(char::is_control));
        }

        let mut absolute_state = cleanup_state();
        absolute_state.record_failure(
            StaleUploadCleanupStage::InspectEntry,
            Path::new("/outside/secret"),
            anyhow::anyhow!("injected absolute-path test"),
        );
        assert_eq!(
            absolute_state.report.failure_diagnostics[0].relative_path,
            "<invalid-capability-relative-path>"
        );
    }

    #[test]
    fn cleanup_honors_deletion_entry_depth_and_deadline_budgets() -> Result<()> {
        let deletion_root = TempDir::new()?;
        for index in 10..13 {
            let path = deletion_root.path().join(format!(
                ".ram-upload-00000000-0000-4000-8000-{index:012}.tmp"
            ));
            drop(old_private_file(&path)?);
        }
        let root = RootFs::new(deletion_root.path(), false, false)?;
        let mut deletion_limits = limits();
        deletion_limits.max_deletions = 1;
        let report = root.cleanup_stale_uploads(deletion_limits)?;
        assert_eq!(report.deleted, 1);
        assert!(report.deletion_limit_reached);
        assert_eq!(
            std::fs::read_dir(deletion_root.path())?.count(),
            2,
            "deletion budget was exceeded"
        );

        let entry_root = TempDir::new()?;
        for index in 0..3 {
            std::fs::write(entry_root.path().join(format!("ordinary-{index}")), b"x")?;
        }
        let root = RootFs::new(entry_root.path(), false, false)?;
        let mut entry_limits = limits();
        entry_limits.max_entries = 1;
        let report = root.cleanup_stale_uploads(entry_limits)?;
        assert_eq!(report.scanned_entries, 1);
        assert!(report.entry_limit_reached);

        let depth_root = TempDir::new()?;
        std::fs::create_dir_all(depth_root.path().join("one/two"))?;
        let deep_candidate = depth_root.path().join(format!("one/two/{UPLOAD}"));
        drop(old_private_file(&deep_candidate)?);
        let root = RootFs::new(depth_root.path(), false, false)?;
        let mut depth_limits = limits();
        depth_limits.max_depth = 1;
        let report = root.cleanup_stale_uploads(depth_limits)?;
        assert!(report.depth_limit_reached);
        assert!(deep_candidate.exists());

        let deadline_root = TempDir::new()?;
        let deadline_candidate = deadline_root.path().join(UPLOAD);
        drop(old_private_file(&deadline_candidate)?);
        let root = RootFs::new(deadline_root.path(), false, false)?;
        let mut deadline_limits = limits();
        deadline_limits.timeout = Duration::ZERO;
        let report = root.cleanup_stale_uploads(deadline_limits)?;
        assert!(report.deadline_reached);
        assert!(deadline_candidate.exists());
        Ok(())
    }
}

#[cfg(test)]
mod mutation_transaction_tests {
    use super::{
        CandidateCleanup, DirectorySyncPoint, EntryExpectation, MutationOps, NodeKind, RootFs,
        WalkAction, drain_candidate_cleanup, post_publish_directory_lookup_error,
        sync_renamed_parents_with, unavailable_capability_entry,
    };
    use crate::server::error::{AdmissionError, DurabilityStage, FsError, MutationEndpointRole};
    use crate::server::walk::RequestCancellation;
    use crate::server::{MutationGuards, MutationIntent, is_internal_temp_name};
    use anyhow::{Context, Result};
    use assert_fs::TempDir;
    use rustix::fs::{AtFlags, FlockOperation, Mode, OFlags, RenameFlags, flock};
    use rustix::io::Errno;
    use std::ffi::OsStr;
    use std::fs::File;
    use std::io::{self, Read as _, Write as _};
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::os::unix::net::UnixListener;
    use std::os::unix::process::CommandExt as _;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Barrier, mpsc};
    use std::time::Duration;

    fn empty_guards() -> MutationGuards {
        MutationGuards::new(Vec::new())
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ScriptedEvent {
        CandidateWrite,
        CandidateFlush,
        CandidateDataSync,
        NamespaceMkdir,
        NamespaceUnlink { directory: bool },
        NamespaceRename { no_replace: bool },
        PublishedChmod,
        PublishedFileSync,
        DirectorySync(DirectorySyncPoint),
    }

    #[derive(Default)]
    struct ScriptedOps {
        events: Vec<ScriptedEvent>,
        fail: Option<ScriptedEvent>,
        probe_candidate_lock_on_rename_failure: bool,
        candidate_lock_was_held: bool,
    }

    impl ScriptedOps {
        fn failing(event: ScriptedEvent) -> Self {
            Self {
                events: Vec::new(),
                fail: Some(event),
                probe_candidate_lock_on_rename_failure: false,
                candidate_lock_was_held: false,
            }
        }

        fn failing_candidate_rename() -> Self {
            Self {
                probe_candidate_lock_on_rename_failure: true,
                ..Self::failing(ScriptedEvent::NamespaceRename { no_replace: true })
            }
        }

        fn before(&mut self, event: ScriptedEvent) -> std::result::Result<(), Errno> {
            self.events.push(event);
            if self.fail == Some(event) {
                Err(Errno::IO)
            } else {
                Ok(())
            }
        }

        fn before_io(&mut self, event: ScriptedEvent) -> io::Result<()> {
            self.before(event)
                .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))
        }
    }

    impl MutationOps for ScriptedOps {
        fn write_candidate(&mut self, file: &mut File, data: &[u8]) -> io::Result<()> {
            self.before_io(ScriptedEvent::CandidateWrite)?;
            file.write_all(data)
        }

        fn flush_candidate(&mut self, file: &mut File) -> io::Result<()> {
            self.before_io(ScriptedEvent::CandidateFlush)?;
            std::io::Write::flush(file)
        }

        fn sync_candidate_data(&mut self, file: &File) -> io::Result<()> {
            self.before_io(ScriptedEvent::CandidateDataSync)?;
            file.sync_data()
        }

        fn mkdir(
            &mut self,
            parent: &File,
            name: &OsStr,
            mode: Mode,
        ) -> std::result::Result<(), Errno> {
            self.before(ScriptedEvent::NamespaceMkdir)?;
            rustix::fs::mkdirat(parent, name, mode)
        }

        fn unlink(
            &mut self,
            parent: &File,
            name: &OsStr,
            flags: AtFlags,
        ) -> std::result::Result<(), Errno> {
            self.before(ScriptedEvent::NamespaceUnlink {
                directory: flags.contains(AtFlags::REMOVEDIR),
            })?;
            rustix::fs::unlinkat(parent, name, flags)
        }

        fn rename(
            &mut self,
            source_parent: &File,
            source_name: &OsStr,
            destination_parent: &File,
            destination_name: &OsStr,
            no_replace: bool,
        ) -> std::result::Result<(), Errno> {
            let before = self.before(ScriptedEvent::NamespaceRename { no_replace });
            if before.is_err() && self.probe_candidate_lock_on_rename_failure {
                let competing: File = rustix::fs::openat(
                    source_parent,
                    source_name,
                    OFlags::RDONLY | OFlags::CLOEXEC,
                    Mode::empty(),
                )?
                .into();
                self.candidate_lock_was_held = matches!(
                    flock(&competing, FlockOperation::NonBlockingLockExclusive),
                    Err(Errno::WOULDBLOCK)
                );
            }
            before?;
            if no_replace {
                rustix::fs::renameat_with(
                    source_parent,
                    source_name,
                    destination_parent,
                    destination_name,
                    RenameFlags::NOREPLACE,
                )
            } else {
                rustix::fs::renameat(
                    source_parent,
                    source_name,
                    destination_parent,
                    destination_name,
                )
            }
        }

        fn chmod_published(&mut self, file: &File, mode: Mode) -> std::result::Result<(), Errno> {
            self.before(ScriptedEvent::PublishedChmod)?;
            rustix::fs::fchmod(file, mode)
        }

        fn sync_published_file(&mut self, file: &File) -> io::Result<()> {
            self.before_io(ScriptedEvent::PublishedFileSync)?;
            file.sync_all()
        }

        fn sync_directory(
            &mut self,
            directory: &File,
            point: DirectorySyncPoint,
        ) -> std::result::Result<(), Errno> {
            self.before(ScriptedEvent::DirectorySync(point))?;
            rustix::fs::fsync(directory)
        }
    }

    fn assert_durability(error: &anyhow::Error, stage: DurabilityStage, published: bool) {
        assert!(
            matches!(
                FsError::in_anyhow_chain(error),
                Some(FsError::Durability {
                    stage: actual_stage,
                    published: actual_published,
                    ..
                }) if *actual_stage == stage && *actual_published == published
            ),
            "unexpected durability classification: {error:#}"
        );
    }

    #[test]
    fn scripted_put_commit_orders_real_publication() -> Result<()> {
        let directory = TempDir::new()?;
        let root = RootFs::new(directory.path(), false, false)?;
        let mut candidate = root.create_blocking_temp("target.bin", false, 0o700)?;
        let mut ops = ScriptedOps::default();
        candidate.write_all_with_ops(b"published content", &mut ops)?;
        candidate.commit_with_ops(
            EntryExpectation::Missing,
            0o640,
            &RequestCancellation::new(),
            &mut ops,
        )?;

        assert_eq!(
            std::fs::read(directory.path().join("target.bin"))?,
            b"published content"
        );
        assert_eq!(
            ops.events,
            vec![
                ScriptedEvent::CandidateWrite,
                ScriptedEvent::CandidateFlush,
                ScriptedEvent::CandidateDataSync,
                ScriptedEvent::NamespaceRename { no_replace: true },
                ScriptedEvent::PublishedChmod,
                ScriptedEvent::PublishedFileSync,
                ScriptedEvent::DirectorySync(DirectorySyncPoint::DestinationParent),
            ]
        );
        Ok(())
    }

    #[test]
    fn scripted_put_prepublish_failures_clean_candidate_ancestors_with_lock_held() -> Result<()> {
        let directory = TempDir::new()?;
        let root = RootFs::new(directory.path(), false, false)?;
        let mut candidate = root.create_blocking_temp("one/two/target.bin", true, 0o700)?;
        let mut ops = ScriptedOps::failing(ScriptedEvent::CandidateWrite);
        let error = candidate
            .write_all_with_ops(b"candidate", &mut ops)
            .unwrap_err();
        assert_durability(&error, DurabilityStage::CandidateFile, false);
        drop(candidate);
        assert!(drain_candidate_cleanup(std::time::Duration::from_secs(2)));
        assert!(
            !directory.path().join("one").exists(),
            "candidate-write failure left a temporary file or auto-created parent"
        );

        for failure in [
            ScriptedEvent::CandidateFlush,
            ScriptedEvent::CandidateDataSync,
        ] {
            let directory = TempDir::new()?;
            let root = RootFs::new(directory.path(), false, false)?;
            let mut candidate = root.create_blocking_temp("one/two/target.bin", true, 0o700)?;
            candidate.write_all(b"candidate")?;
            let mut ops = ScriptedOps::failing(failure);
            let error = candidate
                .commit_with_ops(
                    EntryExpectation::Missing,
                    0o640,
                    &RequestCancellation::new(),
                    &mut ops,
                )
                .unwrap_err();
            assert_durability(&error, DurabilityStage::CandidateFile, false);
            assert!(!directory.path().join("one").exists());
        }

        let directory = TempDir::new()?;
        let root = RootFs::new(directory.path(), false, false)?;
        let mut candidate = root.create_blocking_temp("one/two/target.bin", true, 0o700)?;
        candidate.write_all(b"candidate")?;
        let mut ops = ScriptedOps::failing_candidate_rename();
        let error = candidate
            .commit_with_ops(
                EntryExpectation::Missing,
                0o640,
                &RequestCancellation::new(),
                &mut ops,
            )
            .unwrap_err();
        assert!(
            FsError::in_anyhow_chain(&error)
                .is_none_or(|error| !matches!(error, FsError::Durability { .. })),
            "prepublication rename failure was mislabeled as durability: {error:#}"
        );
        assert!(
            ops.candidate_lock_was_held,
            "candidate flock was released before the injected rename failure"
        );
        assert!(drain_candidate_cleanup(std::time::Duration::from_secs(2)));
        assert!(!directory.path().join("one").exists());
        Ok(())
    }

    #[test]
    fn scripted_put_postpublish_failures_keep_visible_target_and_marker() -> Result<()> {
        for (failure, expected_stage) in [
            (
                ScriptedEvent::PublishedFileSync,
                DurabilityStage::PublishedFile,
            ),
            (
                ScriptedEvent::DirectorySync(DirectorySyncPoint::DestinationParent),
                DurabilityStage::DestinationParent,
            ),
        ] {
            let directory = TempDir::new()?;
            let root = RootFs::new(directory.path(), false, false)?;
            let mut candidate = root.create_blocking_temp("target.bin", false, 0o700)?;
            candidate.write_all(b"published despite sync failure")?;
            let mut ops = ScriptedOps::failing(failure);
            let error = candidate
                .commit_with_ops(
                    EntryExpectation::Missing,
                    0o640,
                    &RequestCancellation::new(),
                    &mut ops,
                )
                .unwrap_err();
            assert_durability(&error, expected_stage, true);
            assert_eq!(
                std::fs::read(directory.path().join("target.bin"))?,
                b"published despite sync failure"
            );
            assert_eq!(
                std::fs::read_dir(directory.path())?.count(),
                1,
                "post-publication sync failure left a private candidate"
            );
        }
        Ok(())
    }

    fn expected_namespace_race(error: &anyhow::Error) -> bool {
        matches!(
            FsError::in_anyhow_chain(error),
            Some(
                FsError::NotFound { .. }
                    | FsError::Conflict { .. }
                    | FsError::OutsideRoot { .. }
                    | FsError::Changed { .. }
            )
        )
    }

    /// 能力边界的有界并发回归：外部命名空间变更器反复重命名/替换服务名称并指向同级秘密，
    /// 同时 RootFs 并发读取和原子写入。成功读取只能观察完整安全版本，任何写入都不得到达
    /// 同级目标。
    /// Bounded concurrency regression for the capability boundary. An external mutator repeatedly
    /// replaces the served name with a sibling secret during RootFs reads/writes. Reads see only
    /// complete safe generations and writes never reach the sibling.
    #[test]
    fn concurrent_rename_symlink_replace_reads_and_writes_stay_beneath_root() -> Result<()> {
        const MUTATIONS: usize = 160;
        const READS: usize = 320;
        const WRITES: usize = 160;
        const DEADLINE: Duration = Duration::from_secs(10);

        let sandbox = TempDir::new()?;
        let served = sandbox.path().join("served");
        std::fs::create_dir(&served)?;
        let slot = served.join("slot");
        let held = served.join("held");
        let outside = sandbox.path().join("outside-secret");
        std::fs::write(&slot, b"safe-initial")?;
        std::fs::write(&outside, b"outside-secret-must-never-be-read-or-written")?;

        let root = RootFs::new(&served, false, false)?;
        let barrier = Arc::new(Barrier::new(4));
        let stop = Arc::new(AtomicBool::new(false));
        let (done_tx, done_rx) = mpsc::channel::<(&'static str, std::result::Result<(), String>)>();

        std::thread::scope(|scope| -> Result<()> {
            let mutator_barrier = barrier.clone();
            let mutator_stop = stop.clone();
            let mutator_done = done_tx.clone();
            let mutator_slot = slot.clone();
            let mutator_held = held.clone();
            let mutator_outside = outside.clone();
            let mutator_served = served.clone();
            let mutator = scope.spawn(move || {
                mutator_barrier.wait();
                let result = (|| -> Result<()> {
                    for generation in 0..MUTATIONS {
                        if mutator_stop.load(Ordering::Acquire) {
                            break;
                        }
                        let _ = std::fs::remove_file(&mutator_held);
                        let _ = std::fs::rename(&mutator_slot, &mutator_held);
                        match symlink(&mutator_outside, &mutator_slot) {
                            Ok(()) => std::thread::yield_now(),
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    io::ErrorKind::AlreadyExists | io::ErrorKind::NotFound
                                ) => {}
                            Err(error) => return Err(error.into()),
                        }
                        let _ = std::fs::remove_file(&mutator_slot);
                        if std::fs::rename(&mutator_held, &mutator_slot).is_err() {
                            let replacement =
                                mutator_served.join(format!("replacement-{generation}"));
                            std::fs::write(&replacement, format!("safe-{generation:03}"))?;
                            let _ = std::fs::rename(&replacement, &mutator_slot);
                            let _ = std::fs::remove_file(replacement);
                        }
                    }
                    Ok(())
                })()
                .map_err(|error| format!("{error:#}"));
                let _ = mutator_done.send(("mutator", result));
            });

            let reader_barrier = barrier.clone();
            let reader_stop = stop.clone();
            let reader_done = done_tx.clone();
            let reader_root = root.clone();
            let reader = scope.spawn(move || {
                reader_barrier.wait();
                let result = (|| -> Result<()> {
                    for _ in 0..READS {
                        if reader_stop.load(Ordering::Acquire) {
                            break;
                        }
                        match reader_root.open_raw(Path::new("slot"), NodeKind::File) {
                            Ok(mut file) => {
                                let mut body = Vec::new();
                                std::io::Read::by_ref(&mut file)
                                    .take(128)
                                    .read_to_end(&mut body)?;
                                assert!(
                                    body == b"safe-initial"
                                        || body.starts_with(b"safe-")
                                        || body.starts_with(b"writer-"),
                                    "capability read unexpected bytes: {:?}",
                                    String::from_utf8_lossy(&body)
                                );
                            }
                            Err(error) if expected_namespace_race(&error) => {}
                            Err(error) => return Err(error),
                        }
                    }
                    Ok(())
                })()
                .map_err(|error| format!("{error:#}"));
                let _ = reader_done.send(("reader", result));
            });

            let writer_barrier = barrier.clone();
            let writer_stop = stop.clone();
            let writer_done = done_tx.clone();
            let writer_root = root.clone();
            let writer = scope.spawn(move || {
                writer_barrier.wait();
                let result = (|| -> Result<()> {
                    for generation in 0..WRITES {
                        if writer_stop.load(Ordering::Acquire) {
                            break;
                        }
                        let expected = match writer_root.entry_expectation_sync(Path::new("slot")) {
                            Ok(expected) => expected,
                            Err(error) if expected_namespace_race(&error) => continue,
                            Err(error) => return Err(error),
                        };
                        let mut candidate =
                            writer_root.create_blocking_temp("slot", false, 0o700)?;
                        candidate.write_all(format!("writer-{generation:03}").as_bytes())?;
                        if let Err(error) =
                            candidate.commit(expected, 0o600, &RequestCancellation::new())
                            && !expected_namespace_race(&error)
                        {
                            return Err(error);
                        }
                    }
                    Ok(())
                })()
                .map_err(|error| format!("{error:#}"));
                let _ = writer_done.send(("writer", result));
            });

            barrier.wait();
            drop(done_tx);
            let mut failures = Vec::new();
            for _ in 0..3 {
                match done_rx.recv_timeout(DEADLINE) {
                    Ok((_name, Ok(()))) => {}
                    Ok((name, Err(error))) => failures.push(format!("{name}: {error}")),
                    Err(error) => {
                        stop.store(true, Ordering::Release);
                        failures.push(format!("stress worker exceeded {DEADLINE:?}: {error}"));
                        break;
                    }
                }
            }
            stop.store(true, Ordering::Release);
            for (name, result) in [
                ("mutator", mutator.join()),
                ("reader", reader.join()),
                ("writer", writer.join()),
            ] {
                if result.is_err() {
                    failures.push(format!("{name} panicked"));
                }
            }
            assert!(failures.is_empty(), "{}", failures.join("; "));
            Ok(())
        })?;

        assert!(drain_candidate_cleanup(Duration::from_secs(2)));
        assert_eq!(
            std::fs::read(&outside)?,
            b"outside-secret-must-never-be-read-or-written"
        );
        for entry in std::fs::read_dir(&served)? {
            let name = entry?.file_name();
            if let Some(name) = name.to_str() {
                assert!(!is_internal_temp_name(name), "leaked candidate {name}");
            }
        }
        Ok(())
    }

    #[test]
    fn scripted_mkcol_sync_order_and_failures_preserve_rollback() -> Result<()> {
        let directory = TempDir::new()?;
        let root = RootFs::new(directory.path(), false, false)?;
        let mut ops = ScriptedOps::default();
        root.mkdir_sync_with_ops(Path::new("collection"), 0o710, &mut ops)?;
        assert!(directory.path().join("collection").is_dir());
        assert_eq!(
            ops.events,
            vec![
                ScriptedEvent::NamespaceMkdir,
                ScriptedEvent::DirectorySync(DirectorySyncPoint::CreatedDirectory),
                ScriptedEvent::DirectorySync(DirectorySyncPoint::CreatedDirectoryParent),
            ]
        );

        let failed_mkdir_root = TempDir::new()?;
        let root = RootFs::new(failed_mkdir_root.path(), false, false)?;
        let mut ops = ScriptedOps::failing(ScriptedEvent::NamespaceMkdir);
        let error = root
            .mkdir_sync_with_ops(Path::new("collection"), 0o710, &mut ops)
            .unwrap_err();
        assert!(FsError::in_anyhow_chain(&error).is_none());
        assert!(!failed_mkdir_root.path().join("collection").exists());

        for failure in [
            ScriptedEvent::DirectorySync(DirectorySyncPoint::CreatedDirectory),
            ScriptedEvent::DirectorySync(DirectorySyncPoint::CreatedDirectoryParent),
        ] {
            let directory = TempDir::new()?;
            let root = RootFs::new(directory.path(), false, false)?;
            let mut ops = ScriptedOps::failing(failure);
            let error = root
                .mkdir_sync_with_ops(Path::new("collection"), 0o710, &mut ops)
                .unwrap_err();
            assert_durability(&error, DurabilityStage::CreatedDirectory, true);
            assert!(
                !directory.path().join("collection").exists(),
                "failed MKCOL did not roll back its exact new directory"
            );
        }
        Ok(())
    }

    #[test]
    fn scripted_delete_syncs_file_and_directory_and_marks_postunlink_failure() -> Result<()> {
        for (name, directory_entry) in [("file", false), ("collection", true)] {
            let directory = TempDir::new()?;
            if directory_entry {
                std::fs::create_dir(directory.path().join(name))?;
            } else {
                std::fs::write(directory.path().join(name), b"content")?;
            }
            let root = RootFs::new(directory.path(), false, false)?;
            let expected = root.entry_expectation_sync(Path::new(name))?;
            let mut ops = ScriptedOps::default();
            root.remove_sync_with_ops(
                Path::new(name),
                false,
                expected,
                8,
                8,
                &RequestCancellation::new(),
                &mut ops,
                |_| {},
            )?;
            assert!(!directory.path().join(name).exists());
            assert_eq!(
                ops.events,
                vec![
                    ScriptedEvent::NamespaceUnlink {
                        directory: directory_entry,
                    },
                    ScriptedEvent::DirectorySync(DirectorySyncPoint::RemovedEntryParent),
                ]
            );
        }

        let directory = TempDir::new()?;
        std::fs::write(directory.path().join("file"), b"content")?;
        let root = RootFs::new(directory.path(), false, false)?;
        let expected = root.entry_expectation_sync(Path::new("file"))?;
        let mut ops = ScriptedOps::failing(ScriptedEvent::NamespaceUnlink { directory: false });
        let error = root
            .remove_sync_with_ops(
                Path::new("file"),
                false,
                expected,
                8,
                8,
                &RequestCancellation::new(),
                &mut ops,
                |_| {},
            )
            .unwrap_err();
        assert!(FsError::in_anyhow_chain(&error).is_none());
        assert_eq!(std::fs::read(directory.path().join("file"))?, b"content");

        let directory = TempDir::new()?;
        std::fs::write(directory.path().join("file"), b"content")?;
        let root = RootFs::new(directory.path(), false, false)?;
        let expected = root.entry_expectation_sync(Path::new("file"))?;
        let mut ops = ScriptedOps::failing(ScriptedEvent::DirectorySync(
            DirectorySyncPoint::RemovedEntryParent,
        ));
        let error = root
            .remove_sync_with_ops(
                Path::new("file"),
                false,
                expected,
                8,
                8,
                &RequestCancellation::new(),
                &mut ops,
                |_| {},
            )
            .unwrap_err();
        assert_durability(&error, DurabilityStage::RemovedEntryParent, true);
        assert!(!directory.path().join("file").exists());
        Ok(())
    }

    #[test]
    fn scripted_move_attempts_cross_parent_syncs_and_rolls_back_before_rename() -> Result<()> {
        let directory = TempDir::new()?;
        std::fs::create_dir(directory.path().join("source-parent"))?;
        std::fs::create_dir(directory.path().join("destination-parent"))?;
        std::fs::write(
            directory.path().join("source-parent/source"),
            b"move content",
        )?;
        let root = RootFs::new(directory.path(), false, false)?;
        let expected_source = root.entry_expectation_sync(Path::new("source-parent/source"))?;
        let mut ops = ScriptedOps::failing(ScriptedEvent::DirectorySync(
            DirectorySyncPoint::DestinationParent,
        ));
        let error = root
            .rename_sync_with_ops(
                Path::new("source-parent/source"),
                Path::new("destination-parent/destination"),
                false,
                expected_source,
                EntryExpectation::Missing,
                &mut ops,
            )
            .unwrap_err();
        assert_durability(&error, DurabilityStage::DestinationParent, true);
        assert_eq!(
            ops.events,
            vec![
                ScriptedEvent::NamespaceRename { no_replace: true },
                ScriptedEvent::DirectorySync(DirectorySyncPoint::DestinationParent),
                ScriptedEvent::DirectorySync(DirectorySyncPoint::SourceParent),
            ]
        );
        assert!(!directory.path().join("source-parent/source").exists());
        assert_eq!(
            std::fs::read(directory.path().join("destination-parent/destination"))?,
            b"move content"
        );

        let directory = TempDir::new()?;
        std::fs::write(directory.path().join("source"), b"source remains")?;
        let root = RootFs::new(directory.path(), false, false)?;
        let expected_source = root.entry_expectation_sync(Path::new("source"))?;
        let mut ops = ScriptedOps::failing(ScriptedEvent::NamespaceRename { no_replace: true });
        let error = root
            .rename_sync_with_ops(
                Path::new("source"),
                Path::new("new/parent/destination"),
                true,
                expected_source,
                EntryExpectation::Missing,
                &mut ops,
            )
            .unwrap_err();
        assert!(
            FsError::in_anyhow_chain(&error)
                .is_none_or(|error| !matches!(error, FsError::Durability { .. }))
        );
        assert_eq!(
            std::fs::read(directory.path().join("source"))?,
            b"source remains"
        );
        assert!(!directory.path().join("new").exists());

        let directory = TempDir::new()?;
        std::fs::write(directory.path().join("source"), b"same parent")?;
        let root = RootFs::new(directory.path(), false, false)?;
        let expected_source = root.entry_expectation_sync(Path::new("source"))?;
        let mut ops = ScriptedOps::default();
        root.rename_sync_with_ops(
            Path::new("source"),
            Path::new("destination"),
            false,
            expected_source,
            EntryExpectation::Missing,
            &mut ops,
        )?;
        assert_eq!(
            ops.events,
            vec![
                ScriptedEvent::NamespaceRename { no_replace: true },
                ScriptedEvent::DirectorySync(DirectorySyncPoint::DestinationParent),
            ]
        );
        Ok(())
    }

    #[test]
    fn post_mkdir_lookup_failures_never_degrade_to_not_found_or_forbidden() {
        for errno in [
            rustix::io::Errno::NOENT,
            rustix::io::Errno::NOTDIR,
            rustix::io::Errno::LOOP,
            rustix::io::Errno::XDEV,
        ] {
            let error = post_publish_directory_lookup_error(
                Path::new("new/directory"),
                "published directory",
                "fault-injected lookup",
                errno,
            );
            assert!(
                matches!(
                    FsError::in_anyhow_chain(&error),
                    Some(FsError::Changed {
                        role: MutationEndpointRole::Target,
                        ..
                    })
                ),
                "namespace race errno {errno} was not Changed: {error:#}"
            );
        }

        for errno in [rustix::io::Errno::ACCESS, rustix::io::Errno::IO] {
            let error = post_publish_directory_lookup_error(
                Path::new("new/directory"),
                "published directory",
                "fault-injected lookup",
                errno,
            );
            assert!(
                matches!(
                    FsError::in_anyhow_chain(&error),
                    Some(FsError::Durability {
                        published: true,
                        ..
                    })
                ),
                "infrastructure errno {errno} was not published durability: {error:#}"
            );
        }
    }

    #[test]
    fn mutation_helpers_preserve_closed_outside_root_and_changed_markers() -> Result<()> {
        let served = TempDir::new()?;
        let outside = TempDir::new()?;
        let root = RootFs::new(served.path(), false, true)?;
        symlink(outside.path(), served.path().join("escape"))?;

        for error in [
            root.entry_expectation_sync(Path::new("escape/new.bin"))
                .expect_err("escaping expectation parent must fail"),
            root.entry_size_nofollow(Path::new("escape/new.bin"))
                .expect_err("escaping size parent must fail"),
            root.ensure_dir_sync(Path::new("escape/new"), 0o700)
                .err()
                .expect("escaping ancestor creation must fail"),
            root.resolve_mutation_locks_sync(&[MutationIntent::write("escape/new.bin")])
                .expect_err("escaping lock prefix must fail"),
        ] {
            assert!(
                matches!(
                    FsError::in_anyhow_chain(&error),
                    Some(FsError::OutsideRoot { .. })
                ),
                "closed OutsideRoot marker was overwritten: {error:#}"
            );
        }
        assert!(
            !outside.path().join("new").exists(),
            "ensure_dir_sync created outside the served capability"
        );

        std::fs::create_dir(served.path().join("parent"))?;
        let parent = root.open_parent_sync(Path::new("parent/file.bin"), false)?;
        std::fs::rename(
            served.path().join("parent"),
            served.path().join("replaced-parent"),
        )?;
        symlink(outside.path(), served.path().join("parent"))?;
        let error = root
            .verify_parent_with_role(&parent, MutationEndpointRole::Destination)
            .expect_err("replaced mutation parent must fail");
        assert!(
            matches!(
                FsError::in_anyhow_chain(&error),
                Some(FsError::Changed {
                    role: MutationEndpointRole::Destination,
                    ..
                })
            ),
            "parent namespace replacement was reclassified: {error:#}"
        );
        Ok(())
    }

    #[test]
    fn traversal_skips_only_closed_unavailable_names_not_permission_or_io_failures() {
        let not_found = anyhow::Error::new(FsError::from_anyhow(
            "opening traversal entry",
            anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::NotFound)),
        ));
        let outside = anyhow::Error::new(FsError::outside_root(
            "opening traversal entry",
            anyhow::anyhow!("link target is outside the authorized traversal root"),
        ));
        assert!(unavailable_capability_entry(&not_found));
        assert!(unavailable_capability_entry(&outside));

        let forbidden = anyhow::Error::new(FsError::from_anyhow(
            "opening traversal entry",
            anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
        ));
        let io = anyhow::Error::new(FsError::io(
            "opening traversal entry",
            std::io::Error::other("injected device failure"),
        ));
        assert!(
            !unavailable_capability_entry(&forbidden),
            "EACCES must abort search/archive instead of returning a partial 200"
        );
        assert!(
            !unavailable_capability_entry(&io),
            "I/O failures must abort search/archive instead of returning a partial 200"
        );
    }

    #[test]
    fn real_traversal_io_failure_aborts_instead_of_returning_partial_success() -> Result<()> {
        let served = TempDir::new()?;
        std::fs::write(served.path().join("ordinary.txt"), b"visible")?;
        let socket_path = served.path().join("unopenable.sock");
        let _socket = UnixListener::bind(&socket_path).with_context(|| {
            let mode = std::fs::metadata(served.path())
                .map(|metadata| format!("{:04o}", metadata.mode() & 0o7777))
                .unwrap_or_else(|_| "unavailable".to_owned());
            let umask = std::fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|status| {
                    status
                        .lines()
                        .find(|line| line.starts_with("Umask:"))
                        .map(str::to_owned)
                })
                .unwrap_or_else(|| "Umask: unavailable".to_owned());
            format!(
                "AF_UNIX traversal fixture bind failed for `{}` (parent mode {mode}; {umask})",
                socket_path.display()
            )
        })?;
        let root = RootFs::new(served.path(), false, false)?;
        let running = AtomicBool::new(true);
        let cancelled = AtomicBool::new(false);
        let error = root
            .walk(vec![PathBuf::new()], &running, &cancelled, 32, 4, |_| {
                Ok(WalkAction::Continue)
            })
            .expect_err("a Unix socket cannot be opened as file content");
        assert!(
            matches!(FsError::in_anyhow_chain(&error), Some(FsError::Io { .. })),
            "real traversal I/O failure was silently skipped or reclassified: {error:#}"
        );
        Ok(())
    }

    #[test]
    fn candidate_parent_depth_cannot_exceed_recovery_scan_depth() -> Result<()> {
        let directory = TempDir::new()?;
        std::fs::create_dir_all(directory.path().join("one/two/three"))?;
        let identity = crate::path_identity::ServedPathIdentity::capture(directory.path(), false)?;
        let root =
            RootFs::from_verified_identity_with_candidate_cleanup(&identity, false, false, 2)?;

        let at_boundary = root.create_blocking_temp("one/two/file.bin", false, 0o700)?;
        drop(at_boundary);

        let error = match root.create_blocking_temp("one/two/three/file.bin", false, 0o700) {
            Ok(_) => panic!("candidate deeper than its recovery scan was accepted"),
            Err(error) => error,
        };
        assert!(matches!(
            AdmissionError::in_anyhow_chain(&error),
            Some(AdmissionError::LimitExceeded {
                resource: crate::server::error::AdmissionResource::WalkDepth,
                ..
            })
        ));
        assert_eq!(
            std::fs::read_dir(directory.path().join("one/two/three"))?.count(),
            0
        );
        Ok(())
    }

    #[test]
    fn move_attempts_both_parent_syncs_even_when_destination_sync_fails() -> Result<()> {
        let directory = TempDir::new()?;
        std::fs::create_dir(directory.path().join("source-parent"))?;
        std::fs::create_dir(directory.path().join("destination-parent"))?;
        let source = File::open(directory.path().join("source-parent"))?;
        let destination = File::open(directory.path().join("destination-parent"))?;
        let mut stages = Vec::new();
        let error = sync_renamed_parents_with(&destination, &source, false, |_parent, stage| {
            stages.push(stage);
            Err(rustix::io::Errno::IO)
        })
        .unwrap_err();
        assert_eq!(
            stages,
            vec![
                DurabilityStage::DestinationParent,
                DurabilityStage::SourceParent,
            ]
        );
        assert!(matches!(
            FsError::in_anyhow_chain(&error),
            Some(FsError::Durability {
                published: true,
                ..
            })
        ));

        let mut same_parent_calls = 0;
        sync_renamed_parents_with(&destination, &destination, true, |_parent, _stage| {
            same_parent_calls += 1;
            Ok(())
        })?;
        assert_eq!(same_parent_calls, 1);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn extreme_umask_subprocess_helper() -> Result<()> {
        let Some(root_path) = std::env::var_os("RAM_MODE_UMASK_TEST_ROOT") else {
            return Ok(());
        };
        assert!(
            !rustix::process::geteuid().is_root(),
            "extreme-umask helper must run without root permission"
        );
        rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o777));
        let root_path = std::path::PathBuf::from(root_path);
        let root = RootFs::new(&root_path, false, false)?;
        root.mkdir("collection", 0o710, empty_guards()).await?;
        let mut candidate = root.create_blocking_temp("one/two/fresh.bin", true, 0o710)?;
        candidate.file_mut().write_all(b"content")?;
        candidate.commit(
            EntryExpectation::Missing,
            0o640,
            &RequestCancellation::new(),
        )?;
        assert_eq!(
            std::fs::metadata(root_path.join("collection"))?.mode() & 0o7777,
            0o710
        );
        assert_eq!(
            std::fs::metadata(root_path.join("one"))?.mode() & 0o7777,
            0o710
        );
        assert_eq!(
            std::fs::metadata(root_path.join("one/two"))?.mode() & 0o7777,
            0o710
        );
        assert_eq!(
            std::fs::metadata(root_path.join("one/two/fresh.bin"))?.mode() & 0o7777,
            0o640
        );
        Ok(())
    }

    #[test]
    fn configured_modes_ignore_an_extreme_process_umask() -> Result<()> {
        let directory = TempDir::new()?;
        let mut command = Command::new(std::env::current_exe()?);
        if rustix::process::geteuid().is_root() {
            let uid = rustix::fs::Uid::from_raw(65_534);
            let gid = rustix::fs::Gid::from_raw(65_534);
            if let Err(error) = rustix::fs::chown(directory.path(), Some(uid), Some(gid)) {
                if matches!(error, rustix::io::Errno::PERM | rustix::io::Errno::INVAL) {
                    eprintln!(
                        "skipping non-root extreme-umask test: nobody uid is not mapped: {error}"
                    );
                    return Ok(());
                }
                return Err(error.into());
            }
            command.gid(gid.as_raw()).uid(uid.as_raw());
        }
        let output = command
            .arg("--exact")
            .arg("server::filesystem::mutation_transaction_tests::extreme_umask_subprocess_helper")
            .arg("--nocapture")
            .env("RAM_MODE_UMASK_TEST_ROOT", directory.path())
            .env("RUST_TEST_THREADS", "1")
            .output()?;
        assert!(
            output.status.success(),
            "umask helper failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::metadata(directory.path().join("collection"))?.mode() & 0o7777,
            0o710
        );
        assert_eq!(
            std::fs::metadata(directory.path().join("one"))?.mode() & 0o7777,
            0o710
        );
        assert_eq!(
            std::fs::metadata(directory.path().join("one/two"))?.mode() & 0o7777,
            0o710
        );
        assert_eq!(
            std::fs::metadata(directory.path().join("one/two/fresh.bin"))?.mode() & 0o7777,
            0o640
        );
        Ok(())
    }

    #[test]
    fn commit_rejects_present_and_missing_namespace_replacements() -> Result<()> {
        for initially_present in [true, false] {
            let directory = TempDir::new()?;
            let root = RootFs::new(directory.path(), false, false)?;
            let target = directory.path().join("target.bin");
            if initially_present {
                std::fs::write(&target, b"selected A")?;
            }
            let expected = root.entry_expectation_sync(Path::new("target.bin"))?;
            let mut candidate = root.create_blocking_temp("target.bin", false, 0o700)?;
            candidate.file_mut().write_all(b"candidate")?;

            if initially_present {
                std::fs::rename(&target, directory.path().join("selected-a.bin"))?;
            }
            std::fs::write(&target, b"attacker B")?;
            let error = candidate
                .commit(expected, 0o640, &RequestCancellation::new())
                .unwrap_err();
            assert!(matches!(
                FsError::in_anyhow_chain(&error),
                Some(FsError::Changed { .. })
            ));
            assert_eq!(std::fs::read(&target)?, b"attacker B");
            assert_eq!(
                std::fs::read_dir(directory.path())?
                    .filter_map(std::result::Result::ok)
                    .filter(|entry| entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".ram-upload-"))
                    .count(),
                0
            );
        }
        Ok(())
    }

    #[test]
    fn create_only_eexist_keeps_mkcol_upload_and_destination_race_roles() -> Result<()> {
        let directory = TempDir::new()?;
        let root = RootFs::new(directory.path(), false, false)?;
        let parent = root.open_parent_sync(Path::new("target.bin"), false)?;

        for role in [
            MutationEndpointRole::Target,
            MutationEndpointRole::Destination,
        ] {
            let error =
                parent.create_only_error(EntryExpectation::Missing, role, rustix::io::Errno::EXIST);
            assert!(matches!(
                FsError::in_anyhow_chain(&error),
                Some(FsError::Changed {
                    role: actual_role,
                    ..
                }) if *actual_role == role
            ));
        }
        Ok(())
    }

    #[test]
    fn copy_source_revalidation_rejects_namespace_replacement() -> Result<()> {
        let directory = TempDir::new()?;
        std::fs::write(directory.path().join("source.bin"), b"selected A")?;
        let root = RootFs::new(directory.path(), false, false)?;
        let source = root.open_raw(Path::new("source.bin"), NodeKind::File)?;
        let expected = EntryExpectation::from_metadata(&source.metadata()?);
        std::fs::rename(
            directory.path().join("source.bin"),
            directory.path().join("selected-a.bin"),
        )?;
        std::fs::write(directory.path().join("source.bin"), b"attacker B")?;
        let error = root
            .verify_opened_entry_sync(
                Path::new("source.bin"),
                &source,
                expected,
                MutationEndpointRole::Source,
            )
            .unwrap_err();
        assert!(matches!(
            FsError::in_anyhow_chain(&error),
            Some(FsError::Changed {
                role: MutationEndpointRole::Source,
                ..
            })
        ));
        assert_eq!(
            std::fs::read(directory.path().join("source.bin"))?,
            b"attacker B"
        );
        Ok(())
    }

    #[test]
    fn publication_modes_are_exact_strip_special_bits_and_break_hardlinks() -> Result<()> {
        let directory = TempDir::new()?;
        let root = RootFs::new(directory.path(), false, false)?;

        let mut fresh = root.create_blocking_temp("fresh.bin", false, 0o700)?;
        fresh.file_mut().write_all(b"fresh")?;
        fresh.commit(
            EntryExpectation::Missing,
            0o4_751,
            &RequestCancellation::new(),
        )?;
        assert_eq!(
            std::fs::metadata(directory.path().join("fresh.bin"))?.mode() & 0o7777,
            0o751
        );

        let target = directory.path().join("target.bin");
        let alias = directory.path().join("alias.bin");
        std::fs::write(&target, b"old inode")?;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o674))?;
        std::fs::hard_link(&target, &alias)?;
        let expected = root.entry_expectation_sync(Path::new("target.bin"))?;
        let old_mode = std::fs::metadata(&target)?.mode() & 0o777;
        let old_inode = std::fs::metadata(&target)?.ino();
        let mut replacement = root.create_blocking_temp("target.bin", false, 0o700)?;
        replacement.file_mut().write_all(b"new inode")?;
        replacement.commit(expected, old_mode, &RequestCancellation::new())?;
        let metadata = std::fs::metadata(&target)?;
        assert_eq!(metadata.mode() & 0o7777, 0o674);
        assert_ne!(metadata.ino(), old_inode);
        assert_eq!(std::fs::read(&target)?, b"new inode");
        assert_eq!(std::fs::read(&alias)?, b"old inode");
        Ok(())
    }

    #[test]
    fn failed_candidate_rolls_back_only_its_exact_empty_ancestors() -> Result<()> {
        let directory = TempDir::new()?;
        let root = RootFs::new(directory.path(), false, false)?;
        let candidate = root.create_blocking_temp("one/two/file.bin", true, 0o710)?;
        assert_eq!(
            std::fs::metadata(directory.path().join("one"))?.mode() & 0o7777,
            0o710
        );
        assert_eq!(
            std::fs::metadata(directory.path().join("one/two"))?.mode() & 0o7777,
            0o710
        );
        drop(candidate);
        assert!(!directory.path().join("one").exists());

        let candidate = root.create_blocking_temp("one/two/file.bin", true, 0o700)?;
        std::fs::rename(
            directory.path().join("one"),
            directory.path().join("original-one"),
        )?;
        std::fs::create_dir(directory.path().join("one"))?;
        std::fs::write(directory.path().join("one/replacement"), b"must survive")?;
        drop(candidate);
        assert_eq!(
            std::fs::read(directory.path().join("one/replacement"))?,
            b"must survive"
        );
        Ok(())
    }

    #[test]
    fn failed_reaper_attempt_retains_ancestor_rollback_responsibility() -> Result<()> {
        let directory = TempDir::new()?;
        let root = RootFs::new(directory.path(), false, false)?;
        let mut candidate = root.create_blocking_temp("one/two/file.bin", true, 0o700)?;
        let cleanup = CandidateCleanup::candidate(
            Some(candidate.parent.fd.try_clone()?),
            candidate.temp_name.clone(),
            candidate.candidate_expectation,
            std::mem::take(&mut candidate.parent.created_ancestors),
            candidate.candidate_lock.take(),
            candidate.cleanup_guard.take(),
        );
        candidate.committed = true;
        drop(candidate);

        let cleanup = cleanup
            .run_with(|_parent, _name| Err(rustix::io::Errno::IO))
            .expect("failed unlink must retain the complete cleanup record");
        assert_eq!(cleanup.created_ancestors.len(), 2);
        assert!(
            directory
                .path()
                .join("one/two")
                .join(&cleanup.name)
                .exists()
        );
        assert!(directory.path().join("one/two").exists());

        assert!(cleanup.run().is_none());
        assert!(!directory.path().join("one").exists());
        Ok(())
    }

    #[test]
    fn candidate_replacement_is_neither_published_nor_unlinked() -> Result<()> {
        let directory = TempDir::new()?;
        let root = RootFs::new(directory.path(), false, false)?;
        let mut candidate = root.create_blocking_temp("one/two/target.bin", true, 0o700)?;
        let candidate_path = directory.path().join("one/two").join(&candidate.temp_name);
        let moved_path = directory.path().join("one/two/original-candidate");
        std::fs::rename(&candidate_path, &moved_path)?;
        std::fs::write(&candidate_path, b"attacker replacement B")?;

        let error = candidate
            .parent
            .verify_candidate_identity(&candidate.temp_name, candidate.candidate_expectation)
            .unwrap_err();
        assert!(matches!(
            FsError::in_anyhow_chain(&error),
            Some(FsError::Changed { .. })
        ));
        assert!(!directory.path().join("one/two/target.bin").exists());

        let cleanup = CandidateCleanup::candidate(
            Some(candidate.parent.fd.try_clone()?),
            candidate.temp_name.clone(),
            candidate.candidate_expectation,
            std::mem::take(&mut candidate.parent.created_ancestors),
            candidate.candidate_lock.take(),
            candidate.cleanup_guard.take(),
        );
        candidate.committed = true;
        drop(candidate);
        let cleanup = cleanup
            .run()
            .expect("replacement identity must keep cleanup fail-closed");
        assert_eq!(std::fs::read(&candidate_path)?, b"attacker replacement B");

        std::fs::remove_file(&candidate_path)?;
        std::fs::remove_file(&moved_path)?;
        assert!(cleanup.run().is_none());
        assert!(!directory.path().join("one").exists());
        Ok(())
    }

    #[test]
    fn delete_rejects_replacement_and_recursive_budgets_are_zero_mutation() -> Result<()> {
        let directory = TempDir::new()?;
        let root = RootFs::new(directory.path(), false, false)?;
        std::fs::write(directory.path().join("target"), b"A")?;
        let expected = root.entry_expectation_sync(Path::new("target"))?;
        std::fs::rename(
            directory.path().join("target"),
            directory.path().join("selected-a"),
        )?;
        std::fs::write(directory.path().join("target"), b"B")?;
        let error = root
            .remove_sync(
                Path::new("target"),
                false,
                expected,
                10,
                10,
                &RequestCancellation::new(),
            )
            .unwrap_err();
        assert!(matches!(
            FsError::in_anyhow_chain(&error),
            Some(FsError::Changed { .. })
        ));
        assert_eq!(std::fs::read(directory.path().join("target"))?, b"B");

        for (limit, succeeds) in [(2, false), (3, true), (4, true)] {
            let case = TempDir::new()?;
            std::fs::create_dir(case.path().join("tree"))?;
            for name in ["a", "b", "c"] {
                std::fs::write(case.path().join("tree").join(name), name)?;
            }
            let root = RootFs::new(case.path(), false, false)?;
            let expected = root.entry_expectation_sync(Path::new("tree"))?;
            let result = root.remove_sync(
                Path::new("tree"),
                true,
                expected,
                limit,
                8,
                &RequestCancellation::new(),
            );
            assert_eq!(result.is_ok(), succeeds, "entry limit {limit}");
            if succeeds {
                assert!(!case.path().join("tree").exists());
            } else {
                assert!(AdmissionError::in_anyhow_chain(&result.unwrap_err()).is_some());
                assert_eq!(std::fs::read_dir(case.path().join("tree"))?.count(), 3);
            }
        }

        for (limit, succeeds) in [(1, false), (2, true), (3, true)] {
            let case = TempDir::new()?;
            std::fs::create_dir_all(case.path().join("tree/one/two"))?;
            std::fs::write(case.path().join("tree/one/two/file"), b"x")?;
            let root = RootFs::new(case.path(), false, false)?;
            let expected = root.entry_expectation_sync(Path::new("tree"))?;
            let result = root.remove_sync(
                Path::new("tree"),
                true,
                expected,
                16,
                limit,
                &RequestCancellation::new(),
            );
            assert_eq!(result.is_ok(), succeeds, "depth limit {limit}");
            if !succeeds {
                assert!(case.path().join("tree/one/two/file").exists());
            }
        }
        Ok(())
    }

    #[test]
    fn recursive_delete_cancellation_after_mutation_is_durably_partial() -> Result<()> {
        let directory = TempDir::new()?;
        std::fs::create_dir(directory.path().join("tree"))?;
        std::fs::write(directory.path().join("tree/a"), b"a")?;
        std::fs::write(directory.path().join("tree/b"), b"b")?;
        let root = RootFs::new(directory.path(), false, false)?;
        let expected = root.entry_expectation_sync(Path::new("tree"))?;
        let cancellation = RequestCancellation::new();
        let cancel_from_hook = cancellation.clone();
        let error = root
            .remove_sync_with_observer(
                Path::new("tree"),
                true,
                expected,
                8,
                8,
                &cancellation,
                move |removed| {
                    if removed == 1 {
                        cancel_from_hook.cancel();
                    }
                },
            )
            .unwrap_err();
        assert!(AdmissionError::in_anyhow_chain(&error).is_some());
        assert!(directory.path().join("tree").exists());
        assert_eq!(std::fs::read_dir(directory.path().join("tree"))?.count(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn move_rechecks_both_source_and_destination_versions() -> Result<()> {
        for replace_source in [true, false] {
            let directory = TempDir::new()?;
            std::fs::write(directory.path().join("source"), b"source A")?;
            std::fs::write(directory.path().join("destination"), b"destination A")?;
            let root = RootFs::new(directory.path(), false, false)?;
            let expected_source = root.entry_expectation_sync(Path::new("source"))?;
            let expected_destination = root.entry_expectation_sync(Path::new("destination"))?;
            let replaced = if replace_source {
                "source"
            } else {
                "destination"
            };
            std::fs::rename(
                directory.path().join(replaced),
                directory.path().join(format!("{replaced}-a")),
            )?;
            std::fs::write(directory.path().join(replaced), b"attacker B")?;
            let error = root
                .rename(
                    "source",
                    "destination",
                    false,
                    expected_source,
                    expected_destination,
                    empty_guards(),
                )
                .await
                .unwrap_err();
            assert!(matches!(
                FsError::in_anyhow_chain(&error),
                Some(FsError::Changed { .. })
            ));
            assert_eq!(
                std::fs::read(directory.path().join(replaced))?,
                b"attacker B"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn failed_move_rolls_back_its_auto_created_destination_ancestors() -> Result<()> {
        let directory = TempDir::new()?;
        std::fs::write(directory.path().join("source"), b"source A")?;
        let root = RootFs::new(directory.path(), false, false)?;
        let expected_source = root.entry_expectation_sync(Path::new("source"))?;
        let expected_destination =
            root.entry_expectation_sync(Path::new("new/deep/destination"))?;

        std::fs::rename(
            directory.path().join("source"),
            directory.path().join("selected-source-a"),
        )?;
        std::fs::write(directory.path().join("source"), b"attacker B")?;
        let error = root
            .rename(
                "source",
                "new/deep/destination",
                true,
                expected_source,
                expected_destination,
                empty_guards(),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            FsError::in_anyhow_chain(&error),
            Some(FsError::Changed {
                role: MutationEndpointRole::Source,
                ..
            })
        ));
        assert_eq!(
            std::fs::read(directory.path().join("source"))?,
            b"attacker B"
        );
        assert!(
            !directory.path().join("new").exists(),
            "failed MOVE leaked its auto-created destination ancestors"
        );
        Ok(())
    }
}

#[cfg(test)]
mod root_identity_tests {
    use super::{NodeKind, RootFs};
    use crate::path_identity::ServedPathIdentity;
    use anyhow::Result;
    use assert_fs::TempDir;
    use rustix::fs::ResolveFlags;
    use std::io::Read;
    use std::path::Path;

    #[test]
    fn verified_root_uses_pinned_directory_after_namespace_replacement() -> Result<()> {
        let temp = TempDir::new()?;
        let served = temp.path().join("served");
        let moved = temp.path().join("validated-but-moved");
        std::fs::create_dir(&served)?;
        std::fs::write(served.join("trusted.txt"), b"trusted")?;
        let expected = ServedPathIdentity::capture(&served, false)?;

        std::fs::rename(&served, &moved)?;
        std::fs::create_dir(&served)?;
        std::fs::write(served.join("decoy.txt"), b"decoy")?;
        let root = RootFs::from_verified_identity(&expected, false, false)?;
        let mut trusted = root.open_raw(Path::new("trusted.txt"), NodeKind::File)?;
        let mut body = String::new();
        trusted.read_to_string(&mut body)?;
        assert_eq!(body, "trusted");
        assert!(
            root.open_raw(Path::new("decoy.txt"), NodeKind::File)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn verified_single_file_uses_pinned_inode_after_namespace_replacement() -> Result<()> {
        let temp = TempDir::new()?;
        let served = temp.path().join("served.txt");
        std::fs::write(&served, b"validated")?;
        let expected = ServedPathIdentity::capture(&served, true)?;

        std::fs::remove_file(&served)?;
        std::fs::write(&served, b"replacement")?;
        let root = RootFs::from_verified_identity(&expected, false, false)?;
        let mut opened = root.open_raw(Path::new("served.txt"), NodeKind::File)?;
        let mut body = String::new();
        opened.read_to_string(&mut body)?;
        assert_eq!(body, "validated");
        Ok(())
    }

    #[test]
    fn initialized_single_file_keeps_serving_only_the_pinned_inode() -> Result<()> {
        let temp = TempDir::new()?;
        let served = temp.path().join("served.txt");
        let moved = temp.path().join("old.txt");
        std::fs::write(&served, b"validated inode")?;
        let expected = ServedPathIdentity::capture(&served, true)?;
        let root = RootFs::from_verified_identity(&expected, false, false)?;

        std::fs::rename(&served, &moved)?;
        std::fs::remove_file(&moved)?;
        std::fs::write(&served, b"replacement secret")?;

        let mut first = root.open_raw(Path::new("served.txt"), NodeKind::File)?;
        let mut second = root.open_raw(Path::new("served.txt"), NodeKind::File)?;
        let mut first_body = String::new();
        let mut second_body = String::new();
        first.read_to_string(&mut first_body)?;
        second.read_to_string(&mut second_body)?;
        assert_eq!(first_body, "validated inode");
        assert_eq!(second_body, "validated inode");
        assert_eq!(
            root.real_relative_verified(&first)?,
            Path::new("served.txt")
        );
        Ok(())
    }

    #[test]
    fn single_file_readiness_tracks_the_configured_namespace_identity() -> Result<()> {
        let temp = TempDir::new()?;
        let parent = temp.path().join("configured-parent");
        let moved_parent = temp.path().join("startup-parent");
        std::fs::create_dir(&parent)?;
        let served = parent.join("served.txt");
        std::fs::write(&served, b"startup inode")?;
        let expected = ServedPathIdentity::capture(&served, true)?;
        let root = RootFs::from_verified_identity(&expected, false, false)?;
        expected.verify_namespace()?;

        std::fs::rename(&parent, &moved_parent)?;
        std::fs::create_dir(&parent)?;
        std::fs::write(&served, b"replacement inode")?;
        assert!(
            expected.verify_namespace().is_err(),
            "replacement of an ancestor must make readiness fail"
        );

        let mut opened = root.open_raw(Path::new("served.txt"), NodeKind::File)?;
        let mut body = String::new();
        opened.read_to_string(&mut body)?;
        assert_eq!(
            body, "startup inode",
            "read requests must remain pinned to the startup capability"
        );
        Ok(())
    }

    #[test]
    fn no_xdev_policy_is_default_and_compatibility_must_be_explicit() -> Result<()> {
        let temp = TempDir::new()?;
        let expected = ServedPathIdentity::capture(temp.path(), false)?;
        let strict = RootFs::from_verified_identity(&expected, false, false)?;
        assert!(strict.resolve_flags().contains(ResolveFlags::NO_XDEV));

        let compatibility = RootFs::from_verified_identity(&expected, false, true)?;
        assert!(
            !compatibility
                .resolve_flags()
                .contains(ResolveFlags::NO_XDEV)
        );
        Ok(())
    }
}

#[cfg(test)]
mod blocking_admission_tests {
    use super::{FilesystemBlockingAdmission, GuardedBlockingFile, NodeKind, RootFs};
    use crate::server::error::{AdmissionError, AdmissionResource};
    use anyhow::Result;
    use assert_fs::TempDir;
    use std::io::SeekFrom;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, mpsc};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    fn single_blocking_worker_runtime() -> Result<tokio::runtime::Runtime> {
        Ok(tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(1)
            .enable_all()
            .build()?)
    }

    async fn wait_for_permits(
        admission: &FilesystemBlockingAdmission,
        expected: usize,
    ) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(2), async {
            while admission.available_permits() != expected {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok(())
    }

    fn assert_filesystem_admission_timeout(error: &anyhow::Error) {
        assert!(matches!(
            AdmissionError::in_anyhow_chain(error),
            Some(AdmissionError::Timeout {
                resource: AdmissionResource::FilesystemTasks,
                ..
            })
        ));
    }

    /// 中文：即使被取消任务尚在 Tokio blocking queue，闭包捕获的唯一许可仍封住队列；
    /// worker 最终弹出 abort 任务时不得执行用户闭包，并在那之后才归还容量。
    /// English: A cancelled task queued behind Tokio's only blocking worker keeps the sole permit,
    /// bounding the queue. Dequeuing the aborted task must not execute user work and only then frees capacity.
    #[test]
    fn queued_cancellation_keeps_admission_bounded_until_dequeue() -> Result<()> {
        let runtime = single_blocking_worker_runtime()?;
        let admission = FilesystemBlockingAdmission::new(1, Duration::from_millis(50));
        let (blocker_started_tx, blocker_started_rx) = mpsc::sync_channel(1);
        let (release_blocker_tx, release_blocker_rx) = mpsc::sync_channel(1);
        let blocker = runtime.spawn_blocking(move || {
            blocker_started_tx.send(()).expect("test is listening");
            release_blocker_rx.recv().expect("test releases blocker");
        });
        blocker_started_rx.recv_timeout(Duration::from_secs(2))?;

        let executed = Arc::new(AtomicBool::new(false));
        let queued_executed = executed.clone();
        let queued_admission = admission.clone();
        let queued = runtime.spawn(async move {
            queued_admission
                .run(move || {
                    queued_executed.store(true, Ordering::SeqCst);
                    Ok(())
                })
                .await
        });
        runtime.block_on(wait_for_permits(&admission, 0))?;
        queued.abort();
        let cancellation = runtime
            .block_on(queued)
            .expect_err("request task is cancelled");
        assert!(cancellation.is_cancelled());
        assert_eq!(admission.available_permits(), 0);

        let timeout = runtime
            .block_on(admission.run(|| Ok(())))
            .expect_err("the queued aborted closure still owns the sole permit");
        assert_filesystem_admission_timeout(&timeout);

        release_blocker_tx.send(())?;
        runtime.block_on(blocker)?;
        runtime.block_on(wait_for_permits(&admission, 1))?;
        assert!(!executed.load(Ordering::SeqCst));
        Ok(())
    }

    /// 中文：`spawn_blocking` 已开始后 abort 无法停止 syscall；许可必须由真实闭包保留到
    /// 返回，不能因 HTTP/request future 被丢弃而提前允许第二个文件系统任务进入。
    /// English: Once `spawn_blocking` starts, abort cannot stop a syscall. The real closure must keep
    /// admission until return instead of admitting a second filesystem task when its request future drops.
    #[test]
    fn running_cancellation_keeps_permit_until_worker_returns() -> Result<()> {
        let runtime = single_blocking_worker_runtime()?;
        let admission = FilesystemBlockingAdmission::new(1, Duration::from_millis(50));
        let (worker_started_tx, worker_started_rx) = mpsc::sync_channel(1);
        let (release_worker_tx, release_worker_rx) = mpsc::sync_channel(1);
        let worker_admission = admission.clone();
        let request = runtime.spawn(async move {
            worker_admission
                .run(move || {
                    worker_started_tx.send(()).expect("test is listening");
                    release_worker_rx.recv().expect("test releases worker");
                    Ok(())
                })
                .await
        });
        worker_started_rx.recv_timeout(Duration::from_secs(2))?;
        request.abort();
        let cancellation = runtime
            .block_on(request)
            .expect_err("request task is cancelled");
        assert!(cancellation.is_cancelled());
        assert_eq!(admission.available_permits(), 0);

        let timeout = runtime
            .block_on(admission.run(|| Ok(())))
            .expect_err("the running closure still owns the sole permit");
        assert_filesystem_admission_timeout(&timeout);

        release_worker_tx.send(())?;
        runtime.block_on(wait_for_permits(&admission, 1))?;
        Ok(())
    }

    /// 中文：准入状态机不改变普通下载的游标语义；每个 read/seek 独立获取许可并能连续复用。
    /// English: Per-operation admission preserves normal download cursor semantics across repeated reads and seeks.
    #[tokio::test]
    async fn guarded_file_reads_and_seeks_across_independent_leases() -> Result<()> {
        let directory = TempDir::new()?;
        std::fs::write(directory.path().join("sample.txt"), b"abcdef")?;
        let root = RootFs::new(directory.path(), false, false)?;
        let opened = root.open("sample.txt", NodeKind::File).await?;
        let mut file: GuardedBlockingFile = opened.file;

        let mut prefix = [0_u8; 3];
        file.read_exact(&mut prefix).await?;
        assert_eq!(&prefix, b"abc");
        assert_eq!(file.seek(SeekFrom::Start(1)).await?, 1);
        let mut suffix = String::new();
        file.read_to_string(&mut suffix).await?;
        assert_eq!(suffix, "bcdef");
        assert_eq!(root.blocking_admission().available_permits(), 32);
        Ok(())
    }
}
