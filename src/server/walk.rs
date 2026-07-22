//! 递归遍历目录树，并应用服务器的"可见性策略"：
//! 隐藏名过滤（`--hidden`）、符号链接越界拦截、以及通过共享的 `running`
//! 标志支持协作式取消（服务器关停时中断长遍历）。
//! 搜索（`?q=`）和 zip 打包（`?zip`）都复用这里的遍历逻辑。
//!
//! ## 本模块的 Rust 知识点
//! - **泛型 + 闭包参数**：`walk_dir_entries` 接收 visitor 闭包，搜索和
//!   打包在同一套已打开 fd 上消费条目。
//! - **`Arc` 跨线程共享**：这个函数运行在 `spawn_blocking` 的阻塞线程池里
//!   （dirfd 遍历是同步 IO，不能阻塞异步运行时），所以参数必须是拥有所有权
//!   或 `Arc` 共享的数据，不能借用请求栈上的临时变量。
//! - **原子布尔**：`AtomicBool` 允许多线程无锁地读写"是否继续运行"标志。
//!
//! Recursively walk directory trees while applying the server's visibility policy: hidden-name
//! filtering (`--hidden`), symlink containment, and cooperative cancellation through the shared
//! `running` flag so long traversals stop during server shutdown. Search (`?q=`) and ZIP generation
//! (`?zip`) both reuse this traversal.
//!
//! ## Rust concepts in this module
//! - **Generics and closure parameters**: `walk_dir_entries` accepts a visitor closure, allowing
//!   search and archiving to consume entries through the same set of opened descriptors.
//! - **Sharing with `Arc` across threads**: the function runs in the `spawn_blocking` pool because
//!   dirfd traversal is synchronous I/O that cannot block the async runtime. Arguments must
//!   therefore own their values or share them through `Arc`, not borrow request-stack temporaries.
//! - **Atomic boolean**: `AtomicBool` lets threads read and update the keep-running flag without a
//!   lock.

use super::error::{AdmissionError, AdmissionResource, ChangedStatus, FsError, ResponseErrorRef};
use super::filesystem::{RootFs, WalkAction, WalkEntry};
use super::is_internal_temp_name;
use crate::auth::AccessPaths;

use anyhow::{Context, Result, anyhow};
use hyper::Method;
use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use tokio::sync::oneshot;

pub(super) use super::filesystem::{
    WalkAction as CapabilityWalkAction, WalkEntry as CapabilityWalkEntry,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct WalkDirectoryOutcome {
    pub(super) omitted_non_utf8: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActualPathAccess {
    Allowed,
    Denied,
    NonUtf8Denied,
}

/// 针对请求能力树重新授权描述符派生路径；可读祖先可授权任意 Linux basename 字节，IndexOnly 不能命名原始字节子项并以专用 omission 结果 fail closed。
/// Re-authorize descriptor-derived paths; readable ancestors cover raw bytes, while IndexOnly raw children fail closed distinctly.
fn actual_path_access(
    access_paths: &AccessPaths,
    base_rel: &Path,
    actual_rel: &Path,
) -> ActualPathAccess {
    let Ok(suffix) = actual_rel.strip_prefix(base_rel) else {
        return ActualPathAccess::Denied;
    };
    if let Some(suffix) = suffix.to_str() {
        return access_paths
            .guard(suffix, &Method::GET)
            .filter(|access| !access.perm().indexonly())
            .map(|_| ActualPathAccess::Allowed)
            .unwrap_or(ActualPathAccess::Denied);
    }

    let mut representable_prefix = PathBuf::new();
    for component in suffix.components() {
        let component = component.as_os_str();
        if component.to_str().is_none() {
            let inherited = representable_prefix
                .to_str()
                .and_then(|prefix| access_paths.guard(prefix, &Method::GET));
            return if inherited.is_some_and(|access| !access.perm().indexonly()) {
                ActualPathAccess::Allowed
            } else {
                ActualPathAccess::NonUtf8Denied
            };
        }
        representable_prefix.push(component);
    }
    ActualPathAccess::NonUtf8Denied
}

/// 请求级协作取消。阻塞遍历无法被 Tokio 强制终止，因此 handler、
/// response body 和阻塞 worker 共享这个原子标志。
/// Request-level cooperative cancellation shared by handler, body, and blocking worker because Tokio cannot force-stop traversal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum CancellationReason {
    Running = 0,
    RequestDropped = 1,
    DeadlineExceeded = 2,
    Shutdown = 3,
}

#[derive(Debug, Default)]
struct RequestCancellationState {
    reason: AtomicU8,
    cancelled: AtomicBool,
    worker_exited: AtomicBool,
    /// 运行时拥有进程级标志；即使 Hyper 尚未丢 HTTP future，worker 也能把优雅关停识别为独立取消原因。
    /// Runtime-owned process flag lets workers observe shutdown separately before Hyper drops request futures.
    shutdown_running: Option<Arc<AtomicBool>>,
}

#[derive(Clone, Debug, Default)]
pub(super) struct RequestCancellation {
    state: Arc<RequestCancellationState>,
}

impl RequestCancellation {
    #[cfg(test)]
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn linked_to_shutdown(running: Arc<AtomicBool>) -> Self {
        Self {
            state: Arc::new(RequestCancellationState {
                shutdown_running: Some(running),
                ..RequestCancellationState::default()
            }),
        }
    }

    pub(super) fn cancel(&self) {
        self.cancel_with(CancellationReason::RequestDropped);
    }

    pub(super) fn is_cancelled(&self) -> bool {
        self.reason() != CancellationReason::Running
    }

    pub(super) fn flag(&self) -> &AtomicBool {
        self.refresh_shutdown();
        // 中文：遍历接口接收 AtomicBool；保留单独单调标志，使紧循环不必每条解码原因。
        // English: A separate monotonic flag feeds tight traversal loops without decoding a reason per entry.
        &self.state.cancelled
    }

    pub(super) fn reason(&self) -> CancellationReason {
        self.refresh_shutdown();
        match self.state.reason.load(Ordering::Acquire) {
            1 => CancellationReason::RequestDropped,
            2 => CancellationReason::DeadlineExceeded,
            3 => CancellationReason::Shutdown,
            _ => CancellationReason::Running,
        }
    }

    pub(super) fn worker_exited(&self) -> bool {
        self.state.worker_exited.load(Ordering::Acquire)
    }

    pub(super) fn cancel_for_deadline(&self) {
        self.refresh_shutdown();
        self.cancel_with(CancellationReason::DeadlineExceeded);
    }

    fn refresh_shutdown(&self) {
        if self
            .state
            .shutdown_running
            .as_ref()
            .is_some_and(|running| !running.load(Ordering::Acquire))
        {
            self.cancel_with(CancellationReason::Shutdown);
        }
    }

    fn cancel_with(&self, reason: CancellationReason) {
        if self.worker_exited() {
            return;
        }
        if self
            .state
            .reason
            .compare_exchange(
                CancellationReason::Running as u8,
                reason as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            self.state.cancelled.store(true, Ordering::Release);
        }
    }

    fn mark_worker_exited(&self) {
        self.state.worker_exited.store(true, Ordering::Release);
    }
}

/// 把请求 future/body Drop 转成 worker 可见取消。 / Convert request-future/body Drop into blocking-worker cancellation.
pub(super) struct CancelOnDrop(RequestCancellation);

impl CancelOnDrop {
    pub(super) fn new(cancellation: RequestCancellation) -> Self {
        Self(cancellation)
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

struct MarkWorkerExitedOnDrop(RequestCancellation);

impl Drop for MarkWorkerExitedOnDrop {
    fn drop(&mut self) {
        self.0.mark_worker_exited();
    }
}

/// JoinHandle 由分离 async supervisor 持有的阻塞文件系统 worker；请求侧 Drop 只发取消，supervisor 继续等待真实退出。
/// Blocking worker supervised after request drop so cancellation does not orphan its actual exit.
pub(super) struct SupervisedBlocking<T> {
    cancellation: RequestCancellation,
    result_rx: oneshot::Receiver<Result<T>>,
}

pub(super) fn is_blocking_deadline(error: &anyhow::Error) -> bool {
    matches!(
        AdmissionError::in_anyhow_chain(error),
        Some(AdmissionError::Timeout {
            resource: AdmissionResource::ExpensiveTasks,
            kind: super::error::AdmissionTimeoutKind::Execution,
            ..
        })
    )
}

impl<T> SupervisedBlocking<T> {
    pub(super) fn cancellation(&self) -> RequestCancellation {
        self.cancellation.clone()
    }

    pub(super) async fn wait_until(mut self, deadline: tokio::time::Instant) -> Result<T> {
        // 中文：保留边界观察到的真实预算；调用方可加上下文/映射资源，但不能用占位时长重建超时。
        // English: Retain the actual observed budget; callers may add context but not reconstruct a placeholder timeout.
        let waited = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout_at(deadline, &mut self.result_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(anyhow!(
                "blocking filesystem supervisor stopped unexpectedly"
            )),
            Err(_) => {
                self.cancellation.cancel_for_deadline();
                Err(anyhow::Error::new(AdmissionError::execution_timeout(
                    AdmissionResource::ExpensiveTasks,
                    waited,
                ))
                .context("blocking filesystem operation exceeded its deadline"))
            }
        }
    }
}

impl<T> Drop for SupervisedBlocking<T> {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

/// 在 owned guard 下启动阻塞任务；guard 移入闭包，使 permit/锁/临时文件在超时或取消后仍存活至 worker 真正返回。
/// Spawn blocking work with its guard inside the closure so resources outlive request timeout/cancellation until real exit.
#[cfg(test)]
pub(super) fn spawn_supervised_blocking<T, G, F>(guard: G, work: F) -> SupervisedBlocking<T>
where
    T: Send + 'static,
    G: Send + 'static,
    F: FnOnce(RequestCancellation) -> Result<T> + Send + 'static,
{
    spawn_supervised_blocking_with_cancellation(RequestCancellation::new(), guard, work)
}

/// 服务操作变体：除请求 Drop/deadline 外，还协作观察进程关停原因。
/// Server-operation variant additionally exposes process shutdown as a distinct cancellation reason.
pub(super) fn spawn_supervised_blocking_with_shutdown<T, G, F>(
    running: Arc<AtomicBool>,
    guard: G,
    work: F,
) -> SupervisedBlocking<T>
where
    T: Send + 'static,
    G: Send + 'static,
    F: FnOnce(RequestCancellation) -> Result<T> + Send + 'static,
{
    spawn_supervised_blocking_with_cancellation(
        RequestCancellation::linked_to_shutdown(running),
        guard,
        work,
    )
}

fn spawn_supervised_blocking_with_cancellation<T, G, F>(
    cancellation: RequestCancellation,
    guard: G,
    work: F,
) -> SupervisedBlocking<T>
where
    T: Send + 'static,
    G: Send + 'static,
    F: FnOnce(RequestCancellation) -> Result<T> + Send + 'static,
{
    let worker_cancellation = cancellation.clone();
    let exit_cancellation = cancellation.clone();
    let (result_tx, result_rx) = oneshot::channel();
    let task = tokio::task::spawn_blocking(move || {
        let _mark_exited = MarkWorkerExitedOnDrop(exit_cancellation);
        let _guard = guard;
        work(worker_cancellation)
    });
    tokio::spawn(async move {
        let result = task
            .await
            .map_err(anyhow::Error::new)
            .context("blocking filesystem worker failed")
            .and_then(|result| result);
        let _ = result_tx.send(result);
    });
    SupervisedBlocking {
        cancellation,
        result_rx,
    }
}

/// 带 deadline 与协作取消运行阻塞文件工作；超时请求返回但 supervisor 继续等待 worker，避免孤儿。
/// Run blocking filesystem work with deadline; timeout signals cancellation while supervision continues to real exit.
pub(super) async fn run_guarded_cancellable_blocking<T, G, F>(
    deadline: tokio::time::Instant,
    running: Arc<AtomicBool>,
    guard: G,
    work: F,
) -> Result<T>
where
    T: Send + 'static,
    G: Send + 'static,
    F: FnOnce(RequestCancellation) -> Result<T> + Send + 'static,
{
    spawn_supervised_blocking_with_shutdown(running, guard, work)
        .wait_until(deadline)
        .await
}

/// `--hidden` 通配符规则，启动时一次性编译。
///
/// 规则语义：以 `/` 结尾的模式只隐藏**目录**；由于目录条目名里不可能
/// 含分隔符，未去掉 `/` 的原始模式本来就永远匹配不上文件，二者等价。
/// 非法模式直接丢弃——与旧行为（非法模式永不匹配）一致。
///
/// 预编译的意义：目录列表、搜索、打包都会对**每个条目 × 每条规则**
/// 做一次匹配，如果每次都现场解析 glob 模式，开销会被放大成千上万倍。
/// Compile hidden globs once. Trailing-slash patterns are directory-only;
/// invalid patterns retain the legacy never-match behavior with a warning.
#[derive(Debug)]
pub(super) struct HiddenRules {
    rules: Vec<(glob::Pattern, bool)>, // （模式，是否仅目录）/ (pattern, directory-only)
}

impl HiddenRules {
    pub(super) fn compile(hidden: &[String]) -> Self {
        let rules = hidden
            .iter()
            .filter_map(|v| {
                let (pattern, dir_only) = match v.strip_suffix('/') {
                    Some(x) => (x, true),
                    None => (v.as_str(), false),
                };
                match glob::Pattern::new(pattern) {
                    Ok(pattern) => Some((pattern, dir_only)),
                    Err(err) => {
                        // 中文：hidden 不是访问控制，但静默忽略会误导运维；输出不泄露其他配置的警告。
                        // English: Hidden rules are not access control, but invalid patterns need a non-secret warning rather than silent surprise.
                        warn!("Ignoring invalid hidden glob {v:?}: {err}");
                        None
                    }
                }
            })
            .collect();
        Self { rules }
    }

    /// 条目名是否命中 hidden 规则。 / Whether an entry name matches any hidden rule.
    pub(super) fn is_hidden(&self, file_name: &str, is_dir: bool) -> bool {
        self.rules
            .iter()
            .any(|(pattern, dir_only)| (is_dir || !dir_only) && pattern.matches(file_name))
    }
}

/// 遍历 `path` 下的目录树并逐条交给调用者，避免搜索/ZIP 先构造一个
/// O(entries) 的 Vec。`access_paths.entry_paths()` 使 IndexOnly 用户只从
/// 获准的子树开始；visitor 返回 false 时
/// 立即停止，供请求取消/下游断开实现背压取消。
/// Walk and visit entries without an O(entries) Vec; IndexOnly starts at allowed roots and visitor false stops immediately for cancellation/backpressure.
#[allow(clippy::too_many_arguments)]
pub(super) fn walk_dir_entries<V>(
    fs_root: RootFs,
    access_paths: AccessPaths,
    running: Arc<AtomicBool>,
    cancellation: RequestCancellation,
    max_entries: usize,
    max_depth: usize,
    base_rel: PathBuf,
    hidden: Arc<HiddenRules>,
    mut visitor: V,
) -> Result<WalkDirectoryOutcome>
where
    V: FnMut(&mut WalkEntry) -> WalkAction,
{
    let roots = access_paths.entry_paths(&base_rel);
    let omitted_non_utf8 = Cell::new(false);
    let root_access_paths = access_paths.clone();
    let root_base_rel = base_rel.clone();
    let entry_access_paths = access_paths;
    let entry_base_rel = base_rel;
    let result = fs_root.walk_with_root_filter(
        roots,
        &running,
        cancellation.flag(),
        max_entries,
        max_depth,
        |_, real_root, _| {
            Ok(
                match actual_path_access(&root_access_paths, &root_base_rel, real_root) {
                    ActualPathAccess::Allowed => true,
                    ActualPathAccess::Denied => false,
                    ActualPathAccess::NonUtf8Denied => {
                        omitted_non_utf8.set(true);
                        false
                    }
                },
            )
        },
        |entry| {
            let is_dir = entry.metadata.is_dir();
            match actual_path_access(&entry_access_paths, &entry_base_rel, &entry.real_rel) {
                ActualPathAccess::Allowed => {}
                ActualPathAccess::Denied => {
                    return Ok(if is_dir {
                        WalkAction::SkipDirectory
                    } else {
                        WalkAction::Continue
                    });
                }
                ActualPathAccess::NonUtf8Denied => {
                    omitted_non_utf8.set(true);
                    return Ok(if is_dir {
                        WalkAction::SkipDirectory
                    } else {
                        WalkAction::Continue
                    });
                }
            }
            if let Some(base_name) = entry.name.to_str()
                && (is_internal_temp_name(base_name) || hidden.is_hidden(base_name, is_dir))
            {
                return Ok(if is_dir {
                    WalkAction::SkipDirectory
                } else {
                    WalkAction::Continue
                });
            }
            Ok(visitor(entry))
        },
    );
    if cancellation.is_cancelled() {
        Err(
            anyhow::Error::new(AdmissionError::cancelled(AdmissionResource::WalkEntries))
                .context("directory traversal was cancelled"),
        )
    } else {
        result
            .map_err(|error| {
                if ResponseErrorRef::from_anyhow_typed(&error, ChangedStatus::Conflict).is_some() {
                    error
                } else {
                    anyhow::Error::new(FsError::from_anyhow(
                        "walking visible directory entries",
                        error,
                    ))
                }
            })
            .context("walking visible directory entries")?;
        Ok(WalkDirectoryOutcome {
            omitted_non_utf8: omitted_non_utf8.get(),
        })
    }
}

#[cfg(test)]
mod supervised_blocking_tests {
    use super::{CancellationReason, spawn_supervised_blocking};
    use crate::server::error::{AdmissionError, AdmissionResource, AdmissionTimeoutKind};
    use anyhow::Result;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Condvar, Mutex, mpsc};
    use std::time::{Duration, Instant};
    use tokio::sync::Semaphore;

    struct DropProbe(Arc<AtomicBool>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deadline_returns_but_worker_keeps_guard_until_real_exit() -> Result<()> {
        let limiter = Arc::new(Semaphore::new(1));
        let permit = limiter.clone().acquire_owned().await?;
        let dropped = Arc::new(AtomicBool::new(false));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let worker_release = release.clone();
        let (started_tx, started_rx) = mpsc::channel();

        let operation =
            spawn_supervised_blocking((permit, DropProbe(dropped.clone())), move |cancellation| {
                started_tx.send(()).unwrap();
                let (lock, wake) = &*worker_release;
                let mut released = lock.lock().unwrap();
                while !*released {
                    let waited = wake
                        .wait_timeout(released, Duration::from_millis(10))
                        .unwrap();
                    released = waited.0;
                }
                assert!(cancellation.is_cancelled());
                Ok(())
            });
        let state = operation.cancellation();
        started_rx.recv_timeout(Duration::from_secs(1))?;

        let started = Instant::now();
        let result = operation
            .wait_until(tokio::time::Instant::now() + Duration::from_millis(20))
            .await;
        let error = result.expect_err("blocking worker must exceed its deadline");
        assert!(matches!(
            AdmissionError::in_anyhow_chain(&error),
            Some(AdmissionError::Timeout {
                resource: AdmissionResource::ExpensiveTasks,
                kind: AdmissionTimeoutKind::Execution,
                waited,
            }) if *waited > Duration::ZERO
        ));
        assert!(started.elapsed() < Duration::from_millis(150));
        assert_eq!(state.reason(), CancellationReason::DeadlineExceeded);
        assert!(!state.worker_exited());
        assert!(!dropped.load(Ordering::Acquire));
        assert!(limiter.clone().try_acquire_owned().is_err());

        *release.0.lock().unwrap() = true;
        release.1.notify_all();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !state.worker_exited() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        assert!(dropped.load(Ordering::Acquire));
        assert!(limiter.try_acquire_owned().is_ok());
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_request_handle_signals_worker_without_orphaning_guard() -> Result<()> {
        let dropped = Arc::new(AtomicBool::new(false));
        let operation = spawn_supervised_blocking(DropProbe(dropped.clone()), |cancellation| {
            while !cancellation.is_cancelled() {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(())
        });
        let state = operation.cancellation();
        drop(operation);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !state.worker_exited() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        assert_eq!(state.reason(), CancellationReason::RequestDropped);
        assert!(dropped.load(Ordering::Acquire));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn runtime_shutdown_is_distinct_from_request_drop_and_worker_exit() -> Result<()> {
        let running = Arc::new(AtomicBool::new(true));
        let operation =
            super::spawn_supervised_blocking_with_shutdown(running.clone(), (), |cancellation| {
                while !cancellation.is_cancelled() {
                    std::thread::sleep(Duration::from_millis(5));
                }
                assert_eq!(cancellation.reason(), CancellationReason::Shutdown);
                Ok(())
            });
        let state = operation.cancellation();
        running.store(false, Ordering::Release);
        operation
            .wait_until(tokio::time::Instant::now() + Duration::from_secs(1))
            .await?;
        assert_eq!(state.reason(), CancellationReason::Shutdown);
        assert!(state.worker_exited());
        Ok(())
    }
}
