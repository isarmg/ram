//! Ram 的启动流程、网络监听、TLS 接入与优雅关停。
//!
//! ## 本模块的 Rust 知识点
//! - **每连接一个任务**：accept 循环里对每个连接 `tokio::spawn`，
//!   任务比线程轻得多，几千并发连接毫无压力。
//! - **优雅关停三件套**：`watch` 通道广播"该停了"、`AtomicBool` 让长任务
//!   自查、hyper 的 `GracefulShutdown` 等在途请求收尾（限时 30 秒）。
//! - **`Semaphore` 限流**：全局连接数信号量，取不到许可就暂停 accept，
//!   多余连接排在操作系统 backlog 里，防止耗尽文件描述符。
//!
//! ## Rust concepts used here
//! - **One task per connection**: the accept loop uses `tokio::spawn` for every
//!   accepted connection. Tasks are substantially lighter than operating-system
//!   threads, so the runtime can supervise large connection sets efficiently.
//! - **Three-part graceful shutdown**: a `watch` channel broadcasts shutdown,
//!   an `AtomicBool` lets long-running workers cooperate, and Hyper's
//!   `GracefulShutdown` drains in-flight requests for at most 30 seconds.
//! - **`Semaphore` admission**: a process-wide connection semaphore pauses
//!   `accept` when no permit is available. Excess connections remain in the
//!   kernel backlog instead of consuming unbounded process file descriptors.

#[cfg(feature = "tls")]
use crate::config::StartupInputKind;
use crate::config::{
    Args, BindAddr, ParsePurpose, StartupOutputKind, build_cli, print_completions,
};
use crate::http::{IoWatchdog, body_full, body_with_response_write_idle_timeout};
use crate::logging;
use crate::path_identity::{OutputPathIdentity, PathIdentity};
use crate::server::{Response, Server};
use crate::source_identity::PeerIdentity;
use crate::utils::is_trusted_file_owner;
#[cfg(feature = "tls")]
use crate::utils::{load_certs_from_reader, load_private_key_from_reader};

use anyhow::{Context, Result, anyhow, bail};
use clap_complete::Shell;
use futures_util::future::{BoxFuture, join_all, select_all};

use hyper::{
    Method, Request, StatusCode, Version,
    body::{Body, Incoming},
    header::{CACHE_CONTROL, CONNECTION, CONTENT_LENGTH, HeaderValue},
    service::service_fn,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder,
    server::graceful::{GracefulShutdown, Watcher},
};
use socket2::{Domain, SockAddr, Socket, Type};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::future::Future;
use std::net::{IpAddr, SocketAddr, TcpListener as StdTcpListener};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Notify, Semaphore, watch};
#[cfg(feature = "tls")]
use tokio::time::timeout_at;
use tokio::time::{Instant as TokioInstant, sleep, sleep_until};
use tokio::{
    net::{TcpListener, TcpStream},
    runtime::{Builder as RuntimeBuilder, Runtime},
    task::{JoinHandle, JoinSet},
};
#[cfg(feature = "tls")]
use tokio_rustls::{TlsAcceptor, rustls::ServerConfig};

/// 收到关停后等待在途请求的最长时间。 / Maximum drain time for in-flight requests after shutdown.
const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// Tokio 不能终止已运行阻塞 syscall；HTTP drain 后仅等待此时长，卡在不可信内核文件系统的 worker 最终由进程退出硬终止。
/// Tokio cannot kill a running syscall; wait this long after HTTP drain, then let process exit terminate any stuck worker.
const BLOCKING_POOL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
/// 私有上传候选清理任务的关停等待上限；超时后保留精确恢复记录并关闭失败。
/// Shutdown wait ceiling for private-upload cleanup; timeout preserves exact recovery records and fails closed.
const CANDIDATE_CLEANUP_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// 在 accept 循环外执行 TLS 握手的最大时长。 / Maximum TLS handshake time off the accept loop.
#[cfg(feature = "tls")]
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// HTTP/2 按此间隔 ping 空闲连接，超时未确认则断开；HTTP/1 已有头/连接空闲超时，而 h2 流之间没有请求头超时，keepalive 防半开连接永久占 permit。
/// HTTP/2 keepalive reaps half-open idle connections that otherwise lack an inter-stream request-head deadline.
const H2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);
/// 发送 keepalive ping 后等待 ACK 的上限。 / Maximum wait for an ACK after sending an HTTP/2 keepalive ping.
const H2_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(20);
/// 限制单流初始接收窗口，避免一个未消费流预留过多内存。
/// Bound each stream's initial receive window so one unread stream cannot reserve excessive memory.
const H2_INITIAL_STREAM_WINDOW_SIZE: u32 = 64 * 1024;
/// 连接窗口允许多个流推进，但仍给每连接未消费 DATA 设置固定上界。
/// Let several streams progress while retaining a fixed per-connection ceiling on unread DATA.
const H2_INITIAL_CONNECTION_WINDOW_SIZE: u32 = 1024 * 1024;
const H2_MAX_SEND_BUFFER_SIZE: usize = 64 * 1024;
const H2_MAX_HEADER_LIST_SIZE: u32 = 64 * 1024;
/// 限制每连接保留的完整 HTTP/1 请求头，与 HTTP/2 列表预算对齐，避免继承依赖的大默认值。
/// Bound the complete HTTP/1 head and align it with HTTP/2 rather than dependency defaults.
const HTTP1_MAX_REQUEST_HEAD_SIZE: usize = 64 * 1024;
/// HTTP/1 字段数独立于总字节受限；Hyper 默认值不属于 Ram 契约且升级可变。
/// Cap HTTP/1 field count independently because Hyper defaults are not Ram's stable budget.
const HTTP1_MAX_HEADERS: usize = 100;

/// 返回已解析 HTTP/1 头的规范语义大小；Hyper 已规范名并裁可选空白，故预算确定性表示：
///
/// `METHOD SP request-target SP HTTP/x.y CRLF`
/// `name: SP value CRLF`
/// `CRLF`
///
/// 原 wire 拼写已不可得；parser 缓冲/字段数是第一层，此二次检查封闭一次大 socket read
/// 刚越过缓冲增长阈值后完成解析的情况。
/// Return deterministic semantic head size after Hyper normalization; this
/// second check closes parsing completed just beyond a buffer-growth threshold.
fn http1_request_head_semantic_size<B>(request: &Request<B>) -> Option<usize> {
    let version_len = match request.version() {
        Version::HTTP_10 | Version::HTTP_11 => "HTTP/1.1".len(),
        _ => return None,
    };
    let uri = request.uri();
    let uri_len = uri
        .scheme_str()
        .map_or(0, |scheme| scheme.len().saturating_add(3))
        .saturating_add(
            uri.authority()
                .map_or(0, |authority| authority.as_str().len()),
        )
        .saturating_add(uri.path().len())
        .saturating_add(uri.query().map_or(0, |query| query.len().saturating_add(1)));
    let request_line_len = request
        .method()
        .as_str()
        .len()
        .saturating_add(1)
        .saturating_add(uri_len)
        .saturating_add(1)
        .saturating_add(version_len)
        .saturating_add(2);
    Some(
        request
            .headers()
            .iter()
            .fold(request_line_len, |size, (name, value)| {
                size.saturating_add(name.as_str().len())
                    .saturating_add(2)
                    .saturating_add(value.as_bytes().len())
                    .saturating_add(2)
            })
            .saturating_add(2),
    )
}

fn http1_request_head_exceeds_budget<B>(request: &Request<B>) -> bool {
    http1_request_head_semantic_size(request).is_some_and(|size| size > HTTP1_MAX_REQUEST_HEAD_SIZE)
}

fn http1_request_head_too_large_response() -> Response {
    let mut response = Response::new(body_full(""));
    *response.status_mut() = StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE;
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("close"));
    response
        .headers_mut()
        .insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
    response
}

struct ActiveRequestGuard(Arc<AtomicUsize>);

impl ActiveRequestGuard {
    fn new(active: Arc<AtomicUsize>) -> Self {
        active.fetch_add(1, Ordering::AcqRel);
        Self(active)
    }
}

impl Drop for ActiveRequestGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UnixSocketObjectIdentity {
    dev: u64,
    ino: u64,
}

#[derive(Clone, Debug)]
struct UnixSocketExpectation {
    path: PathBuf,
    object: UnixSocketObjectIdentity,
    mode: u32,
    uid: u32,
    gid: u32,
}

impl UnixSocketExpectation {
    fn capture(path: &Path) -> Result<Self> {
        let metadata = std::fs::symlink_metadata(path)
            .with_context(|| format!("Failed to inspect Unix socket `{}`", path.display()))?;
        Self::from_metadata(path, &metadata)
    }

    fn from_metadata(path: &Path, metadata: &std::fs::Metadata) -> Result<Self> {
        if !metadata.file_type().is_socket() {
            return Err(anyhow!(
                "Unix socket path `{}` is not a socket",
                path.display()
            ));
        }
        Ok(Self {
            path: path.to_path_buf(),
            object: UnixSocketObjectIdentity {
                dev: metadata.dev(),
                ino: metadata.ino(),
            },
            mode: metadata.mode() & 0o7777,
            uid: metadata.uid(),
            gid: metadata.gid(),
        })
    }

    fn verify_exact(&self) -> Result<()> {
        let current = Self::capture(&self.path)?;
        if current.object != self.object {
            return Err(anyhow!(
                "Unix socket `{}` changed inode after binding",
                self.path.display()
            ));
        }
        if current.mode != self.mode || current.uid != self.uid || current.gid != self.gid {
            return Err(anyhow!(
                "Unix socket `{}` metadata changed: expected mode {:04o} uid {} gid {}, found mode {:04o} uid {} gid {}",
                self.path.display(),
                self.mode,
                self.uid,
                self.gid,
                current.mode,
                current.uid,
                current.gid,
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct UnixSocketPathGuard {
    expectation: UnixSocketExpectation,
    parent: File,
    basename: OsString,
}

impl UnixSocketPathGuard {
    fn verify_pinned(&self) -> Result<()> {
        let file = open_unix_socket_child(&self.parent, &self.basename)?;
        let metadata = file.metadata()?;
        let current = UnixSocketObjectIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
        };
        if !metadata.file_type().is_socket() || current != self.expectation.object {
            bail!(
                "pinned Unix socket `{}` changed after binding",
                self.expectation.path.display()
            );
        }
        Ok(())
    }
}

impl Drop for UnixSocketPathGuard {
    fn drop(&mut self) {
        if self.verify_pinned().is_ok()
            && let Err(error) =
                rustix::fs::unlinkat(&self.parent, &self.basename, rustix::fs::AtFlags::empty())
        {
            warn!(
                "Failed to remove owned Unix socket `{}`: {error}",
                self.expectation.path.display()
            );
        }
    }
}

struct PreparedUnixListener {
    configured: String,
    listener: StdUnixListener,
    expectation: Option<UnixSocketExpectation>,
    cleanup: Option<UnixSocketPathGuard>,
}

impl PreparedUnixListener {
    fn verify(&self) -> Result<()> {
        if let Some(expectation) = self.expectation.as_ref() {
            expectation.verify_exact()?;
        }
        if let Some(cleanup) = self.cleanup.as_ref() {
            cleanup.verify_pinned()?;
        }
        Ok(())
    }
}

#[derive(Default)]
struct PreparedUnixListeners {
    listeners: Vec<PreparedUnixListener>,
}

impl PreparedUnixListeners {
    fn take(&mut self, configured: &str) -> Result<PreparedUnixListener> {
        let Some(index) = self
            .listeners
            .iter()
            .position(|listener| listener.configured == configured)
        else {
            return Err(anyhow!(
                "Unix listener `{configured}` was not safely prepared before runtime startup"
            ));
        };
        Ok(self.listeners.swap_remove(index))
    }

    fn ensure_empty(&self) -> Result<()> {
        if self.listeners.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(
                "prepared Unix listener set did not match bind configuration"
            ))
        }
    }
}

struct UmaskRestore(rustix::fs::Mode);

impl UmaskRestore {
    fn private_socket() -> Self {
        Self(rustix::process::umask(rustix::fs::Mode::from_raw_mode(
            0o177,
        )))
    }
}

impl Drop for UmaskRestore {
    fn drop(&mut self) {
        rustix::process::umask(self.0);
    }
}

fn prepare_unix_listeners(args: &Args) -> Result<PreparedUnixListeners> {
    let mut prepared = PreparedUnixListeners::default();
    let startup_paths = args
        .startup_paths
        .as_ref()
        .ok_or_else(|| anyhow!("configuration did not retain startup path capabilities"))?;
    for (listener_index, address) in args.addrs.iter().enumerate() {
        let BindAddr::SocketPath(configured) = address else {
            continue;
        };
        let retained = if configured.starts_with('@') {
            None
        } else {
            Some(
                startup_paths
                    .output(StartupOutputKind::ListenerSocket(listener_index))
                    .cloned()
                    .ok_or_else(|| {
                        anyhow!(
                            "pathname Unix listener `{configured}` has no retained startup capability"
                        )
                    })?,
            )
        };
        prepared
            .listeners
            .push(prepare_unix_listener(configured, args, retained)?);
    }
    Ok(prepared)
}

/// 在不 bind/probe/unlink Unix socket 下检查所有可静态建立的不变量；存活/陈旧探测留给启动。
/// Check every invariant available without socket mutation; live/stale probing remains startup-only.
fn validate_unix_listener_configuration(args: &Args) -> Result<()> {
    let startup_paths = args
        .startup_paths
        .as_ref()
        .ok_or_else(|| anyhow!("configuration did not retain startup path capabilities"))?;
    for (listener_index, address) in args.addrs.iter().enumerate() {
        let BindAddr::SocketPath(configured) = address else {
            continue;
        };
        if configured.starts_with('@') {
            let mut abstract_name = configured.as_bytes().to_vec();
            abstract_name[0] = 0;
            SockAddr::unix(std::ffi::OsString::from_vec(abstract_name)).with_context(|| {
                format!("Abstract Unix socket `{configured}` cannot be represented in sockaddr_un")
            })?;
            continue;
        }

        let path = Path::new(configured);
        validate_unix_socket_client_path(path)?;
        // 中文：配置合并阶段已经固定了父目录/末段；check-config 只能消费该能力，
        // 不能重新解析可能已被 rename/symlink 替换的配置字符串。
        // English: Configuration merging already pinned parent/basename authority; check-config
        // consumes it instead of re-resolving a pathname that may since have been replaced.
        let output = startup_paths
            .output(StartupOutputKind::ListenerSocket(listener_index))
            .ok_or_else(|| {
                anyhow!("pathname Unix listener `{configured}` has no retained startup capability")
            })?;
        let shared_sticky_parent = validate_unix_socket_ancestor_chain(path, output.parent())?;
        if let Some(uid) = args.unix_socket_uid {
            validate_unix_socket_owner_policy(
                path,
                shared_sticky_parent,
                is_trusted_file_owner(uid),
            )?;
        }
        if let Some(existing) = output.existing() {
            let metadata = existing.open_metadata_pinned()?.metadata()?;
            if !metadata.file_type().is_socket() {
                bail!(
                    "Unix socket path `{}` already exists and is not a socket",
                    path.display()
                );
            }
            validate_stale_unix_socket_owner_policy(path, is_trusted_file_owner(metadata.uid()))?;
        }
    }
    Ok(())
}

fn prepare_unix_listener(
    configured: &str,
    args: &Args,
    retained: Option<OutputPathIdentity>,
) -> Result<PreparedUnixListener> {
    if configured.starts_with('@') {
        if retained.is_some() {
            bail!(
                "abstract Unix socket `{configured}` unexpectedly retained a pathname capability"
            );
        }
        let mut abstract_name = configured.as_bytes().to_vec();
        abstract_name[0] = 0;
        let listener = StdUnixListener::bind(std::ffi::OsString::from_vec(abstract_name))
            .with_context(|| format!("Failed to bind abstract Unix socket `{configured}`"))?;
        listener.set_nonblocking(true)?;
        return Ok(PreparedUnixListener {
            configured: configured.to_owned(),
            listener,
            expectation: None,
            cleanup: None,
        });
    }

    let path = Path::new(configured);
    validate_unix_socket_client_path(path)?;
    // 中文：从 Args 取得配置阶段固定能力；后续 stale 检查、bind 和清理都沿同一父目录描述符。
    // English: Consume the configuration-time capability so stale probing, bind, and cleanup all follow the same pinned parent descriptor.
    let mut output = retained.ok_or_else(|| {
        anyhow!("pathname Unix listener `{configured}` has no retained startup capability")
    })?;
    let parent = output.open_parent_pinned()?;
    let shared_sticky_parent = validate_unix_socket_ancestor_chain(path, output.parent())?;
    if let Some(uid) = args.unix_socket_uid {
        validate_unix_socket_owner_policy(path, shared_sticky_parent, is_trusted_file_owner(uid))?;
    }
    let operation_path = output.parent().proc_fd_path()?.join(output.basename());
    remove_stale_unix_socket(&output, &operation_path)?;
    // 中文：条件清理 stale socket 后刷新缺失期望，同时保留同一固定父能力。
    // English: Refresh absence after stale cleanup while retaining the pinned parent capability.
    output = output.with_current_expectation()?;
    if output.existing().is_some() {
        bail!(
            "Unix socket `{}` still exists after stale cleanup",
            path.display()
        );
    }
    let listener = {
        let _umask = UmaskRestore::private_socket();
        StdUnixListener::bind(&operation_path)
            .with_context(|| format!("Failed to bind Unix socket `{}`", path.display()))?
    };

    // 中文：立即固定精确 socket inode；后续经 /proc/self/fd 对描述符改元数据，不重开可变路径，symlink swap 不能重定向 chmod/chown。
    // English: Pin the socket inode and mutate through its descriptor so pathname swaps cannot redirect metadata changes.
    let socket_file = open_unix_socket_child(&parent, output.basename())?;
    let initial = UnixSocketExpectation::from_metadata(path, &socket_file.metadata()?)?;
    let mut cleanup = Some(UnixSocketPathGuard {
        expectation: initial.clone(),
        parent: parent.try_clone()?,
        basename: output.basename().to_os_string(),
    });
    if initial.mode != 0o600 {
        return Err(anyhow!(
            "Unix socket `{}` was not created private (mode {:04o})",
            path.display(),
            initial.mode,
        ));
    }

    let socket_fd_path = PathBuf::from(format!("/proc/self/fd/{}", socket_file.as_raw_fd()));
    if args.unix_socket_uid.is_some() || args.unix_socket_gid.is_some() {
        rustix::fs::chown(
            &socket_fd_path,
            args.unix_socket_uid.map(rustix::fs::Uid::from_raw),
            args.unix_socket_gid.map(rustix::fs::Gid::from_raw),
        )
        .with_context(|| format!("Failed to set Unix socket owner `{}`", path.display()))?;
    }
    rustix::fs::chmod(
        &socket_fd_path,
        rustix::fs::Mode::from_raw_mode(args.unix_socket_mode),
    )
    .with_context(|| format!("Failed to set Unix socket mode `{}`", path.display()))?;

    let expectation = UnixSocketExpectation::from_metadata(path, &socket_file.metadata()?)?;
    if expectation.object != initial.object {
        return Err(anyhow!(
            "Unix socket `{}` changed inode while applying metadata",
            path.display()
        ));
    }
    let expected_uid = args.unix_socket_uid.unwrap_or(initial.uid);
    let expected_gid = args.unix_socket_gid.unwrap_or(initial.gid);
    if expectation.mode != args.unix_socket_mode
        || expectation.uid != expected_uid
        || expectation.gid != expected_gid
    {
        return Err(anyhow!(
            "Unix socket `{}` metadata did not match requested mode/owner/group",
            path.display()
        ));
    }
    expectation.verify_exact()?;
    let cleanup_guard = cleanup.as_mut().expect("cleanup guard exists");
    cleanup_guard.expectation = expectation.clone();
    cleanup_guard.verify_pinned()?;
    listener.set_nonblocking(true)?;
    Ok(PreparedUnixListener {
        configured: configured.to_owned(),
        listener,
        expectation: Some(expectation),
        cleanup,
    })
}

fn validate_unix_socket_client_path(path: &Path) -> Result<()> {
    // 中文：通过短 /proc/self/fd 能力路径 bind 不能让服务接受普通 AF_UNIX 客户端放不进 sun_path 的配置拼写。
    // English: A short capability bind path must not admit a configured spelling ordinary clients cannot encode in sockaddr_un.
    SockAddr::unix(path).map(|_| ()).with_context(|| {
        format!(
            "Unix socket path `{}` cannot be represented by clients in sockaddr_un",
            path.display()
        )
    })
}

fn validate_unix_socket_ancestor_chain(path: &Path, parent: &PathIdentity) -> Result<bool> {
    let ancestors = parent.pinned_ancestor_metadata()?;
    validate_unix_socket_ancestor_chain_policy(
        path,
        ancestors.into_iter().map(|(ancestor, metadata)| {
            (
                ancestor,
                metadata.mode(),
                is_trusted_file_owner(metadata.uid()),
            )
        }),
    )
}

fn validate_unix_socket_ancestor_chain_policy<I, P>(path: &Path, ancestors: I) -> Result<bool>
where
    I: IntoIterator<Item = (P, u32, bool)>,
    P: AsRef<Path>,
{
    let mut immediate_parent_is_shared_sticky = None;
    for (ancestor, mode, trusted_owner) in ancestors {
        validate_unix_socket_ancestor_policy(path, ancestor.as_ref(), mode, trusted_owner)?;
        immediate_parent_is_shared_sticky = Some(mode & 0o022 != 0);
    }
    immediate_parent_is_shared_sticky.ok_or_else(|| {
        anyhow!(
            "Unix socket `{}` has no pinned parent identity",
            path.display()
        )
    })
}

fn validate_unix_socket_ancestor_policy(
    path: &Path,
    ancestor: &Path,
    mode: u32,
    trusted_owner: bool,
) -> Result<()> {
    // 中文：sticky 限制他人替换子项，但目录属主始终可替换；不能信任攻击者拥有的 sticky 目录。
    // English: Sticky does not constrain the directory owner, so an attacker-owned sticky parent cannot protect the socket name.
    if !trusted_owner {
        bail!(
            "Unix socket ancestor `{}` for `{}` has an untrusted owner",
            ancestor.display(),
            path.display(),
        );
    }
    // 中文：sticky 可写目录（如 /tmp）防其他 UID 替换本进程 socket；非 sticky 的组/全局可写父目录不提供边界。
    // English: Sticky writable parents protect owner entries; non-sticky group/world-writable parents are rejected.
    if mode & 0o022 != 0 && mode & 0o1000 == 0 {
        bail!(
            "Unix socket ancestor `{}` for `{}` is group/world writable without the sticky bit",
            ancestor.display(),
            path.display(),
        );
    }
    Ok(())
}

fn validate_unix_socket_owner_policy(
    path: &Path,
    shared_sticky_parent: bool,
    trusted_owner: bool,
) -> Result<()> {
    // 中文：共享 sticky 目录中属主是路径完整性边界；私有父目录仍由管理员控制，显式目标 UID 视为有意委托。
    // English: Ownership is part of shared-sticky integrity, while a private parent may intentionally delegate to an explicit UID.
    if shared_sticky_parent && !trusted_owner {
        bail!(
            "Unix socket `{}` cannot be assigned to an untrusted owner in a shared sticky parent",
            path.display()
        );
    }
    Ok(())
}

fn validate_stale_unix_socket_owner_policy(path: &Path, trusted_owner: bool) -> Result<()> {
    // 中文：即使私有父目录也检查属主；root 服务不能把任意用户断连 socket 当作自身崩溃残留并 unlink。
    // English: Even under a private parent, root must not treat another user's disconnected socket as its own residue.
    if !trusted_owner {
        bail!(
            "Refusing to clean Unix socket `{}` with an untrusted owner",
            path.display()
        );
    }
    Ok(())
}

fn open_unix_socket_child(parent: &File, basename: &OsStr) -> Result<File> {
    let fd = rustix::fs::openat(
        parent,
        basename,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )?;
    let file = File::from(fd);
    if !file.metadata()?.file_type().is_socket() {
        bail!("Unix socket child changed to a non-socket object");
    }
    Ok(file)
}

fn remove_stale_unix_socket(output: &OutputPathIdentity, operation_path: &Path) -> Result<()> {
    let Some(existing) = output.existing() else {
        return Ok(());
    };
    let metadata = existing.open_metadata_pinned()?.metadata()?;
    let path = output.display_path();
    if !metadata.file_type().is_socket() {
        return Err(anyhow!(
            "Unix socket path `{}` already exists and is not a socket",
            path.display()
        ));
    }
    validate_stale_unix_socket_owner_policy(&path, is_trusted_file_owner(metadata.uid()))?;
    // 中文：活 listener backlog 满时阻塞 AF_UNIX connect 可永久等待；只用非阻塞探测并仅在权威 ECONNREFUSED 时删除，其他结果一律视为 live/busy。
    // English: Probe nonblocking and delete only on authoritative ECONNREFUSED; every ambiguous result is live/busy.
    let probe = Socket::new(Domain::UNIX, Type::STREAM.nonblocking(), None)
        .context("Failed to create nonblocking Unix socket probe")?;
    let probe_address = SockAddr::unix(operation_path)
        .with_context(|| format!("Invalid Unix socket probe path `{}`", path.display()))?;
    match probe.connect(&probe_address) {
        Ok(_) => Err(anyhow!(
            "Unix socket `{}` is already served by a live process",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            let parent = output.open_parent_pinned()?;
            let current = open_unix_socket_child(&parent, output.basename())?;
            let current = current.metadata()?;
            if current.dev() != metadata.dev() || current.ino() != metadata.ino() {
                return Err(anyhow!(
                    "stale Unix socket `{}` changed before cleanup",
                    path.display()
                ));
            }
            rustix::fs::unlinkat(&parent, output.basename(), rustix::fs::AtFlags::empty())
                .with_context(|| format!("Failed to remove stale Unix socket `{}`", path.display()))
        }
        Err(error) => Err(error).with_context(|| {
            format!(
                "Unix socket `{}` is live, busy, or could not be verified without blocking",
                path.display()
            )
        }),
    }
}

/// 解析配置并手工构造有界 blocking pool 与显式关停超时的 Tokio runtime；`tokio::main` 会隐藏限制并在 Drop 时永久等卡住 worker。
/// Parse config and manually build bounded Tokio runtime/shutdown policy instead of hidden `tokio::main` defaults.
pub fn run() -> Result<()> {
    // 中文：仅子进程路径必须早于 clap/log/Tokio；stdin 是服务映射的固定 quota hook 描述符，helper 立即 exec 替换自身。
    // English: The child-only quota-helper path runs before all initialization and immediately execs its pinned stdin object.
    let mut process_args = std::env::args_os();
    let _program = process_args.next();
    if process_args.next().as_deref()
        == Some(std::ffi::OsStr::new(
            crate::server::STORAGE_QUOTA_HOOK_HELPER_ARG,
        ))
    {
        if crate::server::run_storage_quota_hook_helper(process_args).is_err() {
            std::process::exit(crate::server::STORAGE_QUOTA_HOOK_HELPER_FAILURE_EXIT_CODE);
        }
        unreachable!("a successful quota-hook helper replaces its process image");
    }

    let cmd = build_cli();
    let matches = cmd.get_matches();
    // 中文：`--completions` 打印脚本后退出，不启动服务。 / English: `--completions` prints and exits without starting the server.
    if let Some(generator) = matches.get_one::<Shell>("completions") {
        let mut cmd = build_cli();
        print_completions(*generator, &mut cmd);
        return Ok(());
    }
    let check_config = matches.get_flag("check-config");
    let purpose = if check_config {
        ParsePurpose::Check
    } else {
        ParsePurpose::Run
    };
    let args = Args::parse(matches, purpose)?;
    if check_config {
        validate_unix_listener_configuration(&args)?;
        if let Some(log_file) = args
            .startup_paths
            .as_ref()
            .and_then(|paths| paths.log_file())
        {
            logging::validate_existing_log_file(log_file)?;
        }
        Server::validate_static_configuration(&args)?;
        #[cfg(feature = "tls")]
        let _ = build_tls_acceptor(&args)?;
        println!("Configuration OK");
        return Ok(());
    }
    // 中文：pathname socket 必须以私有 mode 创建；在单线程且 runtime/logger 建线程前切换全局 umask，避免影响无关文件。
    // English: Create pathname sockets privately while single-threaded so the process-global umask cannot affect unrelated helper-thread files.
    let prepared_unix = prepare_unix_listeners(&args)?;
    let log_file = args
        .startup_paths
        .as_ref()
        .ok_or_else(|| anyhow!("configuration did not retain startup path capabilities"))?
        .log_file()
        .cloned();
    logging::init(log_file).map_err(|e| anyhow!("Failed to init logger, {e}"))?;
    let runtime = build_runtime(args.max_blocking_threads as usize)?;
    let result = runtime.block_on(run_async(args, prepared_unix));
    runtime.shutdown_timeout(BLOCKING_POOL_SHUTDOWN_TIMEOUT);
    result
}

fn build_runtime(max_blocking_threads: usize) -> Result<Runtime> {
    RuntimeBuilder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(max_blocking_threads)
        .thread_name("ram-async")
        .build()
        .context("Failed to build the bounded Tokio runtime")
}

async fn run_async(mut args: Args, prepared_unix: PreparedUnixListeners) -> Result<()> {
    let (new_addrs, print_addrs) = check_addrs(&args)?;
    args.addrs = new_addrs;
    let running = Arc::new(AtomicBool::new(true));
    let listening = print_listening(&args, &print_addrs)?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (server, handles) = serve(args, prepared_unix, running.clone(), shutdown_rx)?;
    println!("{listening}");

    // 中文：等待 Ctrl-C/SIGTERM，期间服务由后台任务运行。 / English: Wait for Ctrl-C/SIGTERM while background tasks serve.
    shutdown_signal().await?;
    info!("Shutdown signal received; draining in-flight requests");
    // 中文：running=false 让扫描退出，watch 让 accept 停止新连接并 drain 在途连接。
    // English: `running=false` stops scans; watch stops accepts and starts connection drain.
    running.store(false, Ordering::SeqCst);
    server.close_request_admission();
    let _ = shutdown_tx.send(true);

    for r in join_all(handles).await {
        if let Err(e) = r {
            error!("{e}");
        }
    }
    if !crate::server::drain_private_candidate_cleanup(CANDIDATE_CLEANUP_SHUTDOWN_TIMEOUT) {
        warn!(
            "Private upload candidate cleanup did not drain before the shutdown deadline; exact cleanup records remain fail-closed for crash recovery"
        );
    }
    // 中文：所有连接任务结束后尝试在日志器硬 deadline 内 drain 有界 FIFO。健康目的端会交付
    // barrier 前的最终记录；队列或 I/O 卡死时允许丢失尾部日志，以保证关停仍有确定上界。
    // English: After connection tasks finish, attempt to drain the bounded FIFO within the logger's
    // hard deadline. A healthy destination receives every record before the barrier; a saturated queue
    // or stuck I/O may lose tail records so shutdown retains a deterministic bound.
    log::logger().flush();
    Ok(())
}

/// 所有监听地址（TCP/TLS/Unix socket）由一个全局 accept 协调器管理。
/// 三种监听形态的差异（流类型、TLS 握手）被封装进 [`Acceptor`] /
/// [`AcceptedConn`]。协调器先取得连接许可，再公平等待任意监听器，
/// 因此不会让空闲监听器预占许可，也不会在进程内保留超限连接。
/// One coordinator owns all TCP/TLS/Unix listeners, acquiring a global permit before fairly awaiting any listener so idle listeners cannot hoard capacity.
fn serve(
    args: Args,
    mut prepared_unix: PreparedUnixListeners,
    running: Arc<AtomicBool>,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<(Arc<Server>, Vec<JoinHandle<()>>)> {
    let addrs = args.addrs.clone();
    let port = args.port;
    #[cfg(feature = "tls")]
    let tls_acceptor = build_tls_acceptor(&args)?;
    // 中文：所有监听器共享连接上限；满时不调用 accept，让额外连接留在内核 backlog 而不耗进程 fd/内存。
    // English: At capacity, stop accepting and leave excess connections in the kernel backlog.
    let conn_limit = Arc::new(Semaphore::new(args.max_connections.max(1) as usize));
    let server_handle = Arc::new(Server::init(args, running)?);
    let mut handles = vec![];
    if let Some(maintenance) = server_handle.spawn_stale_upload_maintenance(shutdown_rx.clone()) {
        handles.push(maintenance);
    }
    let mut acceptors = Vec::with_capacity(addrs.len());
    for bind_addr in addrs.iter() {
        let acceptor = match bind_addr {
            BindAddr::IpAddr(ip) => {
                let listener = create_listener(SocketAddr::new(*ip, port))
                    .with_context(|| format!("Failed to bind `{ip}:{port}`"))?;
                #[cfg(feature = "tls")]
                let acceptor = match &tls_acceptor {
                    Some(tls) => Acceptor::Tls(listener, tls.clone()),
                    None => Acceptor::Tcp(listener),
                };
                #[cfg(not(feature = "tls"))]
                let acceptor = Acceptor::Tcp(listener);
                acceptor
            }
            BindAddr::SocketPath(path) => {
                let prepared = prepared_unix.take(path)?;
                prepared.verify()?;
                let listener = tokio::net::UnixListener::from_std(prepared.listener)
                    .with_context(|| format!("Failed to activate Unix listener `{path}`"))?;
                Acceptor::Unix(listener, prepared.cleanup)
            }
        };
        acceptors.push(acceptor);
    }
    prepared_unix.ensure_empty()?;
    handles.push(spawn_accept_loop(
        acceptors,
        server_handle.clone(),
        conn_limit,
        shutdown_rx,
    ));
    Ok((server_handle, handles))
}

/// 不绑定 listener 即解析校验完整 TLS 身份；启动和 check-config 共用，不能预检放过畸形 PEM 或证书/私钥不匹配。
/// Parse and validate TLS identity without binding; startup and preflight share this exact path.
#[cfg(feature = "tls")]
fn build_tls_acceptor(args: &Args) -> Result<Option<TlsAcceptor>> {
    match (&args.tls_cert, &args.tls_key) {
        (Some(cert_file), Some(key_file)) => {
            let startup_paths = args
                .startup_paths
                .as_ref()
                .ok_or_else(|| anyhow!("configuration did not retain TLS input capabilities"))?;
            let cert_identity = startup_paths
                .input(StartupInputKind::TlsCertificate)
                .ok_or_else(|| anyhow!("TLS certificate capability is missing"))?;
            let key_identity = startup_paths
                .input(StartupInputKind::TlsPrivateKey)
                .ok_or_else(|| anyhow!("TLS private-key capability is missing"))?;
            let certs =
                load_certs_from_reader(cert_identity.open_regular_file_pinned()?, cert_file)?;
            let key =
                load_private_key_from_reader(key_identity.open_regular_file_pinned()?, key_file)?;
            let mut config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)?;
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            Ok(Some(TlsAcceptor::from(Arc::new(config))))
        }
        (None, None) => Ok(None),
        // 中文：config 已保证 cert/key 成对。 / English: Config validation already guarantees cert/key pairing.
        _ => unreachable!(),
    }
}

/// 一个已绑定的监听器。三种形态（明文 TCP / TLS / Unix socket）在
/// `accept` 处收敛成同一个接口，统一的 accept 循环无需关心差异。
/// A bound cleartext/TLS/Unix listener converging at `accept` behind one interface.
enum Acceptor {
    Tcp(TcpListener),
    #[cfg(feature = "tls")]
    Tls(TcpListener, TlsAcceptor),
    Unix(tokio::net::UnixListener, Option<UnixSocketPathGuard>),
}

impl Acceptor {
    async fn accept(&self) -> std::io::Result<AcceptedConn> {
        match self {
            Acceptor::Tcp(listener) => {
                let (stream, addr) = listener.accept().await?;
                Ok(AcceptedConn::Tcp(stream, addr, TokioInstant::now()))
            }
            #[cfg(feature = "tls")]
            Acceptor::Tls(listener, tls) => {
                let (stream, addr) = listener.accept().await?;
                Ok(AcceptedConn::Tls(
                    stream,
                    addr,
                    tls.clone(),
                    TokioInstant::now(),
                ))
            }
            Acceptor::Unix(listener, _cleanup) => {
                let (stream, _addr) = listener.accept().await?;
                let accepted_at = TokioInstant::now();
                let credentials = stream.peer_cred()?;
                let pid = credentials.pid().ok_or_else(|| {
                    std::io::Error::other("SO_PEERCRED did not return a peer pid")
                })?;
                let pid = u32::try_from(pid).map_err(|_| {
                    std::io::Error::other("SO_PEERCRED returned an invalid peer pid")
                })?;
                Ok(AcceptedConn::Unix(
                    stream,
                    PeerIdentity::unix(credentials.uid(), credentials.gid(), pid),
                    accepted_at,
                ))
            }
        }
    }
}

/// 刚 accept 下来的一条连接。`serve` 在连接自己的任务里完成剩余
/// 准备（TLS 形态多一步握手）后交给 hyper——`serve_watched` 本身
/// 是泛型的，每个分支用各自的具体流类型单态化，无需统一流类型。
/// A newly accepted connection finishes per-kind setup in its own task and then enters generic Hyper serving.
enum AcceptedConn {
    Tcp(TcpStream, SocketAddr, TokioInstant),
    #[cfg(feature = "tls")]
    Tls(TcpStream, SocketAddr, TlsAcceptor, TokioInstant),
    Unix(tokio::net::UnixStream, PeerIdentity, TokioInstant),
}

#[derive(Clone, Copy)]
enum HttpProtocol {
    Http1,
    #[cfg(feature = "tls")]
    Http2,
    Auto,
}

impl AcceptedConn {
    async fn serve(self, watcher: Watcher, server: Arc<Server>) {
        match self {
            AcceptedConn::Tcp(stream, addr, accepted_at) => {
                let protocol = if server.allow_h2c() {
                    HttpProtocol::Auto
                } else {
                    HttpProtocol::Http1
                };
                serve_watched(
                    watcher,
                    server,
                    stream,
                    PeerIdentity::tcp(addr),
                    protocol,
                    accepted_at,
                )
                .await;
            }
            #[cfg(feature = "tls")]
            AcceptedConn::Tls(stream, addr, tls, accepted_at) => {
                // 中文：TLS 握手在连接任务内进行，慢握手不阻塞 accept。 / English: TLS handshakes run per connection and cannot block accept.
                let lifetime_deadline =
                    connection_lifetime_deadline(accepted_at, server.connection_max_lifetime());
                let handshake_deadline =
                    (accepted_at + TLS_HANDSHAKE_TIMEOUT).min(lifetime_deadline);
                let Ok(Ok(stream)) = timeout_at(handshake_deadline, tls.accept(stream)).await
                else {
                    return;
                };
                let protocol = match stream.get_ref().1.alpn_protocol() {
                    Some(b"h2") => HttpProtocol::Http2,
                    _ => HttpProtocol::Http1,
                };
                serve_watched(
                    watcher,
                    server,
                    stream,
                    PeerIdentity::tcp(addr),
                    protocol,
                    accepted_at,
                )
                .await;
            }
            AcceptedConn::Unix(stream, peer, accepted_at) => {
                let protocol = if server.allow_h2c() {
                    HttpProtocol::Auto
                } else {
                    HttpProtocol::Http1
                };
                serve_watched(watcher, server, stream, peer, protocol, accepted_at).await;
            }
        }
    }
}

/// 全局 accept 协调器：公平取得一个连接名额后，才在所有当前健康的
/// listener 上执行 cancel-safe `accept()`。只有一个协调器会保留这个
/// 尚未对应连接的许可，因此空闲 listener 不可能各自囤积许可；连接
/// 在内核 backlog 与进程之间的边界也严格服从 `max-connections`。
///
/// 单个 listener 的持续 accept 错误使用独立退避窗口，不能凭借一个
/// 永远 ready 的错误 future 饿死其他健康 listener。
/// 收到关停信号后停止接受新连接，并等在途连接优雅收尾。
/// The global coordinator reserves one permit before cancel-safe fair accept;
/// each failing listener has independent backoff, and shutdown stops admission then drains tasks.
fn spawn_accept_loop(
    acceptors: Vec<Acceptor>,
    server: Arc<Server>,
    conn_limit: Arc<Semaphore>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let graceful = GracefulShutdown::new();
        let mut connections = JoinSet::new();
        let mut accept_error_delays = vec![Duration::from_millis(25); acceptors.len()];
        let mut retry_at = vec![TokioInstant::now(); acceptors.len()];
        let mut next_acceptor = 0usize;
        loop {
            // 中文：运行期间持续回收已完成任务，使注册表按活动连接而非进程累计连接有界。
            // English: Reap tasks continuously so the registry is bounded by live, not lifetime, connections.
            while let Some(result) = connections.try_join_next() {
                log_connection_task_result(result);
            }
            let now = TokioInstant::now();
            if retry_at.iter().all(|deadline| *deadline > now) {
                let earliest = retry_at
                    .iter()
                    .copied()
                    .min()
                    .expect("at least one listener is configured");
                tokio::select! {
                    _ = sleep_until(earliest) => {}
                    _ = shutdown_rx.changed() => break,
                }
                continue;
            }

            // 中文：跨过内核 accept 边界前先预留容量。 / English: Reserve capacity before crossing the kernel accept boundary.
            let permit = tokio::select! {
                permit = conn_limit.clone().acquire_owned() => {
                    let Ok(permit) = permit else { break };
                    permit
                }
                _ = shutdown_rx.changed() => break,
            };

            let accept_started = TokioInstant::now();
            let next_retry = retry_at
                .iter()
                .copied()
                .filter(|deadline| *deadline > accept_started)
                .min();
            let retry_deadline = next_retry.unwrap_or(accept_started);
            let accepted = tokio::select! {
                accepted = accept_from_available(
                    &acceptors,
                    &retry_at,
                    next_acceptor,
                    accept_started,
                ) => accepted,
                _ = shutdown_rx.changed() => break,
                _ = sleep_until(retry_deadline), if next_retry.is_some() => None,
            };
            let Some((acceptor_index, accepted)) = accepted else {
                drop(permit);
                continue;
            };
            next_acceptor = (acceptor_index + 1) % acceptors.len();
            let conn = match accepted {
                Ok(conn) => {
                    accept_error_delays[acceptor_index] = Duration::from_millis(25);
                    retry_at[acceptor_index] = TokioInstant::now();
                    conn
                }
                Err(err) => {
                    drop(permit);
                    let delay = accept_error_delays[acceptor_index];
                    warn!(
                        "Accept failed on listener {acceptor_index}: {err}; retrying in {}ms",
                        delay.as_millis()
                    );
                    retry_at[acceptor_index] = TokioInstant::now() + delay;
                    accept_error_delays[acceptor_index] = (delay * 2).min(Duration::from_secs(2));
                    continue;
                }
            };
            let watcher = graceful.watcher();
            let server = server.clone();
            connections.spawn(async move {
                // 中文：permit 移入连接任务，结束时 RAII 自动归还。 / English: Move the permit into the task for RAII release at task end.
                let _permit = permit;
                conn.serve(watcher, server).await;
            });
        }
        drain_connections(graceful, &mut connections).await;
    })
}

async fn accept_from_available(
    acceptors: &[Acceptor],
    retry_at: &[TokioInstant],
    start: usize,
    now: TokioInstant,
) -> Option<(usize, std::io::Result<AcceptedConn>)> {
    let mut futures: Vec<BoxFuture<'_, (usize, std::io::Result<AcceptedConn>)>> =
        Vec::with_capacity(acceptors.len());
    for offset in 0..acceptors.len() {
        let index = (start + offset) % acceptors.len();
        if retry_at[index] > now {
            continue;
        }
        let acceptor = &acceptors[index];
        futures.push(Box::pin(async move { (index, acceptor.accept().await) }));
    }
    if futures.is_empty() {
        None
    } else {
        Some(select_all(futures).await.0)
    }
}

/// 服务单条连接：把 hyper 的连接 future 注册进监听器的
/// `GracefulShutdown`，关停时能被追踪、等待收尾。
/// 连接层错误几乎都是客户端正常断开，直接忽略。
///
/// `service_fn` 把闭包适配成 hyper 的请求处理服务；同一条连接上的
/// 多个请求（HTTP keep-alive）都会调用它。
/// Serve one connection under GracefulShutdown. `service_fn` handles every keep-alive request; ordinary client disconnect errors are ignored.
fn serve_watched<I>(
    watcher: Watcher,
    server: Arc<Server>,
    io: I,
    peer: PeerIdentity,
    protocol: HttpProtocol,
    accepted_at: TokioInstant,
) -> impl Future<Output = ()>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let h2_max_concurrent_streams = server.h2_max_concurrent_streams();
    let header_read_timeout = server.header_read_timeout();
    let connection_max_lifetime = server.connection_max_lifetime();
    let response_write_idle_timeout = server.response_write_idle_timeout();
    let active_requests = Arc::new(AtomicUsize::new(0));
    let io = TokioIo::new(IoWatchdog::with_active_requests(
        io,
        server.connection_idle_timeout(),
        server.response_write_idle_timeout(),
        active_requests.clone(),
    ));
    // 中文：自动协议探测会在协议头超时生效前读最多 24-byte h2 preface；首个解析请求进入服务时发信号，
    // 使部分 preface/静默连接仍有硬 deadline。
    // English: Bound the auto-detector's pre-request preface phase until the first parsed request signals service entry.
    let first_request = Arc::new(Notify::new());
    let request_signal = first_request.clone();
    let response_timeout = Arc::new(Notify::new());
    let request_response_timeout = response_timeout.clone();
    let service = service_fn(move |request: Request<Incoming>| {
        request_signal.notify_one();
        let request_head_too_large = http1_request_head_exceeds_budget(&request);
        let active_guard = ActiveRequestGuard::new(active_requests.clone());
        let server = server.clone();
        let request_method = request.method().clone();
        let response_timeout = request_response_timeout.clone();
        async move {
            let _active_guard = active_guard;
            let mut response = if request_head_too_large {
                http1_request_head_too_large_response()
            } else {
                server.call(request, peer).await?
            };
            if response_has_wire_body(&request_method, &response) {
                let body = std::mem::replace(response.body_mut(), body_full(""));
                *response.body_mut() = body_with_response_write_idle_timeout(
                    body,
                    response_write_idle_timeout,
                    response_timeout,
                );
            }
            Ok::<_, hyper::Error>(response)
        }
    });
    let mut builder = Builder::new(TokioExecutor::new());
    builder = match protocol {
        HttpProtocol::Http1 => builder.http1_only(),
        #[cfg(feature = "tls")]
        HttpProtocol::Http2 => builder.http2_only(),
        HttpProtocol::Auto => builder,
    };
    // 中文：Hyper 1.x 超时需显式 timer，否则会静默忽略。 / English: Hyper 1.x silently ignores timeout settings without an explicit timer.
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(header_read_timeout)
        .max_buf_size(HTTP1_MAX_REQUEST_HEAD_SIZE)
        .max_headers(HTTP1_MAX_HEADERS);
    // 中文：TLS 固定使用 ALPN 结果；明文自动探测只在运维显式允许 prior-knowledge h2c 时使用。
    // English: TLS is pinned to ALPN; plaintext auto-detection is only for explicitly enabled prior-knowledge h2c.
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(h2_max_concurrent_streams)
        .initial_stream_window_size(H2_INITIAL_STREAM_WINDOW_SIZE)
        .initial_connection_window_size(H2_INITIAL_CONNECTION_WINDOW_SIZE)
        .max_send_buf_size(H2_MAX_SEND_BUFFER_SIZE)
        .max_header_list_size(H2_MAX_HEADER_LIST_SIZE)
        .keep_alive_interval(H2_KEEP_ALIVE_INTERVAL)
        .keep_alive_timeout(H2_KEEP_ALIVE_TIMEOUT);
    // 中文：Ram 无 HTTP Upgrade 端点；使用非 upgrade API 也保证 hyper-util 的 http1_only 生效。
    // English: Ram has no Upgrade endpoints, and the non-upgrade API is required for effective `http1_only`.
    let conn = builder.serve_connection(io, service);
    let fut = watcher.watch(conn.into_owned());
    async move {
        tokio::pin!(fut);
        let mut first_request_seen = false;
        let header_deadline = TokioInstant::now() + header_read_timeout;
        let lifetime_deadline = connection_lifetime_deadline(accepted_at, connection_max_lifetime);
        if lifetime_deadline <= TokioInstant::now() {
            debug!("HTTP connection exhausted its configured lifetime before service began");
            return;
        }
        let result = loop {
            tokio::select! {
                result = &mut fut => break result,
                _ = first_request.notified(), if !first_request_seen => {
                    first_request_seen = true;
                }
                _ = sleep_until(header_deadline), if !first_request_seen => {
                    debug!("HTTP connection closed before its first request completed");
                    return;
                }
                _ = sleep_until(lifetime_deadline) => {
                    debug!("HTTP connection reached its configured maximum lifetime");
                    return;
                }
                _ = response_timeout.notified() => {
                    debug!("HTTP connection closed because one response exceeded its write-idle deadline");
                    return;
                }
            }
        };
        if let Err(err) = result {
            debug!("HTTP connection ended with an error: {err}");
        }
    }
}

fn response_has_wire_body(request_method: &Method, response: &Response) -> bool {
    if request_method == Method::HEAD
        || response.status().is_informational()
        || matches!(
            response.status(),
            StatusCode::NO_CONTENT | StatusCode::RESET_CONTENT | StatusCode::NOT_MODIFIED
        )
    {
        return false;
    }
    if response.body().is_end_stream() {
        return false;
    }
    response.body().size_hint().upper() != Some(0)
}

fn connection_lifetime_deadline(
    accepted_at: TokioInstant,
    connection_max_lifetime: Duration,
) -> TokioInstant {
    accepted_at + connection_max_lifetime
}

/// 等待 `graceful` 追踪的所有在途连接自然结束，
/// 以 `GRACEFUL_SHUTDOWN_TIMEOUT` 为限——卡死的连接不能永远拖住退出。
/// Wait for graceful-tracked connections up to the fixed timeout; stuck peers cannot block exit forever.
async fn drain_connections(graceful: GracefulShutdown, connections: &mut JoinSet<()>) {
    let graceful_finished = tokio::select! {
        _ = graceful.shutdown() => true,
        _ = sleep(GRACEFUL_SHUTDOWN_TIMEOUT) => {
            warn!(
                "Graceful shutdown timed out after {}s; aborting remaining connection tasks",
                GRACEFUL_SHUTDOWN_TIMEOUT.as_secs()
            );
            false
        }
    };
    if !graceful_finished {
        connections.abort_all();
    }
    // 中文：Hyper future 完成后任务仍可能执行最终正文 Drop/访问日志回调；accept 循环返回前 join 全部任务，随后 run_async 才 flush 日志。
    // English: Join every connection task after Hyper completion so final body/log callbacks finish before logger flush.
    while let Some(result) = connections.join_next().await {
        log_connection_task_result(result);
    }
}

fn log_connection_task_result(result: std::result::Result<(), tokio::task::JoinError>) {
    if let Err(error) = result
        && !error.is_cancelled()
    {
        error!("HTTP connection task failed: {error}");
    }
}

/// 手工构建 TCP 监听 socket（socket2 提供比标准库更细的控制）：
/// IPv6 socket 设为 only_v6 避免与 IPv4 监听冲突；
/// SO_REUSEADDR 让重启时不必等旧连接的 TIME_WAIT 结束。
/// Build TCP sockets explicitly: IPv6-only avoids IPv4 collision and SO_REUSEADDR permits restart through TIME_WAIT.
fn create_listener(addr: SocketAddr) -> Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024 /* 显式监听队列 / Explicit listen backlog */)?;
    let std_listener = StdTcpListener::from(socket);
    std_listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(std_listener)?;
    Ok(listener)
}

/// 整理监听地址：返回（实际绑定的地址列表, 启动横幅要打印的地址列表）。
/// 绑定 0.0.0.0/:: 这类"任意地址"时，打印列表展开成各网卡的具体 IP，
/// 方便用户直接点击访问。
/// Normalize bind addresses and expand wildcard banners into clickable interface IPs.
fn check_addrs(args: &Args) -> Result<(Vec<BindAddr>, Vec<BindAddr>)> {
    if args.addrs.is_empty() {
        return Err(anyhow!("At least one bind address is required"));
    }
    let mut new_addrs = vec![];
    let mut print_addrs = vec![];
    let has_unspecified = args
        .addrs
        .iter()
        .any(|a| matches!(a, BindAddr::IpAddr(ip) if ip.is_unspecified()));
    let (ipv4_addrs, ipv6_addrs) = if has_unspecified {
        interface_addrs()?
    } else {
        (vec![], vec![])
    };
    for bind_addr in args.addrs.iter() {
        match bind_addr {
            BindAddr::IpAddr(ip) => {
                new_addrs.push(bind_addr.clone());
                match &ip {
                    IpAddr::V4(_) => {
                        if ip.is_unspecified() {
                            print_addrs.extend(ipv4_addrs.clone());
                        } else {
                            print_addrs.push(bind_addr.clone());
                        }
                    }
                    IpAddr::V6(_) => {
                        if ip.is_unspecified() {
                            print_addrs.extend(ipv6_addrs.clone());
                        } else {
                            print_addrs.push(bind_addr.clone());
                        }
                    }
                }
            }
            #[cfg(unix)]
            _ => {
                new_addrs.push(bind_addr.clone());
                print_addrs.push(bind_addr.clone())
            }
        }
    }
    print_addrs.sort_unstable();
    Ok((new_addrs, print_addrs))
}

fn interface_addrs() -> Result<(Vec<BindAddr>, Vec<BindAddr>)> {
    let (mut ipv4_addrs, mut ipv6_addrs) = (vec![], vec![]);
    let ifaces =
        if_addrs::get_if_addrs().with_context(|| "Failed to get local interface addresses")?;
    for iface in ifaces.into_iter() {
        let ip = iface.ip();
        if ip.is_ipv4() {
            ipv4_addrs.push(BindAddr::IpAddr(ip))
        }
        if ip.is_ipv6() {
            ipv6_addrs.push(BindAddr::IpAddr(ip))
        }
    }
    Ok((ipv4_addrs, ipv6_addrs))
}

fn print_listening(args: &Args, print_addrs: &[BindAddr]) -> Result<String> {
    let mut output = String::new();
    output.push_str(&format!(
        "Serving {} (TLS {})\n",
        args.serve_path.display(),
        if args.tls_cert.is_some() {
            "enabled"
        } else {
            "disabled"
        }
    ));
    let urls = print_addrs
        .iter()
        .map(|bind_addr| match bind_addr {
            BindAddr::IpAddr(addr) => {
                let addr = match addr {
                    IpAddr::V4(_) => format!("{}:{}", addr, args.port),
                    IpAddr::V6(_) => format!("[{}]:{}", addr, args.port),
                };
                let protocol = if args.tls_cert.is_some() {
                    "https"
                } else {
                    "http"
                };
                format!("{}://{}{}", protocol, addr, args.uri_prefix)
            }
            #[cfg(unix)]
            BindAddr::SocketPath(path) => path.to_string(),
        })
        .collect::<Vec<_>>();

    if urls.len() == 1 {
        output.push_str(&format!("Listening on {}", urls[0]))
    } else {
        let info = urls
            .iter()
            .map(|v| format!("  {v}"))
            .collect::<Vec<String>>()
            .join("\n");
        output.push_str(&format!("Listening on:\n{info}\n"))
    }

    Ok(output)
}

/// 挂起直到收到关停信号。 / Wait until a shutdown signal arrives.
async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        // 中文：除 Ctrl-C 外处理 systemd/容器 stop 使用的 SIGTERM，避免宽限期后被 SIGKILL 而无法干净收尾。
        // English: Handle SIGTERM as well as Ctrl-C so service managers permit clean drain instead of eventual SIGKILL.
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate =
            signal(SignalKind::terminate()).context("Failed to install SIGTERM handler")?;
        let mut interrupt =
            signal(SignalKind::interrupt()).context("Failed to install SIGINT handler")?;
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("Failed to install CTRL+C signal handler")?;
    }
    Ok(())
}

#[cfg(test)]
mod runtime_limit_tests {
    use super::{
        BLOCKING_POOL_SHUTDOWN_TIMEOUT, build_runtime, connection_lifetime_deadline,
        http1_request_head_semantic_size, prepare_unix_listener, remove_stale_unix_socket,
        response_has_wire_body, validate_stale_unix_socket_owner_policy,
        validate_unix_socket_ancestor_chain_policy, validate_unix_socket_owner_policy,
    };
    use crate::config::Args;
    use crate::http::body_full;
    use crate::path_identity::OutputPathIdentity;
    use crate::server::Response;
    use anyhow::{Context, Result};
    use assert_fs::TempDir;
    use hyper::{Method, Request, StatusCode, Version};
    use socket2::{Domain, SockAddr, Socket, Type};
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    fn capture_socket(path: &Path) -> Result<(OutputPathIdentity, PathBuf)> {
        let output = OutputPathIdentity::capture_no_symlinks(path)?;
        let operation_path = output.parent().proc_fd_path()?.join(output.basename());
        Ok((output, operation_path))
    }

    fn socket_bind_diagnostics(path: &Path) -> String {
        let parent_mode = path
            .parent()
            .and_then(|parent| std::fs::metadata(parent).ok())
            .map(|metadata| format!("{:04o}", metadata.mode() & 0o7777))
            .unwrap_or_else(|| "unavailable".to_owned());
        let process_umask = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find(|line| line.starts_with("Umask:"))
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "Umask: unavailable".to_owned());
        format!(
            "AF_UNIX test bind failed for `{}` (parent mode {parent_mode}; {process_umask})",
            path.display()
        )
    }

    #[test]
    fn blocking_pool_has_a_hard_global_running_worker_limit() -> Result<()> {
        let runtime = build_runtime(1)?;
        let (first_started_tx, first_started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let first = runtime.handle().spawn_blocking(move || {
            first_started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        first_started_rx.recv_timeout(Duration::from_secs(1))?;

        let (second_started_tx, second_started_rx) = mpsc::channel();
        let second = runtime.handle().spawn_blocking(move || {
            second_started_tx.send(()).unwrap();
        });
        assert!(
            second_started_rx
                .recv_timeout(Duration::from_millis(50))
                .is_err(),
            "a second blocking worker ran above the configured hard limit"
        );

        release_tx.send(())?;
        runtime.block_on(async {
            first.await.unwrap();
            second.await.unwrap();
        });
        second_started_rx.recv_timeout(Duration::from_secs(1))?;
        runtime.shutdown_timeout(BLOCKING_POOL_SHUTDOWN_TIMEOUT);
        Ok(())
    }

    #[test]
    fn runtime_shutdown_timeout_does_not_claim_to_terminate_stuck_syscall() -> Result<()> {
        let runtime = build_runtime(1)?;
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (exited_tx, exited_rx) = mpsc::channel();
        runtime.handle().spawn_blocking(move || {
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            exited_tx.send(()).unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(1))?;

        let started = Instant::now();
        runtime.shutdown_timeout(Duration::from_millis(20));
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "runtime shutdown waited indefinitely for a stuck blocking worker"
        );
        assert!(exited_rx.try_recv().is_err());

        // 中文：shutdown_timeout 只分离而不杀 syscall；测试需释放它，避免保留 worker 线程。
        // English: `shutdown_timeout` detaches rather than kills the syscall; release it so tests do not retain the worker.
        release_tx.send(())?;
        exited_rx.recv_timeout(Duration::from_secs(1))?;
        Ok(())
    }

    #[test]
    fn unix_socket_ancestors_require_both_trusted_owners_and_safe_write_policy() {
        let path = Path::new("/example/ram.sock");
        assert!(
            validate_unix_socket_ancestor_chain_policy(
                path,
                [
                    (Path::new("/"), 0o755, true),
                    (Path::new("/example"), 0o700, true),
                ],
            )
            .is_ok()
        );
        assert!(
            validate_unix_socket_ancestor_chain_policy(
                path,
                [
                    (Path::new("/"), 0o755, true),
                    (Path::new("/attacker"), 0o700, false),
                    (Path::new("/attacker/example"), 0o700, true),
                ],
            )
            .is_err(),
            "a trusted immediate parent beneath an attacker-owned grandparent is unsafe"
        );
        assert!(
            validate_unix_socket_ancestor_chain_policy(
                path,
                [
                    (Path::new("/"), 0o755, true),
                    (Path::new("/example"), 0o777, true),
                ],
            )
            .is_err(),
            "a non-sticky writable ancestor cannot protect the socket name"
        );
        assert!(
            validate_unix_socket_ancestor_chain_policy(
                path,
                [
                    (Path::new("/"), 0o755, true),
                    (Path::new("/tmp"), 0o1777, true),
                ],
            )
            .unwrap(),
            "the final ancestor determines whether the parent is shared sticky"
        );
    }

    #[test]
    fn unix_socket_owner_policy_distinguishes_private_and_shared_namespaces() {
        let path = Path::new("/example/ram.sock");
        assert!(validate_unix_socket_owner_policy(path, true, true).is_ok());
        assert!(
            validate_unix_socket_owner_policy(path, true, false).is_err(),
            "an untrusted socket owner can replace its name in a shared sticky directory"
        );
        assert!(
            validate_unix_socket_owner_policy(path, false, false).is_ok(),
            "a private parent makes an explicit target UID an administrator delegation"
        );
    }

    #[test]
    fn stale_unix_socket_cleanup_always_requires_a_trusted_owner() {
        let path = Path::new("/example/ram.sock");
        assert!(validate_stale_unix_socket_owner_policy(path, true).is_ok());
        assert!(
            validate_stale_unix_socket_owner_policy(path, false).is_err(),
            "private parent access alone must not authorize deleting another owner's socket"
        );
    }

    #[test]
    fn live_unix_socket_is_never_removed_by_startup_probe() -> Result<()> {
        let temp = TempDir::new()?;
        let path = temp.path().join("ram.sock");
        let _listener =
            UnixListener::bind(&path).with_context(|| socket_bind_diagnostics(&path))?;
        let inode = std::fs::symlink_metadata(&path)?.ino();
        let (output, operation_path) = capture_socket(&path)?;

        let error = remove_stale_unix_socket(&output, &operation_path)
            .expect_err("a live listener was incorrectly classified as stale");
        assert!(
            format!("{error:#}").contains("already served by a live process"),
            "unexpected live-socket error: {error:#}"
        );
        assert_eq!(std::fs::symlink_metadata(&path)?.ino(), inode);
        Ok(())
    }

    #[test]
    fn disconnected_unix_socket_is_removed_as_stale() -> Result<()> {
        let temp = TempDir::new()?;
        let path = temp.path().join("ram.sock");
        let listener = UnixListener::bind(&path).with_context(|| socket_bind_diagnostics(&path))?;
        drop(listener);
        let (output, operation_path) = capture_socket(&path)?;

        remove_stale_unix_socket(&output, &operation_path)?;
        assert!(
            !path.exists(),
            "an unserved socket inode survived authoritative ECONNREFUSED"
        );
        Ok(())
    }

    #[test]
    fn retained_unix_listener_parent_cannot_be_redirected_by_namespace_replacement() -> Result<()> {
        let temp = TempDir::new()?;
        let configured_parent = temp.path().join("sockets");
        let pinned_parent = temp.path().join("pinned-sockets");
        std::fs::create_dir(&configured_parent)?;
        let configured_path = configured_parent.join("ram.sock");
        let retained = OutputPathIdentity::capture_no_symlinks(&configured_path)?;

        // 中文：配置捕获后替换同名父目录并放入诱饵文件；启动只能在已固定旧目录中 bind，
        // 最终 namespace 复核必须安全失败，且清理 guard 不得删除新目录中的诱饵。
        // English: Replace the configured parent after capture and plant a decoy. Startup may bind
        // only below the pinned old parent, then must fail namespace verification without unlinking the decoy.
        std::fs::rename(&configured_parent, &pinned_parent)?;
        std::fs::create_dir(&configured_parent)?;
        let decoy = configured_parent.join("ram.sock");
        std::fs::write(&decoy, b"replacement namespace")?;

        let configured = configured_path.to_string_lossy();
        let error = match prepare_unix_listener(&configured, &Args::default(), Some(retained)) {
            Ok(_) => anyhow::bail!("listener startup followed a replaced configured namespace"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}").contains("is not a socket"),
            "unexpected namespace-replacement failure: {error:#}"
        );
        assert_eq!(
            std::fs::read(&decoy)?,
            b"replacement namespace",
            "pinned cleanup touched the replacement namespace"
        );
        assert!(
            !pinned_parent.join("ram.sock").exists(),
            "failed preparation left its socket in the pinned old parent"
        );
        Ok(())
    }

    #[test]
    fn saturated_unix_backlog_probe_is_nonblocking_and_fail_closed() -> Result<()> {
        let temp = TempDir::new()?;
        let path = temp.path().join("ram.sock");
        let address = SockAddr::unix(&path)?;
        let listener = Socket::new(Domain::UNIX, Type::STREAM, None)?;
        listener
            .bind(&address)
            .with_context(|| socket_bind_diagnostics(&path))?;
        listener.listen(1)?;
        let inode = std::fs::symlink_metadata(&path)?.ino();
        let (output, operation_path) = capture_socket(&path)?;

        let mut queued_clients = Vec::new();
        let mut saturated = false;
        for _ in 0..128 {
            let client = Socket::new(Domain::UNIX, Type::STREAM.nonblocking(), None)?;
            match client.connect(&address) {
                Ok(()) => queued_clients.push(client),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    saturated = true;
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }
        assert!(saturated, "failed to saturate the AF_UNIX accept backlog");

        let started = Instant::now();
        let error = remove_stale_unix_socket(&output, &operation_path)
            .expect_err("a saturated live socket was incorrectly deleted");
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "nonblocking live-socket probe stalled for {:?}",
            started.elapsed()
        );
        assert!(
            format!("{error:#}").contains("live, busy, or could not be verified"),
            "unexpected saturated-socket error: {error:#}"
        );
        assert_eq!(
            std::fs::symlink_metadata(&path)?.ino(),
            inode,
            "fail-closed probe removed the original live socket inode"
        );
        drop(queued_clients);
        drop(listener);
        Ok(())
    }

    #[test]
    fn connection_lifetime_deadline_is_anchored_to_accept_time() {
        let observed_now = tokio::time::Instant::now();
        let accepted_at = observed_now - Duration::from_secs(9);
        let deadline = connection_lifetime_deadline(accepted_at, Duration::from_secs(10));
        assert_eq!(deadline - accepted_at, Duration::from_secs(10));
        assert!(
            deadline <= observed_now + Duration::from_secs(1),
            "time spent before HTTP service incorrectly extended the absolute lifetime"
        );
    }

    #[test]
    fn response_idle_monitor_is_skipped_for_head_and_bodyless_responses() {
        let response = Response::new(body_full("payload"));
        assert!(response_has_wire_body(&Method::GET, &response));
        assert!(!response_has_wire_body(&Method::HEAD, &response));

        let empty = Response::new(body_full(""));
        assert!(!response_has_wire_body(&Method::GET, &empty));

        for status in [
            StatusCode::NO_CONTENT,
            StatusCode::RESET_CONTENT,
            StatusCode::NOT_MODIFIED,
        ] {
            let mut response = Response::new(body_full("must not reach the wire"));
            *response.status_mut() = status;
            assert!(!response_has_wire_body(&Method::GET, &response));
        }
    }

    #[test]
    fn http1_semantic_head_size_matches_its_canonical_wire_form() -> Result<()> {
        let wire = "CUSTOM http://example.test/path?q=1 HTTP/1.0\r\nHost: example.test\r\nX-Test: abc\r\n\r\n";
        let request = Request::builder()
            .method("CUSTOM")
            .uri("http://example.test/path?q=1")
            .version(Version::HTTP_10)
            .header("host", "example.test")
            .header("x-test", "abc")
            .body(())?;
        assert_eq!(http1_request_head_semantic_size(&request), Some(wire.len()));

        let h2 = Request::builder()
            .uri("https://example.test/")
            .version(Version::HTTP_2)
            .body(())?;
        assert_eq!(http1_request_head_semantic_size(&h2), None);
        Ok(())
    }
}
