//! HTTP 请求路由与服务器共享状态——整个项目的"中枢"模块。
//!
//! 本模块持有 `Server` 结构体（进程级只读状态），负责顶层的
//! `call`/`handle` 分发、请求路径解析、以及符号链接越界防护。
//! 具体的响应逻辑分散在各个职责单一的子模块里：
//!
//! - [`browse`]：目录列表、搜索、index 页渲染、404 页
//! - [`content`]：文件下载（Range/条件请求）、编辑器、哈希、令牌、
//!   内置前端资源与健康检查端点
//! - [`write`]：PUT/PATCH 上传、DELETE、MKCOL、COPY、MOVE
//! - [`archive`]：流式 `?zip` 打包下载
//! - [`webdav`]：PROPFIND/PROPPATCH 与 WebDAV 能力声明
//! - [`walk`]：带可见性策略的目录遍历（搜索/打包共用）
//! - [`model`]/[`range`]/[`reply`]/[`security_headers`]：视图模型与
//!   响应构建辅助
//!
//! ## 一次请求的生命周期（建议初学者顺着这条线读）
//! 1. runtime 模块的 accept 循环收到连接，hyper 解析出请求后调用 [`Server::call`]；
//! 2. `call` 负责"包外层"：记访问日志、兜住内部错误转成 500、补 CORS/安全头；
//! 3. [`Server::handle`] 是真正的路由器：解析路径 → 认证鉴权 → 按
//!    HTTP 方法和查询参数分发到各 `handle_*` 处理函数；
//! 4. 处理函数把结果写进 `&mut Response`（状态码、响应头、响应体）。
//!
//! ## 本模块的 Rust 知识点
//! - **`Arc<Server>` 共享状态**：每个连接的处理任务都持有一份
//!   `Arc`（原子引用计数指针）克隆，所有请求共享同一份只读配置，
//!   无需加锁——"共享不可变数据"是 Rust 并发的第一选择。
//! - **`async fn` 与 `.await`**：可能阻塞的文件系统工作会进入受控的
//!   blocking worker；网络与可异步文件操作在等待时不占用执行线程。
//! - **中央方法注册表**：标准 HTTP 与 WebDAV 方法都先解析为
//!   `ResourceMethod`，能力、CORS、鉴权和路由共用同一份策略元数据。
//!
//! ## English overview
//! HTTP request routing and shared server state: the central module for the project.
//!
//! This module owns the process-wide read-only [`Server`] structure and handles top-level
//! `call`/`handle` dispatch, request-path resolution, and symlink-containment enforcement. Focused
//! submodules implement the concrete response behavior:
//!
//! - [`browse`]: directory listings, search, index-page rendering, and 404 pages;
//! - [`content`]: file downloads with Range/conditional requests, the editor, hashes, tokens,
//!   embedded frontend assets, and the health-check endpoint;
//! - [`write`]: PUT/PATCH uploads, DELETE, MKCOL, COPY, and MOVE;
//! - [`archive`]: streaming `?zip` downloads;
//! - [`webdav`]: PROPFIND/PROPPATCH and WebDAV capability declarations;
//! - [`walk`]: visibility-aware directory traversal shared by search and archive generation;
//! - [`model`]/[`range`]/[`reply`]/[`security_headers`]: view models and response-building helpers.
//!
//! ## A request's lifetime
//! 1. The runtime module's accept loop receives a connection; once Hyper parses a request, it calls
//!    [`Server::call`].
//! 2. `call` supplies the outer shell: access logging, mapping internal errors to 500 responses, and
//!    applying CORS/security headers.
//! 3. [`Server::handle`] is the actual router: it resolves the path, authenticates and authorizes the
//!    caller, then dispatches to `handle_*` functions by HTTP method and query parameters.
//! 4. A handler writes status, headers, and body into `&mut Response`.
//!
//! ## Rust concepts in this module
//! - **Sharing `Arc<Server>` state**: every connection task holds an `Arc` clone, so all requests
//!   share one immutable configuration without locking. Shared immutable data is Rust's preferred
//!   concurrency pattern.
//! - **`async fn` and `.await`**: potentially blocking filesystem work enters controlled blocking
//!   workers; network and asynchronous file waits do not occupy an execution thread.
//! - **Central method registry**: standard HTTP and WebDAV methods are first parsed as
//!   `ResourceMethod`; capabilities, CORS, authorization, and routing share the same policy metadata.

mod archive;
mod authentication;
mod browse;
mod capabilities;
mod content;
mod dav_routes;
mod error;
mod filesystem;
mod model;
mod mutation_version;
mod preconditions;
mod range;
mod read_routes;
mod reply;
mod request_context;
mod router;
mod security_headers;
mod state;
mod walk;
mod webdav;
mod write;
mod write_routes;

#[cfg(feature = "fuzzing")]
pub(crate) use archive::fuzz_zip_entry_name;
#[cfg(feature = "fuzzing")]
pub(crate) use preconditions::fuzz_range_if_range;
#[cfg(feature = "fuzzing")]
pub(crate) use webdav::fuzz_webdav_xml;
#[cfg(feature = "fuzzing")]
pub(crate) use write::fuzz_destination_host_prefix;

use self::authentication::canonical_authorization_path_is_unavailable;
#[cfg(test)]
use self::authentication::canonicalize_authorization_path;
use self::error::ChangedStatus;
use self::model::DataKind;
use self::mutation_version::{
    MutationActivityGuard, MutationVersionBeginError, MutationVersionState, MutationVersionToken,
};
use self::preconditions::{ParsedPreconditions, method_uses_preconditions};

use self::capabilities::{CorsPreflightCapabilities, ResourceCapabilities, ResourceTarget};

use self::error::{
    AdmissionError, AdmissionResource, FsError, QueueScope, ResponseError, ResponseErrorRef,
    apply_anyhow_or_internal,
};
use self::filesystem::{
    FilesystemBlockingAdmission, GuardedBlockingFile, NodeKind, OpenedNode, RootFs,
    StaleUploadCleanupLimits, StaleUploadCleanupReport,
};
use self::reply::{status_bad_request, status_forbid, status_not_found};
use self::request_context::{NormalizedRequestPath, OpenedRequestTarget, RequestContext};
use self::security_headers::{CorsRequest, add_cors, add_security_headers};
use self::walk::HiddenRules;
use self::webdav::validate_mkcol_empty_body;
pub(crate) use self::write::{
    STORAGE_QUOTA_HOOK_HELPER_ARG, STORAGE_QUOTA_HOOK_HELPER_FAILURE_EXIT_CODE,
    run_storage_quota_hook_helper,
};
use self::write::{
    StagedUpload, UploadCommit, UploadProjection, parse_upload_offset, write_precondition_passes,
};
use crate::auth::{
    AccessPaths, AuthDecision, AuthRequest, AuthSource, TokenRevokeError, www_authenticate,
};
use crate::config::Args;
use crate::http::{
    ResourceMethod, ResourceRoute, ResponseBodyCompletion, ResponseBodyOutcome, body_full,
    body_with_completion_observer, body_with_request_permits,
};
use crate::logging::HttpLogger;
use crate::source_identity::{PeerIdentity, SourceIdentity, TrustedProxyPolicy};
use crate::utils::{decode_uri, encode_uri, get_file_name};

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use headers::{CacheControl, ETag, HeaderMapExt, LastModified};
use http_body_util::combinators::BoxBody;
use hyper::{
    Method, StatusCode,
    body::{Body as _, Incoming},
    header::{ALLOW, AUTHORIZATION, CONTENT_LENGTH, HeaderName, HeaderValue, RETRY_AFTER},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::Metadata;
use std::hash::Hash;
use std::io::SeekFrom;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::{Duration, Instant, SystemTime};
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt},
    sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, OwnedSemaphorePermit, RwLock, Semaphore},
};
use uuid::Uuid;

// 类型别名：给"带具体泛型参数的长类型"起短名，全项目统一使用。
// Type aliases give long concrete generic types one consistent short name across the project.
pub type Request = hyper::Request<Incoming>;
pub type Response = hyper::Response<BoxBody<Bytes, anyhow::Error>>;

fn request_admission_rejection(error: AdmissionError) -> Response {
    let mut response = Response::default();
    ResponseError::admission(error).apply(&mut response);
    response
        .headers_mut()
        .typed_insert(CacheControl::new().with_no_store());
    response
}

/// 判断哪些 `RootFs::open` 失败属于合法的查找未命中。
/// Determines which `RootFs::open` failures are legitimate lookup misses.
///
/// 面向请求的探测会隐藏不可用名称，避免 ACL 和命名空间形状成为存在性预言机。可信内部
/// 资源只将真正缺失视为可回退；权限、解析器和工作线程故障表示服务端资源能力损坏，返回
/// 500。
/// Request-facing probes hide unavailable names so ACL and namespace shape do not become an
/// existence oracle. Trusted internal assets only treat a truly missing name as fallback-worthy;
/// permission, resolver, and worker failures indicate a broken server-side capability and become 500.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpenErrorPolicy {
    HideUnavailable,
    TrustedInternalAsset,
}

fn classify_open_result(
    result: Result<OpenedNode>,
    operation: &'static str,
    policy: OpenErrorPolicy,
) -> Result<Option<OpenedNode>> {
    let error = match result {
        Ok(opened) => return Ok(Some(opened)),
        Err(error) => error,
    };
    let error = if ResponseErrorRef::from_anyhow_typed(&error, ChangedStatus::Conflict).is_some() {
        error
    } else {
        anyhow::Error::new(FsError::from_anyhow(operation, error))
    };
    let filesystem_error = FsError::in_anyhow_chain(&error);
    let is_hidden_miss = matches!(filesystem_error, Some(FsError::NotFound { .. }))
        || policy == OpenErrorPolicy::HideUnavailable
            && matches!(
                filesystem_error,
                Some(
                    FsError::Forbidden { .. }
                        | FsError::Conflict { .. }
                        | FsError::OutsideRoot { .. }
                )
            );
    if is_hidden_miss {
        return Ok(None);
    }
    if policy == OpenErrorPolicy::TrustedInternalAsset {
        return Err(anyhow::Error::new(FsError::io(operation, error)));
    }
    Err(error)
}

fn response_must_not_have_wire_body(res: &Response, request_method: &Method) -> bool {
    request_method == Method::HEAD
        || res.status().is_informational()
        || matches!(
            res.status(),
            StatusCode::NO_CONTENT | StatusCode::RESET_CONTENT | StatusCode::NOT_MODIFIED
        )
}

fn expected_wire_body_length(res: &Response, request_method: &Method) -> Option<u64> {
    // 即使 Content-Length 描述所选表示（尤其 HEAD 和 304），这些响应也绝不携带线上响应体。
    // These responses never carry a wire body even when Content-Length describes the selected
    // representation, notably HEAD and 304.
    if response_must_not_have_wire_body(res, request_method) {
        return Some(0);
    }

    res.headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .or_else(|| res.body().size_hint().exact())
}

#[allow(clippy::too_many_arguments)]
fn observe_response_completion(
    res: &mut Response,
    request_method: &Method,
    request_permits: Vec<OwnedSemaphorePermit>,
    logger: HttpLogger,
    mut data: HashMap<String, String>,
    request_started: Instant,
    response_ready_after: Duration,
    handler_error: Option<String>,
    skip_successful_asset: bool,
) {
    let request_id = data
        .get("request_id")
        .expect("server-generated request id is present")
        .clone();
    res.headers_mut().insert(
        HeaderName::from_static("x-request-id"),
        HeaderValue::from_str(&request_id).expect("UUID is a valid header value"),
    );
    data.insert("status".to_string(), res.status().as_u16().to_string());
    data.insert(
        "response_ready_time".to_string(),
        format!("{:.6}", response_ready_after.as_secs_f64()),
    );
    data.insert("response_started".to_string(), "1".to_string());

    let expected_length = expected_wire_body_length(res, request_method);
    if let Some(expected) = expected_length {
        data.insert("expected_body_bytes".to_string(), expected.to_string());
    }

    let body = std::mem::replace(res.body_mut(), body_full(Bytes::new()));
    let body = if response_must_not_have_wire_body(res, request_method) {
        // Hyper 的 HTTP/1 分发器会抑制 HEAD 负载字节，但 H2 会按协议无响应体语义校验 DATA
        // 帧。在共享响应边界丢弃响应体，避免处理器 `head_only` 分支后生成的错误泄露响应体
        // 或重置流。
        // Hyper's HTTP/1 dispatcher suppresses HEAD bytes, while H2 validates DATA frames against
        // bodyless semantics. Discard at the shared boundary so later errors cannot leak a body or
        // reset the stream.
        drop(body);
        body_full(Bytes::new())
    } else {
        body
    };
    let body = if request_permits.is_empty() {
        body
    } else {
        body_with_request_permits(body, request_permits)
    };
    *res.body_mut() = body_with_completion_observer(
        body,
        expected_length,
        move |completion: ResponseBodyCompletion| {
            let outcome = completion.outcome.as_str();
            data.insert("response_outcome".to_string(), outcome.to_string());
            data.insert("body_bytes".to_string(), completion.body_bytes.to_string());
            // 为 nginx 风格自定义格式保留别名；其运维人员通常把该字段称为 `$bytes_sent`。
            // Retain an alias for nginx-style custom formats whose operators naturally call the
            // field `$bytes_sent`.
            data.insert("bytes_sent".to_string(), completion.body_bytes.to_string());
            data.insert(
                "client_cancelled".to_string(),
                if completion.outcome == ResponseBodyOutcome::DownstreamCancelled {
                    "1"
                } else {
                    "0"
                }
                .to_string(),
            );
            data.insert(
                "request_time".to_string(),
                format!("{:.6}", request_started.elapsed().as_secs_f64()),
            );

            let stream_error = match completion.outcome {
                ResponseBodyOutcome::Complete | ResponseBodyOutcome::DownstreamCancelled => None,
                ResponseBodyOutcome::BodyError => Some(format!(
                    "response body failed after {} bytes: {}",
                    completion.body_bytes,
                    completion.error.as_deref().unwrap_or("unknown body error")
                )),
                ResponseBodyOutcome::Truncated => Some(format!(
                    "response body ended after {} bytes, before its declared length",
                    completion.body_bytes
                )),
                ResponseBodyOutcome::LengthMismatch => Some(format!(
                    "response body exceeded its declared length after {} bytes",
                    completion.body_bytes
                )),
            };
            let error = match (handler_error, stream_error) {
                (Some(handler), Some(stream)) => Some(format!("{handler}; {stream}")),
                (Some(handler), None) => Some(handler),
                (None, stream) => stream,
            };

            // 日常访问日志刻意省略内置静态资源，但流式传输故障绝不能被该降噪过滤器隐藏。
            // Built-in static assets are deliberately omitted from routine access logs, but the
            // noise filter must never hide a streaming failure.
            if skip_successful_asset
                && error.is_none()
                && completion.outcome != ResponseBodyOutcome::DownstreamCancelled
            {
                return;
            }
            if skip_successful_asset
                && completion.outcome == ResponseBodyOutcome::DownstreamCancelled
            {
                return;
            }
            logger.log(&data, error);
        },
    );
}

/// 仅在认证成功后放入响应扩展，供最外层访问日志读取；响应扩展不会被
/// 序列化到网络，因此不会改变任何 HTTP 接口。
/// Inserted into response extensions only after authentication for the outer access logger.
/// Extensions are never serialized to the wire and do not alter any HTTP interface.
#[derive(Clone)]
struct AuthenticatedUser(String);

#[derive(Clone, Copy)]
struct TokenAuthenticated;

// `include_str!` 在**编译期**把前端页面模板嵌进二进制，
// 所以发布单个可执行文件即可运行，无需附带资源目录。
// `include_str!` embeds the frontend template at compile time, so one executable runs without an
// accompanying asset directory.
const INDEX_HTML: &str = include_str!("../../web/index.html");
/// 流式 IO 的统一块大小（文件下载、zip 管道、Range 下载共用）。
/// Shared streaming-I/O chunk size for file downloads, ZIP pipes, and range responses.
pub(crate) const BUF_SIZE: usize = 65536;
/// 统计目录子条目数量时的上限（避免为超大目录数到天荒地老）。
/// Maximum children counted in a directory, preventing unbounded scans of huge directories.
const TOKENGEN_ALLOW: &str = "GET, POST";
const TOKEN_REVOKE_ALLOW: &str = "POST";
const CUSTOM_ASSET_INDEX_MAX_BYTES: usize = 1024 * 1024;
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum MutationLockMode {
    Read,
    Write,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) enum MutationLockKey {
    /// 规范化的根相对命名空间前缀。在创建缺失祖先期间保持稳定；对于尚无法打开 inode
    /// 身份的文件系统，也是保守回退。
    /// A normalized root-relative namespace prefix. It remains stable while missing ancestors are
    /// created and is the conservative fallback when an inode identity cannot yet be opened.
    Path(PathBuf),
    /// 一个已打开目录对象。设备/inode 身份使绑定别名和允许的符号链接别名汇聚到同一祖先锁。
    /// One opened directory object. Device/inode identity makes bind and allowed symlink aliases
    /// converge on the same ancestor lock.
    Directory { device: u64, inode: u64 },
    /// 已打开父目录中的一个目录项。与目标 inode 不同，原子重命名替换目录项时该身份保持稳定。
    /// One directory entry in an opened parent. Unlike the target inode, this identity stays stable
    /// when an atomic rename replaces the entry.
    Slot {
        parent_device: u64,
        parent_inode: u64,
        name: Vec<u8>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct MutationLockRequest {
    key: MutationLockKey,
    mode: MutationLockMode,
}

impl MutationLockRequest {
    pub(super) fn new(key: MutationLockKey, mode: MutationLockMode) -> Self {
        Self { key, mode }
    }
}

#[derive(Clone, Debug)]
struct MutationIntent {
    path: PathBuf,
    mode: MutationLockMode,
}

impl MutationIntent {
    fn read(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            mode: MutationLockMode::Read,
        }
    }

    fn write(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            mode: MutationLockMode::Write,
        }
    }
}

struct WriteLockTable {
    /// 弱引用让已完成且由攻击者选择的路径自动消失。每次获取前在短暂持有标准互斥锁时清理
    /// 死条目；该临界区内没有 await 或文件系统 I/O。
    /// Weak values let completed attacker-selected paths disappear. Dead entries are pruned before
    /// acquisition under the short standard mutex; no await or filesystem I/O occurs there.
    locks: StdMutex<HashMap<MutationLockKey, Weak<RwLock<()>>>>,
}

type MaterializedMutationLock = (MutationLockMode, Arc<RwLock<()>>);

struct KeyedLimit<K> {
    permits: StdMutex<HashMap<K, Weak<Semaphore>>>,
    limit: usize,
}

impl<K> KeyedLimit<K>
where
    K: Clone + Eq + Hash,
{
    fn new(limit: usize) -> Self {
        Self {
            permits: StdMutex::new(HashMap::new()),
            limit,
        }
    }

    fn try_acquire(&self, key: &K) -> Result<Option<OwnedSemaphorePermit>> {
        let semaphore = {
            let mut permits = self
                .permits
                .lock()
                .map_err(|_| anyhow::anyhow!("keyed admission limit table was poisoned"))?;
            permits.retain(|_, semaphore| semaphore.strong_count() > 0);
            permits.get(key).and_then(Weak::upgrade).unwrap_or_else(|| {
                let semaphore = Arc::new(Semaphore::new(self.limit));
                permits.insert(key.clone(), Arc::downgrade(&semaphore));
                semaphore
            })
        };
        Ok(semaphore.try_acquire_owned().ok())
    }

    #[cfg(test)]
    fn entry_count(&self) -> usize {
        self.permits
            .lock()
            .map(|permits| permits.len())
            .unwrap_or(usize::MAX)
    }
}

enum MutationGuard {
    Read { _guard: OwnedRwLockReadGuard<()> },
    Write { _guard: OwnedRwLockWriteGuard<()> },
}

/// 一次变更事务拥有的守卫。最终文件系统工作线程取得此值所有权，因此阻塞式
/// rename/remove/mkdir 仍运行时，取消 HTTP future 不会提前释放锁。
/// Owned guards for one mutation transaction. Final filesystem workers own this value so cancelling
/// the HTTP future cannot release locks while blocking rename/remove/mkdir still runs.
pub(super) struct MutationGuards {
    _guards: Vec<MutationGuard>,
    /// 与路径锁具有完全相同的所有权寿命；最终 worker 未结束时目录快照不会被签名。
    /// Shares the path locks' ownership lifetime, preventing snapshot signing until the final
    /// worker has actually stopped.
    mutation_activity: Option<MutationActivityGuard>,
}

impl MutationGuards {
    fn new(guards: Vec<MutationGuard>) -> Self {
        Self {
            _guards: guards,
            mutation_activity: None,
        }
    }

    /// 必须在全部路径锁获取后、任何最终文件系统副作用前调用。
    /// Must run after every path lock is held and before any final filesystem side effect.
    fn activate(
        &mut self,
        versions: &MutationVersionState,
        expected: Option<&MutationVersionToken>,
    ) -> std::result::Result<(), MutationVersionBeginError> {
        debug_assert!(self.mutation_activity.is_none());
        self.mutation_activity = Some(versions.begin_mutation(expected)?);
        Ok(())
    }
}

#[derive(Default)]
struct RequestAdmission {
    permits: Vec<OwnedSemaphorePermit>,
}

impl RequestAdmission {
    fn hold(&mut self, permit: OwnedSemaphorePermit) {
        self.permits.push(permit);
    }

    fn into_permits(self) -> Vec<OwnedSemaphorePermit> {
        self.permits
    }
}

struct CallResponseContext {
    request_method: Method,
    cors_request: CorsRequest,
    http_log_data: HashMap<String, String>,
    request_started: Instant,
    hsts_max_age: Option<u64>,
    skip_successful_asset: bool,
}

impl WriteLockTable {
    fn new() -> Self {
        Self {
            locks: StdMutex::new(HashMap::new()),
        }
    }

    async fn acquire(
        &self,
        fs_root: &RootFs,
        intents: &[MutationIntent],
        timeout: Duration,
    ) -> Result<MutationGuards> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let requests = fs_root.resolve_mutation_locks(intents).await?;
            let locks = self.materialize(&requests)?;
            let mut guards = Vec::with_capacity(locks.len());
            for (mode, lock) in locks {
                let guard = match mode {
                    MutationLockMode::Read => {
                        match tokio::time::timeout_at(deadline, lock.read_owned()).await {
                            Ok(guard) => MutationGuard::Read { _guard: guard },
                            Err(_) => {
                                return Err(anyhow::Error::new(AdmissionError::queue_timeout(
                                    AdmissionResource::MutationLocks,
                                    QueueScope::WorkerPool,
                                    timeout,
                                ))
                                .context("waiting for a filesystem mutation read lock"));
                            }
                        }
                    }
                    MutationLockMode::Write => {
                        match tokio::time::timeout_at(deadline, lock.write_owned()).await {
                            Ok(guard) => MutationGuard::Write { _guard: guard },
                            Err(_) => {
                                return Err(anyhow::Error::new(AdmissionError::queue_timeout(
                                    AdmissionResource::MutationLocks,
                                    QueueScope::WorkerPool,
                                    timeout,
                                ))
                                .context("waiting for a filesystem mutation write lock"));
                            }
                        }
                    }
                };
                guards.push(guard);
            }

            // 请求等待锁期间端点身份可能已变化（例如目录被重命名或缺失祖先被创建）。绝不能
            // 在过期对象的锁下继续：释放它们并在原截止时间内重试。
            // Endpoint identities may change while waiting for a lock. Never continue under locks
            // for stale objects; release them and retry within the original deadline.
            let verified = fs_root.resolve_mutation_locks(intents).await?;
            if verified == requests {
                return Ok(MutationGuards::new(guards));
            }
            drop(guards);
            if tokio::time::Instant::now() >= deadline {
                return Err(anyhow::Error::new(AdmissionError::queue_timeout(
                    AdmissionResource::MutationLocks,
                    QueueScope::WorkerPool,
                    timeout,
                ))
                .context("filesystem mutation namespace kept changing while acquiring locks"));
            }
        }
    }

    fn materialize(
        &self,
        requests: &[MutationLockRequest],
    ) -> Result<Vec<MaterializedMutationLock>, anyhow::Error> {
        let mut table = self
            .locks
            .lock()
            .map_err(|_| anyhow::anyhow!("filesystem mutation lock table was poisoned"))?;
        table.retain(|_, lock| lock.strong_count() > 0);
        Ok(requests
            .iter()
            .map(|request| {
                let lock = table
                    .get(&request.key)
                    .and_then(Weak::upgrade)
                    .unwrap_or_else(|| {
                        let lock = Arc::new(RwLock::new(()));
                        table.insert(request.key.clone(), Arc::downgrade(&lock));
                        lock
                    });
                (request.mode, lock)
            })
            .collect())
    }

    #[cfg(test)]
    fn entry_count(&self) -> usize {
        self.locks
            .lock()
            .map(|table| table.len())
            .unwrap_or(usize::MAX)
    }
}

#[cfg(test)]
mod mutation_lock_tests {
    use super::{MutationIntent, WriteLockTable};
    use crate::server::error::{
        AdmissionError, AdmissionResource, AdmissionTimeoutKind, ChangedStatus, QueueScope,
        ResponseErrorRef,
    };
    use crate::server::filesystem::RootFs;
    use anyhow::Result;
    use assert_fs::TempDir;
    use hyper::StatusCode;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Barrier;

    fn capability_root(allow_symlink: bool) -> Result<(TempDir, RootFs)> {
        let directory = TempDir::new()?;
        let root = RootFs::new(directory.path(), false, allow_symlink)?;
        Ok((directory, root))
    }

    #[tokio::test]
    async fn unrelated_paths_can_mutate_while_same_path_waits() -> Result<()> {
        let (_directory, root) = capability_root(false)?;
        let table = WriteLockTable::new();
        let held = table
            .acquire(
                &root,
                &[MutationIntent::write("first")],
                Duration::from_secs(1),
            )
            .await?;

        let unrelated = table
            .acquire(
                &root,
                &[MutationIntent::write("second")],
                Duration::from_millis(100),
            )
            .await?;

        let same_error = table
            .acquire(
                &root,
                &[MutationIntent::write("first")],
                Duration::from_millis(30),
            )
            .await
            .err()
            .expect("the same namespace slot was not serialized");
        assert_lock_timeout(&same_error);

        drop(unrelated);
        drop(held);
        Ok(())
    }

    #[tokio::test]
    async fn ancestor_mutation_excludes_descendant_mutation() -> Result<()> {
        let (directory, root) = capability_root(false)?;
        std::fs::create_dir(directory.path().join("parent"))?;
        let table = WriteLockTable::new();
        let ancestor = table
            .acquire(
                &root,
                &[MutationIntent::write("parent")],
                Duration::from_secs(1),
            )
            .await?;

        let descendant_error = table
            .acquire(
                &root,
                &[MutationIntent::write("parent/child")],
                Duration::from_millis(30),
            )
            .await
            .err()
            .expect("a descendant write bypassed its ancestor's exclusive lock");
        assert_lock_timeout(&descendant_error);

        drop(ancestor);
        table
            .acquire(
                &root,
                &[MutationIntent::write("parent/child")],
                Duration::from_secs(1),
            )
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn copy_source_reads_share_but_destination_write_excludes() -> Result<()> {
        let (directory, root) = capability_root(false)?;
        std::fs::write(directory.path().join("source"), b"data")?;
        let table = WriteLockTable::new();
        let first_reader = table
            .acquire(
                &root,
                &[MutationIntent::read("source")],
                Duration::from_secs(1),
            )
            .await?;
        let second_reader = table
            .acquire(
                &root,
                &[MutationIntent::read("source")],
                Duration::from_millis(100),
            )
            .await?;

        let writer_error = table
            .acquire(
                &root,
                &[MutationIntent::write("source")],
                Duration::from_millis(30),
            )
            .await
            .err()
            .expect("a writer bypassed active COPY readers");
        assert_lock_timeout(&writer_error);
        drop(second_reader);
        drop(first_reader);
        Ok(())
    }

    #[tokio::test]
    async fn directory_aliases_share_fd_identity_locks() -> Result<()> {
        use std::os::unix::fs::symlink;

        let (directory, root) = capability_root(true)?;
        std::fs::create_dir(directory.path().join("real"))?;
        symlink("real", directory.path().join("alias"))?;
        let table = WriteLockTable::new();
        let real = table
            .acquire(
                &root,
                &[MutationIntent::write("real")],
                Duration::from_secs(1),
            )
            .await?;

        let alias_error = table
            .acquire(
                &root,
                &[MutationIntent::write("alias/child")],
                Duration::from_millis(30),
            )
            .await
            .err()
            .expect("an alias bypassed the opened directory identity lock");
        assert_lock_timeout(&alias_error);
        drop(real);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reversed_two_path_transactions_do_not_deadlock() -> Result<()> {
        let (_directory, root) = capability_root(false)?;
        let table = Arc::new(WriteLockTable::new());
        let barrier = Arc::new(Barrier::new(3));
        let mut tasks = Vec::new();
        for reverse in [false, true] {
            let table = table.clone();
            let root = root.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                for _ in 0..64 {
                    let intents = if reverse {
                        vec![MutationIntent::write("b"), MutationIntent::write("a")]
                    } else {
                        vec![MutationIntent::write("a"), MutationIntent::write("b")]
                    };
                    let guards = table
                        .acquire(&root, &intents, Duration::from_secs(1))
                        .await?;
                    tokio::task::yield_now().await;
                    drop(guards);
                }
                Ok::<_, anyhow::Error>(())
            }));
        }
        barrier.wait().await;
        tokio::time::timeout(Duration::from_secs(5), async {
            for task in tasks {
                task.await??;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .map_err(|_| anyhow::anyhow!("reversed lock order deadlocked"))??;
        Ok(())
    }

    #[tokio::test]
    async fn completed_path_locks_are_reclaimed() -> Result<()> {
        let (_directory, root) = capability_root(false)?;
        let table = WriteLockTable::new();
        for index in 0..512 {
            let guards = table
                .acquire(
                    &root,
                    &[MutationIntent::write(format!("attacker-{index}"))],
                    Duration::from_secs(1),
                )
                .await?;
            drop(guards);
        }
        assert!(
            table.entry_count() <= 4,
            "dead weak entries accumulated in the path lock table: {}",
            table.entry_count()
        );
        Ok(())
    }

    fn assert_lock_timeout(error: &anyhow::Error) {
        assert!(matches!(
            AdmissionError::in_anyhow_chain(error),
            Some(AdmissionError::Timeout {
                resource: AdmissionResource::MutationLocks,
                kind: AdmissionTimeoutKind::Queue(QueueScope::WorkerPool),
                ..
            })
        ));
        let response = ResponseErrorRef::from_anyhow_typed(error, ChangedStatus::Conflict)
            .expect("mutation-lock timeout retained its typed admission marker");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}

#[cfg(test)]
mod keyed_limit_tests {
    use super::KeyedLimit;
    use crate::source_identity::SourceIdentity;
    use anyhow::Result;

    #[test]
    fn keyed_upload_permits_release_by_raii_and_dead_keys_are_reclaimed() -> Result<()> {
        let limits = KeyedLimit::new(1);
        let first = limits.try_acquire(&Some("user".to_string()))?.unwrap();
        assert!(limits.try_acquire(&Some("user".to_string()))?.is_none());
        assert!(limits.try_acquire(&Some("other".to_string()))?.is_some());
        drop(first);
        assert!(limits.try_acquire(&Some("user".to_string()))?.is_some());

        for index in 0..512 {
            let permit = limits
                .try_acquire(&Some(format!("attacker-{index}")))?
                .expect("fresh identity permit");
            drop(permit);
        }
        assert!(
            limits.entry_count() <= 2,
            "dead keyed upload buckets accumulated: {}",
            limits.entry_count()
        );
        Ok(())
    }

    #[test]
    fn missing_identity_uses_one_shared_bucket() -> Result<()> {
        let limits = KeyedLimit::<Option<String>>::new(1);
        let first = limits.try_acquire(&None)?.unwrap();
        assert!(limits.try_acquire(&None)?.is_none());
        drop(first);
        assert!(limits.try_acquire(&None)?.is_some());
        Ok(())
    }

    #[test]
    fn distinct_unix_peer_credentials_have_independent_source_buckets() -> Result<()> {
        let limits = KeyedLimit::new(1);
        let first = SourceIdentity::Unix {
            uid: 1000,
            gid: 100,
            pid: 41,
        };
        let second = SourceIdentity::Unix {
            uid: 1001,
            gid: 100,
            pid: 42,
        };
        let _first_permit = limits.try_acquire(&first)?.unwrap();
        assert!(limits.try_acquire(&first)?.is_none());
        assert!(limits.try_acquire(&second)?.is_some());
        Ok(())
    }

    #[test]
    fn unix_process_churn_for_one_uid_shares_a_source_bucket() -> Result<()> {
        let limits = KeyedLimit::new(1);
        let first_process = SourceIdentity::Unix {
            uid: 1000,
            gid: 100,
            pid: 41,
        };
        let forked_or_regrouped_process = SourceIdentity::Unix {
            uid: 1000,
            gid: 200,
            pid: 9001,
        };

        let _permit = limits.try_acquire(&first_process)?.unwrap();
        assert!(
            limits.try_acquire(&forked_or_regrouped_process)?.is_none(),
            "changing a Unix PID/GID bypassed the UID-scoped source limit"
        );
        Ok(())
    }
}

/// 服务器的进程级状态。启动时构建一次，之后只读，
/// 用 `Arc` 在所有连接间共享（见模块文档）。
/// Process-wide server state, built once at startup, read-only thereafter, and shared across all
/// connections through `Arc`.
pub struct Server {
    args: Args,
    /// 服务文件系统树固定的 Linux dirfd 能力。
    /// Pinned Linux dirfd capability for the served filesystem tree.
    fs_root: RootFs,
    /// 自定义公开资源位于单独且拒绝符号链接的能力下。
    /// Custom public assets live under a separate, symlink-denying capability.
    assets_root: Option<RootFs>,
    /// 内置前端资源的路径前缀（形如 `__ram_v<version>__/`，带版本号
    /// 使升级后浏览器缓存自动失效）。
    /// Built-in frontend asset prefix such as `__ram_v<version>__/`; the version invalidates browser
    /// caches after an upgrade.
    assets_prefix: String,
    /// 内置资源的完整请求路径前缀（`{uri_prefix}{assets_prefix}`），
    /// 用于替换进页面模板，也用于判断"该请求是资源请求，不记访问日志"。
    /// Full request prefix for built-in assets (`{uri_prefix}{assets_prefix}`), inserted into the
    /// page template and used to omit asset requests from routine access logs.
    assets_uri: String,
    /// 页面模板按 `__INDEX_DATA__` 占位符切成的前后两段，
    /// `__ASSETS_PREFIX__` 已在启动时替换完毕；这样每次渲染页面
    /// 只需一次字符串拼接，而不是对整个模板做两遍全文替换。
    /// 模板里没有占位符时 `html_tail` 为 `None`，此时原样输出模板。
    /// Page-template halves split around `__INDEX_DATA__`, with `__ASSETS_PREFIX__` already replaced
    /// at startup. Each render needs one concatenation instead of two full scans. If the data marker
    /// is absent, `html_tail` is `None` and the template is emitted unchanged.
    html_head: String,
    html_tail: Option<String>,
    /// 预编译的 `--hidden` 隐藏规则（见 walk.rs）。
    /// Precompiled `--hidden` visibility rules; see walk.rs.
    hidden: Arc<HiddenRules>,
    /// 单文件服务模式（serve 的路径是文件而非目录）下，
    /// 允许命中该文件的几种请求路径。
    /// Accepted request aliases for the served file in single-file mode.
    single_file_req_paths: Vec<String>,
    /// 全局"仍在运行"标志；关停时置 false，长任务（搜索/打包）检查它提前退出。
    /// Process-wide running flag, cleared at shutdown and polled by long searches/archives.
    running: Arc<AtomicBool>,
    /// 哈希、搜索、打包等高 IO/CPU 任务的独立并发闸门。
    /// 连接总上限只能防止连接数爆炸，不能防止少量已认证请求
    /// 同时扫描大目录/大文件。子模块在启动这些任务前获取 permit。
    /// Separate concurrency gate for high-I/O/CPU hashing, search, and archive work. A connection cap
    /// cannot stop a few authenticated requests scanning large trees/files; tasks acquire a permit.
    pub(super) expensive_task_limit: Arc<Semaphore>,
    /// PUT/PATCH 候选在网络请求体到达时占用磁盘；该容量与 CPU 密集的搜索/打包准入分离。
    /// PUT/PATCH candidates consume disk while their network bodies arrive. Keep that capacity
    /// separate from CPU-heavy search/archive admission.
    pub(super) upload_limit: Arc<Semaphore>,
    /// 已认证身份和经验证传输来源各有独立子上限，避免单个账户或来源耗尽所有全局上传槽。
    /// 来源就是认证、请求准入和访问日志共用的不可变 `SourceIdentity`：允许列表中的直连
    /// 代理后严格解析出的客户端 IP、直连 TCP 对端，或内核提供的 Unix 对端凭据。
    /// Authenticated identities and verified transport sources receive independent sub-limits so one
    /// account/source cannot consume every upload slot. The immutable `SourceIdentity` is shared by
    /// authentication, admission, and logging: a strictly parsed forwarded IP behind an allowlisted
    /// direct proxy, the direct TCP peer, or kernel-supplied Unix peer credentials.
    upload_user_limit: KeyedLimit<Option<String>>,
    upload_source_limit: KeyedLimit<SourceIdentity>,
    /// 每个 HTTP 请求的进程级准入控制。与 `runtime` 连接信号量不同，它也限制 HTTP/2 流。
    /// 所有权 permit 转移到响应体，使慢速下载一直计入统计直至 EOS 或客户端取消。
    /// Process-wide admission for every HTTP request. Unlike the runtime connection semaphore, it
    /// also bounds HTTP/2 streams. Its owned permit moves into the response body until EOS/cancel.
    request_limit: Arc<Semaphore>,
    /// 最多允许这么多请求等待进程级执行槽；获得执行 permit 后立即释放等待 permit。
    /// At most this many requests may wait for a process-wide execution slot. The waiting permit is
    /// released as soon as an execution permit is obtained.
    request_queue_limit: Arc<Semaphore>,
    /// 来源准入不阻塞，并发生在全局队列之前。
    /// Source admission is non-blocking and happens before the global queue.
    request_source_limit: KeyedLimit<SourceIdentity>,
    /// 已认证账户准入不阻塞，在凭据校验后且资源工作开始前立即执行。
    /// Authenticated-account admission is non-blocking and happens immediately after credential
    /// verification, before resource work starts.
    request_user_limit: KeyedLimit<String>,
    trusted_proxy_policy: TrustedProxyPolicy,
    /// 从权威状态观察到提交，串行化最终文件系统事务。PUT/PATCH 请求体在获取该锁前接收，
    /// 因此涓流客户端无法独占变更协调。
    /// Serialize final filesystem transactions from authoritative observation through commit.
    /// PUT/PATCH bodies arrive before this lock, so a trickle client cannot monopolize coordination.
    write_locks: WriteLockTable,
    /// 进程唯一启动标识、单调变更 revision 与在途 worker 计数；用于保护目录页发起的
    /// DELETE/MOVE，且不被误当成持久文件系统版本。
    /// Process-unique boot identity, monotonic mutation revision, and in-flight worker count used
    /// to protect listing-originated DELETE/MOVE without pretending to be a persistent FS version.
    mutation_versions: MutationVersionState,
}

fn normalize_request_path(path: &str, path_prefix: &str) -> Option<String> {
    let path = decode_uri(path)?;
    let path = path.trim_matches('/');
    let mut parts = vec![];
    for comp in Path::new(path).components() {
        if let Component::Normal(v) = comp {
            // URL 解码后仍可能含 `%00` 产生的 NUL；Linux 路径 API
            // 无法表示它。应在路由层返回 400，而不是让后续 open/stat
            // 变成模糊的 500 I/O 错误。
            // URL decoding can leave a NUL from `%00`, which Linux path APIs cannot represent. Return
            // 400 in routing instead of turning a later open/stat into an opaque 500 I/O failure.
            let v = v.to_str()?;
            if v.contains('\0') {
                return None;
            }
            // 原子 PUT/COPY 在目标目录内使用保留的临时文件名。
            // 这些候选在提交前绝不能被另一个 HTTP 请求列出、读取或
            // 修改；崩溃后遗留的候选同样保持不可访问。
            // Atomic PUT/COPY uses reserved temporary names in the destination directory. Other HTTP
            // requests must never list/read/change candidates before commit; crash remnants stay hidden.
            if is_internal_temp_name(v) {
                return None;
            }
            parts.push(v);
        } else {
            return None;
        }
    }
    let new_path = parts.join("/");
    if path_prefix.is_empty() {
        return Some(new_path);
    }
    if new_path == path_prefix {
        return Some(String::new());
    }
    new_path
        .strip_prefix(&format!("{path_prefix}/"))
        .map(ToOwned::to_owned)
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_uri_path(data: &[u8]) {
    if data.len() > 64 * 1024 {
        return;
    }
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    // 换行分帧使检入的种子语料可按文本审查；变异器仍可生成 URL 中不可能出现的 NUL 分帧。
    // Newline framing keeps the checked-in seed corpus reviewable as text; NUL framing remains
    // available to the mutator and cannot occur in a URL.
    let (path_prefix, path) = input
        .split_once('\0')
        .or_else(|| input.split_once('\n'))
        .unwrap_or(("", input));
    let Ok(path_prefix) = crate::config::normalize_path_prefix(path_prefix) else {
        return;
    };
    if let Some(normalized) = normalize_request_path(path, &path_prefix) {
        assert!(!normalized.starts_with('/'));
        assert!(!normalized.ends_with('/'));
        assert!(!normalized.contains('\0'));
        assert!(
            Path::new(&normalized)
                .components()
                .all(|component| { matches!(component, Component::Normal(_)) })
        );
        let encoded = crate::utils::encode_uri(&normalized);
        assert_eq!(decode_uri(&encoded).as_deref(), Some(normalized.as_str()));
        let encoded_prefix = crate::utils::encode_uri(&path_prefix);
        let routed = if path_prefix.is_empty() {
            format!("/{encoded}")
        } else if encoded.is_empty() {
            format!("/{encoded_prefix}")
        } else {
            format!("/{encoded_prefix}/{encoded}")
        };
        assert_eq!(
            normalize_request_path(&routed, &path_prefix).as_deref(),
            Some(normalized.as_str())
        );
    }
}

/// 原子写入候选文件的保留命名空间。严格校验 UUID 形状，避免仅因普通
/// 用户文件碰巧以 `.ram-upload-` 开头就被隐藏。
/// Reserved namespace for atomic-write candidates. Strict UUID-shape validation prevents an ordinary
/// user file from being hidden merely because its name starts with `.ram-upload-`.
pub(super) fn is_internal_temp_name(name: &str) -> bool {
    let Some(value) = name
        .strip_prefix(".ram-upload-")
        .or_else(|| name.strip_prefix(".ram-staging-"))
        .and_then(|value| value.strip_suffix(".tmp"))
    else {
        return false;
    };
    value.len() == 36
        && value.as_bytes().iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
            }
        })
}

#[cfg(test)]
mod internal_temp_name_tests {
    use super::is_internal_temp_name;

    #[test]
    fn only_canonical_lowercase_hyphenated_candidate_names_are_reserved() {
        for valid in [
            ".ram-upload-00000000-0000-4000-8000-000000000001.tmp",
            ".ram-staging-01234567-89ab-cdef-0123-456789abcdef.tmp",
        ] {
            assert!(is_internal_temp_name(valid), "{valid}");
        }
        for invalid in [
            ".ram-upload-00000000000040008000000000000001.tmp",
            ".ram-upload-urn:uuid:00000000-0000-4000-8000-000000000001.tmp",
            ".ram-upload-{00000000-0000-4000-8000-000000000001}.tmp",
            ".ram-upload-00000000-0000-4000-8000-000000000001-extra.tmp",
            ".ram-upload-00000000-0000-4000-8000-00000000000A.tmp",
            ".ram-upload-00000000_0000_4000_8000_000000000001.tmp",
            ".ram-upload-not-a-uuid.tmp",
            ".ram-staging",
        ] {
            assert!(!is_internal_temp_name(invalid), "{invalid}");
        }
    }
}

#[cfg(test)]
mod path_encoding_property_tests {
    use super::{NodeKind, RootFs, normalize_request_path};
    use crate::utils::encode_uri;
    use anyhow::Result;
    use assert_fs::TempDir;
    use std::collections::BTreeSet;
    use std::path::{Component, Path};

    /// 确定性生成路径性质：每个获准 URL 往返后仍为规范路径，且保留的 RootFs 能力会在
    /// 固定目录下解析它。固定种子和数量让失败可复现并限制 CI 工作量。
    /// Deterministic generated-path property: every accepted URL round trip remains normalized and
    /// resolves below the pinned RootFs directory. Fixed seed/count makes failures reproducible and bounded.
    #[test]
    fn accepted_path_encoding_round_trips_inside_capability_root() -> Result<()> {
        const COMPONENTS: [&str; 12] = [
            "plain",
            "space name",
            "percent%name",
            "query?name",
            "hash#name",
            "amp&name",
            "quote\"name",
            "résumé",
            "文件",
            "emoji-🙂",
            "dot.name",
            "dash_name~ok",
        ];
        const CASES: usize = 192;

        let directory = TempDir::new()?;
        let mut generated = BTreeSet::new();
        let mut state = 0x5eed_cafe_d15c_a11eu64;
        for case in 0..CASES {
            // xorshift64*：确定且无依赖的输入生成。
            // xorshift64*: deterministic, dependency-free input generation.
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            let segment_count = 1 + (state as usize % 4);
            let mut segments = Vec::with_capacity(segment_count);
            for segment in 0..segment_count {
                state = state.wrapping_mul(0x2545_f491_4f6c_dd1d);
                let atom = COMPONENTS[state as usize % COMPONENTS.len()];
                segments.push(format!("{case:03}-{segment}-{atom}"));
            }
            let relative = segments.join("/");
            std::fs::create_dir_all(directory.path().join(&relative))?;
            generated.insert(relative);
        }
        assert_eq!(generated.len(), CASES);

        let root = RootFs::new(directory.path(), false, false)?;
        for prefix in ["", "cap", "cap/前缀"] {
            for relative in &generated {
                let request_path = if prefix.is_empty() {
                    format!("/{}", encode_uri(relative))
                } else {
                    format!("/{}", encode_uri(&format!("{prefix}/{relative}")))
                };
                let normalized = normalize_request_path(&request_path, prefix)
                    .expect("generated accepted path must normalize");
                assert_eq!(&normalized, relative);
                assert!(
                    Path::new(&normalized)
                        .components()
                        .all(|part| matches!(part, Component::Normal(_)))
                );

                let opened = root.open_raw(Path::new(&normalized), NodeKind::Directory)?;
                assert_eq!(root.real_relative_verified(&opened)?, Path::new(relative));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod open_error_policy_tests {
    use super::{
        ChangedStatus, FsError, OpenErrorPolicy, OpenedNode, ResponseErrorRef, RootFs,
        canonical_authorization_path_is_unavailable, canonicalize_authorization_path,
        classify_open_result,
    };
    use anyhow::Result;
    use assert_fs::TempDir;
    use hyper::StatusCode;
    use std::io;
    use std::os::unix::fs::symlink;

    fn raw_open_failure(kind: io::ErrorKind, detail: &'static str) -> anyhow::Result<OpenedNode> {
        Err(anyhow::Error::new(io::Error::new(kind, detail)))
    }

    #[test]
    fn request_facing_open_hides_only_closed_unavailable_classes() {
        for kind in [
            io::ErrorKind::NotFound,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::NotADirectory,
        ] {
            let opened = classify_open_result(
                raw_open_failure(kind, "private lookup detail"),
                "probing a request target",
                OpenErrorPolicy::HideUnavailable,
            )
            .expect("closed lookup failures are intentional misses");
            assert!(opened.is_none());
        }

        let error = match classify_open_result(
            raw_open_failure(io::ErrorKind::Other, "private device failure"),
            "probing a request target",
            OpenErrorPolicy::HideUnavailable,
        ) {
            Err(error) => error,
            Ok(_) => panic!("infrastructure failure must not become a lookup miss"),
        };
        assert!(format!("{error:#}").contains("private device failure"));
        let response = ResponseErrorRef::from_anyhow_typed(&error, ChangedStatus::Conflict)
            .expect("open infrastructure failures are typed");
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn trusted_internal_asset_permission_failure_is_internal_not_a_public_miss() {
        let missing = classify_open_result(
            raw_open_failure(io::ErrorKind::NotFound, "private missing asset"),
            "opening a trusted internal asset",
            OpenErrorPolicy::TrustedInternalAsset,
        )
        .expect("a genuinely absent optional asset permits fallback");
        assert!(missing.is_none());

        let error = match classify_open_result(
            raw_open_failure(io::ErrorKind::PermissionDenied, "private asset permission"),
            "opening a trusted internal asset",
            OpenErrorPolicy::TrustedInternalAsset,
        ) {
            Err(error) => error,
            Ok(_) => panic!("a broken trusted asset capability must be reported"),
        };
        assert!(format!("{error:#}").contains("private asset permission"));
        assert!(matches!(
            FsError::in_anyhow_chain(&error),
            Some(FsError::Io { .. })
        ));
        let response = ResponseErrorRef::from_anyhow_typed(&error, ChangedStatus::Conflict)
            .expect("trusted asset failures are typed");
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn canonical_authorization_only_falls_back_across_missing_components() -> Result<()> {
        let root = TempDir::new()?;
        std::fs::create_dir(root.path().join("real"))?;
        symlink("real", root.path().join("alias"))?;
        let capability = RootFs::new(root.path(), false, false)?;

        let resolved =
            canonicalize_authorization_path(&capability, root.path(), "alias/missing/file.txt")
                .await?;
        assert_eq!(resolved, "real/missing/file.txt");
        Ok(())
    }

    #[tokio::test]
    async fn canonical_authorization_types_outside_root_and_infrastructure_failures() -> Result<()>
    {
        let root = TempDir::new()?;
        let outside = TempDir::new()?;
        let capability = RootFs::new(root.path(), false, false)?;
        symlink(outside.path(), root.path().join("escape"))?;
        let outside_error =
            canonicalize_authorization_path(&capability, root.path(), "escape/file.txt")
                .await
                .expect_err("an outside-root symlink must never select an ACL path");
        assert!(matches!(
            FsError::in_anyhow_chain(&outside_error),
            Some(FsError::OutsideRoot { .. })
        ));
        assert_eq!(
            ResponseErrorRef::from_anyhow_typed(&outside_error, ChangedStatus::Conflict)
                .expect("outside-root resolution is typed")
                .status(),
            StatusCode::FORBIDDEN
        );

        symlink("loop", root.path().join("loop"))?;
        let unavailable_error = canonicalize_authorization_path(&capability, root.path(), "loop")
            .await
            .expect_err("a symlink loop must not silently reuse the request path");
        assert!(matches!(
            FsError::in_anyhow_chain(&unavailable_error),
            Some(FsError::Conflict { .. })
        ));
        assert!(canonical_authorization_path_is_unavailable(
            &unavailable_error
        ));
        assert_eq!(
            ResponseErrorRef::from_anyhow_typed(&unavailable_error, ChangedStatus::Conflict)
                .expect("unavailable resolver state is typed")
                .status(),
            StatusCode::CONFLICT
        );

        let missing_root = root.path().join("missing-root");
        let infrastructure_error =
            canonicalize_authorization_path(&capability, &missing_root, "child")
                .await
                .expect_err("a missing configured root is a backend failure");
        assert!(matches!(
            FsError::in_anyhow_chain(&infrastructure_error),
            Some(FsError::Io { .. })
        ));
        assert!(!canonical_authorization_path_is_unavailable(
            &infrastructure_error
        ));
        assert_eq!(
            ResponseErrorRef::from_anyhow_typed(&infrastructure_error, ChangedStatus::Conflict)
                .expect("resolver infrastructure failure is typed")
                .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        Ok(())
    }
}

fn handle_startup_stale_cleanup(
    result: Result<StaleUploadCleanupReport>,
    writable: bool,
) -> Result<()> {
    match result {
        Ok(report) => {
            let complete = report.is_complete();
            log_stale_upload_cleanup(report);
            if writable && !complete {
                bail!(
                    "refusing to start writable service because private upload recovery could not prove a complete cleanup"
                );
            }
            Ok(())
        }
        Err(error) if writable => {
            Err(error.context("Failed to scan stale private upload candidates"))
        }
        Err(error) => {
            const WARNING: &str =
                "READ-ONLY STARTUP CONTINUES AFTER PRIVATE UPLOAD RECOVERY FAILURE";
            eprintln!("WARNING: {WARNING}: {error:#}");
            warn!("{WARNING}: {error:#}");
            Ok(())
        }
    }
}

fn log_stale_upload_cleanup(report: StaleUploadCleanupReport) {
    if !report.is_complete() {
        warn!(
            "Stale upload cleanup incomplete: scanned={}, deleted={}, active={}, young={}, unsafe={}, failures={}, suppressed_failures={}, entry_limit={}, depth_limit={}, deletion_limit={}, deadline={}",
            report.scanned_entries,
            report.deleted,
            report.skipped_active,
            report.skipped_young,
            report.skipped_unsafe,
            report.failures,
            report.suppressed_failures,
            report.entry_limit_reached,
            report.depth_limit_reached,
            report.deletion_limit_reached,
            report.deadline_reached,
        );
        for failure in &report.failure_diagnostics {
            warn!(
                "Stale upload cleanup failure: stage={} relative_path={:?} cause={}",
                failure.stage, failure.relative_path, failure.cause
            );
        }
    } else if report.deleted > 0 {
        info!(
            "Removed {} stale private upload candidates after scanning {} entries",
            report.deleted, report.scanned_entries
        );
    }
}

#[cfg(test)]
mod startup_cleanup_tests {
    use super::*;

    #[test]
    fn root_scan_failure_is_fatal_only_for_writable_startup() {
        assert!(
            handle_startup_stale_cleanup(Err(anyhow::anyhow!("root scan failed")), false).is_ok()
        );
        let error =
            handle_startup_stale_cleanup(Err(anyhow::anyhow!("private root scan detail")), true)
                .unwrap_err();
        assert!(format!("{error:#}").contains("Failed to scan stale private upload candidates"));
        assert!(format!("{error:#}").contains("private root scan detail"));
    }

    #[test]
    fn incomplete_report_is_fatal_only_for_writable_startup() {
        let report = StaleUploadCleanupReport {
            failures: 1,
            ..StaleUploadCleanupReport::default()
        };
        assert!(handle_startup_stale_cleanup(Ok(report.clone()), false).is_ok());
        assert!(handle_startup_stale_cleanup(Ok(report), true).is_err());
    }
}

pub(crate) fn drain_private_candidate_cleanup(timeout: Duration) -> bool {
    filesystem::drain_candidate_cleanup(timeout)
}

/// `SystemTime` → Unix 毫秒时间戳（早于 1970 的异常时间按 0 处理）。
/// Convert `SystemTime` to Unix milliseconds, clamping anomalous pre-1970 times to zero.
fn to_timestamp(time: &SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// 把文件系统路径转换成 HTTP/JSON 可表示的 UTF-8 路径。
///
/// Linux 文件名允许任意非 NUL 字节。这里必须显式失败，不能把无法表示
/// 的路径退化成空串，否则非 UTF-8 资源可能意外获得根路径语义。
/// Linux filenames permit arbitrary non-NUL bytes. Fail explicitly instead of degrading an
/// unrepresentable path to an empty string, which could grant a non-UTF-8 object root semantics.
fn normalize_path<P: AsRef<Path>>(path: P) -> Result<String> {
    let Some(path) = path.as_ref().to_str() else {
        bail!("filesystem path is not valid UTF-8")
    };
    Ok(path.to_owned())
}

/// 单文件的 ACL 资源名。配置校验已经拒绝非 UTF-8 文件名；这里仍使用
/// 不会产生有损别名的保守回退，避免未来调用方绕过该不变量。
/// ACL resource name for single-file mode. Configuration rejects non-UTF-8 filenames; this keeps a
/// non-lossy conservative fallback in case a future caller bypasses that invariant.
fn single_file_authorization_path(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "__ram_single_file__".to_string())
}

fn status_method_not_allowed(res: &mut Response, allow: &'static str) {
    *res.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
    res.headers_mut()
        .insert(ALLOW, HeaderValue::from_static(allow));
}

/// OPTIONS 与每个资源的 405 都呈现同一组有效能力。刻意不发送数字 `DAV` 头：Ram 实现的
/// 是有界且有文档说明的子集，而非 DAV class 1 的全部强制语义。
/// OPTIONS and every resource 405 render the same effective capability set. There is deliberately
/// no numeric `DAV` header: Ram implements a bounded documented subset, not all DAV class 1 semantics.
fn set_resource_headers(res: &mut Response, capabilities: ResourceCapabilities) {
    let allow = capabilities.allow_header();
    let value = HeaderValue::from_str(&allow)
        .expect("resource method names always form a valid Allow header");
    res.headers_mut().insert(ALLOW, value);
    res.headers_mut().remove("DAV");
}

fn status_resource_method_not_allowed(res: &mut Response, capabilities: ResourceCapabilities) {
    set_resource_headers(res, capabilities);
    *res.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
}

/// 不大于浏览器编辑器上限的文件获得内容派生的强验证器。这样可保证乐观编辑保存和小型
/// If-Range 请求正确，又不强制每个数 GiB 下载二次完整读取。更大文件获得元数据派生的
/// *弱*验证器：时间戳/inode 元组可用于缓存重验证，但不能在所有文件系统证明逐字节相同。
/// Files no larger than the browser editor limit receive a content-derived strong validator. This
/// keeps optimistic saves and small If-Range requests correct without rereading every huge download.
/// Larger files get a metadata-derived *weak* validator useful for revalidation, not byte identity.
const STRONG_ETAG_MAX_SIZE: u64 = 4 * 1024 * 1024;

pub(super) struct CacheValidators {
    pub(super) etag: ETag,
    pub(super) last_modified: Option<LastModified>,
    pub(super) strong: bool,
}

/// 从调用方使用的同一个已打开描述符构建验证器，并在返回前恢复文件偏移。在 Ram 支持的
/// 写入模型中，变更使用原子替换，因此读取期间已打开 inode 不变；原地外部写入者超出此
/// 模型，由外部写入者 TOCTOU 工作单独处理。
/// Build validators from the caller's already-open descriptor and restore its offset before return.
/// Ram mutations atomically replace files, so the opened inode is immutable during this read.
/// In-place external writers are outside that model and handled by separate TOCTOU protection.
async fn extract_cache_headers(
    file: &mut GuardedBlockingFile,
    meta: &Metadata,
) -> Result<CacheValidators> {
    let last_modified = meta
        .modified()
        .ok()
        .or_else(|| meta.created().ok())
        .map(LastModified::from);

    let (tag, strong) = if meta.len() <= STRONG_ETAG_MAX_SIZE {
        let original_position = file.stream_position().await?;
        file.seek(SeekFrom::Start(0)).await?;
        let mut remaining = meta.len();
        let mut digest = Sha256::new();
        let mut buffer = vec![0_u8; BUF_SIZE];
        while remaining > 0 {
            let limit = remaining.min(buffer.len() as u64) as usize;
            let read = file.read(&mut buffer[..limit]).await?;
            if read == 0 {
                bail!("file changed while calculating its strong ETag");
            }
            digest.update(&buffer[..read]);
            remaining -= read as u64;
        }
        file.seek(SeekFrom::Start(original_position)).await?;
        (format!("sha256:{}", hex::encode(digest.finalize())), true)
    } else {
        let mut version = Sha256::new();
        version.update(meta.dev().to_be_bytes());
        version.update(meta.ino().to_be_bytes());
        version.update(meta.mtime().to_be_bytes());
        version.update(meta.mtime_nsec().to_be_bytes());
        version.update(meta.ctime().to_be_bytes());
        version.update(meta.ctime_nsec().to_be_bytes());
        version.update(meta.len().to_be_bytes());
        (format!("meta:{}", hex::encode(version.finalize())), false)
    };
    let etag = format!("{}\"{tag}\"", if strong { "" } else { "W/" })
        .parse::<ETag>()
        .context("failed to encode file-version ETag")?;
    Ok(CacheValidators {
        etag,
        last_modified,
        strong,
    })
}

/// 查询参数是否以"无值开关"的形式出现：`?zip` 算出现（值为空串），
/// `?zip=1` 不算——这些参数的约定是只看有没有、不看值。
/// Whether a query parameter appears as a valueless switch: `?zip` counts, while `?zip=1` does not.
fn has_query_flag(query_params: &HashMap<String, String>, name: &str) -> bool {
    query_params
        .get(name)
        .map(|v| v.is_empty())
        .unwrap_or_default()
}
