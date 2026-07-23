//! 文件系统、准入控制和 HTTP 层共享的类型化错误。
//! Typed errors shared by the filesystem, admission-control and HTTP layers.
//!
//! 内部错误保留具体原因用于结构化日志；只有 [`ResponseError`] 能分配公开状态码和
//! 响应文本。处理器可以替换公开响应体，但不能改变底层分类。
//! Internal errors keep their concrete cause for structured logging, while [`ResponseError`] is
//! the only place that assigns public status codes and response text. Protocol handlers may replace
//! the public body without changing the underlying classification.

use super::{Response, body_full};

use anyhow::Error as AnyError;
use hyper::StatusCode;
use hyper::header::{
    ACCEPT_RANGES, CONTENT_DISPOSITION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE,
    CONTENT_TYPE, ETAG, HeaderValue, LAST_MODIFIED, RETRY_AFTER,
};
use rustix::io::Errno;
use std::error::Error as StdError;
use std::fmt;
use std::io;
use std::time::Duration;

/// 即使增加 `anyhow` 上下文也必须保留语义的文件系统故障。
/// Filesystem failures whose meaning must survive added `anyhow` context.
#[derive(Debug)]
pub(crate) enum FsError {
    NotFound {
        operation: &'static str,
        source: AnyError,
    },
    Forbidden {
        operation: &'static str,
        source: AnyError,
    },
    Conflict {
        operation: &'static str,
        source: AnyError,
    },
    OutsideRoot {
        operation: &'static str,
        source: AnyError,
    },
    /// 请求验证过快照之后，目录项发生了变化。
    /// The directory entry changed after the request's validated snapshot.
    Changed {
        role: MutationEndpointRole,
        endpoint: Box<str>,
        expected: Box<str>,
        actual: Box<str>,
    },
    NoSpace {
        operation: &'static str,
        source: AnyError,
    },
    /// 持久化操作失败；`published` 记录失败前名称是否可能已对外可见。
    /// A durability operation failed. `published` records whether the name may already have become
    /// externally visible before the failure.
    Durability {
        stage: DurabilityStage,
        published: bool,
        source: AnyError,
    },
    Io {
        operation: &'static str,
        source: AnyError,
    },
}

/// 发生竞态的命名空间端点的语义角色。HTTP 策略匹配此封闭枚举；不得通过字符串比较
/// 诊断路径来恢复语义。
/// Semantic role of a raced namespace endpoint. HTTP policy matches this closed value; the
/// diagnostic path must never be compared as a string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MutationEndpointRole {
    Target,
    Source,
    Destination,
}

/// 文件系统同步阶段。使用封闭枚举可防止处理器通过比较自由格式上下文字符串恢复语义。
/// Filesystem synchronization stage. Keeping this closed prevents handlers from recovering
/// semantics by comparing free-form context strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DurabilityStage {
    CandidateFile,
    PublishedFile,
    CreatedDirectory,
    DestinationParent,
    SourceParent,
    RemovedEntryParent,
}

impl fmt::Display for DurabilityStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CandidateFile => "candidate file before publication",
            Self::PublishedFile => "published file",
            Self::CreatedDirectory => "newly created directory",
            Self::DestinationParent => "destination parent directory",
            Self::SourceParent => "source parent directory",
            Self::RemovedEntryParent => "parent directory after removal",
        })
    }
}

impl FsError {
    /// 仍返回 `anyhow` 链的旧文件系统函数的中央适配器。它保留完整内部错误链，并让
    /// HTTP/业务处理器无需解释 errno。
    /// Central adapter for legacy filesystem functions that still return an `anyhow` chain. It
    /// preserves the complete internal chain while keeping errno interpretation out of handlers.
    pub(crate) fn from_anyhow(operation: &'static str, source: AnyError) -> Self {
        let classification = source.chain().find_map(|cause| {
            if let Some(error) = cause.downcast_ref::<io::Error>() {
                Some(classify_io(error.kind(), error.raw_os_error()))
            } else {
                cause.downcast_ref::<Errno>().map(|errno| {
                    let error = io::Error::from_raw_os_error(errno.raw_os_error());
                    classify_io(error.kind(), error.raw_os_error())
                })
            }
        });
        Self::from_classification(
            operation,
            source,
            classification.unwrap_or(FsClassification::Io),
        )
    }

    fn from_classification(
        operation: &'static str,
        source: AnyError,
        classification: FsClassification,
    ) -> Self {
        match classification {
            FsClassification::NotFound => Self::NotFound { operation, source },
            FsClassification::Forbidden => Self::Forbidden { operation, source },
            FsClassification::Conflict => Self::Conflict { operation, source },
            FsClassification::NoSpace => Self::NoSpace { operation, source },
            FsClassification::Io => Self::Io { operation, source },
        }
    }

    pub(crate) fn conflict(operation: &'static str, source: impl Into<AnyError>) -> Self {
        Self::Conflict {
            operation,
            source: source.into(),
        }
    }

    pub(crate) fn outside_root(operation: &'static str, source: impl Into<AnyError>) -> Self {
        Self::OutsideRoot {
            operation,
            source: source.into(),
        }
    }

    pub(crate) fn no_space(operation: &'static str, source: impl Into<AnyError>) -> Self {
        Self::NoSpace {
            operation,
            source: source.into(),
        }
    }

    pub(crate) fn changed(
        role: MutationEndpointRole,
        endpoint: impl Into<Box<str>>,
        expected: impl Into<Box<str>>,
        actual: impl Into<Box<str>>,
    ) -> Self {
        Self::Changed {
            role,
            endpoint: endpoint.into(),
            expected: expected.into(),
            actual: actual.into(),
        }
    }

    pub(crate) fn durability(
        stage: DurabilityStage,
        published: bool,
        source: impl Into<AnyError>,
    ) -> Self {
        Self::Durability {
            stage,
            published,
            source: source.into(),
        }
    }

    pub(crate) fn io(operation: &'static str, source: impl Into<AnyError>) -> Self {
        Self::Io {
            operation,
            source: source.into(),
        }
    }

    #[cfg(test)]
    pub(crate) fn is_published_durability_failure(&self) -> bool {
        matches!(
            self,
            Self::Durability {
                published: true,
                ..
            }
        )
    }

    pub(crate) fn changed_details(&self) -> Option<(MutationEndpointRole, &str, &str, &str)> {
        match self {
            Self::Changed {
                role,
                endpoint,
                expected,
                actual,
            } => Some((*role, endpoint, expected, actual)),
            _ => None,
        }
    }

    /// 在应用边界附加 `anyhow` 上下文后恢复类型化文件系统故障。这只做类型向下转换，
    /// 从不使用字符串或 errno 链启发式判断。
    /// Recover a typed filesystem failure after an application boundary has attached `anyhow`
    /// context. This is a typed downcast, never a string or errno-chain heuristic.
    pub(crate) fn in_anyhow_chain(error: &AnyError) -> Option<&Self> {
        error.chain().find_map(|cause| cause.downcast_ref::<Self>())
    }
}

#[derive(Clone, Copy)]
enum FsClassification {
    NotFound,
    Forbidden,
    Conflict,
    NoSpace,
    Io,
}

fn classify_io(kind: io::ErrorKind, raw: Option<i32>) -> FsClassification {
    match kind {
        io::ErrorKind::NotFound => FsClassification::NotFound,
        io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem => {
            FsClassification::Forbidden
        }
        io::ErrorKind::AlreadyExists
        | io::ErrorKind::DirectoryNotEmpty
        | io::ErrorKind::NotADirectory
        | io::ErrorKind::IsADirectory
        | io::ErrorKind::CrossesDevices => FsClassification::Conflict,
        _ if matches!(
            raw,
            Some(code)
                if code == Errno::NOSPC.raw_os_error()
                    || code == Errno::DQUOT.raw_os_error()
        ) =>
        {
            FsClassification::NoSpace
        }
        _ => FsClassification::Io,
    }
}

impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { operation, source } => {
                write!(f, "filesystem object not found while {operation}: {source}")
            }
            Self::Forbidden { operation, source } => {
                write!(f, "filesystem access denied while {operation}: {source}")
            }
            Self::Conflict { operation, source } => {
                write!(f, "filesystem conflict while {operation}: {source}")
            }
            Self::OutsideRoot { operation, source } => {
                write!(
                    f,
                    "filesystem resolution escaped the served root while {operation}: {source}"
                )
            }
            Self::Changed {
                role,
                endpoint,
                expected,
                actual,
            } => write!(
                f,
                "filesystem {role:?} entry changed at {endpoint}: expected {expected}, found {actual}"
            ),
            Self::NoSpace { operation, source } => {
                write!(f, "storage exhausted while {operation}: {source}")
            }
            Self::Durability {
                stage,
                published,
                source,
            } => write!(
                f,
                "durability failure at {stage} (published={published}): {source}"
            ),
            Self::Io { operation, source } => {
                write!(f, "filesystem I/O failed while {operation}: {source}")
            }
        }
    }
}

impl StdError for FsError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Changed { .. } => None,
            Self::NotFound { source, .. }
            | Self::Forbidden { source, .. }
            | Self::Conflict { source, .. }
            | Self::OutsideRoot { source, .. }
            | Self::NoSpace { source, .. }
            | Self::Durability { source, .. }
            | Self::Io { source, .. } => Some(source.as_ref()),
        }
    }
}

/// 由请求准入、阻塞工作与协议预算控制的有限资源分类。该分类用于选择状态码、指标和内部
/// 诊断，但枚举名与观测值绝不会复制到公开响应。
/// Classification of finite resources governed by request admission, blocking work, and protocol
/// budgets. It selects status mapping, metrics, and internal diagnostics, but enum names and
/// observed values are never copied into public responses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionResource {
    Requests,
    Uploads,
    /// 短路径解析、metadata 与文件块 read/seek 的共享阻塞池准入。
    /// Shared blocking-pool admission for short path, metadata, and file read/seek work.
    FilesystemTasks,
    ExpensiveTasks,
    MutationLocks,
    UploadBytes,
    ArchiveBytes,
    /// ZIP local/central header 中单个条目名的字节数，上限为 `u16::MAX`（65,535）。
    /// Bytes in one ZIP local/central-header entry name, bounded by `u16::MAX` (65,535).
    ArchiveEntryNameBytes,
    WalkEntries,
    WalkDepth,
}

impl fmt::Display for AdmissionResource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Requests => "requests",
            Self::Uploads => "uploads",
            Self::FilesystemTasks => "filesystem tasks",
            Self::ExpensiveTasks => "expensive tasks",
            Self::MutationLocks => "filesystem mutation locks",
            Self::UploadBytes => "upload bytes",
            Self::ArchiveBytes => "archive output bytes",
            Self::ArchiveEntryNameBytes => "archive entry-name bytes",
            Self::WalkEntries => "walk entries",
            Self::WalkDepth => "walk depth",
        })
    }
}

/// 判断耗尽的队列容量属于单个调用方还是整个服务；该值刻意不携带网络身份。
/// Determines whether exhausted queue capacity belongs to one caller or to the service as a whole.
/// It intentionally carries no network identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QueueScope {
    PerSource,
    PerAccount,
    Global,
    WorkerPool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LimitKind {
    Payload,
    Semantic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionTimeoutKind {
    /// 等待进入有界队列；作用域决定是限制调用方，还是服务整体容量不可用。
    /// Waiting to enter a bounded queue. Scope determines whether the caller is throttled or
    /// service-wide capacity is unavailable.
    Queue(QueueScope),
    /// 已获准的工作线程或上游操作超过了截止时间。
    /// An already-admitted worker/upstream operation exceeded its deadline.
    Execution,
}

#[derive(Debug)]
pub(crate) enum AdmissionError {
    QueueFull {
        resource: AdmissionResource,
        scope: QueueScope,
        limit: u64,
        retry_after: Duration,
    },
    Timeout {
        resource: AdmissionResource,
        kind: AdmissionTimeoutKind,
        waited: Duration,
    },
    Cancelled {
        resource: AdmissionResource,
    },
    LimitExceeded {
        resource: AdmissionResource,
        kind: LimitKind,
        limit: u64,
        observed: Option<u64>,
    },
}

impl AdmissionError {
    pub(crate) fn queue_full(resource: AdmissionResource, scope: QueueScope, limit: u64) -> Self {
        Self::QueueFull {
            resource,
            scope,
            limit,
            retry_after: Duration::from_secs(1),
        }
    }

    pub(crate) fn queue_timeout(
        resource: AdmissionResource,
        scope: QueueScope,
        waited: Duration,
    ) -> Self {
        Self::Timeout {
            resource,
            kind: AdmissionTimeoutKind::Queue(scope),
            waited,
        }
    }

    pub(crate) fn execution_timeout(resource: AdmissionResource, waited: Duration) -> Self {
        Self::Timeout {
            resource,
            kind: AdmissionTimeoutKind::Execution,
            waited,
        }
    }

    pub(crate) fn cancelled(resource: AdmissionResource) -> Self {
        Self::Cancelled { resource }
    }

    pub(crate) fn limit_exceeded(
        resource: AdmissionResource,
        kind: LimitKind,
        limit: u64,
        observed: Option<u64>,
    ) -> Self {
        Self::LimitExceeded {
            resource,
            kind,
            limit,
            observed,
        }
    }

    pub(crate) fn in_anyhow_chain(error: &AnyError) -> Option<&Self> {
        error.chain().find_map(|cause| cause.downcast_ref::<Self>())
    }

    fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::QueueFull { retry_after, .. } => Some(*retry_after),
            Self::Cancelled { .. } => Some(Duration::from_secs(1)),
            Self::Timeout {
                kind: AdmissionTimeoutKind::Queue(_),
                ..
            } => Some(Duration::from_secs(1)),
            Self::Timeout {
                kind: AdmissionTimeoutKind::Execution,
                ..
            }
            | Self::LimitExceeded { .. } => None,
        }
    }
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QueueFull {
                resource,
                scope,
                limit,
                retry_after,
            } => write!(
                f,
                "{resource} queue is full ({scope:?}, limit={limit}, retry_after={retry_after:?})"
            ),
            Self::Timeout {
                resource,
                kind,
                waited,
            } => write!(f, "{resource} {kind:?} timed out after {waited:?}"),
            Self::Cancelled { resource } => {
                write!(f, "{resource} admission was cancelled")
            }
            Self::LimitExceeded {
                resource,
                kind,
                limit,
                observed,
            } => write!(
                f,
                "{resource} {kind:?} limit exceeded (limit={limit}, observed={observed:?})"
            ),
        }
    }
}

impl StdError for AdmissionError {}

/// 不属于文件系统或准入故障的 HTTP 层错误，例如授权判定或畸形请求语法。
/// HTTP-layer failures which are not filesystem or admission failures, such as an authorization
/// decision or malformed request syntax.
#[derive(Debug)]
pub(crate) enum HttpError {
    BadRequest { source: AnyError },
    Forbidden { source: AnyError },
    NotFound { source: AnyError },
}

impl HttpError {
    pub(crate) fn bad_request(source: impl Into<AnyError>) -> Self {
        Self::BadRequest {
            source: source.into(),
        }
    }

    pub(crate) fn forbidden(source: impl Into<AnyError>) -> Self {
        Self::Forbidden {
            source: source.into(),
        }
    }

    pub(crate) fn not_found(source: impl Into<AnyError>) -> Self {
        Self::NotFound {
            source: source.into(),
        }
    }

    pub(crate) fn in_anyhow_chain(error: &AnyError) -> Option<&Self> {
        error.chain().find_map(|cause| cause.downcast_ref::<Self>())
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadRequest { source } => write!(f, "malformed request: {source}"),
            Self::Forbidden { source } => write!(f, "request forbidden: {source}"),
            Self::NotFound { source } => write!(f, "resource not found: {source}"),
        }
    }
}

impl StdError for HttpError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::BadRequest { source }
            | Self::Forbidden { source }
            | Self::NotFound { source } => Some(source.as_ref()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChangedStatus {
    Conflict,
    PreconditionFailed,
}

/// 不改变错误分类的公开响应体。其值必须是固定且经审查的文本；不得传入
/// `Error::to_string` 或从请求派生的路径/请求头值。
/// Public body which does not alter error classification. Values must be fixed,
/// reviewed protocol text; never pass `Error::to_string` or request-derived path/header values.
pub(crate) enum PublicErrorBody {
    Plain(&'static str),
}

impl PublicErrorBody {
    pub(crate) const fn plain(body: &'static str) -> Self {
        Self::Plain(body)
    }
}

#[derive(Debug)]
enum ResponseErrorSource {
    Fs(FsError),
    Admission(AdmissionError),
    Http(HttpError),
    CapturedAnyhow {
        source: AnyError,
        status: StatusCode,
        retry_after: Option<Duration>,
    },
}

fn filesystem_status(error: &FsError, changed_status: ChangedStatus) -> StatusCode {
    match error {
        FsError::NotFound { .. } => StatusCode::NOT_FOUND,
        FsError::Forbidden { .. } | FsError::OutsideRoot { .. } => StatusCode::FORBIDDEN,
        FsError::Conflict { .. } => StatusCode::CONFLICT,
        FsError::Changed { .. } => match changed_status {
            ChangedStatus::Conflict => StatusCode::CONFLICT,
            ChangedStatus::PreconditionFailed => StatusCode::PRECONDITION_FAILED,
        },
        FsError::NoSpace { .. } => StatusCode::INSUFFICIENT_STORAGE,
        // 发布后的持久化失败状态不明确：自动重试可能重复或覆盖其实已成功的变更。
        // A post-publish durability failure is ambiguous: automatic retry can duplicate or overwrite
        // a successful mutation.
        FsError::Durability { .. } | FsError::Io { .. } => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn admission_status(error: &AdmissionError) -> StatusCode {
    match error {
        AdmissionError::QueueFull { scope, .. } => match scope {
            QueueScope::PerSource | QueueScope::PerAccount => StatusCode::TOO_MANY_REQUESTS,
            QueueScope::Global | QueueScope::WorkerPool => StatusCode::SERVICE_UNAVAILABLE,
        },
        AdmissionError::Timeout { kind, .. } => match kind {
            AdmissionTimeoutKind::Queue(QueueScope::PerSource | QueueScope::PerAccount) => {
                StatusCode::TOO_MANY_REQUESTS
            }
            AdmissionTimeoutKind::Queue(QueueScope::Global | QueueScope::WorkerPool) => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            AdmissionTimeoutKind::Execution => StatusCode::GATEWAY_TIMEOUT,
        },
        AdmissionError::Cancelled { .. } => StatusCode::SERVICE_UNAVAILABLE,
        AdmissionError::LimitExceeded { kind, .. } => match kind {
            LimitKind::Payload => StatusCode::PAYLOAD_TOO_LARGE,
            LimitKind::Semantic => StatusCode::UNPROCESSABLE_ENTITY,
        },
    }
}

fn http_status(error: &HttpError) -> StatusCode {
    match error {
        HttpError::BadRequest { .. } => StatusCode::BAD_REQUEST,
        HttpError::Forbidden { .. } => StatusCode::FORBIDDEN,
        HttpError::NotFound { .. } => StatusCode::NOT_FOUND,
    }
}

fn default_public_body(status: StatusCode) -> &'static str {
    match status {
        StatusCode::BAD_REQUEST => "Bad Request",
        StatusCode::FORBIDDEN => "Forbidden",
        StatusCode::NOT_FOUND => "Not Found",
        StatusCode::CONFLICT => "Conflict",
        StatusCode::PRECONDITION_FAILED => "Precondition Failed",
        StatusCode::PAYLOAD_TOO_LARGE => "Payload Too Large",
        StatusCode::UNPROCESSABLE_ENTITY => "Unprocessable Entity",
        StatusCode::TOO_MANY_REQUESTS => "Too Many Requests",
        StatusCode::SERVICE_UNAVAILABLE => "Service Unavailable",
        StatusCode::GATEWAY_TIMEOUT => "Gateway Timeout",
        StatusCode::INSUFFICIENT_STORAGE => "Insufficient Storage",
        _ => "Internal Server Error",
    }
}

fn apply_response_error(
    response: &mut Response,
    status: StatusCode,
    retry_after: Option<Duration>,
    body: PublicErrorBody,
) {
    *response.status_mut() = status;
    // 处理器可能在发现故障前已准备表示元数据。替换为错误响应体时绝不能保留成功表示的长度。
    // Handlers may have prepared representation metadata before discovering the failure. Never
    // retain that successful representation's length for the replacement error body.
    for name in [
        ACCEPT_RANGES,
        CONTENT_DISPOSITION,
        CONTENT_ENCODING,
        CONTENT_LENGTH,
        CONTENT_RANGE,
        ETAG,
        LAST_MODIFIED,
    ] {
        response.headers_mut().remove(name);
    }
    if let Some(retry_after) = retry_after {
        let seconds = retry_after
            .as_secs()
            .saturating_add(u64::from(retry_after.subsec_nanos() != 0))
            .max(1);
        // 十进制 u64 始终是合法的 Retry-After delta-seconds 值。
        // A decimal u64 is always a legal Retry-After delta-seconds value.
        let value = HeaderValue::from_str(&seconds.to_string())
            .expect("integer Retry-After is a valid header value");
        response.headers_mut().insert(RETRY_AFTER, value);
    } else {
        response.headers_mut().remove(RETRY_AFTER);
    }

    let PublicErrorBody::Plain(body) = body;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    *response.body_mut() = body_full(body);
}

/// 所有类型化服务错误的中央 HTTP 映射。
/// Central HTTP mapping for all typed service errors.
#[derive(Debug)]
pub(crate) struct ResponseError {
    source: ResponseErrorSource,
    changed_status: ChangedStatus,
}

impl ResponseError {
    pub(crate) fn filesystem(error: FsError, changed_status: ChangedStatus) -> Self {
        Self {
            source: ResponseErrorSource::Fs(error),
            changed_status,
        }
    }

    pub(crate) fn admission(error: AdmissionError) -> Self {
        Self {
            source: ResponseErrorSource::Admission(error),
            changed_status: ChangedStatus::Conflict,
        }
    }

    pub(crate) fn bad_request(source: impl Into<AnyError>) -> Self {
        Self::http(HttpError::bad_request(source))
    }

    pub(crate) fn http(error: HttpError) -> Self {
        Self {
            source: ResponseErrorSource::Http(error),
            changed_status: ChangedStatus::Conflict,
        }
    }

    /// 接管完整原因链时保留埋在 `anyhow` 上下文中的类型标记。旧式无类型文件系统错误只在
    /// 此边界分类一次。
    /// Preserve a typed marker buried under `anyhow` context while taking ownership of the complete
    /// cause chain. Legacy untyped filesystem errors are classified once at this boundary.
    pub(crate) fn from_anyhow_or_filesystem(
        operation: &'static str,
        error: AnyError,
        changed_status: ChangedStatus,
    ) -> Self {
        let mapping = ResponseErrorRef::from_anyhow_typed(&error, changed_status)
            .map(|mapped| (mapped.status(), mapped.retry_after()));
        match mapping {
            Some((status, retry_after)) => Self {
                source: ResponseErrorSource::CapturedAnyhow {
                    source: error,
                    status,
                    retry_after,
                },
                changed_status,
            },
            None => Self::filesystem(FsError::from_anyhow(operation, error), changed_status),
        }
    }

    pub(crate) fn status(&self) -> StatusCode {
        match &self.source {
            ResponseErrorSource::Http(error) => http_status(error),
            ResponseErrorSource::Fs(error) => filesystem_status(error, self.changed_status),
            ResponseErrorSource::Admission(error) => admission_status(error),
            ResponseErrorSource::CapturedAnyhow { status, .. } => *status,
        }
    }

    pub(crate) fn retry_after(&self) -> Option<Duration> {
        match &self.source {
            ResponseErrorSource::Admission(error) => error.retry_after(),
            ResponseErrorSource::CapturedAnyhow { retry_after, .. } => *retry_after,
            ResponseErrorSource::Fs(_) | ResponseErrorSource::Http(_) => None,
        }
    }

    pub(crate) fn default_public_body(&self) -> &'static str {
        default_public_body(self.status())
    }

    pub(crate) fn apply(&self, response: &mut Response) {
        self.apply_with_body(response, PublicErrorBody::Plain(self.default_public_body()));
    }

    pub(crate) fn apply_with_body(&self, response: &mut Response, body: PublicErrorBody) {
        apply_response_error(response, self.status(), self.retry_after(), body);
    }
}

impl fmt::Display for ResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.source {
            ResponseErrorSource::Fs(error) => write!(f, "filesystem request failed: {error}"),
            ResponseErrorSource::Admission(error) => {
                write!(f, "request admission failed: {error}")
            }
            ResponseErrorSource::Http(error) => write!(f, "HTTP request failed: {error}"),
            ResponseErrorSource::CapturedAnyhow { source, .. } => {
                write!(f, "typed request failed: {source}")
            }
        }
    }
}

impl StdError for ResponseError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match &self.source {
            ResponseErrorSource::Fs(error) => Some(error),
            ResponseErrorSource::Admission(error) => Some(error),
            ResponseErrorSource::Http(error) => Some(error),
            ResponseErrorSource::CapturedAnyhow { source, .. } => Some(source.as_ref()),
        }
    }
}

#[derive(Clone, Copy)]
enum ResponseErrorRefSource<'a> {
    Fs(&'a FsError),
    Admission(&'a AdmissionError),
    Http(&'a HttpError),
}

/// 对 `anyhow` 链中保留的类型标记提供借用式 HTTP 视图。应用边界因此可增加上下文，而
/// 无需克隆或重建原始内部原因。
/// Borrowed HTTP view over a typed marker retained inside an `anyhow` chain. This lets application
/// boundaries add context without cloning or rebuilding the original internal cause.
pub(crate) struct ResponseErrorRef<'a> {
    source: ResponseErrorRefSource<'a>,
    changed_status: ChangedStatus,
}

impl<'a> ResponseErrorRef<'a> {
    pub(crate) fn from_anyhow_typed(
        error: &'a AnyError,
        changed_status: ChangedStatus,
    ) -> Option<Self> {
        if let Some(error) = FsError::in_anyhow_chain(error) {
            return Some(Self {
                source: ResponseErrorRefSource::Fs(error),
                changed_status,
            });
        }
        if let Some(error) = AdmissionError::in_anyhow_chain(error) {
            return Some(Self {
                source: ResponseErrorRefSource::Admission(error),
                changed_status,
            });
        }
        HttpError::in_anyhow_chain(error).map(|error| Self {
            source: ResponseErrorRefSource::Http(error),
            changed_status,
        })
    }

    pub(crate) fn status(&self) -> StatusCode {
        match self.source {
            ResponseErrorRefSource::Fs(error) => filesystem_status(error, self.changed_status),
            ResponseErrorRefSource::Admission(error) => admission_status(error),
            ResponseErrorRefSource::Http(error) => http_status(error),
        }
    }

    pub(crate) fn retry_after(&self) -> Option<Duration> {
        match self.source {
            ResponseErrorRefSource::Fs(_) => None,
            ResponseErrorRefSource::Admission(error) => error.retry_after(),
            ResponseErrorRefSource::Http(_) => None,
        }
    }

    pub(crate) fn default_public_body(&self) -> &'static str {
        default_public_body(self.status())
    }

    pub(crate) fn apply(&self, response: &mut Response) {
        self.apply_with_body(response, PublicErrorBody::Plain(self.default_public_body()));
    }

    pub(crate) fn apply_with_body(&self, response: &mut Response, body: PublicErrorBody) {
        apply_response_error(response, self.status(), self.retry_after(), body);
    }
}

/// 请求边界上的最终安全网。
/// Final request-boundary safety net.
///
/// 即使中间层增加 `anyhow` 上下文，类型化故障仍保留经审查的公开状态/响应体映射；无类型
/// 故障会被刻意收敛为相同、固定且不含细节的 500 响应。
/// Typed failures retain their reviewed public status/body mapping even after intermediate layers
/// add `anyhow` context. Untyped failures collapse to one fixed, detail-free 500 response.
pub(crate) fn apply_anyhow_or_internal(
    response: &mut Response,
    error: &AnyError,
    changed_status: ChangedStatus,
) {
    if let Some(error) = ResponseErrorRef::from_anyhow_typed(error, changed_status) {
        error.apply(response);
    } else {
        apply_response_error(
            response,
            StatusCode::INTERNAL_SERVER_ERROR,
            None,
            PublicErrorBody::plain("Internal Server Error"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::body_full;
    use bytes::Bytes;
    use http_body_util::BodyExt;

    fn io_error(message: &'static str) -> io::Error {
        io::Error::other(message)
    }

    fn fs(error: FsError, changed_status: ChangedStatus) -> ResponseError {
        ResponseError::filesystem(error, changed_status)
    }

    #[tokio::test]
    async fn public_error_mapping_is_complete_and_table_driven() {
        let cases = [
            (
                ResponseError::bad_request(io_error("private parser detail")),
                StatusCode::BAD_REQUEST,
                "Bad Request",
                false,
            ),
            (
                fs(
                    FsError::from_anyhow(
                        "opening",
                        AnyError::new(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "secret path",
                        )),
                    ),
                    ChangedStatus::Conflict,
                ),
                StatusCode::FORBIDDEN,
                "Forbidden",
                false,
            ),
            (
                fs(
                    FsError::from_anyhow(
                        "opening",
                        AnyError::new(io::Error::new(io::ErrorKind::NotFound, "secret path")),
                    ),
                    ChangedStatus::Conflict,
                ),
                StatusCode::NOT_FOUND,
                "Not Found",
                false,
            ),
            (
                fs(
                    FsError::conflict("creating", io_error("secret path")),
                    ChangedStatus::Conflict,
                ),
                StatusCode::CONFLICT,
                "Conflict",
                false,
            ),
            (
                fs(
                    FsError::changed(
                        MutationEndpointRole::Target,
                        "private/name",
                        "inode 1",
                        "inode 2",
                    ),
                    ChangedStatus::PreconditionFailed,
                ),
                StatusCode::PRECONDITION_FAILED,
                "Precondition Failed",
                false,
            ),
            (
                ResponseError::admission(AdmissionError::limit_exceeded(
                    AdmissionResource::UploadBytes,
                    LimitKind::Payload,
                    10,
                    Some(11),
                )),
                StatusCode::PAYLOAD_TOO_LARGE,
                "Payload Too Large",
                false,
            ),
            (
                ResponseError::admission(AdmissionError::limit_exceeded(
                    AdmissionResource::WalkEntries,
                    LimitKind::Semantic,
                    10,
                    Some(11),
                )),
                StatusCode::UNPROCESSABLE_ENTITY,
                "Unprocessable Entity",
                false,
            ),
            (
                ResponseError::admission(AdmissionError::queue_full(
                    AdmissionResource::Requests,
                    QueueScope::PerSource,
                    4,
                )),
                StatusCode::TOO_MANY_REQUESTS,
                "Too Many Requests",
                true,
            ),
            (
                ResponseError::admission(AdmissionError::queue_full(
                    AdmissionResource::Requests,
                    QueueScope::Global,
                    64,
                )),
                StatusCode::SERVICE_UNAVAILABLE,
                "Service Unavailable",
                true,
            ),
            (
                ResponseError::admission(AdmissionError::execution_timeout(
                    AdmissionResource::ExpensiveTasks,
                    Duration::from_secs(5),
                )),
                StatusCode::GATEWAY_TIMEOUT,
                "Gateway Timeout",
                false,
            ),
            (
                fs(
                    FsError::from_anyhow(
                        "committing",
                        AnyError::new(io::Error::from_raw_os_error(Errno::DQUOT.raw_os_error())),
                    ),
                    ChangedStatus::Conflict,
                ),
                StatusCode::INSUFFICIENT_STORAGE,
                "Insufficient Storage",
                false,
            ),
            (
                fs(
                    FsError::io("reading", io_error("private device detail")),
                    ChangedStatus::Conflict,
                ),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                false,
            ),
        ];

        for (error, expected_status, expected_body, has_retry_after) in cases {
            assert_eq!(error.status(), expected_status, "{error}");
            assert_eq!(error.default_public_body(), expected_body, "{error}");
            assert_eq!(error.retry_after().is_some(), has_retry_after, "{error}");

            // 覆盖真实线上响应，包括替换可能已描述成功表示的元数据。
            // Exercise the actual wire response, including replacement of metadata that may already
            // describe a successful representation.
            let mut response = Response::new(body_full("private success body"));
            for name in [
                ACCEPT_RANGES,
                CONTENT_DISPOSITION,
                CONTENT_ENCODING,
                CONTENT_LENGTH,
                CONTENT_RANGE,
                ETAG,
                LAST_MODIFIED,
            ] {
                response
                    .headers_mut()
                    .insert(name, HeaderValue::from_static("private-success-metadata"));
            }
            response.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/private"),
            );
            response
                .headers_mut()
                .insert(RETRY_AFTER, HeaderValue::from_static("999"));

            error.apply(&mut response);

            assert_eq!(response.status(), expected_status, "{error}");
            assert_eq!(
                response.headers().get(CONTENT_TYPE).unwrap(),
                "text/plain; charset=utf-8",
                "{error}"
            );
            for name in [
                ACCEPT_RANGES,
                CONTENT_DISPOSITION,
                CONTENT_ENCODING,
                CONTENT_LENGTH,
                CONTENT_RANGE,
                ETAG,
                LAST_MODIFIED,
            ] {
                assert!(
                    response.headers().get(&name).is_none(),
                    "stale successful representation header survived: {name:?}; {error}"
                );
            }
            assert_eq!(
                response.headers().contains_key(RETRY_AFTER),
                has_retry_after,
                "{error}"
            );
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(&body[..], expected_body.as_bytes(), "{error}");
            let body = String::from_utf8_lossy(&body);
            assert!(!body.contains("private"), "{error}");
            assert!(!body.contains("secret"), "{error}");
        }
    }

    #[tokio::test]
    async fn final_anyhow_boundary_preserves_typed_mapping_and_hides_raw_failures() {
        let typed = AnyError::new(AdmissionError::queue_full(
            AdmissionResource::Requests,
            QueueScope::Global,
            64,
        ))
        .context("private outer context");
        let mut typed_response = Response::new(body_full("private success body"));
        apply_anyhow_or_internal(&mut typed_response, &typed, ChangedStatus::Conflict);
        assert_eq!(typed_response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(typed_response.headers().get(RETRY_AFTER).unwrap(), "1");
        let body = typed_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&body[..], b"Service Unavailable");

        let raw = AnyError::msg("private untyped handler failure");
        let mut raw_response = Response::new(body_full("private success body"));
        raw_response
            .headers_mut()
            .insert(RETRY_AFTER, HeaderValue::from_static("999"));
        apply_anyhow_or_internal(&mut raw_response, &raw, ChangedStatus::Conflict);
        assert_eq!(raw_response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(raw_response.headers().get(RETRY_AFTER).is_none());
        assert_eq!(
            raw_response.headers().get(CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
        let body = raw_response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"Internal Server Error");
        assert!(!String::from_utf8_lossy(&body).contains("private"));
    }

    #[test]
    fn changed_mapping_is_selected_at_the_http_boundary() {
        let conflict = fs(
            FsError::changed(MutationEndpointRole::Target, "entry", "missing", "file"),
            ChangedStatus::Conflict,
        );
        let precondition = fs(
            FsError::changed(MutationEndpointRole::Target, "entry", "missing", "file"),
            ChangedStatus::PreconditionFailed,
        );
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        assert_eq!(precondition.status(), StatusCode::PRECONDITION_FAILED);
    }

    #[test]
    fn durability_failures_are_internal_and_never_advertise_retry() {
        for published in [false, true] {
            let filesystem_error = FsError::durability(
                if published {
                    DurabilityStage::DestinationParent
                } else {
                    DurabilityStage::CandidateFile
                },
                published,
                io_error("private device detail"),
            );
            assert_eq!(
                filesystem_error.is_published_durability_failure(),
                published
            );
            let error = fs(filesystem_error, ChangedStatus::Conflict);
            assert_eq!(error.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(error.default_public_body(), "Internal Server Error");
            assert_eq!(error.retry_after(), None);
        }
    }

    #[test]
    fn queue_timeout_and_execution_timeout_have_distinct_statuses() {
        let global_queue = ResponseError::admission(AdmissionError::queue_timeout(
            AdmissionResource::Requests,
            QueueScope::Global,
            Duration::from_secs(2),
        ));
        let source_queue = ResponseError::admission(AdmissionError::queue_timeout(
            AdmissionResource::Requests,
            QueueScope::PerSource,
            Duration::from_secs(2),
        ));
        let execution = ResponseError::admission(AdmissionError::execution_timeout(
            AdmissionResource::ExpensiveTasks,
            Duration::from_secs(2),
        ));
        assert_eq!(global_queue.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(source_queue.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(execution.status(), StatusCode::GATEWAY_TIMEOUT);
        assert!(global_queue.retry_after().is_some());
        assert!(source_queue.retry_after().is_some());
        assert!(execution.retry_after().is_none());
    }

    #[test]
    fn every_typed_variant_family_has_a_stable_mapping() {
        let cases = [
            (
                ResponseError::filesystem(
                    FsError::outside_root("resolving", io_error("private path")),
                    ChangedStatus::Conflict,
                ),
                StatusCode::FORBIDDEN,
            ),
            (
                ResponseError::filesystem(
                    FsError::durability(
                        DurabilityStage::DestinationParent,
                        true,
                        io_error("private sync cause"),
                    ),
                    ChangedStatus::Conflict,
                ),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                ResponseError::filesystem(
                    FsError::io("reading", io_error("private I/O cause")),
                    ChangedStatus::Conflict,
                ),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                ResponseError::admission(AdmissionError::cancelled(AdmissionResource::Requests)),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                ResponseError::http(HttpError::forbidden(io_error("private policy cause"))),
                StatusCode::FORBIDDEN,
            ),
            (
                ResponseError::http(HttpError::not_found(io_error("private lookup cause"))),
                StatusCode::NOT_FOUND,
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(error.status(), expected, "{error}");
        }
    }

    #[test]
    fn io_classification_is_centralized_at_the_fs_boundary() {
        for errno in [Errno::NOSPC, Errno::DQUOT] {
            let error = FsError::from_anyhow(
                "writing",
                AnyError::new(io::Error::from_raw_os_error(errno.raw_os_error())),
            );
            assert!(matches!(error, FsError::NoSpace { .. }));
        }
        assert!(matches!(
            FsError::from_anyhow(
                "opening",
                AnyError::new(io::Error::from(io::ErrorKind::NotFound))
            ),
            FsError::NotFound { .. }
        ));
        assert!(matches!(
            FsError::from_anyhow(
                "opening",
                AnyError::new(io::Error::from(io::ErrorKind::PermissionDenied))
            ),
            FsError::Forbidden { .. }
        ));
    }

    #[test]
    fn anyhow_context_preserves_typed_fs_classification() {
        let error = AnyError::new(FsError::durability(
            DurabilityStage::DestinationParent,
            true,
            io_error("private device detail"),
        ))
        .context("committing upload");
        let classified = FsError::in_anyhow_chain(&error).expect("typed marker survives context");
        assert!(classified.is_published_durability_failure());
        let response =
            ResponseErrorRef::from_anyhow_typed(&error, ChangedStatus::PreconditionFailed)
                .expect("typed response view survives context");
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn anyhow_context_preserves_typed_admission_classification() {
        let error = AnyError::new(AdmissionError::limit_exceeded(
            AdmissionResource::WalkEntries,
            LimitKind::Semantic,
            100,
            Some(101),
        ))
        .context("pre-scanning recursive delete");
        let classified =
            AdmissionError::in_anyhow_chain(&error).expect("typed marker survives context");
        assert!(matches!(
            classified,
            AdmissionError::LimitExceeded {
                resource: AdmissionResource::WalkEntries,
                ..
            }
        ));
        let response = ResponseErrorRef::from_anyhow_typed(&error, ChangedStatus::Conflict)
            .expect("typed response view survives context");
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn owned_response_mapping_retains_typed_anyhow_chain() {
        let error = AnyError::new(AdmissionError::cancelled(AdmissionResource::WalkEntries))
            .context("directory traversal was cancelled");
        let response = ResponseError::from_anyhow_or_filesystem(
            "walking visible entries",
            error,
            ChangedStatus::Conflict,
        );

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.retry_after(), Some(Duration::from_secs(1)));
        match &response.source {
            ResponseErrorSource::CapturedAnyhow { source, .. } => {
                assert!(matches!(
                    AdmissionError::in_anyhow_chain(source),
                    Some(AdmissionError::Cancelled {
                        resource: AdmissionResource::WalkEntries,
                    })
                ));
            }
            other => panic!("expected an owned anyhow cause chain, got {other:?}"),
        }
    }

    #[test]
    fn owned_timeout_mapping_retains_the_exact_nonzero_waited_duration() {
        let configured = Duration::from_secs(17);
        let error = AnyError::new(AdmissionError::execution_timeout(
            AdmissionResource::ExpensiveTasks,
            configured,
        ))
        .context("blocking worker exceeded its configured deadline");
        let response = ResponseError::from_anyhow_or_filesystem(
            "running blocking filesystem work",
            error,
            ChangedStatus::Conflict,
        );

        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        match &response.source {
            ResponseErrorSource::CapturedAnyhow { source, .. } => assert!(matches!(
                AdmissionError::in_anyhow_chain(source),
                Some(AdmissionError::Timeout {
                    resource: AdmissionResource::ExpensiveTasks,
                    kind: AdmissionTimeoutKind::Execution,
                    waited,
                }) if *waited == configured
            )),
            other => panic!("expected the typed timeout cause chain, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn public_response_never_exposes_internal_cause() {
        let error = fs(
            FsError::outside_root("resolving", io_error("/private/root/secret")),
            ChangedStatus::Conflict,
        );
        let mut response = Response::new(body_full(Bytes::new()));
        error.apply(&mut response);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"Forbidden");
        assert!(!String::from_utf8_lossy(&body).contains("/private"));
    }

    #[tokio::test]
    async fn retry_after_is_written_only_for_retryable_admission_errors() {
        let error = ResponseError::admission(AdmissionError::QueueFull {
            resource: AdmissionResource::Requests,
            scope: QueueScope::PerAccount,
            limit: 2,
            retry_after: Duration::from_millis(1001),
        });
        let mut response = Response::new(body_full(Bytes::new()));
        response
            .headers_mut()
            .insert(CONTENT_LENGTH, HeaderValue::from_static("64"));
        error.apply(&mut response);
        assert_eq!(response.headers().get(RETRY_AFTER).unwrap(), "2");
        assert!(response.headers().get(CONTENT_LENGTH).is_none());

        ResponseError::bad_request(io_error("detail")).apply(&mut response);
        assert!(response.headers().get(RETRY_AFTER).is_none());
    }
}
