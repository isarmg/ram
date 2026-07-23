//! HTTP 消息体、方法注册表和连接 IO 看门狗的共享基础层。
//!
//! 本层刻意不理解文件路径或 ACL，只提供三组可组合的不变量：
//!
//! - [`body`] 把 Hyper 帧适配为有界字节流，并让请求许可一直存活到响应体
//!   完成、报错或被客户端取消；
//! - [`methods`] 维护支持的 HTTP 方法到内部路由类别的唯一映射，使路由、
//!   `Allow` 和 405 响应不会各自维护一份容易漂移的列表；
//! - [`io_watchdog`] 在连接级监督读停滞、写停滞和最大生命周期，防止慢速客户端
//!   永久占用 socket、请求许可或响应生产任务。
//!
//! 入站正文沿 `Incoming -> IncomingStream -> 业务有界读取器` 流动；出站正文沿
//! `处理器 -> permit/completion/idle 包装器 -> Hyper -> IoWatchdog` 流动。边界包装
//! 的顺序很重要：完成观察器必须看到最终线路结果，而准入许可不能在仅生成响应头时
//! 提前释放。
//!
//! Shared foundation for HTTP bodies, the method registry, and connection I/O
//! watchdogs. This layer deliberately knows nothing about filesystem paths or
//! ACLs. It instead composes three invariants: `body` adapts Hyper frames into
//! bounded streams and retains admission permits through terminal response
//! delivery; `methods` is the single mapping from supported HTTP methods to route
//! classes; and `io_watchdog` bounds read stalls, write stalls, and connection
//! lifetime. Inbound data flows from `Incoming` through `IncomingStream` into a
//! feature-specific bounded reader. Outbound data passes through permit,
//! completion, and idle-time wrappers before Hyper and the socket watchdog.
//! Wrapper order is significant: observers must see the final wire outcome,
//! while permits must not be released merely because response headers exist.

mod body;
mod io_watchdog;
mod methods;

pub(crate) use body::{
    IncomingStream, LengthLimitedStream, ResponseBodyCompletion, ResponseBodyOutcome, body_full,
    body_with_completion_observer, body_with_request_permits,
    body_with_response_write_idle_timeout,
};
pub(crate) use io_watchdog::IoWatchdog;
pub(crate) use methods::{ResourceMethod, ResourceRoute};
