//! Ram 的 TCP/HTTP 运行时与优雅关停。
//!
//! 每条 TCP 连接由独立 Tokio 任务处理。全局信号量在跨过 `accept` 边界前
//! 预留连接容量，超额连接留在内核 backlog。运行时只接受 HTTP/1.0 与
//! HTTP/1.1；TLS 由部署网关终止。

use crate::config::{Args, BindAddr, build_cli, print_completions};
use crate::http::{IoWatchdog, body_full, body_with_response_write_idle_timeout};
use crate::identity::PeerIdentity;
use crate::logging;
use crate::server::{Response, Server};

use anyhow::{Context, Result, anyhow};
use clap_complete::Shell;
use futures_util::future::{BoxFuture, join_all, select_all};
use hyper::{
    Method, Request, StatusCode, Version,
    body::{Body, Incoming},
    header::{CACHE_CONTROL, CONNECTION, CONTENT_LENGTH, HeaderValue},
    server::conn::http1::Builder as Http1Builder,
    service::service_fn,
};
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    server::graceful::{GracefulShutdown, Watcher},
};
use socket2::{Domain, Protocol, Socket, Type};
use std::future::Future;
use std::net::{IpAddr, SocketAddr, TcpListener as StdTcpListener};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Notify, Semaphore, watch};
use tokio::time::{Instant as TokioInstant, sleep, sleep_until};
use tokio::{
    net::{TcpListener, TcpStream},
    runtime::{Builder as RuntimeBuilder, Runtime},
    task::{JoinHandle, JoinSet},
};

/// 收到关停后等待在途请求的最长时间。
const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
/// Tokio 不能终止正在运行的阻塞 syscall；HTTP drain 后只等待此时长。
const BLOCKING_POOL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
/// 私有上传候选清理任务的关停等待上限。
const CANDIDATE_CLEANUP_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
/// 一个 HTTP/1 请求头的完整语义字节预算。
const HTTP1_MAX_REQUEST_HEAD_SIZE: usize = 64 * 1024;
/// 请求头字段数独立于总字节数受限。
const HTTP1_MAX_HEADERS: usize = 100;

/// 返回 Hyper 解析、规范化后的 HTTP/1 请求头语义大小。
///
/// 原始 wire 拼写已经不可得，因此按下列规范形式计算：
/// `METHOD SP request-target SP HTTP/x.y CRLF`、每个字段以及末尾空行。
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

/// 解析配置并手工构造有界 blocking pool 与显式关停超时。
pub fn run() -> Result<()> {
    let cmd = build_cli();
    let matches = cmd.get_matches();
    if let Some(generator) = matches.get_one::<Shell>("completions") {
        let mut cmd = build_cli();
        print_completions(*generator, &mut cmd);
        return Ok(());
    }

    let check_config = matches.get_flag("check-config");
    let args = Args::parse(matches)?;
    if check_config {
        Server::validate_static_configuration(&args)?;
        println!("Configuration OK");
        return Ok(());
    }

    logging::init().map_err(|error| anyhow!("Failed to initialize logging: {error}"))?;
    let runtime = build_runtime(args.max_blocking_threads as usize)?;
    let result = runtime.block_on(run_async(args));
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

async fn run_async(mut args: Args) -> Result<()> {
    let (new_addrs, print_addrs) = check_addrs(&args)?;
    args.addrs = new_addrs;
    let running = Arc::new(AtomicBool::new(true));
    let listening = print_listening(&args, &print_addrs);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (server, handles) = serve(args, running.clone(), shutdown_rx)?;
    println!("{listening}");

    shutdown_signal().await?;
    info!("Shutdown signal received; draining in-flight requests");
    running.store(false, Ordering::SeqCst);
    server.close_request_admission();
    let _ = shutdown_tx.send(true);

    for result in join_all(handles).await {
        if let Err(error) = result {
            error!("{error}");
        }
    }
    if !crate::server::drain_private_candidate_cleanup(CANDIDATE_CLEANUP_SHUTDOWN_TIMEOUT) {
        warn!(
            "Private upload candidate cleanup did not drain before the shutdown deadline; exact cleanup records remain fail-closed for crash recovery"
        );
    }
    log::logger().flush();
    Ok(())
}

/// 绑定全部 TCP 地址，并启动一个共享连接上限的公平 accept 协调器。
fn serve(
    args: Args,
    running: Arc<AtomicBool>,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<(Arc<Server>, Vec<JoinHandle<()>>)> {
    let addrs = args.addrs.clone();
    let port = args.port;
    let conn_limit = Arc::new(Semaphore::new(args.max_connections as usize));
    let server_handle = Arc::new(Server::init(args, running)?);
    let mut handles = Vec::new();
    if let Some(maintenance) = server_handle.spawn_stale_upload_maintenance(shutdown_rx.clone()) {
        handles.push(maintenance);
    }

    let mut acceptors = Vec::with_capacity(addrs.len());
    for BindAddr::IpAddr(ip) in addrs {
        let listener = create_listener(SocketAddr::new(ip, port))
            .with_context(|| format!("Failed to bind `{ip}:{port}`"))?;
        acceptors.push(Acceptor(listener));
    }
    handles.push(spawn_accept_loop(
        acceptors,
        server_handle.clone(),
        conn_limit,
        shutdown_rx,
    ));
    Ok((server_handle, handles))
}

/// 一个已绑定的 TCP 监听器。
struct Acceptor(TcpListener);

impl Acceptor {
    async fn accept(&self) -> std::io::Result<AcceptedConn> {
        let (stream, addr) = self.0.accept().await?;
        Ok(AcceptedConn {
            stream,
            peer: PeerIdentity::tcp(addr),
            accepted_at: TokioInstant::now(),
        })
    }
}

/// 刚从 TCP listener 接受的一条连接。
struct AcceptedConn {
    stream: TcpStream,
    peer: PeerIdentity,
    accepted_at: TokioInstant,
}

impl AcceptedConn {
    async fn serve(self, watcher: Watcher, server: Arc<Server>) {
        serve_watched(watcher, server, self.stream, self.peer, self.accepted_at).await;
    }
}

/// 在跨过 accept 边界前取得全局连接许可，并公平轮询全部监听器。
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
                Err(error) => {
                    drop(permit);
                    let delay = accept_error_delays[acceptor_index];
                    warn!(
                        "Accept failed on listener {acceptor_index}: {error}; retrying in {}ms",
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

/// 用 Hyper 的 HTTP/1 builder 服务一条连接，并纳入优雅关停跟踪。
fn serve_watched<I>(
    watcher: Watcher,
    server: Arc<Server>,
    io: I,
    peer: PeerIdentity,
    accepted_at: TokioInstant,
) -> impl Future<Output = ()>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let header_read_timeout = server.header_read_timeout();
    let connection_max_lifetime = server.connection_max_lifetime();
    let response_write_idle_timeout = server.response_write_idle_timeout();
    let active_requests = Arc::new(AtomicUsize::new(0));
    let io = TokioIo::new(IoWatchdog::with_active_requests(
        io,
        server.connection_idle_timeout(),
        response_write_idle_timeout,
        active_requests.clone(),
    ));
    let response_timeout = Arc::new(Notify::new());
    let request_response_timeout = response_timeout.clone();
    let service = service_fn(move |request: Request<Incoming>| {
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

    let mut builder = Http1Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(header_read_timeout)
        .max_buf_size(HTTP1_MAX_REQUEST_HEAD_SIZE)
        .max_headers(HTTP1_MAX_HEADERS);
    let connection = builder.serve_connection(io, service);
    let watched = watcher.watch(connection);
    async move {
        tokio::pin!(watched);
        let lifetime_deadline = connection_lifetime_deadline(accepted_at, connection_max_lifetime);
        if lifetime_deadline <= TokioInstant::now() {
            debug!("HTTP connection exhausted its configured lifetime before service began");
            return;
        }
        let result = tokio::select! {
            result = &mut watched => result,
            _ = sleep_until(lifetime_deadline) => {
                debug!("HTTP connection reached its configured maximum lifetime");
                return;
            }
            _ = response_timeout.notified() => {
                debug!("HTTP connection closed because one response exceeded its write-idle deadline");
                return;
            }
        };
        if let Err(error) = result {
            debug!("HTTP connection ended with an error: {error}");
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

/// 创建 IPv4/IPv6 TCP listener；IPv6-only 避免与 IPv4 wildcard 冲突。
fn create_listener(addr: SocketAddr) -> Result<TcpListener> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    let std_listener = StdTcpListener::from(socket);
    std_listener.set_nonblocking(true)?;
    TcpListener::from_std(std_listener).map_err(Into::into)
}

/// 整理绑定地址，并把 wildcard 展开为启动横幅中可访问的网卡 IP。
fn check_addrs(args: &Args) -> Result<(Vec<BindAddr>, Vec<BindAddr>)> {
    if args.addrs.is_empty() {
        return Err(anyhow!("At least one bind address is required"));
    }
    let has_unspecified = args
        .addrs
        .iter()
        .any(|addr| matches!(addr, BindAddr::IpAddr(ip) if ip.is_unspecified()));
    let (ipv4_addrs, ipv6_addrs) = if has_unspecified {
        interface_addrs()?
    } else {
        (Vec::new(), Vec::new())
    };
    let new_addrs = args.addrs.clone();
    let mut print_addrs = Vec::new();
    for BindAddr::IpAddr(ip) in &args.addrs {
        if ip.is_unspecified() {
            if ip.is_ipv4() {
                print_addrs.extend(ipv4_addrs.clone());
            } else {
                print_addrs.extend(ipv6_addrs.clone());
            }
        } else {
            print_addrs.push(BindAddr::IpAddr(*ip));
        }
    }
    print_addrs.sort_unstable();
    print_addrs.dedup();
    Ok((new_addrs, print_addrs))
}

fn interface_addrs() -> Result<(Vec<BindAddr>, Vec<BindAddr>)> {
    let (mut ipv4_addrs, mut ipv6_addrs) = (Vec::new(), Vec::new());
    let ifaces =
        if_addrs::get_if_addrs().with_context(|| "Failed to get local interface addresses")?;
    for iface in ifaces {
        let ip = iface.ip();
        if ip.is_ipv4() {
            ipv4_addrs.push(BindAddr::IpAddr(ip));
        } else {
            ipv6_addrs.push(BindAddr::IpAddr(ip));
        }
    }
    Ok((ipv4_addrs, ipv6_addrs))
}

fn print_listening(args: &Args, print_addrs: &[BindAddr]) -> String {
    let mut output = format!("Serving {} over HTTP/1.1\n", args.serve_path.display());
    let urls = print_addrs
        .iter()
        .map(|bind_addr| {
            let BindAddr::IpAddr(addr) = bind_addr;
            let addr = match addr {
                IpAddr::V4(_) => format!("{addr}:{}", args.port),
                IpAddr::V6(_) => format!("[{addr}]:{}", args.port),
            };
            format!("http://{addr}{}", args.uri_prefix)
        })
        .collect::<Vec<_>>();

    if urls.len() == 1 {
        output.push_str(&format!("Listening on {}", urls[0]));
    } else {
        let info = urls
            .iter()
            .map(|url| format!("  {url}"))
            .collect::<Vec<_>>()
            .join("\n");
        output.push_str(&format!("Listening on:\n{info}\n"));
    }
    output
}

/// 挂起直到收到 SIGTERM 或 SIGINT。
async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
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
mod runtime_limit_tests;
