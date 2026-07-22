use assert_fs::fixture::TempDir;
use assert_fs::prelude::*;
use reqwest::Url;
use rstest::fixture;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::sleep;
use std::time::{Duration, Instant};

// 整个测试端口范围必须低于内核临时端口范围（默认 32768+）。临时范围内端口可被任意出站
// 连接选为源端口，既与服务器 bind 竞态，也可能令就绪探测在无监听器时自连接成功。
// Keep all test ports below the kernel ephemeral range. An ephemeral source port can race server bind
// and let a readiness probe self-connect even without a listener.
const TEST_PORT_MIN: u16 = 20000;
const TEST_PORT_MAX: u16 = 32000;
const PORT_LOCK_PATH: &str = "/tmp/ram-test-port.lock";
const PORT_STATE_PATH: &str = "/tmp/ram-test-next-port";
const SERVER_READY_TIMEOUT: Duration = Duration::from_secs(15);
pub const TEST_AUTH_USER: &str = "admin";
pub const TEST_AUTH_PASS: &str = "admin";
pub const TEST_AUTH_RULE: &str = "admin:admin@/:rw";

#[allow(dead_code)]
pub type Error = Box<dyn std::error::Error>;

#[allow(dead_code)]
pub const BIN_FILE: &str = "😀.bin";

/// 测试用文件名。 / Filenames used by tests.
#[allow(dead_code)]
pub static FILES: &[&str] = &[
    "test.txt",
    "test.html",
    "index.html",
    "file\n1.txt",
    BIN_FILE,
];

/// 测试不存在目录的名称。 / Directory names used to test absence.
#[allow(dead_code)]
pub static DIR_NO_FOUND: &str = "dir-no-found/";

/// 测试无 index.html 目录的名称。 / Directory names used to test missing index.html.
#[allow(dead_code)]
pub static DIR_NO_INDEX: &str = "dir-no-index/";

/// 测试隐藏目录的名称。 / Directory names used to test hiding.
#[allow(dead_code)]
pub static DIR_GIT: &str = ".git/";

/// 测试资源覆盖的目录名称。 / Directory names used to test asset overrides.
#[allow(dead_code)]
pub static DIR_ASSETS: &str = "dir-assets/";

/// 测试用目录名。 / Directory names used by tests.
#[allow(dead_code)]
pub static DIRECTORIES: &[&str] = &["dir1/", "dir2/", "dir3/", DIR_NO_INDEX, DIR_GIT, DIR_ASSETS];

/// 创建包含若干文件和子目录（子目录也含文件）的临时目录测试夹具。
/// Test fixture creating a temporary directory with files and populated subdirectories.
#[fixture]
#[allow(dead_code)]
pub fn tmpdir() -> TempDir {
    let tmpdir = assert_fs::TempDir::new().expect("Couldn't create a temp dir for tests");
    for file in FILES {
        if *file == BIN_FILE {
            tmpdir.child(file).write_binary(b"bin\0\x00123").unwrap();
        } else {
            tmpdir
                .child(file)
                .write_str(&format!("This is {file}"))
                .unwrap();
        }
    }
    for directory in DIRECTORIES {
        if *directory == DIR_ASSETS {
            tmpdir
                .child(format!("{}{}", directory, "index.html"))
                .write_str("__ASSETS_PREFIX__index.js;<template id=\"index-data\">__INDEX_DATA__</template>")
                .unwrap();
        } else {
            for file in FILES {
                if *directory == DIR_NO_INDEX && *file == "index.html" {
                    continue;
                }
                if *file == BIN_FILE {
                    tmpdir
                        .child(format!("{directory}{file}"))
                        .write_binary(b"bin\0\x00123")
                        .unwrap();
                } else {
                    tmpdir
                        .child(format!("{directory}{file}"))
                        .write_str(&format!("This is {directory}{file}"))
                        .unwrap();
                }
            }
        }
    }
    tmpdir.child("dir4/hidden").touch().unwrap();
    tmpdir
        .child("content-types/bin.tar")
        .write_binary(b"\x7f\x45\x4c\x46\x02\x01\x00\x00")
        .unwrap();
    tmpdir
        .child("content-types/bin")
        .write_binary(b"\x7f\x45\x4c\x46\x02\x01\x00\x00")
        .unwrap();
    tmpdir
        .child("content-types/file-utf8.txt")
        .write_str("世界")
        .unwrap();
    tmpdir
        .child("content-types/file-gbk.txt")
        .write_binary(b"\xca\xc0\xbd\xe7")
        .unwrap();
    tmpdir
        .child("content-types/file")
        .write_str("世界")
        .unwrap();

    tmpdir
}

/// 获取空闲端口。 / Get a free port.
#[fixture]
#[allow(dead_code)]
pub fn port() -> u16 {
    alloc_test_port()
}

/// 以临时目录、空闲端口和可选参数运行 ram，并等待服务器启动完成。
/// Run ram with a temporary directory, free port, and optional arguments, then await readiness.
#[fixture]
#[allow(dead_code)]
pub fn server<I>(#[default(&[] as &[&str])] args: I) -> TestServer
where
    I: IntoIterator + Clone,
    I::Item: AsRef<std::ffi::OsStr>,
{
    let tmpdir = tmpdir();
    let port = alloc_test_port();
    let mut raw_args: Vec<OsString> = args
        .clone()
        .into_iter()
        .map(|x| x.as_ref().to_os_string())
        .collect();
    let mut startup_tempdirs = Vec::new();
    if let Some(key_flag) = raw_args.iter().position(|value| value == "--tls-key") {
        let source = raw_args
            .get(key_flag + 1)
            .expect("--tls-key test argument has a value");
        let secrets = TempDir::new().expect("failed to create TLS test credential directory");
        let private_key = secrets.path().join("private-key.pem");
        fs::copy(Path::new(source), &private_key).expect("failed to copy TLS test private key");
        fs::set_permissions(&private_key, fs::Permissions::from_mode(0o600))
            .expect("failed to protect TLS test private key");
        raw_args[key_flag + 1] = private_key.into_os_string();
        startup_tempdirs.push(secrets);
    }
    let has_auth = raw_args.iter().any(|x| x == "--auth" || x == "-a");
    let mut cmd = ram_command(tmpdir.path(), port);
    if !has_auth {
        cmd.args(["--auth", TEST_AUTH_RULE]);
    }
    cmd.args(raw_args.clone());
    let is_tls = raw_args.iter().any(|x| x.to_str().unwrap().contains("tls"));

    let proc = ServerProc::spawn(cmd);
    TestServer::new(port, tmpdir, proc, is_tls, !has_auth, startup_tempdirs)
}

/// 构造一条标准的测试服务器命令：`RAM_NO_CONFIG` 隔离 + serve 路径 +
/// 端口。调用方可继续 `.args(...)` 追加参数后交给 [`ServerProc::spawn`]。
/// Build a standard isolated test-server command with serve path and port. Callers may append
/// `.args(...)` before passing it to [`ServerProc::spawn`].
#[allow(dead_code)]
pub fn ram_command(serve_path: &Path, port: u16) -> Command {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("ram"));
    // 保持测试封闭：测试二进制位于共享 target 目录，旁边遗留 config.yaml 不得泄入测试服务器。
    // Keep tests hermetic: a stray config.yaml beside the shared-target test binary must not leak in.
    cmd.env("RAM_NO_CONFIG", "1");
    cmd.arg(serve_path).arg("-p").arg(port.to_string());
    cmd
}

/// 启动测试命令时容忍 overlay/网络文件系统复制可执行文件后的短暂 `ETXTBSY` 窗口。只重试
/// 这一内核瞬时错误，一秒截止时间避免真实繁忙文件挂住测试。
/// Start a test command while tolerating the short `ETXTBSY` window after an executable is copied on
/// an overlay/network filesystem. Retry only that transient kernel error; a one-second deadline
/// keeps a genuinely busy file from hanging the test.
fn spawn_with_exec_retry(cmd: &mut Command) -> io::Result<Child> {
    let started = Instant::now();
    loop {
        match cmd.spawn() {
            Ok(child) => return Ok(child),
            Err(error)
                if error.kind() == io::ErrorKind::ExecutableFileBusy
                    && started.elapsed() < Duration::from_secs(1) =>
            {
                sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

/// 对 [`Command::output`] 使用与长运行测试服务器相同的有界复制可执行文件重试。
/// Run [`Command::output`] with the same bounded copied-executable retry used for long-running test
/// servers.
#[allow(dead_code)]
pub fn command_output_with_exec_retry(cmd: &mut Command) -> io::Result<Output> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    spawn_with_exec_retry(cmd)?.wait_with_output()
}

fn alloc_test_port() -> u16 {
    let _process_guard = port_lock().lock().expect("Couldn't lock port allocation");
    let _file_guard = PortFileLock::acquire();

    let mut next = fs::read_to_string(PORT_STATE_PATH)
        .ok()
        .and_then(|v| v.trim().parse::<u16>().ok())
        .filter(|port| (TEST_PORT_MIN..=TEST_PORT_MAX).contains(port))
        .unwrap_or(TEST_PORT_MIN);

    for _ in TEST_PORT_MIN..=TEST_PORT_MAX {
        let port = next;
        next = if next == TEST_PORT_MAX {
            TEST_PORT_MIN
        } else {
            next + 1
        };
        let _ = fs::write(PORT_STATE_PATH, next.to_string());

        if can_bind_port(port) {
            return port;
        }
    }

    panic!("Couldn't find a free local port");
}

fn can_bind_port(port: u16) -> bool {
    TcpListener::bind(("0.0.0.0", port)).is_ok()
}

struct PortFileLock {
    path: PathBuf,
}

impl PortFileLock {
    fn acquire() -> Self {
        let path = PathBuf::from(PORT_LOCK_PATH);
        let started = Instant::now();
        loop {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    // 记录所有者 PID，以区分被杀进程遗留锁和仅繁忙的锁。
                    // Record owner PID to distinguish a killed process's lock from a merely busy one.
                    let _ = write!(file, "{}", std::process::id());
                    return Self { path };
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    // 仅所有者消失时破锁。仅因超时打破慢锁会让两个进程并发分配，把同一端口交给
                    // 两个测试服务器。
                    // Break only when owner is gone; breaking a merely slow lock can allocate one port twice.
                    if started.elapsed() > Duration::from_secs(10) && Self::owner_is_dead(&path) {
                        let _ = fs::remove_file(&path);
                    }
                    sleep(Duration::from_millis(10));
                }
                Err(err) => panic!("Couldn't lock test port allocation: {err}"),
            }
        }
    }

    /// 锁文件记录所有者不存在时为 true。无法读取 PID 的锁也视为死亡：上方时间守卫已给所有者
    /// 充分时间完成单次 PID 写入。
    /// True when the recorded owner no longer exists. An unreadable PID also counts dead after the elapsed guard.
    fn owner_is_dead(path: &Path) -> bool {
        match fs::read_to_string(path)
            .ok()
            .and_then(|v| v.trim().parse::<u32>().ok())
        {
            Some(pid) => !Path::new(&format!("/proc/{pid}")).exists(),
            None => true,
        }
    }
}

impl Drop for PortFileLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn port_lock() -> &'static Mutex<()> {
    static PORT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    PORT_LOCK.get_or_init(|| Mutex::new(()))
}

fn server_startup_lock() -> &'static Mutex<()> {
    static STARTUP_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    STARTUP_LOCK.get_or_init(|| Mutex::new(()))
}

/// 一个由测试拥有的 ram 服务器进程。三件事集中在这里做对：
///
/// - **就绪判定**：等 stdout 出现 `Listening on` 横幅——它只在所有
///   监听器 bind 完成后打印，是确定性信号；TCP 探测可能被幽灵应答
///   假阳性（TCP 自连接、WSL2 环回转发），在子进程尚未 bind 时就
///   宣告就绪，随后的真实请求便得到 connection refused。
/// - **stdout 捕获**：后台线程持续读取每一行存进共享缓冲（顺带防止
///   管道写满阻塞服务器——访问日志走 stdout），测试可用
///   [`Self::wait_for_stdout_line`] / [`Self::stdout_lines`] 断言日志。
/// - **`Drop` 收尸**：kill + wait。测试中途 `?`/断言失败提前返回时
///   也不会留下孤儿服务器占着端口。
///
/// A test-owned ram server process centralizes three invariants:
///
/// - **Readiness**: wait for the `Listening on` banner, emitted only after every listener is bound.
///   TCP probing can produce false positives through self-connect or WSL2 loopback forwarding and
///   announce readiness before the child binds, making the first real request fail.
/// - **stdout capture**: a background reader stores every line and keeps the access-log pipe from
///   filling; tests query it through [`Self::wait_for_stdout_line`] / [`Self::stdout_lines`].
/// - **`Drop` reaping**: kill and wait even when `?` or an assertion exits a test early, so no orphan
///   server retains the allocated port.
pub struct ServerProc {
    child: Child,
    stdout_lines: Arc<Mutex<Vec<String>>>,
}

#[allow(dead_code)]
impl ServerProc {
    /// 启动 `cmd`（stdout 强制改为管道）并在有界时间内等待就绪横幅。
    /// Start `cmd` with piped stdout and wait a bounded time for the readiness banner.
    pub fn spawn(mut cmd: Command) -> Self {
        // 单个集成二进制可并行构建许多 rstest 夹具。只串行化短进程启动阶段，避免 fork/链接器/
        // 调度器拥塞，同时为运行时隔离测试保留并发服务器。
        // One integration binary can construct many rstest fixtures. Serialize only the short
        // process-startup phase to avoid fork/linker/scheduler congestion while preserving concurrent
        // servers for runtime-isolation tests.
        let _startup_guard = server_startup_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cmd.stdout(Stdio::piped());
        let mut child = spawn_with_exec_retry(&mut cmd)
            .unwrap_or_else(|error| panic!("Couldn't run test server binary: {error}"));
        let stdout = child.stdout.take().expect("server stdout must be piped");
        let stdout_lines: Arc<Mutex<Vec<String>>> = Arc::default();
        let lines_writer = stdout_lines.clone();
        std::thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                let Ok(line) = line else { break };
                lines_writer.lock().unwrap().push(line);
            }
        });

        let mut proc = Self {
            child,
            stdout_lines,
        };
        proc.wait_ready();
        proc
    }

    fn wait_ready(&mut self) {
        let start_wait = Instant::now();
        loop {
            if self
                .stdout_lines
                .lock()
                .unwrap()
                .iter()
                .any(|line| line.contains("Listening on"))
            {
                return;
            }
            if let Some(status) = self.child.try_wait().expect("Couldn't poll test server") {
                panic!("server exited before becoming ready: {status}");
            }
            if start_wait.elapsed() > SERVER_READY_TIMEOUT {
                let stdout = self.stdout_lines.lock().unwrap().clone();
                panic!(
                    "timeout after {SERVER_READY_TIMEOUT:?} waiting for test server to print its listening banner; captured stdout: {stdout:?}"
                );
            }
            sleep(Duration::from_millis(10));
        }
    }

    /// 等待 stdout 出现满足 `pred` 的行（含已缓冲的历史行），返回该行。
    /// 超时返回 `None`。
    /// Wait for a stdout line satisfying `pred`, including buffered history; return `None` on timeout.
    pub fn wait_for_stdout_line<F: Fn(&str) -> bool>(
        &self,
        pred: F,
        within: Duration,
    ) -> Option<String> {
        let start = Instant::now();
        loop {
            if let Some(line) = self
                .stdout_lines
                .lock()
                .unwrap()
                .iter()
                .find(|line| pred(line))
            {
                return Some(line.clone());
            }
            if start.elapsed() > within {
                return None;
            }
            sleep(Duration::from_millis(10));
        }
    }

    /// 目前已捕获的全部 stdout 行的快照。
    /// Snapshot all stdout lines captured so far.
    pub fn stdout_lines(&self) -> Vec<String> {
        self.stdout_lines.lock().unwrap().clone()
    }

    /// 操作系统进程 ID，供 Linux 专属资源边界测试检查子进程描述符表。
    /// OS process id used by Linux-only boundary tests to inspect the child's descriptor table.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// 向服务器发送 SIGTERM（模拟 systemd/容器的 stop）。
    /// Send SIGTERM to simulate a systemd/container stop.
    pub fn sigterm(&self) {
        Command::new("kill")
            .arg("-TERM")
            .arg(self.child.id().to_string())
            .status()
            .expect("failed to send SIGTERM");
    }

    /// 等待进程退出，超过 `within` 返回 `None`。
    /// Wait for process exit, returning `None` after `within`.
    pub fn wait_exit(&mut self, within: Duration) -> Option<ExitStatus> {
        let start = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().expect("failed to poll child") {
                return Some(status);
            }
            if start.elapsed() > within {
                return None;
            }
            sleep(Duration::from_millis(25));
        }
    }
}

impl Drop for ServerProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[allow(dead_code)]
pub struct TestServer {
    port: u16,
    tmpdir: TempDir,
    proc: ServerProc,
    is_tls: bool,
    auth_in_url: bool,
    _startup_tempdirs: Vec<TempDir>,
}

#[allow(dead_code)]
impl TestServer {
    pub fn new(
        port: u16,
        tmpdir: TempDir,
        proc: ServerProc,
        is_tls: bool,
        auth_in_url: bool,
        startup_tempdirs: Vec<TempDir>,
    ) -> Self {
        Self {
            port,
            tmpdir,
            proc,
            is_tls,
            auth_in_url,
            _startup_tempdirs: startup_tempdirs,
        }
    }

    pub fn url(&self) -> Url {
        let protocol = if self.is_tls { "https" } else { "http" };
        let mut url = Url::parse(&format!("{}://localhost:{}", protocol, self.port)).unwrap();
        if self.auth_in_url {
            url.set_username(TEST_AUTH_USER).unwrap();
            url.set_password(Some(TEST_AUTH_PASS)).unwrap();
        }
        url
    }

    pub fn path(&self) -> &std::path::Path {
        self.tmpdir.path()
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}
