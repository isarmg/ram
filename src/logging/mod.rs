//! 有界异步日志器与按大小轮转。请求任务只格式化有界单行并 `try_send` 给专用写线程；
//! 慢磁盘、fsync 和轮转不会占用 Tokio worker 或全局文件 mutex。
//!
//! Bounded asynchronous logger with size-based rotation.
//!
//! Request tasks only format a bounded line and `try_send` it to a dedicated
//! writer thread. Slow files, `fsync`, and archive rotation therefore never
//! hold a Tokio worker or a global file mutex.

mod access;

pub(crate) use access::HttpLogger;
#[cfg(feature = "fuzzing")]
pub(crate) use access::fuzz_log_format;

use crate::path_identity::{ObjectIdentity, OutputPathIdentity};
use crate::utils::is_trusted_file_owner;
use anyhow::{Context, Result};
use log::{Level, LevelFilter, Metadata, Record};
use rustix::fs::{self, AtFlags, Mode, OFlags, ResolveFlags};
use rustix::io::Errno;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Mutex, TryLockError};
use std::thread;
use std::time::{Duration, Instant};

const LOG_QUEUE_CAPACITY: usize = 8_192;
const MAX_LOG_LINE_BYTES: usize = 64 * 1024;
const DEFAULT_ROTATE_BYTES: u64 = 100 * 1024 * 1024;
/// 配置阶段也必须保留这些派生 namespace 槽；与轮转器共享常量可防校验和实际 unlink/rename 集合漂移。
/// Configuration reserves these derived namespace slots too; sharing the constant prevents validation from drifting from rotation's unlink/rename set.
pub(crate) const DEFAULT_ROTATE_BACKUPS: usize = 5;
/// 关停日志 drain 的硬上限；目标 I/O 卡死时宁可丢失队尾日志也不能阻止进程退出。
/// Hard shutdown-log drain ceiling; a stuck destination may lose queued tail records but cannot prevent process exit.
const LOG_FLUSH_TIMEOUT: Duration = Duration::from_secs(2);
const LOG_FLUSH_RETRY_INTERVAL: Duration = Duration::from_millis(1);

enum Command {
    Record {
        level: Level,
        text: String,
        dropped_before: u64,
    },
    Flush {
        ack: mpsc::SyncSender<()>,
        /// 在最后一条成功记录之后累积的丢弃量；flush 是关停前报告它的最后机会。
        /// Drops accumulated after the last delivered record; flush is the final shutdown reporting opportunity.
        dropped_before: u64,
    },
}

struct AsyncLogger {
    tx: SyncSender<Command>,
    dropped: AtomicU64,
    /// flush barrier 必须串行，防止后发调用越过正在重试入队的前发调用。
    /// Flush barriers serialize so a later caller cannot overtake an earlier caller retrying enqueue.
    flush_lock: Mutex<()>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FlushOutcome {
    Flushed,
    LockTimeout,
    QueueTimeout,
    AckTimeout,
    Disconnected,
}

impl AsyncLogger {
    /// 在一个总 deadline 内串行排队 flush barrier，再等待该 barrier 的专属 ack。
    /// 串行锁防止后发 barrier 越过正因队列满而重试的前发 barrier；锁等待、入队和
    /// ack 共享同一上限。队列满或目标 I/O 卡死时超时返回，明确以日志完整性换取有限关停。
    /// Serialize flush-barrier enqueue and await its private acknowledgement under one total deadline.
    /// Serialization prevents a later barrier from overtaking an earlier barrier retrying a full queue;
    /// lock wait, enqueue, and acknowledgement share the same bound. Queue saturation or stuck destination
    /// I/O times out, deliberately trading tail-log completeness for bounded shutdown.
    fn flush_with_timeout(&self, timeout: Duration) -> FlushOutcome {
        let deadline = Instant::now() + timeout;
        // 中文：锁等待属于同一个总 deadline，且拿锁前不消费 dropped；既防 barrier
        // 超车，也不会把有界 flush 退化成阻塞 Mutex::lock。
        // English: Lock wait shares the total deadline and precedes the dropped swap, preventing
        // barrier overtaking without turning bounded flush into an unbounded Mutex::lock.
        let _flush_guard = loop {
            match self.flush_lock.try_lock() {
                Ok(guard) => break guard,
                Err(TryLockError::Poisoned(error)) => break error.into_inner(),
                Err(TryLockError::WouldBlock) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return FlushOutcome::LockTimeout;
                    }
                    thread::sleep(remaining.min(LOG_FLUSH_RETRY_INTERVAL));
                }
            }
        };
        let (ack_tx, ack_rx) = mpsc::sync_channel(0);
        // 中文：普通记录会捎带此前的丢弃量，但关停前可能再也没有成功记录；让 FIFO
        // barrier 携带尾部计数。只有成功入队才消费，入队失败必须原子加回。
        // English: Records normally carry prior drop counts, but shutdown may have no later
        // successful record. Attach the tail count to the FIFO barrier and restore it unless sent.
        let dropped_before = self.dropped.swap(0, Ordering::Relaxed);
        let mut command = Command::Flush {
            ack: ack_tx,
            dropped_before,
        };

        loop {
            match self.tx.try_send(command) {
                Ok(()) => break,
                Err(TrySendError::Full(returned)) => {
                    command = returned;
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        self.dropped.fetch_add(dropped_before, Ordering::Relaxed);
                        return FlushOutcome::QueueTimeout;
                    }
                    thread::sleep(remaining.min(LOG_FLUSH_RETRY_INTERVAL));
                }
                Err(TrySendError::Disconnected(_)) => {
                    self.dropped.fetch_add(dropped_before, Ordering::Relaxed);
                    return FlushOutcome::Disconnected;
                }
            }
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        match ack_rx.recv_timeout(remaining) {
            Ok(()) => FlushOutcome::Flushed,
            Err(RecvTimeoutError::Timeout) => FlushOutcome::AckTimeout,
            Err(RecvTimeoutError::Disconnected) => FlushOutcome::Disconnected,
        }
    }
}

impl log::Log for AsyncLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let text = truncate_line(record.args().to_string());
        let dropped_before = self.dropped.swap(0, Ordering::Relaxed);
        let command = Command::Record {
            level: record.level(),
            text,
            dropped_before,
        };
        match self.tx.try_send(command) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                // 中文：包含上方乐观移除的计数。 / English: Include any count optimistically removed above.
                self.dropped
                    .fetch_add(dropped_before.saturating_add(1), Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {
                // 中文：此路径可在 Tokio worker 的正文 Drop 中运行，不能回退同步 stderr I/O；只保留计数供关停/检查。
                // English: This may run from body Drop on Tokio; never perform synchronous stderr I/O, retain diagnostics only.
                self.dropped
                    .fetch_add(dropped_before.saturating_add(1), Ordering::Relaxed);
            }
        }
    }

    fn flush(&self) {
        let _ = self.flush_with_timeout(LOG_FLUSH_TIMEOUT);
    }
}

enum Destination {
    File(RotatingFile),
    Console,
}

impl Destination {
    fn write_record(&mut self, level: Level, text: &str) -> io::Result<()> {
        match self {
            Self::File(file) => file.write_line(text),
            Self::Console => {
                if level < Level::Info {
                    let mut stderr = io::stderr().lock();
                    writeln!(stderr, "{text}")?;
                    stderr.flush()
                } else {
                    let mut stdout = io::stdout().lock();
                    writeln!(stdout, "{text}")?;
                    stdout.flush()
                }
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::File(file) => file.file.flush(),
            Self::Console => {
                io::stdout().flush()?;
                io::stderr().flush()
            }
        }
    }
}

struct RotatingFile {
    parent: File,
    basename: OsString,
    display_path: PathBuf,
    file: File,
    bytes: u64,
    rotate_bytes: u64,
    backups: usize,
}

impl RotatingFile {
    fn open(identity: OutputPathIdentity, rotate_bytes: u64, backups: usize) -> Result<Self> {
        let parent = identity.open_parent_pinned()?;
        let basename = identity.basename().to_os_string();
        let display_path = identity.display_path();
        let file = open_initial(
            &parent,
            &basename,
            &display_path,
            identity.expected_object(),
        )?;
        let bytes = file.metadata().map(|meta| meta.len()).unwrap_or(0);
        Ok(Self {
            parent,
            basename,
            display_path,
            file,
            bytes,
            rotate_bytes,
            backups,
        })
    }

    fn write_line(&mut self, text: &str) -> io::Result<()> {
        let line_bytes = text.len().saturating_add(1) as u64;
        if self.rotate_bytes > 0
            && self.bytes > 0
            && self.bytes.saturating_add(line_bytes) > self.rotate_bytes
        {
            self.rotate()?;
        }
        writeln!(self.file, "{text}")?;
        self.bytes = self.bytes.saturating_add(line_bytes);
        Ok(())
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.file.flush()?;
        self.verify_active_name()?;
        if self.backups == 0 {
            self.file.set_len(0)?;
            self.bytes = 0;
            return Ok(());
        }

        let oldest = rotated_basename(&self.basename, self.backups);
        match fs::unlinkat(&self.parent, &oldest, AtFlags::empty()) {
            Ok(()) => {}
            Err(Errno::NOENT) => {}
            Err(err) => return Err(io::Error::from(err)),
        }
        for index in (1..self.backups).rev() {
            let source = rotated_basename(&self.basename, index);
            let destination = rotated_basename(&self.basename, index + 1);
            match fs::renameat(&self.parent, &source, &self.parent, &destination) {
                Ok(()) => {}
                Err(Errno::NOENT) => {}
                Err(err) => return Err(io::Error::from(err)),
            }
        }
        let first_backup = rotated_basename(&self.basename, 1);
        fs::renameat(&self.parent, &self.basename, &self.parent, &first_backup)
            .map_err(io::Error::from)?;
        self.file = create_append_exclusive(&self.parent, &self.basename, &self.display_path)
            .map_err(io::Error::other)?;
        self.bytes = 0;
        Ok(())
    }

    fn verify_active_name(&self) -> io::Result<()> {
        let held = self.file.metadata()?;
        validate_log_metadata(&held, &self.display_path).map_err(io::Error::other)?;
        validate_log_mode(&held, &self.display_path).map_err(io::Error::other)?;
        let opened = open_relative(
            &self.parent,
            &self.basename,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
            &self.display_path,
        )
        .map_err(io::Error::other)?;
        let current = opened.metadata()?;
        validate_log_metadata(&current, &self.display_path).map_err(io::Error::other)?;
        validate_log_mode(&current, &self.display_path).map_err(io::Error::other)?;
        if ObjectIdentity::from_metadata(&held) != ObjectIdentity::from_metadata(&current) {
            return Err(io::Error::other(format!(
                "log file changed identity before rotation: '{}'",
                self.display_path.display()
            )));
        }
        Ok(())
    }
}

fn open_initial(
    parent: &File,
    basename: &OsStr,
    display_path: &Path,
    expected: Option<ObjectIdentity>,
) -> Result<File> {
    match expected {
        Some(expected) => {
            let file = open_relative(
                parent,
                basename,
                OFlags::WRONLY
                    | OFlags::APPEND
                    | OFlags::CLOEXEC
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK,
                Mode::empty(),
                display_path,
            )?;
            let actual = ObjectIdentity::from_metadata(&file.metadata().with_context(|| {
                format!(
                    "Failed to inspect the log file at '{}'",
                    display_path.display()
                )
            })?);
            if actual != expected {
                anyhow::bail!(
                    "Log file changed identity between validation and open: '{}'",
                    display_path.display()
                );
            }
            secure_log_file(file, display_path)
        }
        None => create_append_exclusive(parent, basename, display_path),
    }
}

fn create_append_exclusive(parent: &File, basename: &OsStr, display_path: &Path) -> Result<File> {
    let file = open_relative(
        parent,
        basename,
        OFlags::WRONLY
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::APPEND
            | OFlags::CLOEXEC
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK,
        Mode::RUSR | Mode::WUSR,
        display_path,
    )?;
    secure_log_file(file, display_path)
}

fn open_relative(
    parent: &File,
    basename: &OsStr,
    flags: OFlags,
    mode: Mode,
    display_path: &Path,
) -> Result<File> {
    fs::openat2(
        parent,
        basename,
        flags,
        mode,
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map(File::from)
    .map_err(io::Error::from)
    .with_context(|| {
        format!(
            "Failed to open the log file at '{}'",
            display_path.display()
        )
    })
}

fn secure_log_file(file: File, path: &Path) -> Result<File> {
    let metadata = file
        .metadata()
        .with_context(|| format!("Failed to inspect the log file at '{}'", path.display()))?;
    validate_log_metadata(&metadata, path)?;
    let mut permissions = metadata.permissions();
    if permissions.mode() & 0o7777 != 0o600 {
        permissions.set_mode(0o600);
        file.set_permissions(permissions)
            .with_context(|| format!("Failed to restrict the log file at '{}'", path.display()))?;
    }
    validate_log_mode(
        &file
            .metadata()
            .with_context(|| format!("Failed to re-inspect log mode at '{}'", path.display()))?,
        path,
    )?;
    Ok(file)
}

fn validate_log_metadata(metadata: &std::fs::Metadata, path: &Path) -> Result<()> {
    if !metadata.is_file() {
        anyhow::bail!("Log path must be a regular file: '{}'", path.display());
    }
    if metadata.nlink() != 1 {
        anyhow::bail!(
            "Log file must not have hard-link aliases: '{}'",
            path.display()
        );
    }
    if !is_trusted_file_owner(metadata.uid()) {
        anyhow::bail!("Log file has an untrusted owner: '{}'", path.display());
    }
    Ok(())
}

/// 校验已存在日志目标而不创建或收紧 mode；正常启动可 chmod 可信文件，`--check-config` 必须严格只读。
/// Validate an existing log destination without mutation; unlike startup, `--check-config` remains read-only.
pub(crate) fn validate_existing_log_file(identity: &OutputPathIdentity) -> Result<()> {
    let Some(existing) = identity.existing() else {
        return Ok(());
    };
    let file = existing.open_metadata_pinned()?;
    validate_log_metadata(&file.metadata()?, &identity.display_path())?;
    existing
        .open_regular_file_pinned_append()
        .with_context(|| {
            format!(
                "Log file is not append-writable: '{}'",
                identity.display_path().display()
            )
        })
        .map(drop)
}

fn validate_log_mode(metadata: &std::fs::Metadata, path: &Path) -> Result<()> {
    if metadata.permissions().mode() & 0o7777 != 0o600 {
        anyhow::bail!(
            "Log file permissions changed from mode 0600: '{}'",
            path.display()
        );
    }
    Ok(())
}

/// 返回轮转器会覆盖的派生路径；启动碰撞检查与实际轮转必须调用同一命名函数。
/// Return a derived path overwritten by rotation; startup collision checks and rotation share this naming rule.
pub(crate) fn rotated_path(path: &Path, index: usize) -> PathBuf {
    rotated_name(path.as_os_str(), index).into()
}

fn rotated_basename(basename: &OsStr, index: usize) -> OsString {
    rotated_name(basename, index)
}

fn rotated_name(name: &OsStr, index: usize) -> OsString {
    let mut value = name.to_os_string();
    value.push(format!(".{index}"));
    value
}

fn truncate_line(mut text: String) -> String {
    if text.len() <= MAX_LOG_LINE_BYTES {
        return text;
    }
    let mut end = MAX_LOG_LINE_BYTES.saturating_sub("...[truncated]".len());
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    text.truncate(end);
    text.push_str("...[truncated]");
    text
}

fn writer_loop(mut destination: Destination, rx: Receiver<Command>) {
    while let Ok(command) = rx.recv() {
        match command {
            Command::Record {
                level,
                text,
                dropped_before,
            } => {
                if dropped_before > 0 {
                    let warning = format!(
                        "ram: dropped {dropped_before} log records because the bounded queue was full"
                    );
                    if let Err(err) = destination.write_record(Level::Warn, &warning) {
                        eprintln!("ram: failed to write dropped-record warning: {err}");
                    }
                }
                if let Err(err) = destination.write_record(level, &text) {
                    eprintln!("ram: failed to write log record: {err}");
                }
            }
            Command::Flush {
                ack,
                dropped_before,
            } => {
                if dropped_before > 0 {
                    let warning = format!(
                        "ram: dropped {dropped_before} log records because the bounded queue was full"
                    );
                    if let Err(err) = destination.write_record(Level::Warn, &warning) {
                        eprintln!("ram: failed to write dropped-record warning: {err}");
                    }
                }
                if let Err(err) = destination.flush() {
                    eprintln!("ram: failed to flush logs: {err}");
                }
                let _ = ack.send(());
            }
        }
    }
    let _ = destination.flush();
}

/// 安装进程级异步日志器。 / Install the process-wide asynchronous logger.
pub(crate) fn init(log_file: Option<OutputPathIdentity>) -> Result<()> {
    let destination = match log_file {
        Some(path) => Destination::File(RotatingFile::open(
            path,
            DEFAULT_ROTATE_BYTES,
            DEFAULT_ROTATE_BACKUPS,
        )?),
        None => Destination::Console,
    };
    let (tx, rx) = mpsc::sync_channel(LOG_QUEUE_CAPACITY);
    thread::Builder::new()
        .name("ram-log-writer".to_string())
        .spawn(move || writer_loop(destination, rx))
        .context("Failed to spawn asynchronous log writer")?;
    log::set_boxed_logger(Box::new(AsyncLogger {
        tx,
        dropped: AtomicU64::new(0),
        flush_lock: Mutex::new(()),
    }))
    .map(|()| log::set_max_level(LevelFilter::Info))
    .context("Failed to init logger")
}

#[cfg(test)]
mod tests {
    use super::{
        AsyncLogger, Command, Destination, FlushOutcome, RotatingFile, rotated_path, writer_loop,
    };
    use crate::path_identity::OutputPathIdentity;
    use assert_fs::TempDir;
    use log::Level;
    use std::io::Write as _;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::AtomicU64;
    use std::sync::{Arc, Mutex, TryLockError, mpsc};
    use std::time::{Duration, Instant};

    fn test_logger(tx: mpsc::SyncSender<Command>) -> AsyncLogger {
        AsyncLogger {
            tx,
            dropped: AtomicU64::new(0),
            flush_lock: Mutex::new(()),
        }
    }

    #[test]
    fn flush_fails_fast_when_the_bounded_queue_is_full() {
        let (tx, _rx) = mpsc::sync_channel(1);
        tx.send(Command::Record {
            level: Level::Info,
            text: "queued".to_string(),
            dropped_before: 0,
        })
        .unwrap();
        let logger = test_logger(tx);
        logger
            .dropped
            .store(3, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            logger.flush_with_timeout(Duration::ZERO),
            FlushOutcome::QueueTimeout
        );
        assert_eq!(
            logger.dropped.load(std::sync::atomic::Ordering::Relaxed),
            3,
            "a flush barrier that never entered the queue consumed the tail-drop count"
        );
    }

    #[test]
    fn disconnected_flush_retains_the_tail_drop_count() {
        let (tx, rx) = mpsc::sync_channel(1);
        drop(rx);
        let logger = test_logger(tx);
        logger
            .dropped
            .store(4, std::sync::atomic::Ordering::Relaxed);

        assert_eq!(
            logger.flush_with_timeout(Duration::from_secs(1)),
            FlushOutcome::Disconnected
        );
        assert_eq!(
            logger.dropped.load(std::sync::atomic::Ordering::Relaxed),
            4,
            "a disconnected writer consumed diagnostics it could not report"
        );
    }

    #[test]
    fn concurrent_flush_cannot_overtake_a_full_queue_retry() {
        let (tx, rx) = mpsc::sync_channel(1);
        tx.send(Command::Record {
            level: Level::Info,
            text: "queued".to_string(),
            dropped_before: 0,
        })
        .unwrap();
        let logger = Arc::new(test_logger(tx));
        logger
            .dropped
            .store(7, std::sync::atomic::Ordering::Relaxed);

        let first_logger = logger.clone();
        let first =
            std::thread::spawn(move || first_logger.flush_with_timeout(Duration::from_millis(500)));
        let observe_deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match logger.flush_lock.try_lock() {
                Err(TryLockError::WouldBlock) => break,
                Err(TryLockError::Poisoned(_)) => panic!("flush lock was unexpectedly poisoned"),
                Ok(guard) => {
                    drop(guard);
                    assert!(
                        Instant::now() < observe_deadline,
                        "first flush never acquired serialization lock"
                    );
                    std::thread::yield_now();
                }
            }
        }

        assert_eq!(
            logger.flush_with_timeout(Duration::from_millis(30)),
            FlushOutcome::LockTimeout
        );
        assert_eq!(first.join().unwrap(), FlushOutcome::QueueTimeout);
        assert_eq!(
            logger.dropped.load(std::sync::atomic::Ordering::Relaxed),
            7,
            "serialized flush failures lost the tail-drop count"
        );

        assert!(matches!(rx.recv().unwrap(), Command::Record { .. }));
        let verifier = std::thread::spawn(move || {
            let Command::Flush {
                ack,
                dropped_before,
            } = rx.recv().unwrap()
            else {
                panic!("retry did not enqueue a flush barrier");
            };
            assert_eq!(dropped_before, 7);
            ack.send(()).unwrap();
        });
        assert_eq!(
            logger.flush_with_timeout(Duration::from_secs(1)),
            FlushOutcome::Flushed
        );
        verifier.join().unwrap();
    }

    #[test]
    fn flush_fails_fast_when_the_writer_never_acknowledges() {
        let (tx, _rx) = mpsc::sync_channel(1);
        let logger = test_logger(tx);
        assert_eq!(
            logger.flush_with_timeout(Duration::ZERO),
            FlushOutcome::AckTimeout
        );
    }

    #[test]
    fn flush_acknowledges_after_all_prior_fifo_records() {
        let (tx, rx) = mpsc::sync_channel(2);
        tx.send(Command::Record {
            level: Level::Info,
            text: "prior".to_string(),
            dropped_before: 0,
        })
        .unwrap();
        let logger = test_logger(tx);
        let writer = std::thread::spawn(move || {
            assert!(matches!(rx.recv().unwrap(), Command::Record { .. }));
            let Command::Flush {
                ack,
                dropped_before,
            } = rx.recv().unwrap()
            else {
                panic!("flush barrier did not follow the prior record");
            };
            assert_eq!(dropped_before, 0);
            ack.send(()).unwrap();
        });
        assert_eq!(
            logger.flush_with_timeout(Duration::from_secs(1)),
            FlushOutcome::Flushed
        );
        writer.join().unwrap();
    }

    #[test]
    fn flush_reports_tail_drops_without_a_following_record() -> anyhow::Result<()> {
        let dir = TempDir::new()?;
        let path = dir.path().join("access.log");
        let destination = Destination::File(RotatingFile::open(
            OutputPathIdentity::capture(&path)?,
            0,
            0,
        )?);
        let (tx, rx) = mpsc::sync_channel(1);
        let logger = test_logger(tx);
        logger
            .dropped
            .store(7, std::sync::atomic::Ordering::Relaxed);
        let writer = std::thread::spawn(move || writer_loop(destination, rx));

        assert_eq!(
            logger.flush_with_timeout(Duration::from_secs(1)),
            FlushOutcome::Flushed
        );
        drop(logger);
        writer.join().unwrap();

        assert_eq!(
            std::fs::read_to_string(path)?,
            "ram: dropped 7 log records because the bounded queue was full\n"
        );
        Ok(())
    }

    #[test]
    fn truncate_rotation_validates_before_mutating_a_hard_link() -> anyhow::Result<()> {
        let dir = TempDir::new()?;
        let path = dir.path().join("access.log");
        let alias = dir.path().join("alias.log");
        let identity = OutputPathIdentity::capture(&path)?;
        let mut log = RotatingFile::open(identity, 6, 0)?;
        log.write_line("old")?;
        log.file.flush()?;
        std::fs::hard_link(&path, &alias)?;

        assert!(log.write_line("new").is_err());
        assert_eq!(std::fs::read(&path)?, b"old\n");
        assert_eq!(std::fs::read(&alias)?, b"old\n");
        Ok(())
    }

    #[test]
    fn rotation_reopens_active_file_and_bounds_backups() -> anyhow::Result<()> {
        let dir = TempDir::new()?;
        let path = dir.path().join("access.log");
        let identity = OutputPathIdentity::capture(&path)?;
        let mut log = RotatingFile::open(identity, 6, 2)?;

        log.write_line("one")?;
        log.write_line("two")?;
        log.write_line("three")?;
        log.write_line("four")?;
        log.file.flush()?;

        assert_eq!(std::fs::read_to_string(&path)?, "four\n");
        assert_eq!(std::fs::read_to_string(rotated_path(&path, 1))?, "three\n");
        assert_eq!(std::fs::read_to_string(rotated_path(&path, 2))?, "two\n");
        assert!(!rotated_path(&path, 3).exists());
        Ok(())
    }

    #[test]
    fn rotation_replaces_backup_symlink_without_following_it() -> anyhow::Result<()> {
        let dir = TempDir::new()?;
        let path = dir.path().join("access.log");
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"must remain intact")?;
        let identity = OutputPathIdentity::capture(&path)?;
        let mut log = RotatingFile::open(identity, 6, 1)?;
        log.write_line("old")?;
        symlink(&victim, rotated_path(&path, 1))?;

        log.write_line("new")?;
        log.file.flush()?;

        assert_eq!(std::fs::read(&victim)?, b"must remain intact");
        assert_eq!(std::fs::read_to_string(&path)?, "new\n");
        assert_eq!(std::fs::read_to_string(rotated_path(&path, 1))?, "old\n");
        Ok(())
    }

    #[test]
    fn absent_output_is_created_in_the_pinned_parent() -> anyhow::Result<()> {
        let dir = TempDir::new()?;
        let parent = dir.path().join("logs");
        std::fs::create_dir(&parent)?;
        let path = parent.join("access.log");
        let identity = OutputPathIdentity::capture(&path)?;

        let mut log = RotatingFile::open(identity, 0, 0)?;
        log.write_line("created")?;
        log.file.flush()?;

        assert_eq!(std::fs::read_to_string(&path)?, "created\n");
        assert_eq!(
            std::fs::metadata(&path)?.permissions().mode() & 0o777,
            0o600
        );
        Ok(())
    }

    #[test]
    fn absent_output_rejects_a_name_created_after_capture() -> anyhow::Result<()> {
        let dir = TempDir::new()?;
        let path = dir.path().join("access.log");
        let identity = OutputPathIdentity::capture(&path)?;
        std::fs::write(&path, b"must remain intact")?;

        assert!(RotatingFile::open(identity, 0, 0).is_err());
        assert_eq!(std::fs::read(&path)?, b"must remain intact");
        Ok(())
    }

    #[test]
    fn existing_output_replacement_is_rejected_before_mutation() -> anyhow::Result<()> {
        let dir = TempDir::new()?;
        let path = dir.path().join("access.log");
        let original = dir.path().join("original.log");
        std::fs::write(&path, b"original")?;
        let identity = OutputPathIdentity::capture(&path)?;
        std::fs::rename(&path, &original)?;
        std::fs::write(&path, b"replacement")?;

        assert!(RotatingFile::open(identity, 0, 0).is_err());
        assert_eq!(std::fs::read(&original)?, b"original");
        assert_eq!(std::fs::read(&path)?, b"replacement");
        Ok(())
    }

    #[test]
    fn parent_path_replacement_cannot_redirect_initial_open() -> anyhow::Result<()> {
        let dir = TempDir::new()?;
        let configured_parent = dir.path().join("logs");
        let pinned_parent = dir.path().join("pinned-logs");
        std::fs::create_dir(&configured_parent)?;
        let path = configured_parent.join("access.log");
        let identity = OutputPathIdentity::capture(&path)?;

        std::fs::rename(&configured_parent, &pinned_parent)?;
        std::fs::create_dir(&configured_parent)?;
        let decoy = configured_parent.join("access.log");
        std::fs::write(&decoy, b"replacement directory")?;

        let mut log = RotatingFile::open(identity, 0, 0)?;
        log.write_line("pinned")?;
        log.file.flush()?;

        assert_eq!(
            std::fs::read_to_string(pinned_parent.join("access.log"))?,
            "pinned\n"
        );
        assert_eq!(std::fs::read(&decoy)?, b"replacement directory");
        Ok(())
    }

    #[test]
    fn rotation_stays_in_pinned_parent_after_parent_path_replacement() -> anyhow::Result<()> {
        let dir = TempDir::new()?;
        let configured_parent = dir.path().join("logs");
        let pinned_parent = dir.path().join("pinned-logs");
        std::fs::create_dir(&configured_parent)?;
        let path = configured_parent.join("access.log");
        let identity = OutputPathIdentity::capture(&path)?;
        let mut log = RotatingFile::open(identity, 6, 1)?;
        log.write_line("old")?;
        log.file.flush()?;

        std::fs::rename(&configured_parent, &pinned_parent)?;
        std::fs::create_dir(&configured_parent)?;
        let decoy = configured_parent.join("access.log");
        std::fs::write(&decoy, b"replacement directory")?;

        log.write_line("new")?;
        log.file.flush()?;

        assert_eq!(
            std::fs::read_to_string(pinned_parent.join("access.log"))?,
            "new\n"
        );
        assert_eq!(
            std::fs::read_to_string(pinned_parent.join("access.log.1"))?,
            "old\n"
        );
        assert_eq!(std::fs::read(&decoy)?, b"replacement directory");
        assert!(!configured_parent.join("access.log.1").exists());
        Ok(())
    }
}
