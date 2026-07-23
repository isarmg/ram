//! 有界异步控制台日志器。
//!
//! 请求任务只格式化一条有界记录并以 `try_send` 投递给专用写线程；慢终端不会阻塞
//! Tokio worker。INFO 写 stdout，WARN/ERROR 写 stderr。

mod access;

pub(crate) use access::HttpLogger;
#[cfg(feature = "fuzzing")]
pub(crate) use access::fuzz_log_format;

use anyhow::{Context, Result};
use log::{Level, LevelFilter, Metadata, Record};
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Mutex, TryLockError};
use std::thread;
use std::time::{Duration, Instant};

const LOG_QUEUE_CAPACITY: usize = 8_192;
const MAX_LOG_LINE_BYTES: usize = 64 * 1024;
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
        dropped_before: u64,
    },
}

struct AsyncLogger {
    tx: SyncSender<Command>,
    dropped: AtomicU64,
    flush_lock: Mutex<()>,
}

impl AsyncLogger {
    fn flush_with_timeout(&self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        let _flush_guard = loop {
            match self.flush_lock.try_lock() {
                Ok(guard) => break guard,
                Err(TryLockError::Poisoned(error)) => break error.into_inner(),
                Err(TryLockError::WouldBlock) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return;
                    }
                    thread::sleep(remaining.min(LOG_FLUSH_RETRY_INTERVAL));
                }
            }
        };

        let dropped_before = self.dropped.swap(0, Ordering::Relaxed);
        let (ack_tx, ack_rx) = mpsc::sync_channel(0);
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
                        return;
                    }
                    thread::sleep(remaining.min(LOG_FLUSH_RETRY_INTERVAL));
                }
                Err(TrySendError::Disconnected(_)) => {
                    self.dropped.fetch_add(dropped_before, Ordering::Relaxed);
                    return;
                }
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        match ack_rx.recv_timeout(remaining) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) | Err(RecvTimeoutError::Timeout) => (),
        };
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
        if self.tx.try_send(command).is_err() {
            self.dropped
                .fetch_add(dropped_before.saturating_add(1), Ordering::Relaxed);
        }
    }

    fn flush(&self) {
        self.flush_with_timeout(LOG_FLUSH_TIMEOUT);
    }
}

fn truncate_line(mut text: String) -> String {
    if text.len() <= MAX_LOG_LINE_BYTES {
        return text;
    }
    const SUFFIX: &str = "...[truncated]";
    let mut end = MAX_LOG_LINE_BYTES.saturating_sub(SUFFIX.len());
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    text.truncate(end);
    text.push_str(SUFFIX);
    text
}

fn write_record(level: Level, text: &str) -> io::Result<()> {
    if level <= Level::Warn {
        let mut output = io::stderr().lock();
        writeln!(output, "{text}")?;
        output.flush()
    } else {
        let mut output = io::stdout().lock();
        writeln!(output, "{text}")?;
        output.flush()
    }
}

fn flush_outputs() -> io::Result<()> {
    io::stdout().flush()?;
    io::stderr().flush()
}

fn report_dropped(count: u64) {
    if count > 0 {
        let warning =
            format!("ram: dropped {count} log records because the bounded queue was full");
        if let Err(error) = write_record(Level::Warn, &warning) {
            eprintln!("ram: failed to write dropped-record warning: {error}");
        }
    }
}

fn writer_loop(rx: Receiver<Command>) {
    while let Ok(command) = rx.recv() {
        match command {
            Command::Record {
                level,
                text,
                dropped_before,
            } => {
                report_dropped(dropped_before);
                if let Err(error) = write_record(level, &text) {
                    eprintln!("ram: failed to write log record: {error}");
                }
            }
            Command::Flush {
                ack,
                dropped_before,
            } => {
                report_dropped(dropped_before);
                if let Err(error) = flush_outputs() {
                    eprintln!("ram: failed to flush logs: {error}");
                }
                let _ = ack.send(());
            }
        }
    }
    let _ = flush_outputs();
}

/// 安装进程级异步控制台日志器。
pub(crate) fn init() -> Result<()> {
    let (tx, rx) = mpsc::sync_channel(LOG_QUEUE_CAPACITY);
    thread::Builder::new()
        .name("ram-log-writer".to_owned())
        .spawn(move || writer_loop(rx))
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
    use super::*;

    #[test]
    fn long_utf8_lines_are_bounded() {
        let line = truncate_line("界".repeat(MAX_LOG_LINE_BYTES));
        assert!(line.len() <= MAX_LOG_LINE_BYTES);
        assert!(line.ends_with("...[truncated]"));
    }

    #[test]
    fn short_lines_are_unchanged() {
        assert_eq!(truncate_line("hello".to_owned()), "hello");
    }
}
