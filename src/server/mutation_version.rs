//! 目录列表操作使用的进程内变更纪元。列表令牌不是文件系统锁，也不是授权凭据；它只是
//! 短期乐观前置条件：启动 UUID 拒绝另一服务进程签发的令牌，单调 revision 拒绝列表快照后
//! 进入最终事务的任何变更，而 active 计数器封闭“阻塞 worker 已启动但尚未发布命名空间”
//! 的隐蔽窗口。
//! 此状态只能观察经过当前 Ram 进程的变更。仅当 Ram 是服务根的唯一写入者时，它才能保护
//! 旧列表操作；其他进程直接写文件系统不会推进该纪元。
//!
//! Process-local mutation epochs used by directory-listing actions. A listing token is not a
//! filesystem lock and is never an authorization credential. It is a short-lived optimistic
//! precondition: the boot UUID rejects tokens from another server process, while the monotonic
//! revision rejects every transaction that entered Ram's final mutation critical section after the
//! listing snapshot. The active counter closes the otherwise subtle window where a blocking worker
//! has started but has not yet advanced visible namespace state.
//! This state observes only mutations routed through this Ram process. It protects stale-listing
//! actions only when Ram is the sole writer of the served root; another process writing the
//! filesystem directly does not advance the epoch.

use hyper::HeaderMap;
use hyper::header::{HeaderName, HeaderValue};
use std::fmt;
use std::sync::{Arc, Mutex as StdMutex};
use uuid::Uuid;

pub(super) const MUTATION_VERSION_HEADER: HeaderName =
    HeaderName::from_static("x-ram-mutation-version");
pub(super) const IF_MUTATION_VERSION_HEADER: HeaderName =
    HeaderName::from_static("x-ram-if-mutation-version");

const UUID_TEXT_LEN: usize = 36;
const MAX_REVISION_TEXT_LEN: usize = 20;
const MIN_TOKEN_LEN: usize = UUID_TEXT_LEN + 2;
const MAX_TOKEN_LEN: usize = UUID_TEXT_LEN + 1 + MAX_REVISION_TEXT_LEN;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct MutationVersionToken {
    boot: Uuid,
    revision: u64,
}

impl MutationVersionToken {
    pub(super) fn encode(&self) -> String {
        format!("{}.{}", self.boot.hyphenated(), self.revision)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct MutationScanSnapshot {
    revision: u64,
}

#[derive(Debug)]
struct MutationVersionInner {
    /// 每个进入最终事务的操作只递增一次；即使操作失败也不回滚，以保守作废旧列表。
    /// Incremented exactly once on final-transaction entry and never rolled back on failure, so
    /// previously issued listings are invalidated conservatively.
    revision: u64,
    /// 已进入最终事务且真实 worker 尚未退出的数量；扫描只能在该值为零时开始和签名。
    /// Number of final transactions whose real workers have not exited; scans may start and sign
    /// only while this remains zero.
    active: u64,
}

/// 可克隆的进程纪元状态；互斥锁让“比较令牌、递增 revision、标记 active”即使面对互不相关
/// 的路径锁也成为一次原子转换。
/// Cloneable process epoch state. The mutex makes “compare token, increment revision, mark active”
/// one atomic transition even for unrelated path locks.
#[derive(Clone, Debug)]
pub(super) struct MutationVersionState {
    boot: Uuid,
    inner: Arc<StdMutex<MutationVersionInner>>,
}

impl MutationVersionState {
    pub(super) fn new() -> Self {
        Self::with_boot(Uuid::new_v4())
    }

    fn with_boot(boot: Uuid) -> Self {
        Self {
            boot,
            inner: Arc::new(StdMutex::new(MutationVersionInner {
                revision: 0,
                active: 0,
            })),
        }
    }

    /// 只在没有最终变更 worker 活跃时捕获扫描起点。
    /// Capture the only admissible scan start: no final mutation worker is active.
    pub(super) fn begin_scan(&self) -> Option<MutationScanSnapshot> {
        let inner = self.inner.lock().ok()?;
        (inner.active == 0).then_some(MutationScanSnapshot {
            revision: inner.revision,
        })
    }

    /// 仅当扫描期间没有事务开始、保持活跃或完成时签发快照；检查后才开始的变更会推进
    /// revision，使刚签发的令牌立即过期。
    /// Sign a snapshot only if no transaction began, remained active, or completed during the scan.
    /// A mutation starting after this check advances the revision and immediately makes the token stale.
    pub(super) fn finish_scan(&self, start: MutationScanSnapshot) -> Option<String> {
        let inner = self.inner.lock().ok()?;
        (inner.active == 0 && inner.revision == start.revision).then(|| {
            MutationVersionToken {
                boot: self.boot,
                revision: inner.revision,
            }
            .encode()
        })
    }

    /// 原子校验可选浏览器快照并进入最终变更事务。revision 在进入时推进，因此随后失败的事务
    /// 仍会保守使旧列表失效；过期条件请求不会进入事务，也不会推进 revision。
    /// Atomically validate an optional browser snapshot and enter a final mutation transaction.
    /// Revision advances on entry, so a transaction that later fails still conservatively invalidates
    /// older listings. A stale conditional request does not enter and does not advance the revision.
    pub(super) fn begin_mutation(
        &self,
        expected: Option<&MutationVersionToken>,
    ) -> Result<MutationActivityGuard, MutationVersionBeginError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| MutationVersionBeginError::Poisoned)?;
        if let Some(expected) = expected
            && (expected.boot != self.boot
                || expected.revision != inner.revision
                || inner.active != 0)
        {
            return Err(MutationVersionBeginError::Stale);
        }
        let next_revision = inner
            .revision
            .checked_add(1)
            .ok_or(MutationVersionBeginError::Exhausted)?;
        let next_active = inner
            .active
            .checked_add(1)
            .ok_or(MutationVersionBeginError::Exhausted)?;
        inner.revision = next_revision;
        inner.active = next_active;
        Ok(MutationActivityGuard {
            inner: self.inner.clone(),
            active: true,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MutationVersionBeginError {
    Stale,
    Exhausted,
    Poisoned,
}

impl fmt::Display for MutationVersionBeginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stale => f.write_str("the directory mutation version is stale"),
            Self::Exhausted => f.write_str("the directory mutation revision is exhausted"),
            Self::Poisoned => f.write_str("the directory mutation state is poisoned"),
        }
    }
}

impl std::error::Error for MutationVersionBeginError {}

/// 由 `MutationGuards`、最终由真实阻塞 worker 持有；HTTP future 被丢弃时，只要内核操作或
/// 清理仍在运行，就不会提前递减 active。
/// Owned by `MutationGuards` and ultimately by the real blocking worker. Dropping an HTTP future
/// cannot decrement active while a kernel operation or cleanup is still running.
#[derive(Debug)]
pub(super) struct MutationActivityGuard {
    inner: Arc<StdMutex<MutationVersionInner>>,
    active: bool,
}

impl Drop for MutationActivityGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.active = inner
            .active
            .checked_sub(1)
            .expect("mutation activity guards cannot underflow");
        self.active = false;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct InvalidMutationVersion;

impl fmt::Display for InvalidMutationVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Invalid X-Ram-If-Mutation-Version header")
    }
}

impl std::error::Error for InvalidMutationVersion {}

/// 严格单值解析器。规范小写 UUID 与规范无符号十进制可防止多种文本拼写跨越代理/日志边界。
/// Strict singleton parser. Canonical lowercase UUID text and canonical unsigned decimal prevent
/// multiple textual spellings from crossing proxy/logging boundaries.
pub(super) fn parse_mutation_version_header(
    headers: &HeaderMap<HeaderValue>,
) -> Result<Option<MutationVersionToken>, InvalidMutationVersion> {
    let mut values = headers.get_all(&IF_MUTATION_VERSION_HEADER).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(InvalidMutationVersion);
    }
    let raw = value.as_bytes();
    if !(MIN_TOKEN_LEN..=MAX_TOKEN_LEN).contains(&raw.len()) || !raw.is_ascii() {
        return Err(InvalidMutationVersion);
    }
    let text = std::str::from_utf8(raw).map_err(|_| InvalidMutationVersion)?;
    let (boot_text, revision_text) = text.split_once('.').ok_or(InvalidMutationVersion)?;
    if boot_text.len() != UUID_TEXT_LEN
        || revision_text.is_empty()
        || revision_text.len() > MAX_REVISION_TEXT_LEN
        || revision_text.bytes().any(|byte| !byte.is_ascii_digit())
        || (revision_text.len() > 1 && revision_text.starts_with('0'))
    {
        return Err(InvalidMutationVersion);
    }
    let boot = Uuid::parse_str(boot_text).map_err(|_| InvalidMutationVersion)?;
    if boot.hyphenated().to_string() != boot_text {
        return Err(InvalidMutationVersion);
    }
    let revision = revision_text
        .parse::<u64>()
        .map_err(|_| InvalidMutationVersion)?;
    Ok(Some(MutationVersionToken { boot, revision }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    fn state(byte: u8) -> MutationVersionState {
        MutationVersionState::with_boot(Uuid::from_bytes([byte; 16]))
    }

    #[test]
    fn scan_token_requires_a_quiescent_unchanged_window() {
        let state = state(1);
        let start = state.begin_scan().expect("initial state is stable");
        let token = state.finish_scan(start).expect("unchanged scan is signed");
        let parsed = {
            let mut headers = HeaderMap::new();
            headers.insert(
                IF_MUTATION_VERSION_HEADER,
                HeaderValue::from_str(&token).unwrap(),
            );
            parse_mutation_version_header(&headers).unwrap().unwrap()
        };

        let activity = state.begin_mutation(Some(&parsed)).unwrap();
        assert!(state.begin_scan().is_none());
        drop(activity);
        assert!(state.finish_scan(start).is_none());
    }

    #[test]
    fn boot_mismatch_and_old_revision_are_stale_without_entering_activity() {
        let first = state(1);
        let second = state(2);
        let start = first.begin_scan().unwrap();
        let token = first.finish_scan(start).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            IF_MUTATION_VERSION_HEADER,
            HeaderValue::from_str(&token).unwrap(),
        );
        let token = parse_mutation_version_header(&headers).unwrap().unwrap();
        assert_eq!(
            second.begin_mutation(Some(&token)).unwrap_err(),
            MutationVersionBeginError::Stale
        );
        assert!(second.begin_scan().is_some());

        let activity = first.begin_mutation(Some(&token)).unwrap();
        drop(activity);
        assert_eq!(
            first.begin_mutation(Some(&token)).unwrap_err(),
            MutationVersionBeginError::Stale
        );
    }

    #[test]
    fn activity_remains_visible_until_the_worker_owned_guard_drops() {
        let state = state(3);
        let activity = state.begin_mutation(None).unwrap();
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let worker = {
            let entered = entered.clone();
            let release = release.clone();
            std::thread::spawn(move || {
                let _activity = activity;
                entered.wait();
                release.wait();
            })
        };
        entered.wait();
        assert!(state.begin_scan().is_none());
        release.wait();
        worker.join().unwrap();
        assert!(state.begin_scan().is_some());
    }

    #[test]
    fn parser_rejects_duplicates_noncanonical_text_and_oversize_values() {
        let canonical = format!("{}.0", Uuid::from_bytes([4; 16]).hyphenated());
        let mut headers = HeaderMap::new();
        headers.insert(
            IF_MUTATION_VERSION_HEADER,
            HeaderValue::from_str(&canonical).unwrap(),
        );
        assert!(parse_mutation_version_header(&headers).unwrap().is_some());

        headers.append(
            IF_MUTATION_VERSION_HEADER,
            HeaderValue::from_str(&canonical).unwrap(),
        );
        assert!(parse_mutation_version_header(&headers).is_err());

        for invalid in [
            "00000000-0000-0000-0000-000000000004.00",
            "00000000-0000-0000-0000-000000000004.-1",
            "00000000000000000000000000000004.0",
            "00000000-0000-0000-0000-000000000004.18446744073709551616",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                IF_MUTATION_VERSION_HEADER,
                HeaderValue::from_str(invalid).unwrap(),
            );
            assert!(
                parse_mutation_version_header(&headers).is_err(),
                "{invalid}"
            );
        }
    }
}
