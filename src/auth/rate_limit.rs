//! 有界认证失败计数与昂贵认证准入。攻击者选择的用户名/来源不能产生无界状态；队列、
//! 来源、账号与全局 worker 上限均 fail closed；即使 HTTP future 被丢弃，真实阻塞 worker
//! 仍持有所有 permit 和暂定失败预留直至退出。
//!
//! Bounded authentication-failure and expensive-authentication admission.
//!
//! Security invariants:
//! - attacker-selected usernames and sources never create unbounded retained state;
//! - queue, per-source, per-account, and global worker limits fail closed;
//! - every permit and provisional reservation stays owned by the real blocking
//!   hash or persistent-revocation worker until it exits, even if the HTTP future is dropped.

use super::*;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(super) struct AuthRateKey {
    pub(super) source: Option<SourceIdentity>,
    /// 固定长度哈希保存来源以外的协议域/主体选择器，同时限制攻击者控制的键内存。
    /// A fixed digest retains the protocol-domain/subject selector while bounding attacker-controlled key memory.
    pub(super) username_hash: [u8; 32],
}

impl AuthRateKey {
    #[cfg(test)]
    pub(super) fn new(source: Option<SourceIdentity>, username: &str) -> Self {
        Self {
            source,
            username_hash: Sha256::digest(username.as_bytes()).into(),
        }
    }

    /// 中文：协议域前缀以非 UTF-8 字节开头，不可能与 `new` 哈希的任意 Rust 用户名字节串
    /// 相同；Bearer 失败、撤销写入与密码登录因此不能互相制造退避。
    /// English: A protocol-domain prefix beginning with invalid UTF-8 cannot equal any Rust username
    /// byte string hashed by `new`, so bearer failures, revocation writes, and password login cannot
    /// impose backoff on one another.
    pub(super) fn namespaced(
        source: Option<SourceIdentity>,
        domain: &[u8],
        username: &str,
    ) -> Self {
        let mut digest = Sha256::new();
        digest.update(domain);
        digest.update(username.as_bytes());
        Self {
            source,
            username_hash: digest.finalize().into(),
        }
    }
}

/// 一个“来源 + 协议域选择器哈希”分区的失败状态。`failures` 是已提交失败，
/// `pending_hash_attempts` 是已准入但 worker 尚未给出结论的暂定尝试；两者共同消耗免费尝试
/// 预算，封闭并发绕过。活跃预留存在时清理器不得驱逐该条目。
/// Failure state for one source+protocol-selector partition. `failures` are committed results and
/// `pending_hash_attempts` are admitted attempts awaiting a worker verdict; both consume the free
/// attempt budget so concurrency cannot bypass throttling. Cleanup must retain live reservations.
#[derive(Debug, Clone)]
pub(super) struct AuthFailureState {
    pub(super) failures: u32,
    /// 昂贵校验进入哈希队列前先暂定预留，并计入免费尝试预算，封闭并发突发同时看到旧计数的竞态。
    /// Expensive checks reserve provisionally before queueing so a concurrent burst cannot share one pre-failure counter.
    pub(super) pending_hash_attempts: u32,
    pub(super) blocked_until: Instant,
    pub(super) last_seen: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HashAttemptReservationReject {
    Blocked { retry_after_secs: u64 },
    ConcurrentAttemptLimit,
    StateCapacity,
    StateUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AuthRateStateError {
    Capacity,
    Unavailable,
}

#[derive(Debug, Default)]
pub(super) struct AuthRateLimiter {
    pub(super) entries: HashMap<AuthRateKey, AuthFailureState>,
    pub(super) last_cleanup: Option<Instant>,
}

impl AuthRateLimiter {
    pub(super) fn retry_after(&mut self, key: &AuthRateKey, now: Instant) -> Option<u64> {
        self.cleanup(now);
        let state = self.entries.get_mut(key)?;
        state.last_seen = now;
        if state.blocked_until > now {
            let remaining = state.blocked_until.duration_since(now);
            Some(
                remaining
                    .as_secs()
                    .saturating_add(u64::from(remaining.subsec_nanos() != 0))
                    .max(1),
            )
        } else {
            None
        }
    }

    pub(super) fn failed(
        &mut self,
        key: AuthRateKey,
        now: Instant,
    ) -> Result<Option<u64>, AuthRateStateError> {
        self.cleanup(now);
        if !self.ensure_entry_capacity(&key) {
            return Err(AuthRateStateError::Capacity);
        }
        let state = self.entries.entry(key).or_insert(AuthFailureState {
            failures: 0,
            pending_hash_attempts: 0,
            blocked_until: now,
            last_seen: now,
        });
        state.failures = state.failures.saturating_add(1);
        state.last_seen = now;
        if state.failures <= AUTH_RATE_FREE_FAILURES {
            return Ok(None);
        }
        let shift = (state.failures - AUTH_RATE_FREE_FAILURES - 1).min(6);
        let delay = (1u64 << shift).min(AUTH_RATE_MAX_BACKOFF_SECS);
        state.blocked_until = now + Duration::from_secs(delay);
        Ok(Some(delay))
    }

    pub(super) fn succeeded(&mut self, key: &AuthRateKey) {
        let Some(state) = self.entries.get_mut(key) else {
            return;
        };
        // 中文：成功 proof 清除已提交失败，但不能抹掉并发暂定预留；后者会自行提交或取消。
        // English: Success clears committed failures, not concurrent provisional reservations that must resolve themselves.
        if state.pending_hash_attempts == 0 {
            self.entries.remove(key);
        } else {
            state.failures = 0;
            state.blocked_until = Instant::now();
            state.last_seen = Instant::now();
        }
    }

    pub(super) fn reserve_hash_attempt(
        &mut self,
        key: AuthRateKey,
        now: Instant,
    ) -> Result<(), HashAttemptReservationReject> {
        self.cleanup(now);
        if let Some(retry_after_secs) = self.retry_after_without_cleanup(&key, now) {
            return Err(HashAttemptReservationReject::Blocked { retry_after_secs });
        }
        if !self.ensure_entry_capacity(&key) {
            return Err(HashAttemptReservationReject::StateCapacity);
        }

        let state = self.entries.entry(key).or_insert(AuthFailureState {
            failures: 0,
            pending_hash_attempts: 0,
            blocked_until: now,
            last_seen: now,
        });
        state.last_seen = now;

        // 中文：退避到期后必须允许恰好一个恢复尝试；否则 `failures >= FREE` 会在每次重试时
        // 重新延长 deadline，正确凭据也永远没有机会被验证。阈值前，failure+pending 共同限制
        // 免费突发；阈值后只允许一个 pending，真实失败由 `finish_hash_attempt` 设置下一退避。
        // English: Once backoff expires, admit exactly one recovery attempt. Rejecting solely because
        // `failures >= FREE` would renew the deadline forever without ever checking correct credentials.
        // Before the threshold, failures+pending bound the free burst; after it, one pending attempt is
        // allowed and only its evaluated failure schedules the next backoff.
        let concurrent_limit_reached = if state.failures >= AUTH_RATE_FREE_FAILURES {
            state.pending_hash_attempts > 0
        } else {
            state.failures.saturating_add(state.pending_hash_attempts) >= AUTH_RATE_FREE_FAILURES
        };
        if concurrent_limit_reached {
            return Err(HashAttemptReservationReject::ConcurrentAttemptLimit);
        }
        state.pending_hash_attempts = state.pending_hash_attempts.saturating_add(1);
        Ok(())
    }

    pub(super) fn hash_attempt_blocked(&mut self, key: &AuthRateKey, now: Instant) -> Option<u64> {
        self.cleanup(now);
        self.retry_after_without_cleanup(key, now)
    }

    pub(super) fn finish_hash_attempt(
        &mut self,
        key: &AuthRateKey,
        succeeded: bool,
        now: Instant,
    ) -> bool {
        let Some(state) = self.entries.get_mut(key) else {
            // 中文：活动预留阻止清理/驱逐；缺失只可能来自状态损坏，应由调用方 fail closed，
            // 不能重建部分状态。
            // English: A live reservation prevents eviction; absence implies corruption, so fail closed rather than rebuild partial state.
            return false;
        };
        if state.pending_hash_attempts == 0 {
            return false;
        }
        state.pending_hash_attempts = state.pending_hash_attempts.saturating_sub(1);
        state.last_seen = now;
        if succeeded {
            state.failures = 0;
            state.blocked_until = now;
        } else {
            state.failures = state.failures.saturating_add(1);
            if state.failures >= AUTH_RATE_FREE_FAILURES {
                let shift = state
                    .failures
                    .saturating_sub(AUTH_RATE_FREE_FAILURES)
                    .min(6);
                let delay = (1u64 << shift).min(AUTH_RATE_MAX_BACKOFF_SECS);
                state.blocked_until = now + Duration::from_secs(delay);
            }
        }
        if state.failures == 0 && state.pending_hash_attempts == 0 {
            self.entries.remove(key);
        }
        true
    }

    pub(super) fn cancel_hash_attempt(&mut self, key: &AuthRateKey, now: Instant) -> bool {
        let Some(state) = self.entries.get_mut(key) else {
            return false;
        };
        if state.pending_hash_attempts == 0 {
            return false;
        }
        state.pending_hash_attempts = state.pending_hash_attempts.saturating_sub(1);
        state.last_seen = now;
        if state.failures == 0 && state.pending_hash_attempts == 0 {
            self.entries.remove(key);
        }
        true
    }

    pub(super) fn retry_after_without_cleanup(
        &mut self,
        key: &AuthRateKey,
        now: Instant,
    ) -> Option<u64> {
        let state = self.entries.get_mut(key)?;
        state.last_seen = now;
        if state.blocked_until <= now {
            return None;
        }
        let remaining = state.blocked_until.duration_since(now);
        Some(
            remaining
                .as_secs()
                .saturating_add(u64::from(remaining.subsec_nanos() != 0))
                .max(1),
        )
    }

    pub(super) fn ensure_entry_capacity(&mut self, key: &AuthRateKey) -> bool {
        if self.entries.contains_key(key) || self.entries.len() < AUTH_RATE_CAPACITY {
            return true;
        }
        // 中文：容量保护必须 fail closed。这里的“无活动 hash”条目仍保存尚未到期的失败次数或
        // 退避 deadline；为攻击者选择的新键驱逐它，会让轮换用户名/伪 token 冲刷受害账号的
        // 密码退避。只有上方 cleanup 按固定 idle expiry 到期删除，满容量时新键一律拒绝。
        // English: Capacity protection must fail closed. An entry without a live hash still carries
        // unexpired failures or a backoff deadline; evicting it for an attacker-selected key lets
        // username/token churn erase a victim's password throttle. Only fixed idle-expiry cleanup may
        // remove retained state, and a new key is rejected while the remaining state is at capacity.
        false
    }

    pub(super) fn cleanup(&mut self, now: Instant) {
        if self.last_cleanup.is_some_and(|last| {
            now.checked_duration_since(last)
                .is_none_or(|elapsed| elapsed < AUTH_RATE_CLEANUP_INTERVAL)
        }) {
            return;
        }
        self.last_cleanup = Some(now);
        self.entries.retain(|_, value| {
            value.pending_hash_attempts > 0
                || now
                    .checked_duration_since(value.last_seen)
                    .is_none_or(|idle| idle < AUTH_RATE_IDLE_EXPIRY)
        });
    }
}

/// 暂定昂贵认证尝试；Drop 是取消路径，只移除预留，绝不伪造凭据失败。
/// A provisional expensive attempt whose Drop path removes only its reservation on queue/timeout/shutdown cancellation.
pub(super) struct HashAttemptReservation {
    pub(super) limiter: Arc<Mutex<AuthRateLimiter>>,
    pub(super) key: AuthRateKey,
    pub(super) active: bool,
}

impl HashAttemptReservation {
    pub(super) fn reserve(
        limiter: Arc<Mutex<AuthRateLimiter>>,
        key: AuthRateKey,
    ) -> Result<Self, HashAttemptReservationReject> {
        limiter
            .lock()
            .map_err(|_| HashAttemptReservationReject::StateUnavailable)?
            .reserve_hash_attempt(key.clone(), Instant::now())?;
        Ok(Self {
            limiter,
            key,
            active: true,
        })
    }

    pub(super) fn blocked_after_global_permit(
        &self,
    ) -> Result<Option<u64>, HashAttemptReservationReject> {
        self.limiter
            .lock()
            .map_err(|_| HashAttemptReservationReject::StateUnavailable)
            .map(|mut limiter| limiter.hash_attempt_blocked(&self.key, Instant::now()))
    }

    pub(super) fn finish(mut self, succeeded: bool) -> bool {
        self.active = false;
        match self.limiter.lock() {
            Ok(mut limiter) => limiter.finish_hash_attempt(&self.key, succeeded, Instant::now()),
            Err(_) => false,
        }
    }
}

impl Drop for HashAttemptReservation {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Ok(mut limiter) = self.limiter.lock() {
            let _ = limiter.cancel_hash_attempt(&self.key, Instant::now());
        }
    }
}

/// 密码尝试同时拥有“来源跨用户名预算”和“来源+声明用户名”两份暂定预留。
/// 两个键只由客户端可见输入派生，与账号是否存在无关；成功仅清除本用户名状态，并取消
/// 来源预留而保留来源既有失败，因此低权账号成功不能擦除同来源对高权账号的猜测记录。
/// A password attempt owns provisional reservations for both the cross-username source budget and
/// the source+claimed-name principal bucket. Both keys depend only on client-visible input, never
/// account existence. Success clears only this claimed name and cancels (rather than succeeds) the
/// source reservation, so a low-privilege login cannot erase guesses against another account.
pub(super) struct PasswordRateReservation {
    pub(super) limiter: Arc<Mutex<AuthRateLimiter>>,
    pub(super) source_key: AuthRateKey,
    pub(super) principal_key: AuthRateKey,
    pub(super) active: bool,
}

impl PasswordRateReservation {
    /// 原子持锁时先预留来源预算，再预留用户名预算。第二步失败会回滚第一份 pending，
    /// 但不会撤销该用户名已经触发的真实退避；凭据尚未求值时不提交另一层失败。
    /// Reserve the source budget first and the claimed-name budget second under one lock. If the
    /// second step rejects, roll back the first pending reservation without undoing a real backoff
    /// already triggered for that name; an unevaluated credential never commits failure elsewhere.
    pub(super) fn reserve(
        limiter: Arc<Mutex<AuthRateLimiter>>,
        source_key: AuthRateKey,
        principal_key: AuthRateKey,
    ) -> Result<Self, HashAttemptReservationReject> {
        let now = Instant::now();
        let mut state = limiter
            .lock()
            .map_err(|_| HashAttemptReservationReject::StateUnavailable)?;
        state.reserve_hash_attempt(source_key.clone(), now)?;
        if let Err(rejection) = state.reserve_hash_attempt(principal_key.clone(), now) {
            let rolled_back = state.cancel_hash_attempt(&source_key, now);
            debug_assert!(rolled_back, "source reservation must exist during rollback");
            return Err(rejection);
        }
        drop(state);
        Ok(Self {
            limiter,
            source_key,
            principal_key,
            active: true,
        })
    }

    /// 排队期间任一层可能被别的请求推进到退避；取得全局 worker 槽后一起重查。
    /// Either layer may enter backoff while this attempt queues; recheck both after acquiring the
    /// global worker slot and return the longer observable delay.
    pub(super) fn blocked_after_global_permit(
        &self,
    ) -> Result<Option<u64>, HashAttemptReservationReject> {
        let mut limiter = self
            .limiter
            .lock()
            .map_err(|_| HashAttemptReservationReject::StateUnavailable)?;
        let now = Instant::now();
        let source = limiter.retry_after_without_cleanup(&self.source_key, now);
        let principal = limiter.retry_after_without_cleanup(&self.principal_key, now);
        Ok(match (source, principal) {
            (Some(left), Some(right)) => Some(left.max(right)),
            (Some(delay), None) | (None, Some(delay)) => Some(delay),
            (None, None) => None,
        })
    }

    /// 在同一 mutex 临界区提交两层结论。失败同时累加用户名和来源；成功清用户名，却只
    /// 取消来源 pending，使跨用户名失败预算无法被任何一次成功登录重置。
    /// Commit both outcomes in one mutex critical section. Failure increments both name and source;
    /// success clears the name but only cancels the source pending reservation, preserving the
    /// cross-name failure budget across every successful login.
    pub(super) fn finish(mut self, accepted: bool) -> bool {
        self.active = false;
        let Ok(mut limiter) = self.limiter.lock() else {
            return false;
        };
        let now = Instant::now();
        let principal_committed = limiter.finish_hash_attempt(&self.principal_key, accepted, now);
        let source_committed = if accepted {
            limiter.cancel_hash_attempt(&self.source_key, now)
        } else {
            limiter.finish_hash_attempt(&self.source_key, false, now)
        };
        principal_committed && source_committed
    }
}

impl Drop for PasswordRateReservation {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Ok(mut limiter) = self.limiter.lock() {
            let now = Instant::now();
            limiter.cancel_hash_attempt(&self.principal_key, now);
            limiter.cancel_hash_attempt(&self.source_key, now);
        }
    }
}

/// 准入失败分为调用方过量（映射 429）与服务容量/基础设施不可用（映射 503）；分类决定
/// HTTP 语义和 `Retry-After`，不能把内部饱和错误归咎于单个客户端。
/// Admission failures distinguish caller excess (HTTP 429) from service capacity/infrastructure
/// failure (HTTP 503); this classification controls HTTP semantics and `Retry-After`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PasswordHashAdmissionOutcome {
    GlobalQueueFull,
    SourceLimit,
    UsernameLimit,
    StateUnavailable,
    QueueTimeout,
    QueueClosed,
    BlockedAfterGlobalPermit { retry_after_secs: u64 },
    WorkerFailed,
    ConcurrentAttemptLimit,
    RateStateCapacity,
    RateStateUnavailable,
}

impl PasswordHashAdmissionOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::GlobalQueueFull => "global_queue_full",
            Self::SourceLimit => "source_limit",
            Self::UsernameLimit => "username_limit",
            Self::StateUnavailable => "state_unavailable",
            Self::QueueTimeout => "queue_timeout",
            Self::QueueClosed => "queue_closed",
            Self::BlockedAfterGlobalPermit { .. } => "blocked_after_global_permit",
            Self::WorkerFailed => "worker_failed",
            Self::ConcurrentAttemptLimit => "concurrent_attempt_limit",
            Self::RateStateCapacity => "rate_state_capacity",
            Self::RateStateUnavailable => "rate_state_unavailable",
        }
    }

    pub(super) const fn mapped_status(self) -> u16 {
        match self {
            Self::SourceLimit
            | Self::UsernameLimit
            | Self::BlockedAfterGlobalPermit { .. }
            | Self::ConcurrentAttemptLimit => 429,
            Self::GlobalQueueFull
            | Self::StateUnavailable
            | Self::QueueTimeout
            | Self::QueueClosed
            | Self::WorkerFailed
            | Self::RateStateCapacity
            | Self::RateStateUnavailable => 503,
        }
    }

    pub(super) const fn into_decision(self) -> AuthDecision {
        let retry_after_secs = match self {
            Self::BlockedAfterGlobalPermit { retry_after_secs } => retry_after_secs,
            _ => PASSWORD_VERIFY_RETRY_AFTER_SECS,
        };
        if self.mapped_status() == 429 {
            AuthDecision::RateLimited { retry_after_secs }
        } else {
            AuthDecision::ServiceUnavailable { retry_after_secs }
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct PasswordHashAdmissionCounters {
    pub(super) global_queue_full: u64,
    pub(super) source_limit: u64,
    pub(super) username_limit: u64,
    pub(super) state_unavailable: u64,
    pub(super) queue_timeout: u64,
    pub(super) queue_closed: u64,
    pub(super) blocked_after_global_permit: u64,
    pub(super) worker_failed: u64,
    pub(super) concurrent_attempt_limit: u64,
    pub(super) rate_state_capacity: u64,
    pub(super) rate_state_unavailable: u64,
}

impl PasswordHashAdmissionCounters {
    pub(super) fn increment(&mut self, outcome: PasswordHashAdmissionOutcome) -> u64 {
        let counter = match outcome {
            PasswordHashAdmissionOutcome::GlobalQueueFull => &mut self.global_queue_full,
            PasswordHashAdmissionOutcome::SourceLimit => &mut self.source_limit,
            PasswordHashAdmissionOutcome::UsernameLimit => &mut self.username_limit,
            PasswordHashAdmissionOutcome::StateUnavailable => &mut self.state_unavailable,
            PasswordHashAdmissionOutcome::QueueTimeout => &mut self.queue_timeout,
            PasswordHashAdmissionOutcome::QueueClosed => &mut self.queue_closed,
            PasswordHashAdmissionOutcome::BlockedAfterGlobalPermit { .. } => {
                &mut self.blocked_after_global_permit
            }
            PasswordHashAdmissionOutcome::WorkerFailed => &mut self.worker_failed,
            PasswordHashAdmissionOutcome::ConcurrentAttemptLimit => {
                &mut self.concurrent_attempt_limit
            }
            PasswordHashAdmissionOutcome::RateStateCapacity => &mut self.rate_state_capacity,
            PasswordHashAdmissionOutcome::RateStateUnavailable => &mut self.rate_state_unavailable,
        };
        *counter = counter.saturating_add(1);
        *counter
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct PasswordHashAdmissionSnapshot {
    pub(super) queued: usize,
    pub(super) active: usize,
    pub(super) in_flight: usize,
    pub(super) capacity: usize,
    pub(super) source_keys: usize,
    pub(super) username_keys: usize,
    pub(super) rejection_count: u64,
}

/// 哈希准入状态满足 `in_flight = queued + active`。全局、来源和用户名计数覆盖从预留到 worker
/// 退出的整个生命周期，防止排队请求绕过并发键预算；每个计数只由对应 guard 增减一次。
/// Hash admission maintains `in_flight = queued + active`. Global/source/username counts cover the
/// full reservation-to-worker-exit lifetime so queued work cannot bypass keyed limits; one guard
/// increments and decrements each count exactly once.
#[derive(Debug, Default)]
pub(super) struct PasswordHashAdmissionState {
    pub(super) in_flight: usize,
    pub(super) active: usize,
    pub(super) per_source: HashMap<Option<SourceIdentity>, usize>,
    pub(super) per_username: HashMap<[u8; 32], usize>,
    pub(super) counters: PasswordHashAdmissionCounters,
}

/// 两层有界准入：mutex 状态先限制总排队量及每来源/主体份额，semaphore 再限制真正执行的
/// 昂贵认证阻塞任务（密码哈希或持久 token 撤销 I/O）。先取得 map 预留可防止无限任务堆积
/// 在 semaphore 前。
/// Two bounded layers: mutex state caps queued work and per-source/subject shares, then the semaphore
/// caps active expensive-auth blocking jobs (password hashing or persistent token-revocation I/O).
/// Reserving map capacity first prevents an unbounded pile-up in front of the semaphore.
#[derive(Debug)]
pub(super) struct PasswordHashAdmission {
    pub(super) verify_limit: Arc<Semaphore>,
    pub(super) state: Mutex<PasswordHashAdmissionState>,
    pub(super) capacity: usize,
    pub(super) per_source_limit: usize,
    pub(super) per_username_limit: usize,
    pub(super) queue_timeout: Duration,
}

impl Default for PasswordHashAdmission {
    fn default() -> Self {
        Self {
            verify_limit: Arc::new(Semaphore::new(PASSWORD_VERIFY_CONCURRENCY)),
            state: Mutex::new(PasswordHashAdmissionState::default()),
            capacity: PASSWORD_VERIFY_ADMISSION_CAPACITY,
            per_source_limit: PASSWORD_VERIFY_PER_SOURCE,
            per_username_limit: PASSWORD_VERIFY_PER_USERNAME,
            queue_timeout: PASSWORD_VERIFY_QUEUE_TIMEOUT,
        }
    }
}

impl PasswordHashAdmission {
    pub(super) fn try_reserve(
        self: &Arc<Self>,
        source: Option<SourceIdentity>,
        username: &str,
    ) -> Result<PasswordHashAdmissionGuard, PasswordHashAdmissionOutcome> {
        self.try_reserve_namespaced(source, PASSWORD_ADMISSION_DOMAIN, username)
    }

    pub(super) fn try_reserve_namespaced(
        self: &Arc<Self>,
        source: Option<SourceIdentity>,
        domain: &[u8],
        username: &str,
    ) -> Result<PasswordHashAdmissionGuard, PasswordHashAdmissionOutcome> {
        // 中文：全局与来源计数跨协议共享，但主体计数带不可碰撞的协议域；撤销 token 洪泛
        // 不能耗尽同用户名的密码哈希或撤销写槽。
        // English: Global and source counts are shared across protocols, while subject counts use an
        // unambiguous protocol domain so revoked-token floods cannot consume password or mutation
        // slots for the same username.
        let mut digest = Sha256::new();
        digest.update(domain);
        digest.update(username.as_bytes());
        let username_hash: [u8; 32] = digest.finalize().into();
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => {
                let outcome = PasswordHashAdmissionOutcome::StateUnavailable;
                warn!(
                    "Expensive authentication admission rejected: admission_outcome={} mapped_status={} admission_state=poisoned",
                    outcome.as_str(),
                    outcome.mapped_status(),
                );
                return Err(outcome);
            }
        };
        let rejection = if state.in_flight >= self.capacity {
            Some(PasswordHashAdmissionOutcome::GlobalQueueFull)
        } else if state.per_source.get(&source).copied().unwrap_or_default()
            >= self.per_source_limit
        {
            Some(PasswordHashAdmissionOutcome::SourceLimit)
        } else if state
            .per_username
            .get(&username_hash)
            .copied()
            .unwrap_or_default()
            >= self.per_username_limit
        {
            Some(PasswordHashAdmissionOutcome::UsernameLimit)
        } else {
            None
        };
        if let Some(outcome) = rejection {
            let snapshot = admission_rejected(&mut state, self.capacity, outcome);
            drop(state);
            log_password_hash_admission_rejection(outcome, snapshot);
            return Err(outcome);
        }

        state.in_flight += 1;
        *state.per_source.entry(source).or_default() += 1;
        *state.per_username.entry(username_hash).or_default() += 1;
        Ok(PasswordHashAdmissionGuard {
            admission: self.clone(),
            source,
            username_hash,
            active: false,
            released: false,
        })
    }

    pub(super) fn reject_without_guard(&self, outcome: PasswordHashAdmissionOutcome) {
        let Ok(mut state) = self.state.lock() else {
            warn!(
                "Expensive authentication admission rejected: admission_outcome={} mapped_status={} admission_state=poisoned",
                outcome.as_str(),
                outcome.mapped_status(),
            );
            return;
        };
        let snapshot = admission_rejected(&mut state, self.capacity, outcome);
        drop(state);
        log_password_hash_admission_rejection(outcome, snapshot);
    }
}

pub(super) fn admission_rejected(
    state: &mut PasswordHashAdmissionState,
    capacity: usize,
    outcome: PasswordHashAdmissionOutcome,
) -> PasswordHashAdmissionSnapshot {
    let rejection_count = state.counters.increment(outcome);
    PasswordHashAdmissionSnapshot {
        queued: state.in_flight.saturating_sub(state.active),
        active: state.active,
        in_flight: state.in_flight,
        capacity,
        source_keys: state.per_source.len(),
        username_keys: state.per_username.len(),
        rejection_count,
    }
}

pub(super) fn log_password_hash_admission_rejection(
    outcome: PasswordHashAdmissionOutcome,
    snapshot: PasswordHashAdmissionSnapshot,
) {
    warn!(
        "Expensive authentication admission rejected: admission_outcome={} mapped_status={} queued={} active={} in_flight={} capacity={} source_keys={} username_keys={} rejection_count={}",
        outcome.as_str(),
        outcome.mapped_status(),
        snapshot.queued,
        snapshot.active,
        snapshot.in_flight,
        snapshot.capacity,
        snapshot.source_keys,
        snapshot.username_keys,
        snapshot.rejection_count,
    );
}

/// 一次 map 预留的唯一所有者。`try_reserve` 创建 queued guard，`started` 只把它转为 active；
/// 无论 future 在排队时取消、worker 启动失败还是正常退出，Drop 都恰好撤销一次全局和键计数。
/// Unique owner of one map reservation. `try_reserve` creates it queued and `started` transitions it
/// to active; Drop releases global and keyed counts exactly once on queued cancellation, worker-start
/// failure, or normal completion.
pub(super) struct PasswordHashAdmissionGuard {
    pub(super) admission: Arc<PasswordHashAdmission>,
    pub(super) source: Option<SourceIdentity>,
    pub(super) username_hash: [u8; 32],
    pub(super) active: bool,
    pub(super) released: bool,
}

impl PasswordHashAdmissionGuard {
    pub(super) fn started(
        &mut self,
    ) -> Result<PasswordHashAdmissionSnapshot, PasswordHashAdmissionOutcome> {
        let mut state = self
            .admission
            .state
            .lock()
            .map_err(|_| PasswordHashAdmissionOutcome::StateUnavailable)?;
        if !self.active {
            state.active += 1;
            self.active = true;
        }
        Ok(PasswordHashAdmissionSnapshot {
            queued: state.in_flight.saturating_sub(state.active),
            active: state.active,
            in_flight: state.in_flight,
            capacity: self.admission.capacity,
            source_keys: state.per_source.len(),
            username_keys: state.per_username.len(),
            rejection_count: 0,
        })
    }

    pub(super) fn reject(&self, outcome: PasswordHashAdmissionOutcome) {
        self.admission.reject_without_guard(outcome);
    }
}

impl Drop for PasswordHashAdmissionGuard {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        let Ok(mut state) = self.admission.state.lock() else {
            return;
        };
        state.in_flight = state.in_flight.saturating_sub(1);
        if self.active {
            state.active = state.active.saturating_sub(1);
        }
        decrement_count(&mut state.per_source, &self.source);
        decrement_count(&mut state.per_username, &self.username_hash);
    }
}

/// worker 可接管单层 token 撤销预留，或密码专用的来源+用户名双层预留。
/// A worker can take either one token-revocation reservation or the password-specific
/// source+claimed-name pair.
pub(super) enum WorkerRateReservation {
    Single(HashAttemptReservation),
    Password(PasswordRateReservation),
}

impl WorkerRateReservation {
    pub(super) fn finish(self, accepted: bool) -> bool {
        match self {
            Self::Single(reservation) => reservation.finish(accepted),
            Self::Password(reservation) => reservation.finish(accepted),
        }
    }
}

impl From<HashAttemptReservation> for WorkerRateReservation {
    fn from(reservation: HashAttemptReservation) -> Self {
        Self::Single(reservation)
    }
}

impl From<PasswordRateReservation> for WorkerRateReservation {
    fn from(reservation: PasswordRateReservation) -> Self {
        Self::Password(reservation)
    }
}

/// 生命周期必须覆盖真实阻塞认证 worker 的全部资源；不可克隆封装防止把暂定预留误留在可取消 async 栈上。
/// Resources that must outlive the real blocking authentication worker; one non-cloneable value
/// prevents reservations from remaining on the cancelable async stack.
/// `start` 原子记录 active 转移并接管 semaphore、准入 guard 与失败预留；`finish` 提交成功/失败
/// 结论，其他退出路径由 Drop 取消暂定失败且释放全部容量。
/// `start` records the active transition and takes ownership of the semaphore, admission guard, and
/// provisional failure reservation; `finish` commits the verdict, while all other exits cancel the
/// provisional failure and release capacity through Drop.
pub(super) struct PasswordHashWorkerLease {
    pub(super) _permit: OwnedSemaphorePermit,
    pub(super) _admission_guard: PasswordHashAdmissionGuard,
    pub(super) reservation: Option<WorkerRateReservation>,
}

impl PasswordHashWorkerLease {
    pub(super) fn start<R>(
        permit: OwnedSemaphorePermit,
        mut admission_guard: PasswordHashAdmissionGuard,
        reservation: R,
    ) -> Result<(Self, PasswordHashAdmissionSnapshot), PasswordHashAdmissionOutcome>
    where
        R: Into<WorkerRateReservation>,
    {
        let snapshot = admission_guard.started()?;
        Ok((
            Self {
                _permit: permit,
                _admission_guard: admission_guard,
                reservation: Some(reservation.into()),
            },
            snapshot,
        ))
    }

    pub(super) fn finish(mut self, accepted: bool) -> bool {
        self.reservation
            .take()
            .is_some_and(|reservation| reservation.finish(accepted))
    }
}
