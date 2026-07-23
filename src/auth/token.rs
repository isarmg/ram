//! 签名 Bearer token 的签发、校验与持久撤销。专用 HMAC-SHA256 绑定版本、主体、
//! audience、路径、时间和唯一标识；撤销状态只经持有事务锁的已验证属主描述符读取/替换；
//! 畸形、超限、回滚或容量耗尽均 fail closed，不能静默恢复已撤销 token。
//!
//! Signed bearer-token issuance, verification, and durable revocation.
//!
//! Security invariants:
//! - tokens are authenticated with a dedicated HMAC-SHA256 key and bind version,
//!   subject, audience, path, issued-at time, expiry, and a unique identifier;
//! - persistent revocation state is read and replaced only through verified,
//!   owner-controlled file descriptors while holding the transaction lock;
//! - malformed, oversized, rolled-back, or capacity-exhausted revocation state
//!   fails closed and cannot silently re-enable a revoked token.

use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct TokenClaims {
    pub(super) v: u8,
    pub(super) sub: String,
    pub(super) path: String,
    pub(super) aud: String,
    pub(super) iat: u64,
    pub(super) exp: u64,
    pub(super) jti: String,
}

#[derive(Debug)]
pub(super) enum TokenVerifyFailure {
    Invalid(anyhow::Error),
    Infrastructure(anyhow::Error),
}

impl fmt::Display for TokenVerifyFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(_) => f.write_str("invalid token"),
            Self::Infrastructure(_) => f.write_str("token revocation infrastructure unavailable"),
        }
    }
}

impl std::error::Error for TokenVerifyFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Invalid(err) | Self::Infrastructure(err) => Some(err.as_ref()),
        }
    }
}

#[derive(Debug)]
pub(crate) enum TokenRevokeError {
    Invalid(anyhow::Error),
    RateLimited { retry_after_secs: u64 },
    Infrastructure(anyhow::Error),
}

impl fmt::Display for TokenRevokeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(_) => f.write_str("invalid token revocation request"),
            Self::RateLimited { .. } => f.write_str("token revocation request rate limited"),
            Self::Infrastructure(_) => f.write_str("token revocation infrastructure unavailable"),
        }
    }
}

impl std::error::Error for TokenRevokeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Invalid(err) | Self::Infrastructure(err) => Some(err.as_ref()),
            Self::RateLimited { .. } => None,
        }
    }
}

/// 磁盘格式：`generation` 是跨进程事务的单调序号，`revoked` 保存 JTI 到到期时间的映射。
/// On-disk format: `generation` is the monotonic cross-process transaction number and `revoked`
/// maps each JTI to its expiry.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RevocationDocument {
    pub(super) version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) generation: Option<u64>,
    pub(super) revoked: HashMap<String, u64>,
}

/// 一次安全打开所得 inode 身份和变化标记；读取前后必须完全相等，缓存命中也以它为依据。
/// Inode identity and change markers from one secure open; they must match before/after a read and
/// are also the cache-coherency key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RevocationFingerprint {
    pub(super) device: u64,
    pub(super) inode: u64,
    pub(super) modified_secs: i64,
    pub(super) modified_nanos: i64,
    pub(super) changed_secs: i64,
    pub(super) changed_nanos: i64,
    pub(super) length: u64,
}

/// 已验证的内存视图。`fingerprint=None` 只表示无持久后端；有后端时 generation 与文件身份
/// 必须共同向前推进，单独改变任一项都不可受信。
/// Verified in-memory view. `fingerprint=None` is reserved for an in-memory backend; persistent
/// snapshots must advance generation and file identity together rather than trusting either alone.
#[derive(Debug)]
pub(super) struct RevocationSnapshot {
    pub(super) revocations: RevocationSet,
    pub(super) generation: u64,
    pub(super) fingerprint: Option<RevocationFingerprint>,
}

/// 启动时捕获的撤销状态及同级事务锁权限；路径只用于诊断，I/O 均相对于固定父目录。
/// Startup-captured revocation-state and sibling-lock authority. Paths are
/// diagnostic only; backend I/O is relative to the pinned parent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TokenRevocationCapabilities {
    pub(super) state: OutputPathIdentity,
    pub(super) lock: OutputPathIdentity,
}

impl TokenRevocationCapabilities {
    pub(crate) fn new(state: OutputPathIdentity, lock: OutputPathIdentity) -> Result<Self> {
        if state.parent() != lock.parent() {
            bail!("token revocation state and transaction lock must share one pinned parent");
        }
        let mut expected_lock_name = state.basename().to_os_string();
        expected_lock_name.push(".lock");
        if lock.basename() != expected_lock_name {
            bail!("token revocation transaction lock must be the state filename plus `.lock`");
        }
        Ok(Self { state, lock })
    }

    pub(crate) fn capture(state_path: &Path) -> Result<Self> {
        let state = OutputPathIdentity::capture(state_path).with_context(|| {
            format!(
                "failed to capture token revocation state capability `{}`",
                state_path.display()
            )
        })?;
        let mut lock_path = state_path.as_os_str().to_os_string();
        lock_path.push(".lock");
        let lock_path = PathBuf::from(lock_path);
        let lock = OutputPathIdentity::capture(&lock_path).with_context(|| {
            format!(
                "failed to capture token revocation lock capability `{}`",
                lock_path.display()
            )
        })?;
        Self::new(state, lock)
    }

    pub(crate) fn state(&self) -> &OutputPathIdentity {
        &self.state
    }

    pub(crate) fn lock(&self) -> &OutputPathIdentity {
        &self.lock
    }

    /// 把两个输出期望绑定到原固定父目录下当前可见名称，服务初始化前立即消费此刷新视图。
    /// Bind output expectations to names currently visible below the original pinned parent immediately before initialization.
    pub(crate) fn with_current_expectations(&self) -> Result<Self> {
        Self::new(
            self.state.with_current_expectation()?,
            self.lock.with_current_expectation()?,
        )
    }
}

/// 固定父目录与稳定 basename；事务操作绝不重新打开配置父路径。
/// A pinned parent plus stable basenames; no transaction reopens the configured parent pathname.
pub(super) struct RevocationBackend {
    pub(super) path: PathBuf,
    pub(super) capabilities: TokenRevocationCapabilities,
    pub(super) parent: fs::File,
    pub(super) state_name: OsString,
    pub(super) lock_name: OsString,
    pub(super) lock_identity: ObjectIdentity,
    #[cfg(test)]
    pub(super) test_io: RevocationIoTestHooks,
}

pub(super) struct TokenState {
    pub(super) secret: [u8; TOKEN_SECRET_BYTES],
    pub(super) audience: String,
    pub(super) ttl_secs: u64,
    pub(super) revocations: Mutex<RevocationSnapshot>,
    pub(super) revocation_backend: Option<RevocationBackend>,
    /// 持久化或锁语义一旦不明确，旧缓存不得再授权 token，必须干净重启才能重建可信快照。
    /// Once persistence/locking is ambiguous, cached state cannot authorize again; a clean restart must re-establish trust.
    pub(super) revocation_degraded: AtomicBool,
    /// 中文：仅供测试统计实际提交到阻塞池的持久撤销校验，证明坏 MAC 不会占用该队列。
    /// English: Test-only count of persistent revocation checks submitted to the blocking pool;
    /// it proves that bad MACs never consume that queue.
    #[cfg(test)]
    pub(super) revocation_workers_started: std::sync::atomic::AtomicUsize,
    /// 中文：仅供测试统计实际提交的持久撤销写 worker。
    /// English: Test-only count of submitted persistent revocation mutation workers.
    #[cfg(test)]
    pub(super) revocation_mutation_workers_started: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
#[derive(Default)]
pub(super) struct RevocationIoTestHooks {
    pub(super) reload: Mutex<Option<Arc<RevocationIoPause>>>,
    pub(super) after_reload: Mutex<Option<Arc<RevocationIoPause>>>,
    pub(super) persist: Mutex<Option<Arc<RevocationIoPause>>>,
}

#[cfg(test)]
pub(super) struct RevocationIoPause {
    pub(super) armed: AtomicBool,
    pub(super) entered: std::sync::Barrier,
    pub(super) release: std::sync::Barrier,
}

#[cfg(test)]
impl RevocationIoPause {
    pub(super) fn new() -> Self {
        Self {
            armed: AtomicBool::new(true),
            entered: std::sync::Barrier::new(2),
            release: std::sync::Barrier::new(2),
        }
    }

    pub(super) fn pause_once(&self) {
        if self.armed.swap(false, Ordering::AcqRel) {
            self.entered.wait();
            self.release.wait();
        }
    }
}

#[cfg(test)]
impl RevocationBackend {
    pub(super) fn pause_reload_for_test(&self) {
        let pause = self
            .test_io
            .reload
            .lock()
            .expect("revocation reload test hook must remain available")
            .clone();
        if let Some(pause) = pause {
            pause.pause_once();
        }
    }

    pub(super) fn pause_persist_for_test(&self) {
        let pause = self
            .test_io
            .persist
            .lock()
            .expect("revocation persistence test hook must remain available")
            .clone();
        if let Some(pause) = pause {
            pause.pause_once();
        }
    }

    pub(super) fn pause_after_reload_for_test(&self) {
        let pause = self
            .test_io
            .after_reload
            .lock()
            .expect("post-reload revocation test hook must remain available")
            .clone();
        if let Some(pause) = pause {
            pause.pause_once();
        }
    }
}

/// 带过期堆的撤销 token ID；通常 O(1)，刚过期条目各清理一次，避免每请求扫描 65k 映射。
/// Revoked IDs with an expiry heap: verification is normally O(1), and each expired entry is removed once.
#[derive(Debug)]
pub(super) struct RevocationSet {
    pub(super) entries: HashMap<String, u64>,
    pub(super) expirations: BinaryHeap<Reverse<(u64, String)>>,
}

impl RevocationSet {
    pub(super) fn new(entries: HashMap<String, u64>) -> Self {
        let expirations = entries
            .iter()
            .map(|(jti, expires_at)| Reverse((*expires_at, jti.clone())))
            .collect();
        Self {
            entries,
            expirations,
        }
    }

    pub(super) fn prune(&mut self, now_secs: u64) {
        while let Some(Reverse((expires_at, _))) = self.expirations.peek() {
            if *expires_at > now_secs {
                break;
            }
            let Reverse((expires_at, jti)) = self
                .expirations
                .pop()
                .expect("peeked revocation expiry must exist");
            if self.entries.get(&jti) == Some(&expires_at) {
                self.entries.remove(&jti);
            }
        }
    }

    pub(super) fn contains(&mut self, jti: &str, now_secs: u64) -> bool {
        self.prune(now_secs);
        self.entries.contains_key(jti)
    }

    pub(super) fn insert(&mut self, jti: String, expires_at: u64) {
        if self.entries.get(&jti) == Some(&expires_at) {
            return;
        }
        self.entries.insert(jti.clone(), expires_at);
        self.expirations.push(Reverse((expires_at, jti)));
    }
}

impl fmt::Debug for TokenState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenState")
            .field("secret", &"***")
            .field("audience", &self.audience)
            .field("ttl_secs", &self.ttl_secs)
            .field(
                "revocation_file",
                &self
                    .revocation_backend
                    .as_ref()
                    .map(|backend| &backend.path),
            )
            .field(
                "revocation_degraded",
                &self.revocation_degraded.load(Ordering::Acquire),
            )
            .finish_non_exhaustive()
    }
}

impl TokenState {
    pub(super) fn new(
        secret: Option<&[u8]>,
        audience: Option<&str>,
        ttl_secs: u64,
        revocation_file: Option<PathBuf>,
    ) -> Result<Self> {
        let revocation_capabilities = revocation_file
            .as_deref()
            .map(TokenRevocationCapabilities::capture)
            .transpose()?;
        Self::new_with_capabilities(secret, audience, ttl_secs, revocation_capabilities)
    }

    pub(super) fn new_with_capabilities(
        secret: Option<&[u8]>,
        audience: Option<&str>,
        ttl_secs: u64,
        revocation_capabilities: Option<TokenRevocationCapabilities>,
    ) -> Result<Self> {
        let secret = match validated_token_secret(secret)? {
            Some(secret) => secret,
            None => random_bytes::<TOKEN_SECRET_BYTES>()?,
        };
        let audience = match validated_token_audience(audience)? {
            Some(audience) => audience,
            None => hex::encode(random_bytes::<16>()?),
        };
        validate_token_ttl(ttl_secs)?;
        let now = unix_now()?.as_secs();
        let (revocation_backend, mut snapshot) = match revocation_capabilities {
            Some(capabilities) => {
                let (backend, snapshot) = open_revocation_backend(capabilities)?;
                (Some(backend), snapshot)
            }
            None => (
                None,
                RevocationSnapshot {
                    revocations: RevocationSet::new(HashMap::new()),
                    generation: 0,
                    fingerprint: None,
                },
            ),
        };
        snapshot.revocations.prune(now);
        Ok(Self {
            secret,
            audience,
            ttl_secs,
            revocations: Mutex::new(snapshot),
            revocation_backend,
            revocation_degraded: AtomicBool::new(false),
            #[cfg(test)]
            revocation_workers_started: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            revocation_mutation_workers_started: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    pub(super) fn verify_revocation_backend_binding(
        &self,
        expected: Option<&TokenRevocationCapabilities>,
    ) -> Result<()> {
        match (self.revocation_backend.as_ref(), expected) {
            (None, None) => Ok(()),
            (Some(_), None) => {
                bail!("token revocation backend exists without a startup capability")
            }
            (None, Some(_)) => {
                bail!("token revocation startup capability has no configured backend")
            }
            (Some(backend), Some(expected)) => {
                let now = unix_now()?.as_secs();
                let result = with_revocation_lock(backend, RevocationLockMode::Shared, || {
                    backend.verify_binding(expected)?;
                    // 中文：状态名刻意不绑定单一 inode（每次持久更新发布新 inode）；持稳定事务锁
                    // 重新解析当前对象，把启动快照推进到最新单调 generation。
                    // English: The state name is replaceable by design. Under
                    // the stable lock, reparse it and advance to the newest monotonic generation.
                    let mut disk = load_revocation_snapshot(backend)?;
                    let mut cached = self
                        .revocations
                        .lock()
                        .map_err(|_| anyhow!("token revocation state is unavailable"))?;
                    validate_revocation_transition(&cached, &disk, now)?;
                    disk.revocations.prune(now);
                    *cached = disk;
                    Ok(())
                });
                if result.is_err() {
                    self.revocation_degraded.store(true, Ordering::Release);
                }
                result
            }
        }
    }

    pub(super) fn sign(&self, claims: &TokenClaims) -> Result<String> {
        let payload = serde_json::to_vec(claims)?;
        let payload = URL_SAFE_NO_PAD.encode(payload);
        let mut mac = token_mac(&self.secret);
        mac.update(payload.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        Ok(format!("{payload}.{signature}"))
    }

    pub(super) fn verify(
        &self,
        token: &str,
        now_secs: u64,
        check_revoked: bool,
    ) -> std::result::Result<TokenClaims, TokenVerifyFailure> {
        let claims = self
            .decode_signed_claims(token)
            .and_then(|claims| {
                self.validate_claims(&claims, now_secs)?;
                Ok(claims)
            })
            .map_err(TokenVerifyFailure::Invalid)?;
        if check_revoked {
            match self.is_revoked(&claims.jti, now_secs) {
                Ok(true) => {
                    return Err(TokenVerifyFailure::Invalid(anyhow!("Token revoked")));
                }
                Ok(false) => {}
                Err(err) => return Err(TokenVerifyFailure::Infrastructure(err)),
            }
        }
        Ok(claims)
    }

    /// 中文：严格限制 token 大小，先验证 HMAC，再解码攻击者不可伪造的 claims；本阶段不访问
    /// 撤销文件，适合直接在 Tokio worker 上执行。
    /// English: Bound the token, verify its HMAC before decoding authenticated claims, and perform
    /// no revocation I/O, so this stage is safe to run directly on a Tokio worker.
    pub(super) fn decode_signed_claims(&self, token: &str) -> Result<TokenClaims> {
        if token.len() > 8192 {
            bail!("Invalid token");
        }
        let (payload, signature) = token
            .split_once('.')
            .ok_or_else(|| anyhow!("Invalid token"))?;
        if payload.is_empty() || signature.is_empty() || signature.contains('.') {
            bail!("Invalid token");
        }
        let signature = URL_SAFE_NO_PAD.decode(signature)?;
        let mut mac = token_mac(&self.secret);
        mac.update(payload.as_bytes());
        mac.verify_slice(&signature)
            .map_err(|_| anyhow!("Invalid token"))?;
        let raw = URL_SAFE_NO_PAD.decode(payload)?;
        serde_json::from_slice(&raw).map_err(Into::into)
    }

    /// 中文：校验已通过 MAC 且成功解码的 claims；拆分该步骤使调用方能在语义失败时仍用
    /// 可信 `sub` 选择主体限流桶。
    /// English: Validate MAC-authenticated, decoded claims separately so callers can still select
    /// the trusted subject rate bucket when semantic validation fails.
    pub(super) fn validate_claims(&self, claims: &TokenClaims, now_secs: u64) -> Result<()> {
        if claims.v != TOKEN_VERSION
            || claims.aud != self.audience
            || claims.sub.is_empty()
            || claims.path.len() > 4096
            || claims.jti.len() != 32
            || !claims.jti.bytes().all(|byte| byte.is_ascii_hexdigit())
            || claims.iat > claims.exp
            || now_secs >= claims.exp
        {
            bail!("Invalid or expired token");
        }
        Ok(())
    }

    pub(super) fn revoke(&self, jti: String, expires_at: u64, now_secs: u64) -> Result<()> {
        self.revoke_with_fault(jti, expires_at, now_secs, RevocationPersistFault::None)
    }

    /// 在排他跨进程锁内完成“重载 → 防回滚校验 → 幂等检查 → 生成新代 → 原子持久化 → 更新缓存”。
    /// 已存在同一未过期 JTI 且 expiry 不短于请求时只推进可信缓存，不重写文件/generation。
    /// 缓存只在无需写或 rename 与父目录 fsync 均成功后提交；任何会使锁或持久性语义不明确
    /// 的错误都会先进入 fail-closed 降级态，后续校验必须重启后才能恢复。
    /// Under the exclusive cross-process lock, reload, validate anti-rollback, check idempotence,
    /// advance generation, persist atomically, then commit cache. An existing unexpired JTI whose
    /// expiry is at least the request only advances the trusted cache and does not rewrite/generate.
    /// Cache changes only on that no-write path or after rename and parent fsync; locking/durability
    /// ambiguity enters fail-closed degraded mode until restart.
    pub(super) fn revoke_with_fault(
        &self,
        jti: String,
        expires_at: u64,
        now_secs: u64,
        persist_fault: RevocationPersistFault,
    ) -> Result<()> {
        if self.revocation_degraded.load(Ordering::Acquire) {
            bail!("token revocation state is degraded; restart required");
        }
        let Some(backend) = self.revocation_backend.as_ref() else {
            let mut snapshot = self
                .revocations
                .lock()
                .map_err(|_| anyhow!("token revocation state is unavailable"))?;
            snapshot.revocations.prune(now_secs);
            if expires_at > now_secs {
                if snapshot.revocations.entries.len() >= TOKEN_REVOCATION_CAPACITY
                    && !snapshot.revocations.entries.contains_key(&jti)
                {
                    return Err(anyhow::Error::new(RevocationCapacityExhausted));
                }
                snapshot.revocations.insert(jti, expires_at);
            }
            return Ok(());
        };

        let result = with_revocation_lock(backend, RevocationLockMode::Exclusive, || {
            let transaction = (|| {
                if self.revocation_degraded.load(Ordering::Acquire) {
                    bail!("token revocation state is degraded; restart required");
                }
                // 中文：持跨进程事务锁重载，避免两个实例基于同一旧 generation 发布快照。
                // English: Reload under the cross-process lock so two instances cannot publish from the same stale generation.
                let mut disk = load_revocation_snapshot(backend)?;
                {
                    let cached = self
                        .revocations
                        .lock()
                        .map_err(|_| anyhow!("token revocation state is unavailable"))?;
                    validate_revocation_transition(&cached, &disk, now_secs)?;
                }
                disk.revocations.prune(now_secs);
                if disk
                    .revocations
                    .entries
                    .get(&jti)
                    .is_some_and(|existing_expiry| *existing_expiry >= expires_at)
                {
                    // 中文：反回滚校验已经通过且仍持独占锁；把可能更新的磁盘快照提交到缓存，
                    // 但重复撤销无需 generation、序列化、fsync 或 rename。
                    // English: Anti-rollback validation passed under the exclusive lock. Commit a
                    // possibly newer disk snapshot to cache, but duplicate revocation needs no
                    // generation, serialization, fsync, or rename.
                    let mut cached = self
                        .revocations
                        .lock()
                        .map_err(|_| anyhow!("token revocation state is unavailable"))?;
                    *cached = disk;
                    return Ok(());
                }
                if expires_at > now_secs {
                    if disk.revocations.entries.len() >= TOKEN_REVOCATION_CAPACITY
                        && !disk.revocations.entries.contains_key(&jti)
                    {
                        return Err(anyhow::Error::new(RevocationCapacityExhausted));
                    }
                    disk.revocations.insert(jti, expires_at);
                }
                let generation = disk
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("token revocation generation exhausted"))?;
                let fingerprint = persist_revocations(
                    backend,
                    generation,
                    &disk.revocations.entries,
                    persist_fault,
                )?;
                // 中文：只有文件同步、原子发布与父目录同步全部成功后才修改缓存；序列化与 I/O
                // 不持缓存 mutex。
                // English: Commit cache only after file sync, atomic publish,
                // and parent sync; serialization/I/O occur outside the cache mutex.
                let mut cached = self
                    .revocations
                    .lock()
                    .map_err(|_| anyhow!("token revocation state is unavailable"))?;
                *cached = RevocationSnapshot {
                    revocations: disk.revocations,
                    generation,
                    fingerprint: Some(fingerprint),
                };
                Ok(())
            })();
            if transaction
                .as_ref()
                .is_err_and(revocation_failure_requires_degraded)
            {
                // 中文：释放排他 flock 前发布 fail-closed 状态，防止等待校验器落入错误到降级的间隙。
                // English: Publish degraded fail-closed state before unlocking so no verifier enters an authorization gap.
                self.revocation_degraded.store(true, Ordering::Release);
            }
            transaction
        });
        if result
            .as_ref()
            .is_err_and(revocation_failure_requires_degraded)
        {
            // 中文：同时覆盖发布前失败与 rename 后持久性不明；比内存回滚更严格，保证旧缓存不能授权。
            // English: Cover both pre-publish failure and post-rename ambiguity; this is stricter than memory rollback and disables old-cache authorization.
            self.revocation_degraded.store(true, Ordering::Release);
        }
        result
    }

    /// 持共享事务锁校验 JTI：fingerprint 相同走缓存快路径，否则在不持缓存 mutex 时重读并验证
    /// generation。解锁后的最终 degraded Acquire 检查会压制与失败 reader 重叠的在途成功，
    /// 因而旧快照不能在故障窗口中授权。
    /// Check a JTI under a shared transaction lock. Matching fingerprints use the cache fast path;
    /// otherwise the file is parsed without holding the cache mutex and its generation is validated.
    /// A final degraded Acquire check suppresses in-flight success overlapping a failed reader.
    pub(super) fn is_revoked(&self, jti: &str, now_secs: u64) -> Result<bool> {
        if self.revocation_degraded.load(Ordering::Acquire) {
            bail!("token revocation state is degraded; restart required");
        }
        let Some(backend) = self.revocation_backend.as_ref() else {
            return self
                .revocations
                .lock()
                .map_err(|_| anyhow!("token revocation state is unavailable"))
                .map(|mut snapshot| snapshot.revocations.contains(jti, now_secs));
        };
        let result = with_revocation_lock(backend, RevocationLockMode::Shared, || {
            let transaction = (|| {
                if self.revocation_degraded.load(Ordering::Acquire) {
                    bail!("token revocation state is degraded; restart required");
                }
                let (file, fingerprint) = open_revocation_state(backend)?;
                {
                    let mut cached = self
                        .revocations
                        .lock()
                        .map_err(|_| anyhow!("token revocation state is unavailable"))?;
                    if cached.fingerprint == Some(fingerprint) {
                        return Ok(cached.revocations.contains(jti, now_secs));
                    }
                }

                // 中文：持共享事务锁解析但不持缓存 mutex；独立共享 flock description 允许无关校验并行。
                // English: Parse under the shared transaction lock, never the cache mutex; independent flock descriptions preserve validation concurrency.
                #[cfg(test)]
                backend.pause_reload_for_test();
                let disk = parse_revocation_file(file, fingerprint)?;
                let revoked = {
                    let mut cached = self
                        .revocations
                        .lock()
                        .map_err(|_| anyhow!("token revocation state is unavailable"))?;
                    validate_revocation_transition(&cached, &disk, now_secs)?;
                    *cached = disk;
                    cached.revocations.contains(jti, now_secs)
                };
                // 中文：测试钩子刻意位于解析、转换校验、缓存提交与解锁之后，用来证明重叠 reader
                // 失败时最终降级检查能压制原本成功的在途授权。
                // English: The post-commit test hook proves the final degraded
                // check suppresses an in-flight success when an overlapping reader fails.
                #[cfg(test)]
                backend.pause_after_reload_for_test();
                Ok(revoked)
            })();
            if transaction.is_err() {
                // 中文：共享事务会重叠；释放 flock 前标记降级，使所有 peer 的最终 Acquire 检查压制旧授权。
                // English: Shared transactions overlap; mark degraded before unlock so every peer's final Acquire check suppresses stale success.
                self.revocation_degraded.store(true, Ordering::Release);
            }
            transaction
        });
        if result.is_err() {
            self.revocation_degraded.store(true, Ordering::Release);
        }
        match result {
            Ok(_) if self.revocation_degraded.load(Ordering::Acquire) => {
                bail!("token revocation state is degraded; restart required")
            }
            result => result,
        }
    }
}

type HmacSha256 = Hmac<Sha256>;

pub(super) fn token_mac(secret: &[u8]) -> HmacSha256 {
    HmacSha256::new_from_slice(secret).expect("HMAC accepts keys of any length")
}

pub(super) fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut output = [0u8; N];
    getrandom::fill(&mut output).map_err(|err| anyhow!("OS random generator failed: {err}"))?;
    Ok(output)
}

pub(super) fn normalize_token_secret(secret: &[u8]) -> Result<[u8; TOKEN_SECRET_BYTES]> {
    if secret.len() < TOKEN_SECRET_BYTES {
        bail!("token secret must contain at least 32 bytes");
    }
    // 中文：始终把配置材料归约为固定大小、均匀分布的 HMAC key，同时避免在内存保留原 secret 字符串。
    // English: Reduce configured material to one fixed-size uniform HMAC key and avoid retaining the original secret string.
    Ok(Sha256::digest(secret).into())
}

pub(super) fn validated_token_secret(
    secret: Option<&[u8]>,
) -> Result<Option<[u8; TOKEN_SECRET_BYTES]>> {
    secret.map(normalize_token_secret).transpose()
}

pub(super) fn validated_token_audience(audience: Option<&str>) -> Result<Option<String>> {
    match audience {
        Some("") => bail!("token audience must not be empty"),
        Some(value) if value.len() > 128 => bail!("token audience is too long"),
        Some(value) => Ok(Some(value.to_string())),
        None => Ok(None),
    }
}

pub(super) fn validate_token_ttl(ttl_secs: u64) -> Result<()> {
    if ttl_secs == 0 || ttl_secs > 7 * 24 * 60 * 60 {
        bail!("token TTL must be between 1 second and 7 days");
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RevocationLockMode {
    Shared,
    Exclusive,
}

/// 单测使用的确定性持久化切点；生产始终传 None，注入位于事务原语以直接测试发布前后保证。
/// Deterministic persistence cut points for tests; production passes None, keeping pre/post-publication guarantees directly testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(super) enum RevocationPersistFault {
    None,
    BeforeWrite,
    PartialWrite,
    FileSync,
    Rename,
    AfterRename,
    ParentSync,
    AfterParentSync,
}

#[derive(Debug)]
pub(super) struct RevocationCapacityExhausted;

impl fmt::Display for RevocationCapacityExhausted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("token revocation capacity exhausted")
    }
}

impl std::error::Error for RevocationCapacityExhausted {}

pub(super) fn revocation_failure_requires_degraded(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<RevocationCapacityExhausted>()
        .is_none()
}

pub(super) struct HeldRevocationLock {
    pub(super) file: fs::File,
    pub(super) held: bool,
}

impl HeldRevocationLock {
    pub(super) fn release(mut self) -> Result<()> {
        flock(&self.file, FlockOperation::Unlock)
            .context("failed to unlock token revocation transaction")?;
        self.held = false;
        Ok(())
    }
}

impl Drop for HeldRevocationLock {
    fn drop(&mut self) {
        if self.held {
            let _ = flock(&self.file, FlockOperation::Unlock);
        }
    }
}

pub(super) fn with_revocation_lock<T>(
    backend: &RevocationBackend,
    mode: RevocationLockMode,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    // 中文：flock 附着于 open-file description；每事务重新打开启动绑定的锁 inode，而非在
    // 进程 mutex 后共享 description。独立共享 description 允许校验重叠，排他撤销仍在内核冲突。
    // English: Reopen the startup-bound lock inode per transaction. Independent
    // shared descriptions overlap, while exclusive revocation still supplies one cross-process linearization point.
    let lock_file = open_revocation_transaction_lock(backend)?;
    let operation_kind = match mode {
        RevocationLockMode::Shared => FlockOperation::LockShared,
        RevocationLockMode::Exclusive => FlockOperation::LockExclusive,
    };
    flock(&lock_file, operation_kind)
        .with_context(|| format!("failed to lock {}", backend.path.display()))?;
    let held = HeldRevocationLock {
        file: lock_file,
        held: true,
    };
    let result = validate_revocation_lock_identity(backend, &held.file).and_then(|()| operation());
    let final_identity = validate_revocation_lock_identity(backend, &held.file);
    let unlock = held.release();
    // 中文：操作后锁校验与解锁属于事务完整性检查，即使操作返回容量耗尽等业务错误也必须优先；
    // 否则替换的锁 inode 会被误判无害并继续使用脑裂后端。
    // English: Post-operation lock validation/unlock outrank business errors;
    // otherwise a replaced lock inode could be mistaken for harmless split-brain state.
    match (final_identity, unlock, result) {
        (Err(err), _, _) => Err(err),
        (Ok(()), Err(err), _) => Err(err),
        (Ok(()), Ok(()), result) => result,
    }
}

pub(super) fn open_revocation_transaction_lock(backend: &RevocationBackend) -> Result<fs::File> {
    let file: fs::File = rustix_fs::openat(
        &backend.parent,
        &backend.lock_name,
        OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .with_context(|| {
        format!(
            "failed to securely open token revocation transaction lock {}.lock",
            backend.path.display()
        )
    })?
    .into();
    let metadata = file.metadata()?;
    validate_revocation_file_metadata(&metadata, false)
        .context("token revocation transaction lock failed trusted-file validation")?;
    if ObjectIdentity::from_metadata(&metadata) != backend.lock_identity {
        bail!("token revocation transaction lock changed object identity");
    }
    Ok(file)
}

pub(super) fn validate_revocation_lock_identity(
    backend: &RevocationBackend,
    lock_file: &fs::File,
) -> Result<()> {
    let held = lock_file.metadata()?;
    validate_revocation_file_metadata(&held, false)
        .context("held token revocation transaction lock is no longer trusted")?;
    if ObjectIdentity::from_metadata(&held) != backend.lock_identity {
        bail!("held token revocation transaction lock changed object identity");
    }
    let linked = rustix_fs::statat(
        &backend.parent,
        &backend.lock_name,
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .context("token revocation transaction lock path is unavailable")?;
    if linked.st_dev != held.dev()
        || linked.st_ino != held.ino()
        || linked.st_nlink != 1
        || rustix_fs::FileType::from_raw_mode(linked.st_mode) != rustix_fs::FileType::RegularFile
        || linked.st_mode & 0o022 != 0
        || !is_trusted_file_owner(linked.st_uid)
    {
        bail!("token revocation transaction lock path no longer names the trusted held inode");
    }
    Ok(())
}

impl RevocationBackend {
    pub(super) fn verify_binding(&self, expected: &TokenRevocationCapabilities) -> Result<()> {
        if expected.state.parent() != self.capabilities.state.parent()
            || expected.lock.parent() != self.capabilities.lock.parent()
            || expected.state.basename() != self.state_name
            || expected.lock.basename() != self.lock_name
        {
            bail!("token revocation output location changed after capability capture");
        }

        if expected.lock.expected_object() != Some(self.lock_identity) {
            bail!("token revocation transaction lock is not bound to the backend-held inode");
        }
        Ok(())
    }
}

pub(super) fn open_revocation_backend(
    capabilities: TokenRevocationCapabilities,
) -> Result<(RevocationBackend, RevocationSnapshot)> {
    let path = capabilities.state.display_path();
    let state_name = capabilities.state.basename().to_os_string();
    let lock_name = capabilities.lock.basename().to_os_string();
    let parent = capabilities.state.open_parent_pinned().with_context(|| {
        format!(
            "failed to reopen pinned token revocation directory for {}",
            path.display()
        )
    })?;
    if ObjectIdentity::from_metadata(&parent.metadata()?) != capabilities.state.parent().object() {
        bail!("pinned token revocation parent changed object identity");
    }
    let (_lock_file, lock_identity) =
        open_revocation_lock_file(&parent, &lock_name, capabilities.lock.expected_object())
            .with_context(|| {
                format!(
                    "failed to securely open token revocation transaction lock {}.lock",
                    path.display()
                )
            })?;
    let backend = RevocationBackend {
        path,
        capabilities,
        parent,
        state_name,
        lock_name,
        lock_identity,
        #[cfg(test)]
        test_io: RevocationIoTestHooks::default(),
    };
    let snapshot = with_revocation_lock(&backend, RevocationLockMode::Exclusive, || {
        match try_open_revocation_state(&backend)? {
            Some((file, fingerprint)) => parse_revocation_file(file, fingerprint),
            None => {
                // 中文：首次启动建立持久空 V2 文件；此后缺失即损坏/删除，校验 fail closed 而不信旧缓存。
                // English: Establish a durable empty V2 file at first startup; later absence is corruption and fails closed.
                let entries = HashMap::new();
                let fingerprint =
                    persist_revocations(&backend, 1, &entries, RevocationPersistFault::None)?;
                Ok(RevocationSnapshot {
                    revocations: RevocationSet::new(entries),
                    generation: 1,
                    fingerprint: Some(fingerprint),
                })
            }
        }
    })?;
    Ok((backend, snapshot))
}

pub(super) fn validate_opened_revocation_lock(
    file: fs::File,
    expected: Option<ObjectIdentity>,
) -> Result<(fs::File, ObjectIdentity)> {
    let metadata = file.metadata()?;
    validate_revocation_file_metadata(&metadata, false)
        .context("token revocation transaction lock failed trusted-file validation")?;
    let identity = ObjectIdentity::from_metadata(&metadata);
    if expected.is_some_and(|expected| expected != identity) {
        bail!("token revocation transaction lock changed after capability capture");
    }
    Ok((file, identity))
}

pub(super) fn open_revocation_lock_file(
    parent: &fs::File,
    name: &OsString,
    expected: Option<ObjectIdentity>,
) -> Result<(fs::File, ObjectIdentity)> {
    if let Some(expected) = expected {
        let file: fs::File = rustix_fs::openat(
            parent,
            name,
            OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )?
        .into();
        return validate_opened_revocation_lock(file, Some(expected));
    }

    loop {
        match rustix_fs::openat(
            parent,
            name,
            OFlags::RDWR
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::CLOEXEC
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(file) => {
                let file: fs::File = file.into();
                // 中文：open(2) mode 会被 umask 过滤，暴露前通过可信 fd 修复新 inode。
                // English: `open(2)` mode is filtered by umask; repair the new inode through its trusted fd before exposure.
                rustix_fs::fchmod(&file, Mode::from_raw_mode(0o600))?;
                return validate_opened_revocation_lock(file, None);
            }
            Err(rustix::io::Errno::EXIST) => {}
            Err(err) => return Err(err.into()),
        }
        // 中文：能力记录了缺失，故先尝试 CREATE|EXCL；EEXIST 可能来自合法并发实例，
        // 只能接受安全打开且可信的 inode 并把后端绑定到它。
        // English: Recorded absence requires CREATE|EXCL first. On competing
        // EEXIST, accept only a securely opened trusted inode and bind the backend to it.
        match rustix_fs::openat(
            parent,
            name,
            OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(file) => return validate_opened_revocation_lock(file.into(), None),
            Err(rustix::io::Errno::NOENT) => continue,
            Err(err) => return Err(err.into()),
        }
    }
}

pub(super) fn validate_revocation_file_metadata(
    metadata: &fs::Metadata,
    enforce_size: bool,
) -> Result<()> {
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || !is_trusted_file_owner(metadata.uid())
    {
        bail!("expected a trusted regular file with one link and no group/world write access");
    }
    if enforce_size && metadata.len() > TOKEN_REVOCATION_FILE_MAX_BYTES {
        bail!("token revocation state exceeds the 8 MiB size limit");
    }
    Ok(())
}

pub(super) fn revocation_fingerprint(metadata: &fs::Metadata) -> RevocationFingerprint {
    RevocationFingerprint {
        device: metadata.dev(),
        inode: metadata.ino(),
        modified_secs: metadata.mtime(),
        modified_nanos: metadata.mtime_nsec(),
        changed_secs: metadata.ctime(),
        changed_nanos: metadata.ctime_nsec(),
        length: metadata.len(),
    }
}

pub(super) fn try_open_revocation_state(
    backend: &RevocationBackend,
) -> Result<Option<(fs::File, RevocationFingerprint)>> {
    let file: fs::File = match rustix_fs::openat(
        &backend.parent,
        &backend.state_name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(file) => file.into(),
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(err) => {
            return Err(anyhow::Error::from(err)).with_context(|| {
                format!(
                    "failed to securely open token revocation state {}",
                    backend.path.display()
                )
            });
        }
    };
    let metadata = file.metadata()?;
    validate_revocation_file_metadata(&metadata, true)
        .context("token revocation state failed trusted-file validation")?;
    Ok(Some((file, revocation_fingerprint(&metadata))))
}

pub(super) fn open_revocation_state(
    backend: &RevocationBackend,
) -> Result<(fs::File, RevocationFingerprint)> {
    try_open_revocation_state(backend)?.ok_or_else(|| {
        anyhow!(
            "token revocation state disappeared: {}",
            backend.path.display()
        )
    })
}

pub(super) fn load_revocation_snapshot(backend: &RevocationBackend) -> Result<RevocationSnapshot> {
    let (file, fingerprint) = open_revocation_state(backend)?;
    parse_revocation_file(file, fingerprint)
}

/// 从已安全打开的描述符限长读取；读取后重验属主、类型、长度和 inode 时间指纹，拒绝读期间
/// 发生的替换或修改，再解析严格版本化文档。调用者必须已经持有相应事务锁。
/// Bounded-read an already securely opened descriptor, then revalidate ownership, type, length, and
/// inode timestamps before parsing the strict versioned document. The caller must hold the matching
/// transaction lock.
pub(super) fn parse_revocation_file(
    mut file: fs::File,
    fingerprint: RevocationFingerprint,
) -> Result<RevocationSnapshot> {
    let mut contents = Vec::with_capacity(fingerprint.length as usize);
    (&mut file)
        .take(TOKEN_REVOCATION_FILE_MAX_BYTES + 1)
        .read_to_end(&mut contents)?;
    if contents.len() as u64 > TOKEN_REVOCATION_FILE_MAX_BYTES {
        bail!("token revocation state exceeds the 8 MiB size limit");
    }
    let after = file.metadata()?;
    validate_revocation_file_metadata(&after, true)
        .context("token revocation state changed to an untrusted file while reading")?;
    if revocation_fingerprint(&after) != fingerprint || contents.len() as u64 != fingerprint.length
    {
        bail!("token revocation state changed while it was being read");
    }
    let document: RevocationDocument =
        serde_json::from_slice(&contents).context("failed to parse token revocation state")?;
    let generation = match (document.version, document.generation) {
        (REVOCATION_FORMAT_V1, None) => 0,
        (REVOCATION_FORMAT_CURRENT, Some(generation)) if generation > 0 => generation,
        (REVOCATION_FORMAT_V1, Some(_)) => {
            bail!("legacy token revocation state must not contain a generation")
        }
        (REVOCATION_FORMAT_CURRENT, _) => {
            bail!("token revocation state has an invalid generation")
        }
        _ => bail!("unsupported token revocation file version"),
    };
    if document.revoked.len() > TOKEN_REVOCATION_CAPACITY {
        bail!("token revocation file exceeds the supported entry limit");
    }
    if document
        .revoked
        .keys()
        .any(|jti| jti.len() != 32 || !jti.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        bail!("token revocation state contains an invalid token identifier");
    }
    Ok(RevocationSnapshot {
        revocations: RevocationSet::new(document.revoked),
        generation,
        fingerprint: Some(fingerprint),
    })
}

/// 接受的新磁盘快照必须使用更大的 generation，且不得删除或缩短缓存中尚未到期的撤销。
/// fingerprint 未变却 generation 改变同样表示不可能的状态。该规则阻止旧文件回滚重新启用
/// token，同时允许到期项被修剪。
/// A new disk snapshot must have a greater generation and may not remove or shorten any unexpired
/// cached revocation. A changed generation under an unchanged fingerprint is also impossible. This
/// rejects rollback while still allowing expired entries to be pruned.
pub(super) fn validate_revocation_transition(
    cached: &RevocationSnapshot,
    disk: &RevocationSnapshot,
    now_secs: u64,
) -> Result<()> {
    if cached.fingerprint == disk.fingerprint {
        if cached.generation != disk.generation {
            bail!("token revocation generation changed without a file identity change");
        }
        return Ok(());
    }
    if disk.generation <= cached.generation {
        bail!(
            "stale token revocation generation {} replaced cached generation {}",
            disk.generation,
            cached.generation
        );
    }
    if cached.revocations.entries.iter().any(|(jti, expires_at)| {
        *expires_at > now_secs
            && disk
                .revocations
                .entries
                .get(jti)
                .copied()
                .unwrap_or_default()
                < *expires_at
    }) {
        bail!("new token revocation generation dropped an unexpired cached revocation");
    }
    Ok(())
}

/// 持久化事务顺序为：同目录 `O_EXCL|NOFOLLOW` 私有临时 inode → 写入并 fsync → 原子 rename
/// → 父目录 fsync → 从固定父目录重新打开并校验内容/身份。发布前失败会清理候选；rename 后
/// 的错误具有可见性或持久性歧义，由调用者切换到 fail-closed degraded 状态。
/// Persistence order is a private same-directory `O_EXCL|NOFOLLOW` inode, write+fsync, atomic rename,
/// parent fsync, then reopen below the pinned parent and verify identity/content. Pre-publication
/// failures clean the candidate; errors after rename are visibility/durability ambiguities that make
/// the caller fail closed.
pub(super) fn persist_revocations(
    backend: &RevocationBackend,
    generation: u64,
    revoked: &HashMap<String, u64>,
    fault: RevocationPersistFault,
) -> Result<RevocationFingerprint> {
    let document = RevocationDocument {
        version: REVOCATION_FORMAT_CURRENT,
        generation: Some(generation),
        revoked: revoked.clone(),
    };
    let contents = serde_json::to_vec(&document)?;
    if contents.len() as u64 > TOKEN_REVOCATION_FILE_MAX_BYTES {
        bail!("token revocation state exceeds the 8 MiB size limit");
    }
    let mut temp_name = OsString::from(".");
    temp_name.push(&backend.state_name);
    temp_name.push(format!(".{}.tmp", Uuid::new_v4()));
    let mut published = false;
    let result = (|| -> Result<RevocationFingerprint> {
        let mut file: fs::File = rustix_fs::openat(
            &backend.parent,
            &temp_name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        )?
        .into();
        // 中文：O_CREAT 权限会被 umask（甚至服务管理器 0777）过滤，故在安全 O_EXCL inode 上设置精确私有 mode。
        // English: umask filters O_CREAT permissions; set the exact private mode on the securely opened O_EXCL inode.
        rustix_fs::fchmod(&file, Mode::from_raw_mode(0o600))?;
        validate_revocation_file_metadata(&file.metadata()?, true)
            .context("new token revocation candidate failed trusted-file validation")?;
        if fault == RevocationPersistFault::BeforeWrite {
            bail!("injected token revocation failure before write");
        }
        if fault == RevocationPersistFault::PartialWrite {
            file.write_all(&contents[..(contents.len() / 2).max(1)])?;
            bail!("injected partial token revocation write");
        }
        file.write_all(&contents)?;
        #[cfg(test)]
        backend.pause_persist_for_test();
        if fault == RevocationPersistFault::FileSync {
            bail!("injected token revocation file sync failure");
        }
        file.sync_all()?;
        let candidate = revocation_fingerprint(&file.metadata()?);
        if fault == RevocationPersistFault::Rename {
            bail!("injected token revocation rename failure");
        }
        rustix_fs::renameat(
            &backend.parent,
            &temp_name,
            &backend.parent,
            &backend.state_name,
        )?;
        published = true;
        if fault == RevocationPersistFault::AfterRename {
            bail!("injected failure after token revocation publication");
        }
        if fault == RevocationPersistFault::ParentSync {
            bail!("injected token revocation parent sync failure");
        }
        rustix_fs::fsync(&backend.parent)?;
        if fault == RevocationPersistFault::AfterParentSync {
            bail!("injected failure after durable token revocation publication");
        }
        // 中文：Linux rename 会更新 inode ctime，rename 前 fingerprint 不能进缓存；相对固定父目录
        // 重新打开，证明发布名仍指向本 inode，并解析一次后才返回发布后身份。
        // English: Rename changes ctime, so never cache the pre-rename fingerprint.
        // Reopen below the pinned parent, prove inode identity, and parse before returning.
        let (published_file, published) = open_revocation_state(backend)?;
        if published.device != candidate.device || published.inode != candidate.inode {
            bail!("published token revocation state no longer names the transaction candidate");
        }
        let verified = parse_revocation_file(published_file, published)?;
        if verified.generation != generation || verified.revocations.entries.ne(revoked) {
            bail!("published token revocation state failed transaction verification");
        }
        Ok(published)
    })();
    if result.is_err() && !published {
        let _ = rustix_fs::unlinkat(&backend.parent, &temp_name, AtFlags::empty());
        // 中文：让候选清理持久化并保留原错误；清理失败仍安全，因为启动/操作不信任临时名，运维可离线删除。
        // English: Durably clean the candidate while retaining the original error; leftover temp names are never trusted and may be removed offline.
        let _ = rustix_fs::fsync(&backend.parent);
    }
    result.with_context(|| format!("failed to persist {}", backend.path.display()))
}
