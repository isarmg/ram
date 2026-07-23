//! RFC 7616 Digest 解析、nonce 校验与有界防重放。proof 绑定真实方法/目标、realm、
//! SHA-256 与 qop=auth；nonce 经服务端认证且会过期；重放状态原子地按主体、nonce 与
//! 已验证传输来源分区，攻击者可控维度全部有界。
//!
//! RFC 7616 Digest parsing, nonce validation, and bounded replay defense.
//!
//! Security invariants:
//! - a proof is accepted only for the actual method and request target, the
//!   advertised realm, SHA-256, and qop=auth;
//! - nonces are server-authenticated, expire after a fixed window, and all
//!   attacker-controlled parser and replay-key dimensions are bounded;
//! - replay acceptance is atomic and partitioned by principal, nonce, and
//!   verified transport source so one identity cannot consume the global cache.

use super::*;

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct DigestReplayKey {
    pub(super) nonce: [u8; 34],
    pub(super) user: Arc<str>,
    pub(super) cnonce: Arc<[u8]>,
    pub(super) nc: u32,
}

#[derive(Debug)]
pub(super) struct DigestReplayAttempt {
    pub(super) key: DigestReplayKey,
    pub(super) expires_at: u64,
}

#[derive(Debug)]
pub(super) struct DigestReplayEntry {
    pub(super) expires_at: u64,
    pub(super) source: Option<SourceIdentity>,
}

#[derive(Debug, Default)]
pub(super) struct DigestUserReplayBucket {
    pub(super) entries: HashMap<(Arc<[u8]>, u32), DigestReplayEntry>,
}

#[derive(Debug, Default)]
pub(super) struct DigestNonceReplayBucket {
    pub(super) users: HashMap<Arc<str>, DigestUserReplayBucket>,
    pub(super) entry_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DigestReplayReject {
    ExactReplay,
    GlobalCapacity,
    UserCapacity,
    NonceCapacity,
    SourceCapacity,
}

pub(super) struct DigestReplayCache {
    /// 重放状态刻意按 nonce → user → (cnonce,nc) 分区，既显式执行独立预算，也能在过期时
    /// 立即删除空桶，避免攻击者创建的映射常驻进程。
    /// Replay state is partitioned nonce → user → (cnonce,nc), making budgets
    /// explicit and allowing expiry to remove attacker-created empty buckets.
    pub(super) nonces: HashMap<[u8; 34], DigestNonceReplayBucket>,
    pub(super) entry_count: usize,
    pub(super) dynamic_key_bytes: usize,
    pub(super) expirations: BinaryHeap<Reverse<(u64, DigestReplayKey)>>,
    pub(super) per_user_entries: HashMap<Arc<str>, usize>,
    pub(super) per_source_entries: HashMap<Option<SourceIdentity>, usize>,
    pub(super) capacity: usize,
    pub(super) per_user_capacity: usize,
    pub(super) per_nonce_capacity: usize,
    pub(super) per_source_capacity: usize,
}

impl Default for DigestReplayCache {
    fn default() -> Self {
        Self {
            nonces: HashMap::new(),
            entry_count: 0,
            dynamic_key_bytes: 0,
            expirations: BinaryHeap::new(),
            per_user_entries: HashMap::new(),
            per_source_entries: HashMap::new(),
            capacity: DIGEST_REPLAY_CAPACITY,
            per_user_capacity: DIGEST_REPLAY_PER_USER_CAPACITY,
            per_nonce_capacity: DIGEST_REPLAY_PER_NONCE_CAPACITY,
            per_source_capacity: DIGEST_REPLAY_PER_SOURCE_CAPACITY,
        }
    }
}

impl DigestReplayCache {
    /// 返回 true 时会原子地记录这次精确 `(nonce,user,cnonce,nc)`。
    /// 不要只记录最大 nc：HTTP/2 并发请求可能 nc=2 先于 nc=1 到达，
    /// 两个未用过的计数都应被接受。满容量时不驱逐仍有效记录，
    /// 因为驱逐会让
    /// 已被接受过的 Authorization 再次变得可重放。
    /// Atomically record the exact tuple. Do not retain only the largest nc or
    /// evict live entries: HTTP/2 may reorder counts, and eviction re-enables replay.
    pub(super) fn accept(
        &mut self,
        attempt: DigestReplayAttempt,
        source: Option<SourceIdentity>,
        now_secs: u64,
    ) -> Result<(), DigestReplayReject> {
        self.prune(now_secs);
        if self.contains(&attempt.key) {
            return Err(DigestReplayReject::ExactReplay);
        }
        if self.entry_count >= self.capacity {
            return Err(DigestReplayReject::GlobalCapacity);
        }
        if self
            .per_user_entries
            .get(&attempt.key.user)
            .copied()
            .unwrap_or_default()
            >= self.per_user_capacity
        {
            return Err(DigestReplayReject::UserCapacity);
        }
        if self
            .nonces
            .get(&attempt.key.nonce)
            .is_some_and(|bucket| bucket.entry_count >= self.per_nonce_capacity)
        {
            return Err(DigestReplayReject::NonceCapacity);
        }
        if self
            .per_source_entries
            .get(&source)
            .copied()
            .unwrap_or_default()
            >= self.per_source_capacity
        {
            return Err(DigestReplayReject::SourceCapacity);
        }
        let key = attempt.key;
        let dynamic_key_bytes = key.user.len() + key.cnonce.len();
        *self.per_user_entries.entry(key.user.clone()).or_default() += 1;
        *self.per_source_entries.entry(source).or_default() += 1;
        self.expirations
            .push(Reverse((attempt.expires_at, key.clone())));
        let nonce_bucket = self.nonces.entry(key.nonce).or_default();
        let user_bucket = nonce_bucket.users.entry(key.user).or_default();
        let old = user_bucket.entries.insert(
            (key.cnonce, key.nc),
            DigestReplayEntry {
                expires_at: attempt.expires_at,
                source,
            },
        );
        debug_assert!(old.is_none(), "exact Digest replay checked before insert");
        nonce_bucket.entry_count += 1;
        self.entry_count += 1;
        self.dynamic_key_bytes += dynamic_key_bytes;
        debug_assert!(self.dynamic_key_bytes <= DIGEST_REPLAY_MAX_DYNAMIC_KEY_BYTES);
        Ok(())
    }

    pub(super) fn contains(&self, key: &DigestReplayKey) -> bool {
        self.nonces
            .get(&key.nonce)
            .and_then(|nonce| nonce.users.get(&key.user))
            .is_some_and(|user| user.entries.contains_key(&(key.cnonce.clone(), key.nc)))
    }

    pub(super) fn prune(&mut self, now_secs: u64) {
        while let Some(Reverse((expires_at, _))) = self.expirations.peek() {
            if *expires_at > now_secs {
                break;
            }
            let Reverse((expires_at, key)) = self.expirations.pop().unwrap();
            let Some(entry) = self.remove_if_expired(&key, expires_at) else {
                continue;
            };
            decrement_count(&mut self.per_user_entries, &key.user);
            decrement_count(&mut self.per_source_entries, &entry.source);
        }
    }

    pub(super) fn remove_if_expired(
        &mut self,
        key: &DigestReplayKey,
        expires_at: u64,
    ) -> Option<DigestReplayEntry> {
        let nonce_bucket = self.nonces.get_mut(&key.nonce)?;
        let user_bucket = nonce_bucket.users.get_mut(&key.user)?;
        if user_bucket
            .entries
            .get(&(key.cnonce.clone(), key.nc))
            .is_none_or(|entry| entry.expires_at != expires_at)
        {
            return None;
        }
        let entry = user_bucket.entries.remove(&(key.cnonce.clone(), key.nc))?;
        let remove_user = user_bucket.entries.is_empty();
        if remove_user {
            nonce_bucket.users.remove(&key.user);
        }
        nonce_bucket.entry_count -= 1;
        self.entry_count -= 1;
        self.dynamic_key_bytes -= key.user.len() + key.cnonce.len();
        if nonce_bucket.entry_count == 0 {
            self.nonces.remove(&key.nonce);
        }
        Some(entry)
    }
}

pub(super) fn decrement_count<K: Eq + std::hash::Hash>(counts: &mut HashMap<K, usize>, key: &K) {
    if let Some(count) = counts.get_mut(key) {
        *count -= 1;
        if *count == 0 {
            counts.remove(key);
        }
    }
}

/// 验证 Authorization 头中的凭据。Basic 成功返回无状态 proof；
/// Digest 成功还返回 nonce/cnonce/nc，调用方必须在共享重放缓存
/// 中原子接受它之后才能认定认证完成。
/// Validate Authorization credentials. Digest success is provisional until
/// the caller atomically accepts its nonce/cnonce/nc in the shared replay cache.
pub(super) fn check_auth(
    authorization: &HeaderValue,
    method: &str,
    request_target: &str,
    auth_user: &str,
    auth_pass: &str,
) -> Option<AuthProof> {
    // 中文：昂贵 Basic 哈希由 AccessControl::check_auth 截获，避免速率预留/准入结果被折叠
    // 成普通密码错误；此回退只处理明文 Basic 与 Digest。
    // English: AccessControl::check_auth intercepts expensive Basic hashes so
    // admission outcomes remain distinct; this fallback handles plaintext Basic and Digest.
    if strip_prefix(authorization.as_bytes(), b"Basic ").is_some() {
        let (user, pass) = decode_basic_credentials(authorization)?;
        if user != auth_user {
            return None;
        }
        if !auth_pass.starts_with("$6$") && constant_time_eq(pass.as_bytes(), auth_pass.as_bytes())
        {
            return Some(AuthProof::Basic);
        }

        None
    // 中文：Digest 只接受 RFC 7616 SHA-256，省略算法或使用 MD5 均拒绝。
    // English: Digest accepts only RFC 7616 SHA-256; omitted algorithms and MD5 are rejected.
    } else if let Some(value) = strip_prefix(authorization.as_bytes(), b"Digest ") {
        let digest_map = to_headermap(value).ok()?;
        if let (
            Some(username),
            Some(realm),
            Some(nonce),
            Some(user_response),
            Some(uri),
            Some(qop),
            Some(nc),
            Some(cnonce),
        ) = (
            digest_param(&digest_map, b"username").and_then(|b| std::str::from_utf8(b).ok()),
            digest_param(&digest_map, b"realm"),
            digest_param(&digest_map, b"nonce"),
            digest_param(&digest_map, b"response"),
            digest_param(&digest_map, b"uri"),
            digest_param(&digest_map, b"qop"),
            digest_param(&digest_map, b"nc"),
            digest_param(&digest_map, b"cnonce"),
        ) {
            match validate_nonce(nonce) {
                Ok(true) => {}
                _ => return None,
            }
            if auth_user != username {
                return None;
            }
            if realm != REALM.as_bytes() {
                return None;
            }
            if !digest_param(&digest_map, b"algorithm")
                .is_some_and(|value| value.eq_ignore_ascii_case(b"SHA-256"))
            {
                return None;
            }
            // Digest 里自报的 `uri` 必须与实际被授权的请求目标一致——
            // 否则截获的"路径 A 的认证头"可以重放到同一用户可达的
            // 任意其他路径：HA2 哈希的只是客户端自己声称的 uri，
            // 而不是真实的请求目标。
            // English: The self-declared Digest `uri` must equal the actual
            // authorized target, or a captured header for path A could replay on path B.
            if uri != request_target.as_bytes() {
                return None;
            }
            // 只有带 qop 的响应才含客户端随机数（cnonce）和计数（nc）；
            // 缺了它们，响应就是一堆静态值的裸哈希，可被原样重放。
            // 服务器始终宣告 `qop="auth"`，规范的客户端必然带上。
            // 服务器挑战只宣告 `auth`。`auth-int` 还必须把请求实体
            // 纳入 HA2，而这里没有在认证层缓存/哈希 body，所以不能
            // “看起来支持”它。
            // English: qop supplies cnonce/nc replay inputs. The challenge
            // advertises only `auth`; `auth-int` would require body hashing not performed here.
            if qop != b"auth" {
                return None;
            }
            if nc.len() != 8
                || !nc.iter().all(u8::is_ascii_hexdigit)
                || cnonce.is_empty()
                || cnonce.len() > DIGEST_CNONCE_MAX_LEN
                || user_response.len() != 64
                || !user_response.iter().all(u8::is_ascii_hexdigit)
            {
                return None;
            }
            let nc_value = u32::from_str_radix(std::str::from_utf8(nc).ok()?, 16).ok()?;
            if nc_value == 0 {
                return None;
            }

            let ha1 = digest_hex(format!("{auth_user}:{REALM}:{auth_pass}").as_bytes());
            let ha2 = digest_hex(&[method.as_bytes(), b":", uri].concat());
            let correct_response = digest_hex(
                &[
                    ha1.as_bytes(),
                    b":",
                    nonce,
                    b":",
                    nc,
                    b":",
                    cnonce,
                    b":",
                    qop,
                    b":",
                    ha2.as_bytes(),
                ]
                .concat(),
            );

            if constant_time_eq(correct_response.as_bytes(), user_response) {
                let nonce_bytes: [u8; 34] = nonce.try_into().ok()?;
                let issued_at = nonce_timestamp(nonce).ok()? as u64;
                return Some(AuthProof::Digest(DigestReplayAttempt {
                    key: DigestReplayKey {
                        nonce: nonce_bytes,
                        user: Arc::from(auth_user),
                        cnonce: Arc::from(cnonce),
                        nc: nc_value,
                    },
                    expires_at: issued_at + DIGEST_AUTH_TIMEOUT,
                }));
            }
        }
        None
    } else {
        None
    }
}

pub(super) fn digest_hex(input: &[u8]) -> String {
    hex::encode(Sha256::digest(input))
}

/// 校验 nonce：格式为 `8 位十六进制时间戳 + 26 位种子哈希截断`。
/// 返回 Ok(true) = 有效；Ok(false) = 曾经有效但已过期；
/// Err = 根本不是本服务器签发的。
/// Validate `8 hex timestamp bytes + 26 seed-MAC bytes`: true is current,
/// false expired, and error means it was never issued by this server.
pub(super) fn validate_nonce(nonce: &[u8]) -> Result<bool> {
    validate_nonce_at(nonce, unix_now()?.as_secs())
}

/// `validate_nonce` 的实现体；显式传入当前时间，避免把时钟读取与
/// nonce 的纯校验逻辑耦合在一起。
/// Pure nonce validation with an explicit current time, decoupled from clock I/O.
pub(super) fn validate_nonce_at(nonce: &[u8], secs_now: u64) -> Result<bool> {
    let secs_nonce = nonce_timestamp(nonce)?;
    if let Some(dur) = secs_now.checked_sub(secs_nonce as u64) {
        let mut mac = token_mac(nonce_start_key()?.as_slice());
        mac.update(&secs_nonce.to_be_bytes());
        let h = hex::encode(mac.finalize().into_bytes());
        if constant_time_eq(&h.as_bytes()[..26], &nonce[8..]) {
            return Ok(dur < DIGEST_AUTH_TIMEOUT);
        }
    }
    bail!("invalid nonce");
}

pub(super) fn nonce_timestamp(nonce: &[u8]) -> Result<u32> {
    if nonce.len() != 34 {
        bail!("invalid nonce");
    }
    // 只把前 8 个**字节**单独解成 ASCII hex。不先将整个 nonce
    // 变成 &str 后再做 `[..8]` 字节切片：恶意 UTF-8 多字节序列
    // 可能让第 8 字节落在字符中间，那种 str 切片会 panic。
    // English: Decode only the first eight bytes as ASCII hex; slicing a full
    // malicious UTF-8 string at byte 8 could split a code point and panic.
    let timestamp = std::str::from_utf8(&nonce[..8]).map_err(|_| anyhow!("invalid nonce"))?;
    u32::from_str_radix(timestamp, 16).map_err(|_| anyhow!("invalid nonce"))
}

pub(super) fn strip_prefix<'a>(search: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let l = prefix.len();
    if search.len() < l {
        return None;
    }
    if &search[..l] == prefix {
        Some(&search[l..])
    } else {
        None
    }
}

/// 把 Digest 头的 `k1=v1, k2="v2", ...` 解析成键值映射。
///
/// 解析器只接受 `token = (token | quoted-string)` 的明确结构：
/// - 所有索引均在访问前做边界检查，任意不受信输入只会返回 `Err`；
/// - 引号里的逗号不是分隔符，反斜杠转义会正确跳过下一字节；
/// - 重复字段直接拒绝，避免代理、客户端和服务器对“取第一个
///   还是最后一个”产生解析差异。
///
/// 字段名按 RFC 7235 以 ASCII 大小写不敏感方式规范化。未转义值借用
/// 输入；只有真正含 quoted-pair 的值才分配并移除反斜杠。
/// Parse only explicit `token=(token|quoted-string)` syntax with checked indices,
/// quoted comma/escape handling, duplicate rejection, and ASCII-insensitive names.
type DigestParamMap<'a> = HashMap<Vec<u8>, Cow<'a, [u8]>>;

pub(super) fn digest_param<'map, 'input>(
    params: &'map DigestParamMap<'input>,
    name: &[u8],
) -> Option<&'map [u8]> {
    params.get(name).map(Cow::as_ref)
}

pub(super) fn to_headermap(header: &[u8]) -> Result<DigestParamMap<'_>, ()> {
    if header.is_empty() || header.len() > DIGEST_AUTH_PARAMS_MAX_BYTES {
        return Err(());
    }
    let mut ret = HashMap::new();
    let mut i = 0;

    while i < header.len() {
        skip_ows(header, &mut i);
        if i == header.len() {
            return (!ret.is_empty()).then_some(ret).ok_or(());
        }

        let key_start = i;
        while i < header.len() && is_token_byte(header[i]) {
            i += 1;
        }
        if i == key_start || i - key_start > DIGEST_AUTH_PARAM_NAME_MAX_BYTES {
            return Err(());
        }
        let key = header[key_start..i]
            .iter()
            .map(u8::to_ascii_lowercase)
            .collect::<Vec<_>>();

        skip_ows(header, &mut i);
        if header.get(i) != Some(&b'=') {
            return Err(());
        }
        i += 1;
        skip_ows(header, &mut i);

        let value = if header.get(i) == Some(&b'"') {
            i += 1;
            let value_start = i;
            let mut unescaped = None::<Vec<u8>>;
            loop {
                match header.get(i).copied() {
                    Some(b'"') => {
                        let value = unescaped
                            .map(Cow::Owned)
                            .unwrap_or_else(|| Cow::Borrowed(&header[value_start..i]));
                        i += 1;
                        break value;
                    }
                    Some(b'\\') => {
                        let escaped = header.get(i + 1).copied().ok_or(())?;
                        if !is_quoted_pair_byte(escaped) {
                            return Err(());
                        }
                        let output =
                            unescaped.get_or_insert_with(|| header[value_start..i].to_vec());
                        output.push(escaped);
                        i += 2;
                    }
                    Some(byte) if is_quoted_text_byte(byte) => {
                        if let Some(output) = &mut unescaped {
                            output.push(byte);
                        }
                        i += 1;
                    }
                    Some(_) => return Err(()),
                    None => return Err(()),
                }
            }
        } else {
            let value_start = i;
            while i < header.len() && is_token_byte(header[i]) {
                i += 1;
            }
            if i == value_start {
                return Err(());
            }
            Cow::Borrowed(&header[value_start..i])
        };

        if ret.len() >= DIGEST_AUTH_PARAMS_MAX_FIELDS {
            return Err(());
        }
        if ret.insert(key, value).is_some() {
            // 中文：auth-param 名称不区分大小写；拒绝 `qop=auth,QOP=...`，避免中间件与本解析器分歧。
            // English: Names are case-insensitive; reject differently cased duplicates instead of permitting parser disagreement.
            return Err(());
        }

        skip_ows(header, &mut i);
        if i == header.len() {
            return Ok(ret);
        }
        if header[i] != b',' {
            return Err(());
        }
        i += 1;
        // 中文：逗号后必须有下一字段，拒绝 `a=b,`。 / English: A comma must be followed by another field; reject `a=b,`.
        let mut next = i;
        skip_ows(header, &mut next);
        if next == header.len() || header[next] == b',' {
            return Err(());
        }
    }

    Err(())
}

pub(super) fn skip_ows(input: &[u8], i: &mut usize) {
    while input.get(*i).copied().is_some_and(is_ows) {
        *i += 1;
    }
}

pub(super) fn is_ows(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

pub(super) fn is_quoted_text_byte(c: u8) -> bool {
    is_ows(c) || c == b'!' || (b'#'..=b'[').contains(&c) || (b']'..=b'~').contains(&c) || c >= 0x80
}

pub(super) fn is_quoted_pair_byte(c: u8) -> bool {
    is_ows(c) || (b'!'..=b'~').contains(&c) || c >= 0x80
}

/// RFC 7230 `tchar`；Digest auth-param 键必须是 token。 / RFC 7230 `tchar`; Digest parameter names must be tokens.
pub(super) fn is_token_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_digest_auth_params(data: &[u8]) {
    if data.len() > DIGEST_AUTH_PARAMS_MAX_BYTES {
        return;
    }
    if let Ok(params) = to_headermap(data) {
        assert!(!params.is_empty());
        assert!(params.len() <= DIGEST_AUTH_PARAMS_MAX_FIELDS);
        for (name, value) in params {
            assert!(!name.is_empty());
            assert!(name.len() <= DIGEST_AUTH_PARAM_NAME_MAX_BYTES);
            assert!(name.iter().all(|byte| is_token_byte(*byte)));
            assert!(name.iter().all(|byte| !byte.is_ascii_uppercase()));
            assert!(value.len() <= data.len());
        }
    }
}

/// 生成 nonce：当前秒级时间戳（8 位 hex）+ 种子哈希（截 26 位）。
/// 时间戳明文放在前面，校验时先取出来算时效，再重算哈希比对真伪。
/// Generate a nonce from an eight-hex current timestamp plus 26 MAC characters, enabling expiry before authenticity comparison.
pub(super) fn create_nonce() -> Result<String> {
    let now = unix_now()?;
    let secs = now.as_secs() as u32;
    let mut mac = token_mac(nonce_start_key()?.as_slice());
    mac.update(&secs.to_be_bytes());
    let n = format!("{secs:08x}{}", hex::encode(mac.finalize().into_bytes()));
    Ok(n[..34].to_string())
}
