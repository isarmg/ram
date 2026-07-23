//! 认证（你是谁）与授权（你能访问哪些路径）。
//!
//! 三大部分：
//! 1. [`AccessControl`]：`--auth user:pass@/dir:rw` 规则的解析与存储，
//!    以及每个请求的准入判定入口 [`AccessControl::guard`]；
//! 2. [`AccessPaths`]：一棵"路径前缀 → 权限"的树，实现目录级的
//!    仅索引（IndexOnly）/ 只读（ReadOnly）/ 读写（ReadWrite）三级权限；
//! 3. HTTP 认证协议实现：Basic（明文密码，可配合 Argon2id/SHA-512-crypt 哈希存储）
//!    与 Digest（挑战-响应，密码不上线），外加基于 HMAC-SHA256 的
//!    短期下载令牌（`?tokengen` 签发，`Authorization: Bearer`
//!    携带）。
//!
//! ## 本模块的 Rust 知识点
//! - **层级数据结构**：`AccessPaths` 的 children 是 `IndexMap<String,
//!   AccessPaths>`。配置深度有硬上限，热路径遍历使用显式栈/循环，避免
//!   ACL 深度消耗线程调用栈。
//! - **可失败的 `OnceLock` 初始化**：进程 nonce 密钥按需从操作系统
//!   CSPRNG 加载；熵源故障沿 `Result` 返回，不会升级为进程 panic。
//! - **字节层解析**：`to_headermap` 直接在 `&[u8]` 上解析 Digest 头，
//!   返回的 HashMap 借用输入的生命周期，零拷贝。
//!
//! ## 安全设计要点（值得细读）
//! - Digest 的 nonce 有时效（5 分钟）且掺入服务器私有随机量，限制重放；
//! - 校验 Digest 的 `uri` 字段必须等于真实请求目标，防止"路径 A 的
//!   认证头被重放到路径 B"；
//! - 下载令牌绑定 audience/用户/路径/过期时间/jti，使用
//!   独立于用户密码的 HMAC 密钥；默认密钥和 audience 均为进程级
//!   CSPRNG 随机值，也可显式配置持久化。
//!
//! ## English overview
//! Authentication answers who the caller is; authorization determines which paths that identity
//! may access.
//!
//! The module has three major parts:
//! 1. [`AccessControl`] parses and stores `--auth user:pass@/dir:rw` rules and exposes the per-request
//!    admission entry point [`AccessControl::guard`];
//! 2. [`AccessPaths`] is a “path prefix → permission” tree implementing directory-level IndexOnly,
//!    ReadOnly, and ReadWrite permissions;
//! 3. the HTTP authentication protocols implement Basic with plaintext or Argon2id/SHA-512-crypt
//!    password storage, challenge-response Digest that never sends the password, and short-lived
//!    HMAC-SHA256 download tokens issued by `?tokengen` and carried by `Authorization: Bearer`.
//!
//! ## Rust concepts in this module
//! - **Hierarchical data structures**: `AccessPaths.children` is an `IndexMap<String, AccessPaths>`.
//!   Configuration has a hard depth limit, and hot-path traversal uses explicit stacks/loops so ACL
//!   depth cannot consume the thread call stack.
//! - **Fallible `OnceLock` initialization**: the process nonce key is loaded lazily from the
//!   operating-system CSPRNG; entropy failure propagates through `Result` instead of becoming a
//!   process panic.
//! - **Byte-level parsing**: `to_headermap` parses a Digest header directly from `&[u8]`; the returned
//!   HashMap borrows the input lifetime without copying.
//!
//! ## Security design points
//! - Digest nonces expire after five minutes and mix in server-private randomness to limit replay;
//! - the Digest `uri` field must equal the real request target, preventing a captured authorization
//!   header for path A from being replayed against path B;
//! - download tokens bind audience, user, path, expiry, and JTI under an HMAC key independent of user
//!   passwords. The default key and audience are process-random CSPRNG values, with explicit durable
//!   configuration available.

use crate::{
    config::Args,
    identity::{ObjectIdentity, OutputPathIdentity, SourceIdentity},
    server::Response,
    utils::{is_trusted_file_owner, unix_now},
};

use anyhow::{Context as _, Result, anyhow, bail};
use argon2::{
    Argon2, Params as Argon2Params, PasswordHash as Argon2PasswordHash,
    PasswordVerifier as Argon2PasswordVerifier,
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use headers::HeaderValue;
use hmac::{Hmac, KeyInit, Mac};
use hyper::{Method, header::WWW_AUTHENTICATE};
use indexmap::IndexMap;
use rustix::fs::{self as rustix_fs, AtFlags, FlockOperation, Mode, OFlags, flock};
use serde::{Deserialize, Serialize};
use sha_crypt::PasswordVerifier as ShaCryptPasswordVerifier;
use sha2::{Digest, Sha256};
use std::{
    borrow::Cow,
    cmp::Reverse,
    collections::{BinaryHeap, HashMap},
    ffi::OsString,
    fmt, fs,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

#[cfg(test)]
use std::sync::atomic::AtomicUsize;

mod acl;
mod basic;
mod digest;
mod rate_limit;
mod token;

use acl::AccessPathBudget;
pub use acl::{AccessPaths, AccessPerm};
#[cfg(feature = "fuzzing")]
pub(crate) use digest::fuzz_digest_auth_params;
pub(crate) use token::{TokenRevocationCapabilities, TokenRevokeError};

use basic::*;
use digest::*;
use rate_limit::*;
use token::*;

const REALM: &str = "RAM";
// 中文：Digest nonce 窗口为 300 秒；期间记录 user+nonce+cnonce+nc 并拒绝精确重放，
// 不同未用 nc 可乱序到达以兼容 HTTP/2 并发。
// English: Digest nonces live 300 seconds. Exact tuples are replay-protected,
// while distinct unused nc values may arrive out of order for HTTP/2 concurrency.
const DIGEST_AUTH_TIMEOUT: u64 = 60 * 5; // 5 分钟 / 5 minutes
/// 每个进程最多记录的已用 Digest `(nonce,user,cnonce,nc)` 数。
/// 65536 能容纳 nonce 的 5 分钟窗口内约 218 req/s 的 Digest 流量，
/// 同时在 cnonce 限长下把最坏内存占用限制在数十 MiB。
/// Per-process exact replay-entry limit: 65,536 supports about 218 requests/s over five minutes while bounding memory.
const DIGEST_REPLAY_CAPACITY: usize = 65_536;
/// 单个已认证主体不能耗尽全局重放缓存并阻断其他账号。
/// A single principal cannot consume the complete replay cache and deny every other account.
const DIGEST_REPLAY_PER_USER_CAPACITY: usize = 16_384;
/// 每个服务端 nonce（同秒挑战共享）与网络来源各有独立子预算，防止热点挑战或 NAT 耗尽进程缓存。
/// Each server nonce and network source has an independent sub-budget, preventing one hot challenge/client/NAT from exhausting the cache.
const DIGEST_REPLAY_PER_NONCE_CAPACITY: usize = 8_192;
const DIGEST_REPLAY_PER_SOURCE_CAPACITY: usize = 16_384;
/// cnonce 由客户端选择，必须单独限长；否则即使条目数有上限，
/// 恶意的已认证客户端仍可用超长键放大缓存内存。
/// Client-selected cnonce has its own length limit so bounded entry count also bounds memory.
const DIGEST_CNONCE_MAX_LEN: usize = 128;
/// 解析器独立于 Hyper 头列表限制执行预算，避免 fuzz 或未来调用方让单个 Digest 字段无界分配/扫描。
/// Bound parsing independently from Hyper so fuzz and future callers cannot create an unbounded Digest field.
const DIGEST_AUTH_PARAMS_MAX_BYTES: usize = 16 * 1024;
const DIGEST_AUTH_PARAMS_MAX_FIELDS: usize = 32;
const DIGEST_AUTH_PARAM_NAME_MAX_BYTES: usize = 64;
/// 用户名会复制进认证/重放状态，故配置时限长，使条目上限同时成为字节上限。
/// Usernames are copied into retained state; configuration-time length bounds make entry caps imply byte caps.
const AUTH_USERNAME_MAX_LEN: usize = 256;
/// 认证文件已有 4,096 行上限；所有来源（含 YAML 与 `|` 展开 CLI）在构造长期状态前应用相同账号规则上限。
/// Apply the 4,096 account-rule limit to every source before building retained state.
const AUTH_ACCOUNT_RULE_MAX_COUNT: usize = 4_096;
/// 一条账号规则可含多个逗号分隔 ACL 路径；根条目没有组件，故除组件总预算外还需独立计数。
/// Account rules may contain multiple ACL paths; root paths need a count independent of component totals.
const AUTH_ACL_PATH_RULE_MAX_COUNT: usize = 16_384;
/// 同时限制 ACL 森林内存及解析/克隆/遍历工作量；重复路径即使折叠到同一节点也消耗输入复杂度预算。
/// Bound ACL memory and parse/clone/walk work; duplicate inputs consume budget even when nodes collapse.
const AUTH_ACL_COMPONENT_MAX_TOTAL: usize = 65_536;
/// 操作遍历虽为迭代，嵌套 `AccessPaths` 的递归析构仍由此深度限制约束。
/// Bound recursive destruction depth even though operational traversals are iterative.
const AUTH_ACL_PATH_MAX_DEPTH: usize = 256;
/// 活动重放键中攻击者控制的变长字节精确上限；当前为 24 MiB，其余固定元数据仅 O(capacity)。
/// Exact variable-byte bound for attacker-controlled replay keys (24 MiB by default); fixed map/heap metadata is O(capacity), never O(input).
const DIGEST_REPLAY_MAX_DYNAMIC_KEY_BYTES: usize =
    DIGEST_REPLAY_CAPACITY * (AUTH_USERNAME_MAX_LEN + DIGEST_CNONCE_MAX_LEN);
pub const DEFAULT_TOKEN_TTL_SECS: u64 = 15 * 60;
const TOKEN_VERSION: u8 = 1;
/// 撤销文件是独立版本化持久格式，不得继承签名 claims 格式变更。
/// The revocation file is independently versioned and must not inherit signed-claim format changes.
const REVOCATION_FORMAT_V1: u64 = 1;
const REVOCATION_FORMAT_CURRENT: u64 = 2;
const TOKEN_SECRET_BYTES: usize = 32;
const TOKEN_REVOCATION_CAPACITY: usize = 65_536;
// 中文：65,536 个 32-byte JTI 加 u64 expiry 远低于此上限；JSON 分配前限制启动读取，
// 防止损坏的可信状态文件消耗无界内存。
// English: 65,536 JTIs plus expiries fit well below this cap. Bound reads before JSON allocation so corrupt trusted state cannot exhaust memory.
const TOKEN_REVOCATION_FILE_MAX_BYTES: u64 = 8 * 1024 * 1024;
const AUTH_RATE_CAPACITY: usize = 16_384;
const AUTH_RATE_FREE_FAILURES: u32 = 4;
/// 中文：首字节不是合法 UTF-8，保证协议域键不可能与直接哈希的配置用户名碰撞。
/// English: The invalid-UTF-8 first byte prevents protocol-domain keys from colliding with a
/// directly hashed configured username.
const BEARER_SUBJECT_RATE_DOMAIN: &[u8] = b"\xffbearer-subject\0";
const BEARER_INVALID_RATE_DOMAIN: &[u8] = b"\xffbearer-invalid\0";
const TOKEN_REVOKE_RATE_DOMAIN: &[u8] = b"\xfftoken-revoke\0";
/// 密码用户名桶只取决于来源和声明名，不取决于查表结果；known/unknown 因此没有分区差异。
/// Password principal buckets depend only on source and claimed name, never lookup results, so
/// known and unknown accounts follow exactly the same partition rule.
const PASSWORD_PRINCIPAL_RATE_DOMAIN: &[u8] = b"\xffpassword-principal\0";
/// 跨用户名来源预算永不被成功登录清零，用于封闭轮换假用户名或低权账号清洗失败记录。
/// The cross-name source budget is never reset by a successful login; it closes fake-name rotation
/// and low-privilege-success laundering of prior failures.
const PASSWORD_SOURCE_RATE_DOMAIN: &[u8] = b"\xffpassword-source\0";
const PASSWORD_ADMISSION_DOMAIN: &[u8] = b"\xffpassword-admission\0";
const BEARER_REVOCATION_ADMISSION_DOMAIN: &[u8] = b"\xffbearer-revocation-admission\0";
const TOKEN_REVOKE_ADMISSION_DOMAIN: &[u8] = b"\xfftoken-revoke-admission\0";
const PASSWORD_VERIFY_QUEUE_TIMEOUT: Duration = Duration::from_secs(1);
/// SHA-512-crypt 可接受极端 rounds；误配会让每请求独占 CPU 数分钟，故 Ram 仅作兼容验证并在启动时拒绝超过运维上限的 profile。
/// SHA-512-crypt permits extreme rounds; Ram keeps compatibility but rejects profiles above the operational ceiling at startup.
const SHA512_CRYPT_MAX_ROUNDS: u32 = 1_000_000;
/// Argon2id 策略是启动拒绝界限而非运行时旋钮；四个并发校验最多用 256 MiB，同时下限拒绝过弱 PHC。
/// Argon2id startup bounds cap four verifiers at 256 MiB and reject trivially weak PHCs.
const ARGON2_M_COST_MIN_KIB: u32 = 19 * 1024;
const ARGON2_M_COST_MAX_KIB: u32 = 64 * 1024;
const ARGON2_T_COST_MIN: u32 = 2;
const ARGON2_T_COST_MAX: u32 = 5;
const ARGON2_P_COST_MIN: u32 = 1;
const ARGON2_P_COST_MAX: u32 = 4;
const ARGON2_SALT_MIN_BYTES: usize = 8;
const ARGON2_SALT_MAX_BYTES: usize = 32;
const ARGON2_OUTPUT_MIN_BYTES: usize = 16;
const ARGON2_OUTPUT_MAX_BYTES: usize = 64;
const ARGON2_VERSION: u32 = 19;
// 中文：仅作为独立校验器 fixture/无配置兜底；真实哈希实例始终选用首个已配置的统一 profile。
// English: Used only as a verifier fixture/fallback; a real hashed instance selects its first
// configured credential after enforcing one uniform profile.
const DUMMY_SHA512_CRYPT: &str = "$6$gQxZwKyWn/ZmWEA2$4uV7KKMnSUnET2BtWTj/9T5.Jq3h/MdkOlnIl5hdlTxDZ4MZKmJ.kl6C.NL9xnNPqC4lVHC1vuI0E5cLpTJX81";
const AUTH_RATE_MAX_BACKOFF_SECS: u64 = 60;
const AUTH_RATE_IDLE_EXPIRY: Duration = Duration::from_secs(15 * 60);
const AUTH_RATE_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const PASSWORD_VERIFY_CONCURRENCY: usize = 4;
// 中文：四个活动 worker 后最多等待一波；该预算独立于更大的 HTTP 请求预算，使认证洪泛快速拒绝而不创建无界 Tokio waiter。
// English: At most one wave waits behind four workers, independently of HTTP limits, so auth floods fail promptly without unbounded waiters.
const PASSWORD_VERIFY_ADMISSION_CAPACITY: usize = PASSWORD_VERIFY_CONCURRENCY * 2;
// 中文：单一来源不能占满某主体预算，单一主体也不能占满四个全局 worker；主体上限高于来源
// 上限，允许合法第二来源校验并为其他主体保留 worker。仅活动主体键始终从声明名一致派生。
// English: Per-source and per-subject ceilings prevent either dimension from filling all workers;
// the subject ceiling exceeds the source ceiling so another source can proceed, and active-only
// subject keys are derived consistently from the claimed name.
const PASSWORD_VERIFY_PER_SOURCE: usize = 2;
const PASSWORD_VERIFY_PER_USERNAME: usize = 3;
const PASSWORD_VERIFY_RETRY_AFTER_SECS: u64 = 1;

// 中文：Digest nonce 种子键由进程随机值生成；每次重启不同，旧 nonce 自动失效。
// English: The process-random Digest nonce key changes on restart, invalidating every old-process nonce.
static NONCE_START_KEY: OnceLock<[u8; TOKEN_SECRET_BYTES]> = OnceLock::new();

/// 初始化 Digest nonce key；操作系统熵失败时返回错误而不 panic，并发首调虽可生成候选但 `OnceLock` 只发布一个。
/// Initialize the nonce key fallibly; concurrent first callers may generate candidates but `OnceLock` publishes exactly one.
fn nonce_start_key() -> Result<&'static [u8; TOKEN_SECRET_BYTES]> {
    if let Some(key) = NONCE_START_KEY.get() {
        return Ok(key);
    }
    let candidate = random_bytes::<TOKEN_SECRET_BYTES>()?;
    Ok(NONCE_START_KEY.get_or_init(|| candidate))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthSource {
    Password,
    Digest,
    Token,
    Anonymous,
}

pub(crate) enum AuthDecision {
    Allowed {
        user: Option<String>,
        access_paths: AccessPaths,
        source: AuthSource,
    },
    Forbidden {
        user: String,
        source: AuthSource,
    },
    Unauthorized,
    RateLimited {
        retry_after_secs: u64,
    },
    /// 认证基础设施饱和或有界状态不再可信；与客户端/账号限流区分，以返回 503 而非归咎凭据。
    /// Infrastructure saturation/untrusted state is distinct from throttling so callers return 503, not credential blame.
    ServiceUnavailable {
        retry_after_secs: u64,
    },
}

/// 全部认证规则的容器：用户名 → (密码, 权限树)。
/// `use_hashed_password`：任一用户使用受支持的单向密码哈希时为 true——
/// 此时只提供 Basic 认证（Digest 算法要求服务器持有明文）。
/// Container mapping usernames to credentials and ACLs. Any one-way password hash restricts the server to Basic because Digest needs plaintext-equivalent A1 material.
#[derive(Clone)]
pub struct AccessControl {
    empty: bool,
    use_hashed_password: bool,
    /// Dummy 工作使用真实已配置的统一 SHA-512-crypt/Argon2id profile；结果总被丢弃。
    /// Dummy work uses the real configured uniform SHA-512-crypt/Argon2id profile and discards its result.
    dummy_password_hash: Option<String>,
    /// 不可预测的进程生命周期明文 dummy；未知 Basic/Digest 走同一解析/计算结构但永不认证。
    /// Unpredictable process-lifetime plaintext dummy used to mirror unknown Basic/Digest work
    /// without ever authenticating it.
    dummy_plaintext_secret: String,
    /// 仅供确定性测试证明 known/unknown Basic 都真实执行一次常数时间比较，不使用 timing 断言。
    /// Test-only deterministic proof that known and unknown Basic paths both execute one real
    /// constant-time comparison, avoiding brittle timing assertions.
    #[cfg(test)]
    plaintext_comparisons: Arc<AtomicUsize>,
    /// 仅供测试统计真正提交的密码哈希 worker，和比较计数共同证明混合部署工作形状一致。
    /// Test-only count of submitted password-hash workers; together with the comparison counter it
    /// proves identical work shape in mixed hash/plaintext deployments.
    #[cfg(test)]
    password_hash_workers_started: Arc<AtomicUsize>,
    argon2id_profile: Option<Argon2idProfile>,
    users: IndexMap<String, (String, AccessPaths)>,
    /// 克隆 AccessControl 时共享同一个进程内重放缓存；否则每个
    /// Server/request 副本都有独立计数，重放保护就可被轮换副本绕过。
    /// Clones share one process replay cache; per-request copies would let rotation bypass protection.
    digest_replay: Arc<Mutex<DigestReplayCache>>,
    token_state: Option<Arc<TokenState>>,
    auth_rate: Arc<Mutex<AuthRateLimiter>>,
    password_hash_admission: Arc<PasswordHashAdmission>,
}

impl fmt::Debug for AccessControl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 中文：凭据包含 Digest 可复用明文及 Basic verifier，不能进入 Args/启动诊断；
        // 手写结构输出可防新增 secret 字段被自动 derive 打印。
        // English: Credentials include reusable Digest plaintext and Basic
        // verifiers. A structural manual Debug prevents future secret fields from being auto-printed.
        formatter
            .debug_struct("AccessControl")
            .field("empty", &self.empty)
            .field("use_hashed_password", &self.use_hashed_password)
            .field("configured_user_count", &self.users.len())
            .field("argon2id_profile", &self.argon2id_profile)
            .field(
                "persistent_revocation",
                &self
                    .token_state
                    .as_ref()
                    .is_some_and(|state| state.revocation_backend.is_some()),
            )
            .finish_non_exhaustive()
    }
}

impl PartialEq for AccessControl {
    fn eq(&self, other: &Self) -> bool {
        // 中文：只比较可声明配置；运行时重放/限流不属配置语义，也不应为比较锁两个 mutex。
        // English: Compare declarative configuration only; runtime replay/rate state is not config semantics and must not require dual locking.
        self.empty == other.empty
            && self.use_hashed_password == other.use_hashed_password
            && self.dummy_password_hash == other.dummy_password_hash
            && self.argon2id_profile == other.argon2id_profile
            && self.users == other.users
    }
}

enum AuthProof {
    Basic,
    Digest(DigestReplayAttempt),
}

enum AuthCheckOutcome {
    /// proof 与两层限流结论都已提交。 / Both the proof and the two-layer rate verdict are committed.
    Authenticated(AuthSource),
    /// 凭据已实际求值，两层暂定尝试已提交为失败。 / Credential evaluated and both provisional reservations committed as failure.
    PasswordRejected,
    /// 准入失败绝不计作错误密码。 / Admission failures never count as incorrect passwords.
    AdmissionRejected(PasswordHashAdmissionOutcome),
    /// 速率预留发现既有退避窗口。 / The rate reservation found an existing backoff window.
    RateLimited { retry_after_secs: u64 },
}

enum TokenRevocationOutcome {
    Accepted,
    Revoked,
    RateLimited { retry_after_secs: u64 },
    AdmissionRejected(PasswordHashAdmissionOutcome),
    Infrastructure(anyhow::Error),
}

enum ExpensiveAuthAdmissionFailure {
    RateLimited { retry_after_secs: u64 },
    AdmissionRejected(PasswordHashAdmissionOutcome),
}

struct CredentialCheck<'a> {
    authorization: &'a HeaderValue,
    method: &'a str,
    request_target: &'a str,
    auth_user: &'a str,
    auth_pass: &'a str,
    source: Option<SourceIdentity>,
    admission_username: &'a str,
    accept_password: bool,
}

#[derive(Clone, Copy)]
enum PasswordHashAcceptance {
    HashResult(bool),
    Fixed(bool),
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PasswordHashWorkProfile {
    Sha512Crypt { rounds: u32 },
    Argon2id(Argon2idProfile),
}

#[derive(Debug)]

/// 单次认证/授权判定所需的请求信息。聚合成结构体后，
/// 调用点不会在多个相邻 `&str`/`&Method` 之间传错位置。
/// Request information for one auth decision, grouped to prevent adjacent string/method arguments being swapped.
pub(crate) struct AuthRequest<'a> {
    pub(crate) path: &'a str,
    /// Basic/Digest 验签的真实 HTTP 方法。 / Actual HTTP method used for Basic/Digest proof verification.
    pub(crate) method: &'a Method,
    /// ACL 资源操作（POST tokengen 按 GET）。 / Resource operation for ACL; POST tokengen is treated as GET.
    pub(crate) authorization_method: &'a Method,
    pub(crate) authorization: Option<&'a HeaderValue>,
    pub(crate) request_target: &'a str,
    pub(crate) source: Option<SourceIdentity>,
    /// Token 凭据不能认证 token 签发/撤销，否则 bearer 可无限自续期。
    /// Bearer credentials cannot authorize issuance/revocation, preventing indefinite self-renewal.
    pub(crate) allow_token_auth: bool,
}

impl Default for AccessControl {
    fn default() -> Self {
        AccessControl {
            empty: true,
            use_hashed_password: false,
            dummy_password_hash: None,
            dummy_plaintext_secret: String::new(),
            #[cfg(test)]
            plaintext_comparisons: Arc::new(AtomicUsize::new(0)),
            #[cfg(test)]
            password_hash_workers_started: Arc::new(AtomicUsize::new(0)),
            argon2id_profile: None,
            users: IndexMap::new(),
            digest_replay: Arc::new(Mutex::new(DigestReplayCache::default())),
            token_state: None,
            auth_rate: Arc::new(Mutex::new(AuthRateLimiter::default())),
            password_hash_admission: Arc::new(PasswordHashAdmission::default()),
        }
    }
}

impl AccessControl {
    /// 解析 `--auth` 规则列表（形如 `user:pass@/dir1:rw,/dir2`）。
    /// 本 fork 已禁用匿名规则（`@/` 开头、无用户名的形式会报错）。
    ///
    /// 任何一条规则解析失败都**整体报错**而不是静默跳过——写错的规则被
    /// 无声吞掉时，运维会以为它已生效（与配置文件 `deny_unknown_fields`
    /// 的严格性保持一致）。报错消息一律经 [`redact_rule`] 打码：规则里
    /// 含明文密码，而启动错误常被收集进服务日志。
    /// Parse auth rules atomically, reject anonymous entries, and redact every
    /// failure because startup diagnostics are commonly logged and rules contain passwords.
    pub fn new(raw_rules: &[&str]) -> Result<Self> {
        if raw_rules.is_empty() {
            return Ok(Self::default());
        }
        let new_raw_rules = split_rules(raw_rules)?;
        let mut use_hashed_password = false;
        let mut dummy_password_hash = None;
        let mut sha512_crypt_profile = None;
        let mut argon2id_profile = None;
        let mut saw_argon2id = false;
        let mut saw_non_argon2id = false;
        let mut account_paths_pairs = vec![];
        for rule in &new_raw_rules {
            let (account, paths) = split_account_paths(rule).ok_or_else(|| {
                anyhow!(
                    "Invalid auth `{}`: missing `@/path` part",
                    redact_rule(rule)
                )
            })?;
            if account.is_empty() {
                bail!("Anonymous auth rules are disabled: `@{paths}`");
            }
            let Some((user, pass)) = account.split_once(':') else {
                bail!(
                    "Invalid auth `{}`: expected `user:pass` before `@`",
                    redact_rule(rule)
                );
            };
            if user.is_empty() || pass.is_empty() {
                bail!(
                    "Invalid auth `{}`: username and password must be non-empty",
                    redact_rule(rule)
                );
            }
            if user.len() > AUTH_USERNAME_MAX_LEN {
                bail!(
                    "Invalid auth `{}`: username exceeds {AUTH_USERNAME_MAX_LEN} bytes",
                    redact_rule(rule)
                );
            }
            account_paths_pairs.push((user, pass, paths));
        }
        let mut users = IndexMap::new();
        let mut access_path_budget = AccessPathBudget::default();
        for (user, pass, paths) in account_paths_pairs.into_iter() {
            if users.contains_key(user) {
                bail!("Duplicate auth username `{user}` is not allowed");
            }
            let mut access_paths = AccessPaths::default();
            access_paths
                .merge_with_budget(paths, &mut access_path_budget)
                .with_context(|| format!("Invalid auth path rules for user `{user}`"))?;
            if pass.starts_with("$6$") {
                saw_non_argon2id = true;
                let rounds = sha512_crypt_rounds(pass).with_context(|| {
                    format!(
                        "Invalid SHA-512-crypt password hash for user `{user}`; the credential was not logged"
                    )
                })?;
                use_hashed_password = true;
                if let Some(configured_rounds) = sha512_crypt_profile {
                    if configured_rounds != rounds {
                        bail!(
                            "All SHA-512-crypt credentials must use one uniform rounds profile; migrate every account in one operation or use a separate Ram instance"
                        );
                    }
                } else {
                    sha512_crypt_profile = Some(rounds);
                    dummy_password_hash = Some(pass.to_string());
                }
            } else if pass.starts_with("$argon2id$") {
                saw_argon2id = true;
                let profile = argon2id_profile_from_phc(pass).with_context(|| {
                    format!(
                        "Invalid Argon2id password hash for user `{user}`; the credential was not logged"
                    )
                })?;
                if let Some(configured) = argon2id_profile {
                    if configured != profile {
                        bail!(
                            "All Argon2id credentials must use one uniform m/t/p/output-length profile; migrate every account in one operation or use a separate Ram instance"
                        );
                    }
                } else {
                    argon2id_profile = Some(profile);
                    dummy_password_hash = Some(pass.to_string());
                }
                use_hashed_password = true;
            } else if pass.starts_with("$argon2i$") || pass.starts_with("$argon2d$") {
                bail!(
                    "Unsupported Argon2 variant for user `{user}`; only `$argon2id$` version 19 is accepted"
                );
            } else if pass.starts_with('$') {
                bail!(
                    "Unsupported password hash encoding for user `{user}`; only SHA-512-crypt `$6$...` and Argon2id `$argon2id$...` are accepted, and unknown PHC strings are never treated as plaintext"
                );
            } else {
                saw_non_argon2id = true;
            }
            if saw_argon2id && saw_non_argon2id {
                bail!(
                    "Argon2id credentials cannot be mixed with plaintext or SHA-512-crypt accounts; migrate every account in one operation or use a separate Ram instance"
                );
            }
            users.insert(user.to_string(), (pass.to_string(), access_paths));
        }

        Ok(Self {
            empty: false,
            use_hashed_password,
            dummy_password_hash,
            dummy_plaintext_secret: hex::encode(random_bytes::<32>()?),
            #[cfg(test)]
            plaintext_comparisons: Arc::new(AtomicUsize::new(0)),
            #[cfg(test)]
            password_hash_workers_started: Arc::new(AtomicUsize::new(0)),
            argon2id_profile,
            users,
            digest_replay: Arc::new(Mutex::new(DigestReplayCache::default())),
            token_state: Some(Arc::new(TokenState::new(
                None,
                None,
                DEFAULT_TOKEN_TTL_SECS,
                None,
            )?)),
            auth_rate: Arc::new(Mutex::new(AuthRateLimiter::default())),
            password_hash_admission: Arc::new(PasswordHashAdmission::default()),
        })
    }

    pub fn configure_security(
        &mut self,
        token_secret: Option<&[u8]>,
        token_audience: Option<&str>,
        token_ttl_secs: u64,
        token_revocation_capabilities: Option<TokenRevocationCapabilities>,
    ) -> Result<()> {
        self.token_state = Some(Arc::new(TokenState::new_with_capabilities(
            token_secret,
            token_audience,
            token_ttl_secs,
            token_revocation_capabilities,
        )?));
        Ok(())
    }

    /// 校验运维 token 设置而不生成运行 secret 或打开/创建撤销后端，是 `--check-config` 的无副作用半边。
    /// Validate token settings without generating secrets or touching persistence; used by `ram --check-config`.
    pub(crate) fn validate_security_configuration(
        &self,
        token_secret: Option<&[u8]>,
        token_audience: Option<&str>,
        token_ttl_secs: u64,
        revocation_capabilities: Option<&TokenRevocationCapabilities>,
    ) -> Result<()> {
        let _ = validated_token_secret(token_secret)?;
        let _ = validated_token_audience(token_audience)?;
        validate_token_ttl(token_ttl_secs)?;
        if let Some(capabilities) = revocation_capabilities {
            if let Some(state) = capabilities.state.existing() {
                let file = state.open_regular_file_pinned()?;
                let metadata = file.metadata()?;
                validate_revocation_file_metadata(&metadata, true)
                    .context("token revocation state failed trusted-file validation")?;
                parse_revocation_file(file, revocation_fingerprint(&metadata))
                    .context("failed to validate existing token revocation state")?;
            }
            if let Some(lock) = capabilities.lock.existing() {
                let metadata = lock.open_metadata_pinned()?.metadata()?;
                validate_revocation_file_metadata(&metadata, false)
                    .context("token revocation transaction lock failed trusted-file validation")?;
                let file = lock.open_regular_file_pinned_read_write()?;
                validate_revocation_file_metadata(&file.metadata()?, false).context(
                    "token revocation transaction lock failed read-write capability validation",
                )?;
            }
        }
        Ok(())
    }

    pub(crate) fn verify_token_revocation_capabilities(
        &self,
        expected: Option<&TokenRevocationCapabilities>,
    ) -> Result<()> {
        self.token_state
            .as_ref()
            .ok_or_else(|| anyhow!("token security state is not configured"))?
            .verify_revocation_backend_binding(expected)
    }

    /// 刷新原固定父目录下两个名称，证明锁仍是后端持有 inode，并加载状态名最新有效单调 generation；状态可替换是原子 rename 的设计。
    /// Refresh both names below the pinned parent, verify the lock inode, and load the latest monotonic state generation; state replacement is intentional.
    pub(crate) fn finalize_token_revocation_capabilities(
        &self,
        initial: Option<&TokenRevocationCapabilities>,
    ) -> Result<Option<TokenRevocationCapabilities>> {
        let current = initial
            .map(TokenRevocationCapabilities::with_current_expectations)
            .transpose()?;
        self.verify_token_revocation_capabilities(current.as_ref())?;
        Ok(current)
    }

    #[cfg(test)]
    fn configure_security_with_revocation_path(
        &mut self,
        token_secret: Option<&[u8]>,
        token_audience: Option<&str>,
        token_ttl_secs: u64,
        token_revocation_file: Option<PathBuf>,
    ) -> Result<()> {
        let capabilities = token_revocation_file
            .as_deref()
            .map(TokenRevocationCapabilities::capture)
            .transpose()?;
        self.configure_security(token_secret, token_audience, token_ttl_secs, capabilities)
    }

    pub fn has_users(&self) -> bool {
        !self.users.is_empty()
    }

    /// 所有昂贵认证槽占用时仍为普通文件系统工作保留一个 worker 的最小 Tokio blocking pool；
    /// 密码哈希或持久 token 撤销后端都会使用这些槽。
    /// Minimum blocking-pool size leaving one filesystem worker when every expensive-auth slot is
    /// occupied; password hashes and persistent token revocation both use those slots.
    #[cfg(test)]
    pub(crate) fn minimum_blocking_threads(&self) -> u64 {
        self.minimum_blocking_threads_with_persistent_revocation(false)
    }

    /// 配置检查模式不打开/创建持久后端，因此调用方把已解析的 effective 持久撤销拓扑作为
    /// hint 传入；正常运行则同时检查实际绑定后端，避免解析顺序让资源下限看见过时状态。
    /// Check-config deliberately does not open/create the durable backend, so callers provide the
    /// parsed effective topology as a hint. Run mode also inspects the bound backend, preventing
    /// validation order from observing stale security state.
    pub(crate) fn minimum_blocking_threads_with_persistent_revocation(
        &self,
        persistent_revocation_hint: bool,
    ) -> u64 {
        let persistent_revocation = persistent_revocation_hint
            || self
                .token_state
                .as_ref()
                .is_some_and(|state| state.revocation_backend.is_some());
        if self.use_hashed_password || persistent_revocation {
            PASSWORD_VERIFY_CONCURRENCY as u64 + 1
        } else {
            1
        }
    }

    /// 任一用户仍用示例占位密码时为 true，强烈表明模板未经编辑即部署。
    /// True when any user retains the example placeholder password, indicating an unedited deployment.
    pub fn has_placeholder_password(&self) -> bool {
        self.users.values().any(|(pass, _)| pass == "change-me")
    }

    /// 每个请求的认证与 ACL 判定。昂贵的密码哈希校验通过
    /// `spawn_blocking` 执行，失败退避只返回 429，不在 Tokio worker 上 sleep。
    /// Authenticate and authorize one request; expensive hashes use `spawn_blocking`, and backoff returns 429 without sleeping a Tokio worker.
    pub(crate) async fn guard(&self, request: AuthRequest<'_>) -> AuthDecision {
        let AuthRequest {
            path,
            method,
            authorization_method,
            authorization,
            request_target,
            source,
            allow_token_auth,
        } = request;
        if self.empty {
            return AuthDecision::Unauthorized;
        }

        // 中文：无凭据 OPTIONS 保持廉价匿名发现；DAV 客户端显式带凭据时必须验证并按真实 ACL
        // 收窄 Allow，错误凭据不能静默继承匿名视图而谎报能力。
        // English: Credential-free OPTIONS is cheap discovery. Supplied
        // credentials must verify so Allow reflects the principal; invalid credentials cannot inherit anonymous capabilities.
        if method == Method::OPTIONS && authorization.is_none() {
            return AuthDecision::Allowed {
                user: None,
                access_paths: AccessPaths::new(AccessPerm::ReadOnly),
                source: AuthSource::Anonymous,
            };
        }

        // 中文：Bearer 分享 token 只接受 Authorization 头，不读 URL 查询串。
        // English: Bearer share tokens are accepted only in Authorization, never the URL query.
        if let Some(authorization) = authorization {
            if let Some(token) = strip_prefix(authorization.as_bytes(), b"Bearer ")
                .and_then(|value| std::str::from_utf8(value).ok())
            {
                if !allow_token_auth {
                    return AuthDecision::Unauthorized;
                }
                return self
                    .guard_token(token, path, method, authorization_method, source)
                    .await;
            }

            let user = get_auth_user(authorization).unwrap_or_else(|| "<invalid>".to_string());
            let configured_user = self.users.get(&user);
            // 中文：每次 Basic/Digest 校验都在 `check_auth` 内先原子预留两层状态：
            // “来源+声明用户名”桶只由该用户名的成功清除；跨用户名来源预算从不因成功清零。
            // 两个键都只依赖客户端声明名而不依赖查表结果，因此既不泄露 known/unknown，
            // 也不能用低权账号成功或轮换假用户名清洗管理员猜测记录。
            // English: `check_auth` atomically reserves two layers before every Basic/Digest check.
            // Success clears only the source+claimed-name bucket; it never clears the cross-name
            // source budget. Both keys depend on the claimed name rather than lookup results, so
            // known/unknown status is not exposed and low-privilege success or fake-name rotation
            // cannot launder guesses against an administrator.
            if let Some((pass, ap)) = configured_user {
                match self
                    .check_auth(CredentialCheck {
                        authorization,
                        method: method.as_str(),
                        request_target,
                        auth_user: &user,
                        auth_pass: pass,
                        source,
                        admission_username: &user,
                        accept_password: true,
                    })
                    .await
                {
                    AuthCheckOutcome::Authenticated(auth_source) => {
                        return match ap.guard(path, authorization_method) {
                            Some(access_paths) => AuthDecision::Allowed {
                                user: Some(user),
                                access_paths,
                                source: auth_source,
                            },
                            None => AuthDecision::Forbidden {
                                user,
                                source: auth_source,
                            },
                        };
                    }
                    AuthCheckOutcome::PasswordRejected => return AuthDecision::Unauthorized,
                    AuthCheckOutcome::AdmissionRejected(outcome) => {
                        return outcome.into_decision();
                    }
                    AuthCheckOutcome::RateLimited { retry_after_secs } => {
                        return AuthDecision::RateLimited { retry_after_secs };
                    }
                }
            } else {
                // 中文：未知账号必须走与同 scheme 已知账号相同的解析/比较结构。哈希 Basic 使用
                // 统一真实 profile；明文 Basic/Digest 使用启动时 CSPRNG 生成的不可预测 dummy，
                // 且 `accept_password=false` 保证任何结果都不能认证。
                // English: Unknown accounts follow the same scheme-specific parse/comparison shape.
                // Hashed Basic uses the configured uniform real profile; plaintext Basic/Digest uses
                // an unpredictable startup-generated dummy, and `accept_password=false` makes every
                // result non-authenticating.
                let dummy_pass = if self.use_hashed_password
                    && strip_prefix(authorization.as_bytes(), b"Basic ").is_some()
                {
                    self.dummy_password_hash
                        .as_deref()
                        .unwrap_or(DUMMY_SHA512_CRYPT)
                } else {
                    &self.dummy_plaintext_secret
                };
                match self
                    .check_auth(CredentialCheck {
                        authorization,
                        method: method.as_str(),
                        request_target,
                        auth_user: &user,
                        auth_pass: dummy_pass,
                        source,
                        // 中文：昂贵准入与用户名失败桶都必须只依赖客户端声明名，不能按账号
                        // 是否存在改用 `<unknown>`，否则并发上限或退避都会成为枚举侧信道。
                        // 独立的来源预算跨全部声明名共享，用来阻止轮换绕过。
                        // English: Expensive admission must depend only on the claimed username, not
                        // account existence; substituting `<unknown>` would turn per-subject limits
                        // or backoff into an enumeration oracle. A separate source budget spans every
                        // claimed name to prevent rotation bypass.
                        admission_username: &user,
                        accept_password: false,
                    })
                    .await
                {
                    AuthCheckOutcome::PasswordRejected => return AuthDecision::Unauthorized,
                    AuthCheckOutcome::AdmissionRejected(outcome) => {
                        return outcome.into_decision();
                    }
                    AuthCheckOutcome::RateLimited { retry_after_secs } => {
                        return AuthDecision::RateLimited { retry_after_secs };
                    }
                    AuthCheckOutcome::Authenticated(_) => {
                        // 中文：`accept_password=false` 是结构性不变量；若未来改动破坏它，
                        // 仍必须 fail closed，不能把 dummy proof 变成身份。
                        // English: `accept_password=false` is structural. If a future change breaks
                        // that invariant, fail closed instead of turning a dummy proof into identity.
                        return AuthDecision::ServiceUnavailable {
                            retry_after_secs: PASSWORD_VERIFY_RETRY_AFTER_SECS,
                        };
                    }
                }
            }
        }

        AuthDecision::Unauthorized
    }

    async fn guard_token(
        &self,
        token: &str,
        path: &str,
        method: &Method,
        authorization_method: &Method,
        source: Option<SourceIdentity>,
    ) -> AuthDecision {
        if matches!(*method, Method::GET | Method::HEAD) {
            let state = match self.token_state.clone() {
                Some(state) => state,
                None => {
                    return AuthDecision::ServiceUnavailable {
                        retry_after_secs: PASSWORD_VERIFY_RETRY_AFTER_SECS,
                    };
                }
            };
            let now_secs = match unix_now() {
                Ok(now) => now.as_secs(),
                Err(err) => {
                    warn!("Bearer verification clock unavailable: {err:#}");
                    return AuthDecision::ServiceUnavailable {
                        retry_after_secs: PASSWORD_VERIFY_RETRY_AFTER_SECS,
                    };
                }
            };

            // 中文：先在 Tokio worker 上完成有 8 KiB 上限的格式、base64、HMAC 与 JSON
            // 校验。只有 MAC 通过且 `sub` 可用后，才允许该主体选择长期限流状态；坏 MAC
            // 永远不会进入持久撤销阻塞队列。
            // English: Perform the 8-KiB-bounded envelope, base64, HMAC, and JSON checks on the
            // Tokio worker first. Only a MAC-authenticated usable `sub` may select retained subject
            // state, and a bad MAC can never reach the persistent revocation blocking queue.
            let claims = match state.decode_signed_claims(token) {
                Ok(claims) if !claims.sub.is_empty() => claims,
                Ok(_) | Err(_) => return self.invalid_bearer_failure(source),
            };
            let user = claims.sub.clone();
            let subject_rate_key =
                AuthRateKey::namespaced(source, BEARER_SUBJECT_RATE_DOMAIN, &user);

            // 中文：audience、过期、路径和账号存在性失败仍有可信主体，应计入该主体桶；
            // 它们不能污染来源共享的“未验签”桶。
            // English: Audience, expiry, path, and account-existence failures still have an
            // authenticated subject and therefore charge that subject, not the shared unsigned bucket.
            if state.validate_claims(&claims, now_secs).is_err()
                || claims.path != path
                || !self.users.contains_key(&user)
            {
                return self.auth_failed_with_precheck(subject_rate_key);
            }

            let revocation_outcome = if state.revocation_backend.is_some() {
                self.verify_persistent_token_revocation(
                    state,
                    &claims,
                    subject_rate_key.clone(),
                    source,
                    &user,
                    now_secs,
                )
                .await
            } else {
                // 中文：内存后端没有阻塞 I/O，但仍在查询前应用主体退避。
                // English: The in-memory backend has no blocking I/O, but still applies subject
                // backoff before its lookup.
                if let Some(decision) = self.rate_precheck(&subject_rate_key) {
                    return decision;
                }
                match state.is_revoked(&claims.jti, now_secs) {
                    Ok(true) => {
                        return self.auth_failed(subject_rate_key);
                    }
                    Ok(false) => TokenRevocationOutcome::Accepted,
                    Err(err) => TokenRevocationOutcome::Infrastructure(err),
                }
            };
            match revocation_outcome {
                TokenRevocationOutcome::Accepted => {}
                TokenRevocationOutcome::Revoked => return AuthDecision::Unauthorized,
                TokenRevocationOutcome::RateLimited { retry_after_secs } => {
                    return AuthDecision::RateLimited { retry_after_secs };
                }
                TokenRevocationOutcome::AdmissionRejected(outcome) => {
                    return outcome.into_decision();
                }
                TokenRevocationOutcome::Infrastructure(err) => {
                    warn!("Bearer verification infrastructure unavailable: {err:#}");
                    // 中文：服务端锁/I/O/缓存失败不是错误凭据，不能修改认证失败状态。
                    // English: A server lock/I/O/cache failure is not a bad credential and must not change failure state.
                    return AuthDecision::ServiceUnavailable {
                        retry_after_secs: PASSWORD_VERIFY_RETRY_AFTER_SECS,
                    };
                }
            }

            if !self.auth_succeeded(&subject_rate_key) {
                return AuthDecision::ServiceUnavailable {
                    retry_after_secs: PASSWORD_VERIFY_RETRY_AFTER_SECS,
                };
            }
            let (_, ap) = self
                .users
                .get(&user)
                .expect("the token user was checked before revocation I/O");
            return match ap.guard(path, authorization_method) {
                Some(access_paths) => AuthDecision::Allowed {
                    user: Some(user),
                    access_paths,
                    source: AuthSource::Token,
                },
                None => AuthDecision::Forbidden {
                    user,
                    source: AuthSource::Token,
                },
            };
        }
        // 中文：签名验证前 payload 完全由攻击者控制，尤其不能把未验签 `sub` 作为保留状态键。
        // 所有畸形/无效 Bearer 按已验证传输来源共享固定桶；验证成功的 token 已在上方只使用
        // 真实主体桶，因此同源伪 token 的退避不会锁死合法 token。
        // English: The payload is attacker-controlled until its MAC verifies, so an unverified `sub`
        // must never select retained state. Malformed/invalid bearer attempts share one fixed key per
        // verified source; a verified token returns above using only its real subject bucket, so invalid
        // traffic from the same source cannot lock out a valid signed token.
        self.invalid_bearer_failure(source)
    }

    fn invalid_bearer_failure(&self, source: Option<SourceIdentity>) -> AuthDecision {
        self.auth_failed_with_precheck(AuthRateKey::namespaced(
            source,
            BEARER_INVALID_RATE_DOMAIN,
            "",
        ))
    }

    fn auth_failed_with_precheck(&self, key: AuthRateKey) -> AuthDecision {
        if let Some(decision) = self.rate_precheck(&key) {
            return decision;
        }
        self.auth_failed(key)
    }

    fn rate_precheck(&self, key: &AuthRateKey) -> Option<AuthDecision> {
        match self.rate_retry_after(key) {
            Ok(Some(retry_after_secs)) => Some(AuthDecision::RateLimited { retry_after_secs }),
            Ok(None) => None,
            Err(_) => Some(AuthDecision::ServiceUnavailable {
                retry_after_secs: PASSWORD_VERIFY_RETRY_AFTER_SECS,
            }),
        }
    }

    fn rate_retry_after(&self, key: &AuthRateKey) -> Result<Option<u64>, AuthRateStateError> {
        self.auth_rate
            .lock()
            .map_err(|_| AuthRateStateError::Unavailable)
            .map(|mut limiter| limiter.retry_after(key, Instant::now()))
    }

    fn auth_failed(&self, key: AuthRateKey) -> AuthDecision {
        match self.auth_rate.lock() {
            Ok(mut limiter) => match limiter.failed(key, Instant::now()) {
                Ok(Some(retry_after_secs)) => AuthDecision::RateLimited { retry_after_secs },
                Ok(None) => AuthDecision::Unauthorized,
                Err(AuthRateStateError::Capacity | AuthRateStateError::Unavailable) => {
                    AuthDecision::ServiceUnavailable {
                        retry_after_secs: PASSWORD_VERIFY_RETRY_AFTER_SECS,
                    }
                }
            },
            Err(_) => AuthDecision::ServiceUnavailable {
                retry_after_secs: PASSWORD_VERIFY_RETRY_AFTER_SECS,
            },
        }
    }

    fn auth_succeeded(&self, key: &AuthRateKey) -> bool {
        let Ok(mut limiter) = self.auth_rate.lock() else {
            return false;
        };
        limiter.succeeded(key);
        true
    }

    /// 中文：测试用确定性工作计划；统一 profile 后 known/unknown 都恰好执行一个同成本哈希。
    /// English: Deterministic test work plan: with uniform profiles, known and unknown users perform
    /// exactly one hash of the same cost.
    #[cfg(test)]
    fn password_hash_work_plan(
        &self,
        configured_hash: Option<&str>,
    ) -> Result<Vec<PasswordHashWorkProfile>> {
        let hash = configured_hash
            .or(self.dummy_password_hash.as_deref())
            .ok_or_else(|| anyhow!("password hash work is not configured"))?;
        let profile = if hash.starts_with("$6$") {
            PasswordHashWorkProfile::Sha512Crypt {
                rounds: sha512_crypt_rounds(hash)?,
            }
        } else {
            PasswordHashWorkProfile::Argon2id(argon2id_profile_from_phc(hash)?)
        };
        Ok(vec![profile])
    }

    /// 无条件执行候选与选定 verifier 的常数时间比较，再由调用方单独应用 `accept_password`。
    /// 不能把授权布尔放在 `&&` 左侧，否则 unknown 的 `false` 会短路掉 dummy 工作。
    /// Always compare the candidate with the selected verifier before separately applying
    /// `accept_password`; placing that policy flag on the left of `&&` would skip dummy work for
    /// unknown accounts.
    fn compare_plaintext_password(&self, candidate: &[u8], verifier: &[u8]) -> bool {
        #[cfg(test)]
        self.plaintext_comparisons.fetch_add(1, Ordering::Relaxed);
        constant_time_eq(candidate, verifier)
    }

    #[cfg(test)]
    fn plaintext_comparison_count(&self) -> usize {
        self.plaintext_comparisons.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn password_hash_worker_count(&self) -> usize {
        self.password_hash_workers_started.load(Ordering::Relaxed)
    }

    async fn check_auth(&self, check: CredentialCheck<'_>) -> AuthCheckOutcome {
        let CredentialCheck {
            authorization,
            method,
            request_target,
            auth_user,
            auth_pass,
            source,
            admission_username,
            accept_password,
        } = check;

        // 中文：两层状态在账号查找结果进入校验分支后、任何阻塞 worker 启动前一次性预留。
        // 用户名键始终采用声明值，所以同一个名字无论存在与否都走完全相同的限流域；来源键
        // 在所有名字间共享且成功不清零，负责限制假用户名轮换。
        // English: Reserve both layers after selecting the verification inputs but before any
        // blocking worker starts. The principal key always uses the claimed name, so existence never
        // changes its domain; the source key is shared across names and is not reset by success,
        // bounding fake-name rotation.
        let reservation = match PasswordRateReservation::reserve(
            self.auth_rate.clone(),
            AuthRateKey::namespaced(source, PASSWORD_SOURCE_RATE_DOMAIN, ""),
            AuthRateKey::namespaced(source, PASSWORD_PRINCIPAL_RATE_DOMAIN, auth_user),
        ) {
            Ok(reservation) => reservation,
            Err(rejection) => return self.password_rate_rejection(rejection),
        };
        if strip_prefix(authorization.as_bytes(), b"Basic ").is_some() {
            let Some((user, password)) = decode_basic_credentials(authorization) else {
                return self.finish_password_check(reservation, None);
            };
            if user != auth_user {
                return self.finish_password_check(reservation, None);
            }

            if self.use_hashed_password {
                // 中文：允许 SHA-512-crypt 与明文账号混用，因此三个可观察分支必须形状一致：
                // 已知 hash、已知明文和 unknown 都先做一次 HMAC 常数时间比较，再做一次统一
                // profile 哈希。hash/unknown 的比较使用同一个不可预测明文 dummy；明文账号比较
                // 真实 verifier。dummy 比较结果不参与 hash 账号授权。
                // English: SHA-512-crypt may coexist with plaintext accounts, so all observable
                // branches—known hash, known plaintext, and unknown—perform one HMAC constant-time
                // comparison followed by one uniform-profile hash. Hash/unknown branches compare
                // against the same unpredictable plaintext dummy; plaintext accounts use their real
                // verifier. The dummy comparison never influences hash-account acceptance.
                let uses_hash_credential = is_supported_password_hash(auth_pass);
                let plaintext_verifier = if uses_hash_credential {
                    self.dummy_plaintext_secret.as_bytes()
                } else {
                    auth_pass.as_bytes()
                };
                let plaintext_matches =
                    self.compare_plaintext_password(password.as_bytes(), plaintext_verifier);
                let (verification_hash, acceptance) = if uses_hash_credential {
                    (
                        auth_pass.to_string(),
                        PasswordHashAcceptance::HashResult(accept_password),
                    )
                } else {
                    (
                        self.dummy_password_hash
                            .clone()
                            .unwrap_or_else(|| DUMMY_SHA512_CRYPT.to_string()),
                        PasswordHashAcceptance::Fixed(plaintext_matches && accept_password),
                    )
                };
                return self
                    .verify_password_hash(
                        password.into_bytes(),
                        verification_hash,
                        acceptance,
                        reservation,
                        source,
                        admission_username,
                    )
                    .await;
            }

            // 中文：构造阶段保证非哈希部署没有 hash verifier；保留此防御分支防未来调用方
            // 绕过构造不变量时把 PHC/crypt 字符串当明文接受。
            // English: Construction guarantees a non-hashed deployment has no hash verifier. Keep
            // this defensive branch so a future caller cannot treat PHC/crypt text as plaintext by
            // bypassing that invariant.
            if is_supported_password_hash(auth_pass) {
                return self.finish_password_check(reservation, None);
            }

            let proof_matches =
                self.compare_plaintext_password(password.as_bytes(), auth_pass.as_bytes());
            return if proof_matches && accept_password {
                self.finish_password_check(reservation, Some(AuthSource::Password))
            } else {
                self.finish_password_check(reservation, None)
            };
        }

        // 中文：实例含密码哈希时 Digest 对所有声明用户名统一禁用；不能让 known 看到哈希后
        // 提前返回、unknown 却用 dummy 做完整 Digest，从而形成 timing oracle。
        // English: When the instance uses password hashes, Digest is uniformly disabled for every
        // claimed username; known hashes must not return early while unknown dummies do full work.
        if self.use_hashed_password {
            return self.finish_password_check(reservation, None);
        }

        match check_auth(authorization, method, request_target, auth_user, auth_pass) {
            Some(proof) if accept_password => {
                if self.accept_auth_proof(proof, source) {
                    self.finish_password_check(reservation, Some(AuthSource::Digest))
                } else {
                    self.finish_password_check(reservation, None)
                }
            }
            Some(_) | None => self.finish_password_check(reservation, None),
        }
    }

    fn password_rate_rejection(&self, rejection: HashAttemptReservationReject) -> AuthCheckOutcome {
        match rejection {
            HashAttemptReservationReject::Blocked { retry_after_secs } => {
                AuthCheckOutcome::RateLimited { retry_after_secs }
            }
            HashAttemptReservationReject::ConcurrentAttemptLimit => {
                let outcome = PasswordHashAdmissionOutcome::ConcurrentAttemptLimit;
                self.password_hash_admission.reject_without_guard(outcome);
                AuthCheckOutcome::AdmissionRejected(outcome)
            }
            HashAttemptReservationReject::StateCapacity => {
                let outcome = PasswordHashAdmissionOutcome::RateStateCapacity;
                self.password_hash_admission.reject_without_guard(outcome);
                AuthCheckOutcome::AdmissionRejected(outcome)
            }
            HashAttemptReservationReject::StateUnavailable => {
                let outcome = PasswordHashAdmissionOutcome::RateStateUnavailable;
                self.password_hash_admission.reject_without_guard(outcome);
                AuthCheckOutcome::AdmissionRejected(outcome)
            }
        }
    }

    /// 提交非阻塞 Basic/Digest 的双层状态；成功只清声明用户名，来源层由 reservation 取消
    /// pending 而保留历史失败。任何状态异常都 fail closed 为 503。
    /// Commit both layers for non-blocking Basic/Digest work. Success clears only the claimed name;
    /// the reservation cancels its source pending slot while retaining prior source failures. Any
    /// state inconsistency fails closed as 503.
    fn finish_password_check(
        &self,
        reservation: PasswordRateReservation,
        authenticated_source: Option<AuthSource>,
    ) -> AuthCheckOutcome {
        if !reservation.finish(authenticated_source.is_some()) {
            let outcome = PasswordHashAdmissionOutcome::RateStateUnavailable;
            self.password_hash_admission.reject_without_guard(outcome);
            return AuthCheckOutcome::AdmissionRejected(outcome);
        }
        match authenticated_source {
            Some(source) => AuthCheckOutcome::Authenticated(source),
            None => AuthCheckOutcome::PasswordRejected,
        }
    }

    async fn verify_password_hash(
        &self,
        password: Vec<u8>,
        password_hash: String,
        acceptance: PasswordHashAcceptance,
        reservation: PasswordRateReservation,
        source: Option<SourceIdentity>,
        admission_username: &str,
    ) -> AuthCheckOutcome {
        // 中文：双层失败预留已在 `check_auth` 中原子取得；从这里起，它会随准入等待并最终
        // 移入真实 hash worker，HTTP future 取消不能提前释放任一层。
        // English: `check_auth` already acquired the two-layer failure reservation atomically. It
        // now survives admission waiting and moves into the real hash worker, so cancellation cannot
        // release either layer early.
        let admission_guard = match self
            .password_hash_admission
            .try_reserve(source, admission_username)
        {
            Ok(guard) => guard,
            Err(outcome) => return AuthCheckOutcome::AdmissionRejected(outcome),
        };
        let queue_started = Instant::now();
        let permit = match tokio::time::timeout(
            self.password_hash_admission.queue_timeout,
            self.password_hash_admission
                .verify_limit
                .clone()
                .acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => {
                admission_guard.reject(PasswordHashAdmissionOutcome::QueueClosed);
                return AuthCheckOutcome::AdmissionRejected(
                    PasswordHashAdmissionOutcome::QueueClosed,
                );
            }
            Err(_) => {
                admission_guard.reject(PasswordHashAdmissionOutcome::QueueTimeout);
                return AuthCheckOutcome::AdmissionRejected(
                    PasswordHashAdmissionOutcome::QueueTimeout,
                );
            }
        };

        // 中文：等待其他来源期间退避可能变化；取得全局执行槽后再检查。中止尝试释放槽与暂定预留，
        // 不运行也不记录密码哈希失败。
        // English: Recheck backoff after acquiring a global slot. Aborted
        // attempts release the slot/reservation without running or recording a hash failure.
        match reservation.blocked_after_global_permit() {
            Ok(Some(retry_after_secs)) => {
                let outcome =
                    PasswordHashAdmissionOutcome::BlockedAfterGlobalPermit { retry_after_secs };
                admission_guard.reject(outcome);
                drop(permit);
                return AuthCheckOutcome::AdmissionRejected(outcome);
            }
            Ok(None) => {}
            Err(_) => {
                let outcome = PasswordHashAdmissionOutcome::RateStateUnavailable;
                admission_guard.reject(outcome);
                drop(permit);
                return AuthCheckOutcome::AdmissionRejected(outcome);
            }
        }

        let (worker_lease, snapshot) =
            match PasswordHashWorkerLease::start(permit, admission_guard, reservation) {
                Ok(value) => value,
                Err(outcome) => {
                    self.password_hash_admission.reject_without_guard(outcome);
                    return AuthCheckOutcome::AdmissionRejected(outcome);
                }
            };
        let queue_wait = queue_started.elapsed();
        #[cfg(test)]
        self.password_hash_workers_started
            .fetch_add(1, Ordering::Relaxed);
        let worker = tokio::task::spawn_blocking(move || {
            // 中文：全局 permit、按键 in-flight guard 与暂定预留都由阻塞闭包持有；丢弃请求 future
            // 不能在分离 CPU 工作仍运行时释放容量或抹掉失败。
            // English: The blocking closure owns every permit/guard/reservation,
            // so dropping the request cannot release capacity while CPU work remains.
            let hash_started = Instant::now();
            let verified = verify_supported_password_hash(&password, password_hash.as_str());
            let accepted = match acceptance {
                PasswordHashAcceptance::HashResult(accept_result) => {
                    verified && accept_result
                }
                PasswordHashAcceptance::Fixed(value) => value,
            };
            // 中文：worker 仍持有全部准入资源时提交已求值凭据；取消 HTTP future 不能把错误密码变成免费尝试。
            // English: Commit evaluated credentials while the worker owns admission resources; cancellation cannot make a wrong password free.
            let rate_state_committed = worker_lease.finish(accepted);
            let hash_elapsed = hash_started.elapsed();
            debug!(
                "Password hash verification completed: auth_hash_outcome={} queue_wait_ms={} hash_time_ms={} queued_at_start={} active_at_start={} in_flight_at_start={}",
                if accepted { "accepted" } else { "rejected" },
                queue_wait.as_millis(),
                hash_elapsed.as_millis(),
                snapshot.queued,
                snapshot.active,
                snapshot.in_flight,
            );
            (accepted, rate_state_committed)
        })
        .await;

        let (accepted, rate_state_committed) = match worker {
            Ok(result) => result,
            Err(err) => {
                self.password_hash_admission
                    .reject_without_guard(PasswordHashAdmissionOutcome::WorkerFailed);
                warn!("Password hash worker failed: error={err}");
                return AuthCheckOutcome::AdmissionRejected(
                    PasswordHashAdmissionOutcome::WorkerFailed,
                );
            }
        };
        if !rate_state_committed {
            self.password_hash_admission
                .reject_without_guard(PasswordHashAdmissionOutcome::RateStateUnavailable);
            return AuthCheckOutcome::AdmissionRejected(
                PasswordHashAdmissionOutcome::RateStateUnavailable,
            );
        }
        if accepted {
            AuthCheckOutcome::Authenticated(AuthSource::Password)
        } else {
            AuthCheckOutcome::PasswordRejected
        }
    }

    fn accept_auth_proof(&self, proof: AuthProof, source: Option<SourceIdentity>) -> bool {
        match proof {
            AuthProof::Basic => true,
            AuthProof::Digest(attempt) => {
                let Ok(now) = unix_now() else {
                    return false;
                };
                // 中文：mutex 中毒表示持锁代码曾 panic，无法确定已接受 nc，必须 fail closed，不能 `into_inner` 放行。
                // English: Poisoning makes accepted replay state unknowable; fail closed rather than recovering with `into_inner`.
                let Ok(mut cache) = self.digest_replay.lock() else {
                    return false;
                };
                match cache.accept(attempt, source, now.as_secs()) {
                    Ok(()) => true,
                    Err(reason) => {
                        warn!(
                            "Rejected Digest replay proof: reason={reason:?} entries={} capacity={} utilization_percent={} dynamic_key_bytes={} dynamic_key_budget_bytes={}",
                            cache.entry_count,
                            cache.capacity,
                            cache.entry_count.saturating_mul(100) / cache.capacity.max(1),
                            cache.dynamic_key_bytes,
                            DIGEST_REPLAY_MAX_DYNAMIC_KEY_BYTES,
                        );
                        false
                    }
                }
            }
        }
    }

    /// 为**已认证**的 `user` 授权 COPY/MOVE 的 `Destination` 目标路径。
    ///
    /// 有意跳过密码/Digest 验证：请求携带的那一个 Authorization 头已经
    /// 针对真实请求目标（源路径）验证过一次，若对目标路径重跑 Digest
    /// 校验，要么必然失败、要么得要求客户端为一个它从未请求过的 URI
    /// 签名。目标路径一律要求**读写**权限——不管 COPY/MOVE 对源路径
    /// 只需要什么权限，对目标都是在写入。
    /// Authorize COPY/MOVE Destination for an already authenticated user. Do
    /// not rerun Digest against an unrequested URI; always require ReadWrite on the destination.
    pub fn guard_dest_for_user(&self, user: &str, path: &str) -> Option<AccessPaths> {
        let (_, ap) = self.users.get(user)?;
        ap.guard_write(path)
    }

    /// 主体是否至少有一个可能写目标；OPTIONS 仅用来避免向匿名/全局只读主体声明 COPY，实际请求仍逐目标检查。
    /// Whether the principal has any possible write destination; OPTIONS uses this only for advertisement, while each COPY checks its concrete target.
    pub(crate) fn user_has_write_access(&self, user: &str) -> bool {
        self.users
            .get(user)
            .is_some_and(|(_, paths)| paths.has_write_access())
    }

    /// 签发绑定 audience、路径、短期过期与唯一 jti 的 Bearer token。 / Issue a bearer token bound to audience, path, short expiry, and unique jti.
    pub fn generate_token(&self, path: &str, user: &str) -> Result<String> {
        self.users
            .get(user)
            .ok_or_else(|| anyhow!("Not found user '{user}'"))?;
        let state = self
            .token_state
            .as_deref()
            .ok_or_else(|| anyhow!("token subsystem is not configured"))?;
        let iat = unix_now()?.as_secs();
        let exp = iat
            .checked_add(state.ttl_secs)
            .ok_or_else(|| anyhow!("Token expiration timestamp overflow"))?;
        state.sign(&TokenClaims {
            v: TOKEN_VERSION,
            sub: user.to_string(),
            path: path.to_string(),
            aud: state.audience.clone(),
            iat,
            exp,
            jti: hex::encode(random_bytes::<16>()?),
        })
    }

    async fn acquire_expensive_auth_worker_lease(
        &self,
        rate_key: AuthRateKey,
        source: Option<SourceIdentity>,
        admission_domain: &[u8],
        admission_subject: &str,
    ) -> std::result::Result<PasswordHashWorkerLease, ExpensiveAuthAdmissionFailure> {
        // 中文：暂定认证预留与同主体并发请求原子竞争；它在昂贵 worker 返回前阻止并发突发
        // 共同看到旧状态。验证 worker 提交 valid/revoked，撤销写 worker 成功时提交 valid；
        // 基础设施失败均由 Drop 取消而不伪造凭据失败。
        // English: A provisional authentication reservation races atomically with same-subject peers,
        // preventing a burst from sharing stale state before expensive workers return. Verification
        // commits valid/revoked, successful mutation commits valid, and infrastructure failure Drop
        // cancels without inventing a credential failure.
        let reservation = match HashAttemptReservation::reserve(self.auth_rate.clone(), rate_key) {
            Ok(reservation) => reservation,
            Err(HashAttemptReservationReject::Blocked { retry_after_secs }) => {
                return Err(ExpensiveAuthAdmissionFailure::RateLimited { retry_after_secs });
            }
            Err(HashAttemptReservationReject::ConcurrentAttemptLimit) => {
                let outcome = PasswordHashAdmissionOutcome::ConcurrentAttemptLimit;
                self.password_hash_admission.reject_without_guard(outcome);
                return Err(ExpensiveAuthAdmissionFailure::AdmissionRejected(outcome));
            }
            Err(HashAttemptReservationReject::StateCapacity) => {
                let outcome = PasswordHashAdmissionOutcome::RateStateCapacity;
                self.password_hash_admission.reject_without_guard(outcome);
                return Err(ExpensiveAuthAdmissionFailure::AdmissionRejected(outcome));
            }
            Err(HashAttemptReservationReject::StateUnavailable) => {
                let outcome = PasswordHashAdmissionOutcome::RateStateUnavailable;
                self.password_hash_admission.reject_without_guard(outcome);
                return Err(ExpensiveAuthAdmissionFailure::AdmissionRejected(outcome));
            }
        };

        // 中文：复用昂贵认证的全局、来源、主体与排队上限；持久撤销 I/O 和密码哈希共享
        // 同一个阻塞工作预算，不能分别把 Tokio 阻塞池压满。
        // English: Reuse global, source, subject, and queue bounds for expensive authentication.
        // Persistent revocation I/O and password hashing share one blocking-work budget instead of
        // independently saturating Tokio's blocking pool.
        let admission_guard = match self.password_hash_admission.try_reserve_namespaced(
            source,
            admission_domain,
            admission_subject,
        ) {
            Ok(guard) => guard,
            Err(outcome) => {
                return Err(ExpensiveAuthAdmissionFailure::AdmissionRejected(outcome));
            }
        };
        let permit = match tokio::time::timeout(
            self.password_hash_admission.queue_timeout,
            self.password_hash_admission
                .verify_limit
                .clone()
                .acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => {
                let outcome = PasswordHashAdmissionOutcome::QueueClosed;
                admission_guard.reject(outcome);
                return Err(ExpensiveAuthAdmissionFailure::AdmissionRejected(outcome));
            }
            Err(_) => {
                let outcome = PasswordHashAdmissionOutcome::QueueTimeout;
                admission_guard.reject(outcome);
                return Err(ExpensiveAuthAdmissionFailure::AdmissionRejected(outcome));
            }
        };
        match reservation.blocked_after_global_permit() {
            Ok(Some(retry_after_secs)) => {
                let outcome =
                    PasswordHashAdmissionOutcome::BlockedAfterGlobalPermit { retry_after_secs };
                admission_guard.reject(outcome);
                drop(permit);
                return Err(ExpensiveAuthAdmissionFailure::AdmissionRejected(outcome));
            }
            Ok(None) => {}
            Err(_) => {
                let outcome = PasswordHashAdmissionOutcome::RateStateUnavailable;
                admission_guard.reject(outcome);
                drop(permit);
                return Err(ExpensiveAuthAdmissionFailure::AdmissionRejected(outcome));
            }
        }

        match PasswordHashWorkerLease::start(permit, admission_guard, reservation) {
            Ok((worker_lease, _snapshot)) => Ok(worker_lease),
            Err(outcome) => {
                self.password_hash_admission.reject_without_guard(outcome);
                Err(ExpensiveAuthAdmissionFailure::AdmissionRejected(outcome))
            }
        }
    }

    async fn verify_persistent_token_revocation(
        &self,
        state: Arc<TokenState>,
        claims: &TokenClaims,
        rate_key: AuthRateKey,
        source: Option<SourceIdentity>,
        admission_subject: &str,
        now_secs: u64,
    ) -> TokenRevocationOutcome {
        let worker_lease = match self
            .acquire_expensive_auth_worker_lease(
                rate_key,
                source,
                BEARER_REVOCATION_ADMISSION_DOMAIN,
                admission_subject,
            )
            .await
        {
            Ok(lease) => lease,
            Err(ExpensiveAuthAdmissionFailure::RateLimited { retry_after_secs }) => {
                return TokenRevocationOutcome::RateLimited { retry_after_secs };
            }
            Err(ExpensiveAuthAdmissionFailure::AdmissionRejected(outcome)) => {
                return TokenRevocationOutcome::AdmissionRejected(outcome);
            }
        };
        let jti = claims.jti.clone();
        #[cfg(test)]
        state
            .revocation_workers_started
            .fetch_add(1, Ordering::Relaxed);
        let worker = tokio::task::spawn_blocking(move || match state.is_revoked(&jti, now_secs) {
            Ok(revoked) => {
                // 中文：真实 worker 在仍持有全部 admission/permit 时提交结果；valid 清除主体
                // 失败，revoked 提交一次失败。I/O 错误则由 Drop 仅取消暂定预留。
                // English: The real worker commits while owning every admission resource: valid
                // clears subject failures, revoked commits one failure, and I/O error Drop merely
                // cancels the provisional reservation.
                let committed = worker_lease.finish(!revoked);
                Ok((revoked, committed))
            }
            Err(err) => Err(err),
        })
        .await;
        let (revoked, committed) = match worker {
            Ok(Ok(result)) => result,
            Ok(Err(err)) => return TokenRevocationOutcome::Infrastructure(err),
            Err(err) => {
                let outcome = PasswordHashAdmissionOutcome::WorkerFailed;
                self.password_hash_admission.reject_without_guard(outcome);
                return TokenRevocationOutcome::Infrastructure(anyhow!(
                    "token revocation worker failed: {err}"
                ));
            }
        };
        if !committed {
            let outcome = PasswordHashAdmissionOutcome::RateStateUnavailable;
            self.password_hash_admission.reject_without_guard(outcome);
            return TokenRevocationOutcome::AdmissionRejected(outcome);
        }
        if revoked {
            TokenRevocationOutcome::Revoked
        } else {
            TokenRevocationOutcome::Accepted
        }
    }

    pub async fn revoke_token(
        &self,
        token: &str,
        user: &str,
        path: &str,
        source: Option<SourceIdentity>,
    ) -> std::result::Result<(), TokenRevokeError> {
        let state = self.token_state.clone().ok_or_else(|| {
            TokenRevokeError::Infrastructure(anyhow!("token subsystem is not configured"))
        })?;
        let now = unix_now()
            .map_err(TokenRevokeError::Infrastructure)?
            .as_secs();
        let claims = state.verify(token, now, false).map_err(|err| match err {
            TokenVerifyFailure::Invalid(err) => TokenRevokeError::Invalid(err),
            TokenVerifyFailure::Infrastructure(err) => TokenRevokeError::Infrastructure(err),
        })?;
        if claims.sub != user || claims.path != path {
            return Err(TokenRevokeError::Invalid(anyhow!(
                "token does not belong to this principal and resource"
            )));
        }
        if state.revocation_backend.is_none() {
            return state
                .revoke(claims.jti, claims.exp, now)
                .map_err(TokenRevokeError::Infrastructure);
        }

        let worker_lease = self
            .acquire_expensive_auth_worker_lease(
                AuthRateKey::namespaced(source, TOKEN_REVOKE_RATE_DOMAIN, user),
                source,
                TOKEN_REVOKE_ADMISSION_DOMAIN,
                user,
            )
            .await
            .map_err(|failure| match failure {
                ExpensiveAuthAdmissionFailure::RateLimited { retry_after_secs } => {
                    TokenRevokeError::RateLimited { retry_after_secs }
                }
                ExpensiveAuthAdmissionFailure::AdmissionRejected(outcome) => {
                    match outcome.into_decision() {
                        AuthDecision::RateLimited { retry_after_secs } => {
                            TokenRevokeError::RateLimited { retry_after_secs }
                        }
                        AuthDecision::ServiceUnavailable { .. } => {
                            TokenRevokeError::Infrastructure(anyhow!(
                                "token revocation admission rejected: {outcome:?}"
                            ))
                        }
                        _ => unreachable!("admission outcomes only map to 429 or 503"),
                    }
                }
            })?;
        #[cfg(test)]
        state
            .revocation_mutation_workers_started
            .fetch_add(1, Ordering::Relaxed);
        let worker =
            tokio::task::spawn_blocking(move || match state.revoke(claims.jti, claims.exp, now) {
                Ok(()) => {
                    if worker_lease.finish(true) {
                        Ok(())
                    } else {
                        Err(anyhow!("authentication rate state became unavailable"))
                    }
                }
                Err(err) => Err(err),
            })
            .await;
        match worker {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(TokenRevokeError::Infrastructure(err)),
            Err(err) => {
                self.password_hash_admission
                    .reject_without_guard(PasswordHashAdmissionOutcome::WorkerFailed);
                Err(TokenRevokeError::Infrastructure(anyhow!(
                    "token revocation worker failed: {err}"
                )))
            }
        }
    }
}

/// 在 401 响应上设置 `WWW-Authenticate` 挑战头，告诉客户端支持哪些
/// 认证方式。密码以哈希存储时只能挑战 Basic；否则提供
/// RFC 7616 SHA-256 Digest（优先）和 Basic。
/// Set WWW-Authenticate challenges. Hashed-password mode offers only Basic;
/// plaintext-equivalent mode prefers RFC 7616 SHA-256 Digest and also offers Basic.
pub fn www_authenticate(res: &mut Response, args: &Args) -> Result<()> {
    if args.auth.use_hashed_password {
        let basic = HeaderValue::from_str(&format!("Basic realm=\"{REALM}\""))?;
        res.headers_mut().insert(WWW_AUTHENTICATE, basic);
    } else {
        let nonce = create_nonce()?;
        let digest = HeaderValue::from_str(&format!(
            "Digest realm=\"{REALM}\", nonce=\"{nonce}\", algorithm=SHA-256, qop=\"auth\""
        ))?;
        let basic = HeaderValue::from_str(&format!("Basic realm=\"{REALM}\""))?;
        res.headers_mut().append(WWW_AUTHENTICATE, digest);
        res.headers_mut().append(WWW_AUTHENTICATE, basic);
    }
    Ok(())
}

/// 从 Authorization 头里提取“自称”的用户名（Basic 解 base64 取冒号前段，Digest 取
/// username 字段）。只用于一致的账号查找和仅活动 admission，绝不作为已认证身份或长期
/// known/unknown 限流分区；验证在 `check_auth`。
/// Extract the claimed Basic/Digest username only for consistent account lookup and active-only
/// admission. It is neither an authenticated identity nor a retained known/unknown rate partition;
/// proof verification happens in `check_auth`.
pub fn get_auth_user(authorization: &HeaderValue) -> Option<String> {
    if let Some(value) = strip_prefix(authorization.as_bytes(), b"Basic ") {
        let value: Vec<u8> = STANDARD.decode(value).ok()?;
        let parts: Vec<&str> = std::str::from_utf8(&value).ok()?.split(':').collect();
        Some(parts[0].to_string())
    } else if let Some(value) = strip_prefix(authorization.as_bytes(), b"Digest ") {
        let digest_map = to_headermap(value).ok()?;
        let username = digest_param(&digest_map, b"username")?;
        std::str::from_utf8(username).map(ToOwned::to_owned).ok()
    } else {
        None
    }
}

fn decode_basic_credentials(authorization: &HeaderValue) -> Option<(String, String)> {
    let value = strip_prefix(authorization.as_bytes(), b"Basic ")?;
    let value = STANDARD.decode(value).ok()?;
    let value = std::str::from_utf8(&value).ok()?;
    let (user, password) = value.split_once(':')?;
    Some((user.to_string(), password.to_string()))
}

#[cfg(test)]
// 物理目录刻意避开 `tests/`，以免命中覆盖率的集成测试排除规则；逻辑模块名仍保持
// `tests`，从而维持被子进程 `--exact` 调用的测试路径。
// The physical directory deliberately avoids `tests/`, which the coverage job excludes as an
// integration-test tree. The logical module remains `tests` to preserve subprocess `--exact` paths.
#[path = "test_suite/mod.rs"]
mod tests;
