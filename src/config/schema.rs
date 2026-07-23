//! 反序列化配置模式、标量解析器与默认值。YAML 拒绝未知字段，secret 的 Debug 不暴露内容，
//! 默认值均为有界生产值。
//!
//! Deserialized configuration schema, scalar parsers and defaults.
//!
//! Invariant: YAML remains deny-unknown-fields and secret values never expose
//! their contents through `Debug`; defaults are bounded production values.

use super::*;
/// 服务端只读持有的完整合并/校验配置；拒绝未知 YAML，避免拼错安全开关静默回落默认。
/// Fully merged validated read-only configuration; unknown YAML fields are rejected rather than defaulted.
#[derive(Debug, Deserialize, SmartDefault, PartialEq)]
#[serde(default)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct Args {
    #[serde(default = "default_serve_path")]
    #[default(default_serve_path())]
    pub serve_path: PathBuf,
    #[serde(deserialize_with = "deserialize_bind_addrs")]
    #[serde(rename = "bind")]
    #[serde(default = "default_addrs")]
    #[default(default_addrs())]
    pub addrs: Vec<BindAddr>,
    #[serde(default = "default_port")]
    #[default(default_port())]
    pub port: u16,
    #[serde(skip)]
    pub path_is_file: bool,
    #[serde(skip)]
    pub(crate) startup_paths: Option<StartupPathIdentities>,
    pub path_prefix: String,
    #[serde(skip)]
    pub uri_prefix: String,
    #[serde(deserialize_with = "deserialize_string_or_vec")]
    pub hidden: Vec<String>,
    #[serde(deserialize_with = "deserialize_access_control")]
    pub auth: AccessControl,
    pub auth_file: Option<PathBuf>,
    pub allow_insecure_http: bool,
    pub allow_filesystem_root: bool,
    pub allow_all: bool,
    pub allow_upload: bool,
    pub allow_delete: bool,
    pub allow_search: bool,
    pub allow_symlink: bool,
    pub allow_archive: bool,
    #[serde(deserialize_with = "deserialize_log_http")]
    #[serde(rename = "log-format")]
    pub http_logger: HttpLogger,
    pub compress: Compress,
    #[serde(default = "default_max_connections")]
    #[default(default_max_connections())]
    pub max_connections: u64,
    #[serde(default = "default_max_concurrent_requests")]
    #[default(default_max_concurrent_requests())]
    pub max_concurrent_requests: u64,
    #[serde(default = "default_max_concurrent_requests_per_source")]
    #[default(default_max_concurrent_requests_per_source())]
    pub max_concurrent_requests_per_source: u64,
    #[serde(default = "default_max_concurrent_requests_per_user")]
    #[default(default_max_concurrent_requests_per_user())]
    pub max_concurrent_requests_per_user: u64,
    #[serde(default = "default_max_request_queue")]
    #[default(default_max_request_queue())]
    pub max_request_queue: u64,
    #[serde(
        default = "default_request_queue_timeout_secs",
        deserialize_with = "deserialize_timeout_secs"
    )]
    #[default(default_request_queue_timeout_secs())]
    pub request_queue_timeout: u64,
    #[serde(
        default = "default_header_read_timeout_secs",
        deserialize_with = "deserialize_timeout_secs"
    )]
    #[default(default_header_read_timeout_secs())]
    pub header_read_timeout: u64,
    #[serde(
        default = "default_connection_idle_timeout_secs",
        deserialize_with = "deserialize_timeout_secs"
    )]
    #[default(default_connection_idle_timeout_secs())]
    pub connection_idle_timeout: u64,
    #[serde(
        default = "default_connection_max_lifetime_secs",
        deserialize_with = "deserialize_timeout_secs"
    )]
    #[default(default_connection_max_lifetime_secs())]
    pub connection_max_lifetime: u64,
    #[serde(
        default = "default_response_write_idle_timeout_secs",
        deserialize_with = "deserialize_timeout_secs"
    )]
    #[default(default_response_write_idle_timeout_secs())]
    pub response_write_idle_timeout: u64,
    #[serde(
        default = "default_write_lock_timeout_secs",
        deserialize_with = "deserialize_timeout_secs"
    )]
    #[default(default_write_lock_timeout_secs())]
    pub write_lock_timeout: u64,
    #[serde(
        default = "default_upload_file_mode",
        deserialize_with = "deserialize_permission_mode"
    )]
    #[default(default_upload_file_mode())]
    pub upload_file_mode: u32,
    #[serde(
        default = "default_upload_dir_mode",
        deserialize_with = "deserialize_permission_mode"
    )]
    #[default(default_upload_dir_mode())]
    pub upload_dir_mode: u32,
    #[serde(default = "default_max_concurrent_uploads")]
    #[default(default_max_concurrent_uploads())]
    pub max_concurrent_uploads: u64,
    #[serde(default = "default_max_concurrent_uploads_per_user")]
    #[default(default_max_concurrent_uploads_per_user())]
    pub max_concurrent_uploads_per_user: u64,
    #[serde(default = "default_max_concurrent_uploads_per_source")]
    #[default(default_max_concurrent_uploads_per_source())]
    pub max_concurrent_uploads_per_source: u64,
    #[serde(default = "default_max_expensive_tasks")]
    #[default(default_max_expensive_tasks())]
    pub max_expensive_tasks: u64,
    #[serde(default = "default_max_blocking_threads")]
    #[default(default_max_blocking_threads())]
    pub max_blocking_threads: u64,
    #[serde(default = "default_max_walk_entries")]
    #[default(default_max_walk_entries())]
    pub max_walk_entries: u64,
    #[serde(default = "default_max_walk_depth")]
    #[default(default_max_walk_depth())]
    pub max_walk_depth: u64,
    #[serde(default = "default_max_search_results")]
    #[default(default_max_search_results())]
    pub max_search_results: u64,
    #[serde(default = "default_max_directory_entries")]
    #[default(default_max_directory_entries())]
    pub max_directory_entries: u64,
    #[serde(
        default = "default_max_archive_size",
        deserialize_with = "deserialize_size"
    )]
    #[default(default_max_archive_size())]
    pub max_archive_size: u64,
    #[serde(
        default = "default_expensive_task_timeout_secs",
        deserialize_with = "deserialize_timeout_secs"
    )]
    #[default(default_expensive_task_timeout_secs())]
    pub expensive_task_timeout: u64,
    #[serde(
        default = "default_upload_idle_timeout_secs",
        deserialize_with = "deserialize_timeout_secs"
    )]
    #[default(default_upload_idle_timeout_secs())]
    pub upload_idle_timeout: u64,
    #[serde(
        default = "default_upload_total_timeout_secs",
        deserialize_with = "deserialize_timeout_secs"
    )]
    #[default(default_upload_total_timeout_secs())]
    pub upload_total_timeout: u64,
    #[serde(
        default = "default_stale_upload_cleanup_age_secs",
        deserialize_with = "deserialize_timeout_secs"
    )]
    #[default(default_stale_upload_cleanup_age_secs())]
    pub stale_upload_cleanup_age: u64,
    #[serde(default = "default_stale_upload_cleanup_max_entries")]
    #[default(default_stale_upload_cleanup_max_entries())]
    pub stale_upload_cleanup_max_entries: u64,
    #[serde(default = "default_stale_upload_cleanup_max_depth")]
    #[default(default_stale_upload_cleanup_max_depth())]
    pub stale_upload_cleanup_max_depth: u64,
    #[serde(default = "default_stale_upload_cleanup_max_deletions")]
    #[default(default_stale_upload_cleanup_max_deletions())]
    pub stale_upload_cleanup_max_deletions: u64,
    #[serde(
        default = "default_stale_upload_cleanup_timeout_secs",
        deserialize_with = "deserialize_timeout_secs"
    )]
    #[default(default_stale_upload_cleanup_timeout_secs())]
    pub stale_upload_cleanup_timeout: u64,
    /// 单次上传最大字节数，必须非零。 / Maximum bytes for one upload; must be nonzero.
    #[serde(
        default = "default_max_upload_size",
        deserialize_with = "deserialize_size"
    )]
    #[default(default_max_upload_size())]
    pub max_upload_size: u64,
    #[serde(default = "default_storage_space_check")]
    #[default(default_storage_space_check())]
    pub storage_space_check: bool,
    #[serde(
        default = "default_storage_reserve",
        deserialize_with = "deserialize_size"
    )]
    #[default(default_storage_reserve())]
    pub storage_reserve: u64,
}

/// 监听地址只接受 TCP IP；TLS 由部署网关统一终止。
/// Listener addresses are TCP IPs only; deployment gateways terminate TLS.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum BindAddr {
    IpAddr(IpAddr),
}

impl BindAddr {
    pub(super) fn parse_addrs(addrs: &[&str]) -> Result<Vec<Self>> {
        let mut bind_addrs = vec![];
        for addr in addrs {
            let parsed = addr
                .parse::<IpAddr>()
                .with_context(|| format!("Invalid TCP bind address `{addr}`"))?;
            bind_addrs.push(BindAddr::IpAddr(parsed));
        }
        Ok(bind_addrs)
    }
}

/// zip 打包的压缩级别（`--compress`）。文件服务器场景默认 Low：
/// 打包下载通常受限于网络而非体积，低压缩省 CPU。
/// ZIP compression level; Low saves CPU because file downloads are usually network-bound.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Compress {
    None,
    #[default]
    Low,
    Medium,
    High,
}

impl ValueEnum for Compress {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::None, Self::Low, Self::Medium, Self::High]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match self {
            Compress::None => PossibleValue::new("none"),
            Compress::Low => PossibleValue::new("low"),
            Compress::Medium => PossibleValue::new("medium"),
            Compress::High => PossibleValue::new("high"),
        })
    }
}

impl Compress {
    pub fn to_compression(self) -> (zip::CompressionMethod, Option<i64>) {
        match self {
            Compress::None => (zip::CompressionMethod::Stored, None),
            Compress::Low => (zip::CompressionMethod::Deflated, Some(1)),
            Compress::Medium => (zip::CompressionMethod::Deflated, Some(6)),
            Compress::High => (zip::CompressionMethod::Deflated, Some(9)),
        }
    }
}

/// YAML `bind` 接受字符串或数组的 Visitor 自定义反序列化。 / Custom Visitor accepting scalar or array `bind` values.
pub(super) fn deserialize_bind_addrs<'de, D>(deserializer: D) -> Result<Vec<BindAddr>, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringOrVec;

    impl<'de> serde::de::Visitor<'de> for StringOrVec {
        type Value = Vec<BindAddr>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("string or list of strings")
        }

        fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            BindAddr::parse_addrs(&[s]).map_err(serde::de::Error::custom)
        }

        fn visit_seq<S>(self, seq: S) -> Result<Self::Value, S::Error>
        where
            S: serde::de::SeqAccess<'de>,
        {
            let addrs: Vec<&'de str> =
                Deserialize::deserialize(serde::de::value::SeqAccessDeserializer::new(seq))?;
            BindAddr::parse_addrs(&addrs).map_err(serde::de::Error::custom)
        }
    }

    deserializer.deserialize_any(StringOrVec)
}

/// `hidden` 的字符串/数组双形态反序列化。 / Scalar-or-array deserialization for `hidden`.
pub(super) fn deserialize_string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringOrVec;

    impl<'de> serde::de::Visitor<'de> for StringOrVec {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("string or list of strings")
        }

        fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(vec![s.to_owned()])
        }

        fn visit_seq<S>(self, seq: S) -> Result<Self::Value, S::Error>
        where
            S: serde::de::SeqAccess<'de>,
        {
            Deserialize::deserialize(serde::de::value::SeqAccessDeserializer::new(seq))
        }
    }

    deserializer.deserialize_any(StringOrVec)
}

pub(super) fn deserialize_access_control<'de, D>(deserializer: D) -> Result<AccessControl, D::Error>
where
    D: Deserializer<'de>,
{
    let rules: Vec<&str> = Vec::deserialize(deserializer)?;
    AccessControl::new(&rules).map_err(serde::de::Error::custom)
}

pub(super) fn deserialize_log_http<'de, D>(deserializer: D) -> Result<HttpLogger, D::Error>
where
    D: Deserializer<'de>,
{
    let value: String = Deserialize::deserialize(deserializer)?;
    value.parse().map_err(serde::de::Error::custom)
}

/// 配置文件里的字节大小：既接受裸整数（`1048576`），
/// 也接受带二进制后缀的人类可读字符串（`1M`、`2G`）。
/// Byte sizes accept a raw integer or a human-readable binary suffix.
pub(super) fn deserialize_size<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    struct SizeVisitor;

    impl serde::de::Visitor<'_> for SizeVisitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a byte size as an integer or string like `512M`")
        }

        fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
            Ok(v)
        }

        fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
            u64::try_from(v).map_err(|_| E::custom("size must not be negative"))
        }

        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
            parse_size(v).map_err(E::custom)
        }
    }

    deserializer.deserialize_any(SizeVisitor)
}

pub(super) fn deserialize_timeout_secs<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    struct DurationVisitor;
    impl serde::de::Visitor<'_> for DurationVisitor {
        type Value = u64;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("seconds or a duration such as 30s, 5m, 1h")
        }
        fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<u64, E> {
            validate_timeout_secs(value).map_err(E::custom)
        }
        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<u64, E> {
            parse_timeout_secs(value).map_err(E::custom)
        }
    }
    deserializer.deserialize_any(DurationVisitor)
}

pub(super) fn parse_duration_value(value: &str) -> Result<u64> {
    let value = value.trim();
    if value.is_empty() {
        bail!("duration must not be empty");
    }
    let (number, multiplier) = match value.as_bytes().last().copied() {
        Some(b's' | b'S') => (&value[..value.len() - 1], 1),
        Some(b'm' | b'M') => (&value[..value.len() - 1], 60),
        Some(b'h' | b'H') => (&value[..value.len() - 1], 60 * 60),
        Some(b'd' | b'D') => (&value[..value.len() - 1], 24 * 60 * 60),
        _ => (value, 1),
    };
    let seconds = number
        .trim()
        .parse::<u64>()?
        .checked_mul(multiplier)
        .ok_or_else(|| anyhow::anyhow!("duration is too large"))?;
    Ok(seconds)
}

pub(super) fn parse_timeout_secs(value: &str) -> Result<u64> {
    validate_timeout_secs(parse_duration_value(value)?)
}

pub(super) fn parse_permission_mode(value: &str) -> std::result::Result<u32, String> {
    let value = value.strip_prefix("0o").unwrap_or(value);
    if value.is_empty() || !value.bytes().all(|byte| matches!(byte, b'0'..=b'7')) {
        return Err("permission mode must be an octal value such as 0600 or 0700".to_string());
    }
    let mode = u32::from_str_radix(value, 8)
        .map_err(|_| "permission mode is outside the supported range".to_string())?;
    if mode > 0o777 {
        return Err("permission mode must contain only 0000..0777 bits".to_string());
    }
    Ok(mode)
}

pub(super) fn deserialize_permission_mode<'de, D>(
    deserializer: D,
) -> std::result::Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    struct PermissionModeVisitor;

    impl<'de> serde::de::Visitor<'de> for PermissionModeVisitor {
        type Value = u32;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a quoted octal permission mode such as \"0600\"")
        }

        fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            parse_permission_mode(value).map_err(E::custom)
        }

        fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            let value = u32::try_from(value)
                .map_err(|_| E::custom("numeric permission mode is too large"))?;
            if value > 0o777 {
                return Err(E::custom(
                    "numeric permission mode exceeds 0777; quote octal values such as \"0600\"",
                ));
            }
            Ok(value)
        }
    }

    deserializer.deserialize_any(PermissionModeVisitor)
}

/// 用 checked multiplication 解析 `512K`/`4M`/`2G`；是否允许 0 由具体字段校验决定。
/// Parse binary suffixes with checked multiplication; each field decides whether zero is valid.
pub(super) fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(0);
    }
    let (num, mult): (&str, u64) = match s.chars().last().unwrap().to_ascii_uppercase() {
        'K' => (&s[..s.len() - 1], 1 << 10),
        'M' => (&s[..s.len() - 1], 1 << 20),
        'G' => (&s[..s.len() - 1], 1 << 30),
        'T' => (&s[..s.len() - 1], 1 << 40),
        'B' => (&s[..s.len() - 1], 1),
        _ => (s, 1),
    };
    let value: u64 = num
        .trim()
        .parse()
        .with_context(|| format!("invalid size `{s}`"))?;
    value
        .checked_mul(mult)
        .ok_or_else(|| anyhow::anyhow!("size `{s}` is too large"))
}

/// Ram 唯一内置的个人内网资源档。高级配置可以逐项覆盖，但省略时始终使用这些有界值。
/// Ram's single built-in personal-intranet resource profile. Advanced configuration may override
/// individual values, while omitted fields always retain these bounded defaults.
#[derive(Clone, Copy)]
struct PersonalIntranetLimits {
    max_connections: u64,
    max_concurrent_requests: u64,
    max_concurrent_requests_per_source: u64,
    max_concurrent_requests_per_user: u64,
    max_request_queue: u64,
    max_blocking_threads: u64,
    max_expensive_tasks: u64,
    max_concurrent_uploads: u64,
    max_concurrent_uploads_per_user: u64,
    max_concurrent_uploads_per_source: u64,
    max_search_results: u64,
    max_directory_entries: u64,
    storage_reserve: u64,
}

const PERSONAL_INTRANET_LIMITS: PersonalIntranetLimits = PersonalIntranetLimits {
    max_connections: 64,
    max_concurrent_requests: 32,
    // 同机 TLS 网关会把所有设备聚合为一个来源；共享账号也会聚合用户键。
    // A same-host TLS gateway aggregates every device into one source, and shared accounts
    // aggregate the user key, so neither keyed ceiling may sit below the global request ceiling.
    max_concurrent_requests_per_source: 32,
    max_concurrent_requests_per_user: 32,
    max_request_queue: 32,
    max_blocking_threads: 12,
    max_expensive_tasks: 2,
    max_concurrent_uploads: 4,
    max_concurrent_uploads_per_user: 2,
    max_concurrent_uploads_per_source: 3,
    max_search_results: 5_000,
    max_directory_entries: 10_000,
    storage_reserve: 5 * 1024 * 1024 * 1024,
};

pub(super) fn default_serve_path() -> PathBuf {
    PathBuf::from(".")
}

pub(super) fn default_max_connections() -> u64 {
    PERSONAL_INTRANET_LIMITS.max_connections
}

pub(super) fn default_upload_file_mode() -> u32 {
    0o600
}

pub(super) fn default_upload_dir_mode() -> u32 {
    0o700
}

pub(super) fn default_max_concurrent_requests() -> u64 {
    PERSONAL_INTRANET_LIMITS.max_concurrent_requests
}

pub(super) fn default_max_concurrent_requests_per_source() -> u64 {
    PERSONAL_INTRANET_LIMITS.max_concurrent_requests_per_source
}

pub(super) fn default_max_concurrent_requests_per_user() -> u64 {
    PERSONAL_INTRANET_LIMITS.max_concurrent_requests_per_user
}

pub(super) fn default_max_request_queue() -> u64 {
    PERSONAL_INTRANET_LIMITS.max_request_queue
}

pub(super) fn default_request_queue_timeout_secs() -> u64 {
    5
}

pub(super) fn default_header_read_timeout_secs() -> u64 {
    30
}

pub(super) fn default_connection_idle_timeout_secs() -> u64 {
    60
}

pub(super) fn default_connection_max_lifetime_secs() -> u64 {
    60 * 60
}

pub(super) fn default_response_write_idle_timeout_secs() -> u64 {
    30
}

pub(super) fn default_write_lock_timeout_secs() -> u64 {
    5
}

pub(super) fn default_max_concurrent_uploads() -> u64 {
    PERSONAL_INTRANET_LIMITS.max_concurrent_uploads
}

pub(super) fn default_max_concurrent_uploads_per_user() -> u64 {
    PERSONAL_INTRANET_LIMITS.max_concurrent_uploads_per_user
}

pub(super) fn default_max_concurrent_uploads_per_source() -> u64 {
    PERSONAL_INTRANET_LIMITS.max_concurrent_uploads_per_source
}

pub(super) fn default_max_expensive_tasks() -> u64 {
    PERSONAL_INTRANET_LIMITS.max_expensive_tasks
}

pub(super) fn default_max_blocking_threads() -> u64 {
    PERSONAL_INTRANET_LIMITS.max_blocking_threads
}

pub(super) fn default_max_walk_entries() -> u64 {
    1_000_000
}

pub(super) fn default_max_walk_depth() -> u64 {
    64
}

pub(super) fn default_max_search_results() -> u64 {
    PERSONAL_INTRANET_LIMITS.max_search_results
}

pub(super) fn default_max_directory_entries() -> u64 {
    PERSONAL_INTRANET_LIMITS.max_directory_entries
}

pub(super) fn default_max_archive_size() -> u64 {
    4 * 1024 * 1024 * 1024
}

pub(super) fn default_expensive_task_timeout_secs() -> u64 {
    5 * 60
}

pub(super) fn default_upload_idle_timeout_secs() -> u64 {
    30
}

pub(super) fn default_upload_total_timeout_secs() -> u64 {
    15 * 60
}

pub(super) fn default_stale_upload_cleanup_age_secs() -> u64 {
    24 * 60 * 60
}

pub(super) fn default_stale_upload_cleanup_max_entries() -> u64 {
    100_000
}

pub(super) fn default_stale_upload_cleanup_max_depth() -> u64 {
    64
}

pub(super) fn default_stale_upload_cleanup_max_deletions() -> u64 {
    1_000
}

pub(super) fn default_stale_upload_cleanup_timeout_secs() -> u64 {
    5
}

pub(super) fn default_max_upload_size() -> u64 {
    4 * 1024 * 1024 * 1024
}

pub(super) const fn default_storage_space_check() -> bool {
    true
}

pub(super) const fn default_storage_reserve() -> u64 {
    PERSONAL_INTRANET_LIMITS.storage_reserve
}

pub(super) fn default_addrs() -> Vec<BindAddr> {
    let addrs = if is_ipv6_available() {
        ["127.0.0.1", "::1"].as_slice()
    } else {
        ["127.0.0.1"].as_slice()
    };
    BindAddr::parse_addrs(addrs).unwrap()
}

pub(super) fn default_port() -> u16 {
    5000
}
