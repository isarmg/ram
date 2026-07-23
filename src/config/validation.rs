//! 跨字段、资源预算与 URL 前缀校验。远程输入预算超过硬上限时必须拒绝，
//! 不能截断或转换为宽松默认值。
//!
//! Cross-field, resource-budget and URL-prefix validation.
//!
//! Invariant: remote-input budgets are rejected above hard ceilings; invalid
//! values are never clamped or converted into permissive defaults.

use super::*;
use crate::http::ResourceMethod;

pub(crate) fn normalize_path_prefix(value: &str) -> Result<String> {
    // 中文：预算按运维者输入的原始拼写计费，而不只看规范化结果；否则任意长的 `/`
    // 会折叠为空前缀并绕过配置内存/扫描预算。
    // English: Charge the operator spelling, not only the canonical result;
    // otherwise an arbitrarily long slash string collapses to an empty prefix
    // and bypasses the configuration memory/scan budget.
    if value.len() > PATH_PREFIX_MAX_BYTES {
        bail!("path-prefix exceeds {PATH_PREFIX_MAX_BYTES} bytes");
    }
    if value.is_empty() || value == "/" {
        return Ok(String::new());
    }
    if value.starts_with("//") || value.ends_with("//") {
        bail!("path-prefix must use at most one optional leading and trailing slash");
    }
    let value = value.strip_prefix('/').unwrap_or(value);
    let value = value.strip_suffix('/').unwrap_or(value);
    for component in value.split('/') {
        if component.is_empty()
            || matches!(component, "." | "..")
            || component.contains('\\')
            || component.chars().any(char::is_control)
        {
            bail!(
                "path-prefix must contain only non-empty URL path components without dot segments, backslashes, or control characters"
            );
        }
    }
    Ok(value.to_string())
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_path_prefix(data: &[u8]) {
    if data.len() > PATH_PREFIX_MAX_BYTES.saturating_add(2) {
        return;
    }
    let Ok(value) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(prefix) = normalize_path_prefix(value) {
        assert!(prefix.len() <= PATH_PREFIX_MAX_BYTES);
        assert!(!prefix.starts_with('/'));
        assert!(!prefix.ends_with('/'));
        assert!(
            prefix.is_empty()
                || prefix.split('/').all(|component| {
                    !component.is_empty()
                        && !matches!(component, "." | "..")
                        && !component.contains('\\')
                        && !component.chars().any(char::is_control)
                })
        );
    }
}

pub(super) fn validate_token_ttl(seconds: u64) -> Result<u64> {
    if seconds == 0 || seconds > 7 * 24 * 60 * 60 {
        bail!("token TTL must be between 1 second and 7 days");
    }
    Ok(seconds)
}

pub(super) fn validate_timeout_secs(seconds: u64) -> Result<u64> {
    if seconds == 0 || seconds > 7 * 24 * 60 * 60 {
        bail!("timeout must be between 1 second and 7 days");
    }
    Ok(seconds)
}

pub(super) fn validate_resource_limits(args: &Args) -> Result<()> {
    if args.unix_socket_mode > 0o777 {
        bail!("unix-socket-mode must contain only 0000..0777 permission bits");
    }
    if args.unix_socket_uid == Some(u32::MAX) || args.unix_socket_gid == Some(u32::MAX) {
        bail!("unix-socket-uid/gid cannot use the reserved all-ones identifier");
    }
    if args.upload_file_mode > 0o777 || args.upload_dir_mode > 0o777 {
        bail!("upload-file-mode and upload-dir-mode must contain only 0000..0777 bits");
    }
    if args.upload_dir_mode & 0o700 != 0o700 {
        bail!(
            "upload-dir-mode must grant owner read, write, and search permissions (0700); Ram owns created directories and must be able to list, traverse, and update them"
        );
    }
    let uses_abstract_socket = args
        .addrs
        .iter()
        .any(|address| matches!(address, BindAddr::SocketPath(path) if path.starts_with('@')));
    if uses_abstract_socket && !args.allow_abstract_unix_socket {
        bail!(
            "abstract Unix sockets have no filesystem permission boundary; pass --allow-abstract-unix-socket only after establishing an external access boundary"
        );
    }
    if uses_abstract_socket {
        eprintln!(
            "WARNING: abstract Unix socket access is not protected by pathname mode/owner/group; every local process able to reach the namespace may connect"
        );
    }
    if args.trusted_proxy.len() > TRUSTED_PROXY_MAX_ENTRIES {
        bail!("trusted-proxy accepts at most {TRUSTED_PROXY_MAX_ENTRIES} CIDRs");
    }
    for (index, network) in args.trusted_proxy.iter().enumerate() {
        if args.trusted_proxy[..index].contains(network) {
            bail!("trusted-proxy contains duplicate CIDR `{network}`");
        }
    }
    TrustedProxyPolicy::new(args.trusted_proxy.clone(), args.trusted_proxy_header)?;
    if args.max_concurrent_requests == 0 {
        bail!("max-concurrent-requests must be greater than zero");
    }
    if args.max_concurrent_requests > tokio::sync::Semaphore::MAX_PERMITS as u64 {
        bail!(
            "max-concurrent-requests exceeds the runtime limit of {}",
            tokio::sync::Semaphore::MAX_PERMITS
        );
    }
    for (name, value) in [
        (
            "max-concurrent-requests-per-source",
            args.max_concurrent_requests_per_source,
        ),
        (
            "max-concurrent-requests-per-user",
            args.max_concurrent_requests_per_user,
        ),
    ] {
        if value == 0 || value > KEYED_REQUEST_LIMIT_HARD_MAX {
            bail!("{name} must be between 1 and {KEYED_REQUEST_LIMIT_HARD_MAX}");
        }
    }
    if args.max_request_queue > KEYED_REQUEST_LIMIT_HARD_MAX {
        bail!("max-request-queue must be between 0 and {KEYED_REQUEST_LIMIT_HARD_MAX}");
    }
    if args.request_queue_timeout == 0 || args.request_queue_timeout > 60 {
        bail!("request-queue-timeout must be between 1 second and 60 seconds");
    }
    validate_timeout_secs(args.header_read_timeout).context("Invalid header-read-timeout")?;
    validate_timeout_secs(args.connection_idle_timeout)
        .context("Invalid connection-idle-timeout")?;
    validate_timeout_secs(args.connection_max_lifetime)
        .context("Invalid connection-max-lifetime")?;
    validate_timeout_secs(args.response_write_idle_timeout)
        .context("Invalid response-write-idle-timeout")?;
    if args.write_lock_timeout == 0 || args.write_lock_timeout > 60 {
        bail!("write-lock-timeout must be between 1 second and 60 seconds");
    }
    if args.max_concurrent_uploads == 0 {
        bail!("max-concurrent-uploads must be greater than zero");
    }
    if args.max_concurrent_uploads > tokio::sync::Semaphore::MAX_PERMITS as u64 {
        bail!(
            "max-concurrent-uploads exceeds the runtime limit of {}",
            tokio::sync::Semaphore::MAX_PERMITS
        );
    }
    for (name, value) in [
        (
            "max-concurrent-uploads-per-user",
            args.max_concurrent_uploads_per_user,
        ),
        (
            "max-concurrent-uploads-per-source",
            args.max_concurrent_uploads_per_source,
        ),
    ] {
        if value == 0 || value > KEYED_UPLOAD_LIMIT_HARD_MAX {
            bail!("{name} must be between 1 and {KEYED_UPLOAD_LIMIT_HARD_MAX}");
        }
    }
    if args.h2_max_concurrent_streams == 0 || args.h2_max_concurrent_streams > 1024 {
        bail!("h2-max-concurrent-streams must be between 1 and 1024");
    }
    if args.max_expensive_tasks == 0 {
        bail!("max-expensive-tasks must be greater than zero");
    }
    if args.max_expensive_tasks > tokio::sync::Semaphore::MAX_PERMITS as u64 {
        bail!(
            "max-expensive-tasks exceeds the runtime limit of {}",
            tokio::sync::Semaphore::MAX_PERMITS
        );
    }
    if args.max_blocking_threads == 0 || args.max_blocking_threads > 256 {
        bail!("max-blocking-threads must be between 1 and 256");
    }
    // 中文：`--check-config` 不实例化持久后端，必须从已合并的 secret+撤销输出拓扑传入
    // hint；Run 模式还会由 AccessControl 检查实际绑定后端。默认撤销路径需在调用本函数前
    // 派生，否则 max-blocking-threads 会基于不完整配置误通过。
    // English: `--check-config` does not instantiate durable state, so pass a hint from the merged
    // secret+revocation-output topology; run mode additionally inspects the backend actually bound by
    // AccessControl. Callers must derive the default revocation path before this validation.
    let persistent_revocation = (args.token_secret.is_some() || args.token_secret_file.is_some())
        && args.token_revocation_file.is_some();
    let minimum_auth_blocking_threads = args
        .auth
        .minimum_blocking_threads_with_persistent_revocation(persistent_revocation);
    if args.max_blocking_threads < minimum_auth_blocking_threads {
        bail!(
            "max-blocking-threads must be at least {minimum_auth_blocking_threads} when expensive authentication (password hashing or persistent token revocation) is configured, reserving one blocking worker for non-authentication requests"
        );
    }

    const MAX_ENTRY_LIMIT: u64 = 10_000_000;
    for (name, value) in [
        ("max-walk-entries", args.max_walk_entries),
        ("max-search-results", args.max_search_results),
        ("max-directory-entries", args.max_directory_entries),
    ] {
        if value == 0 || value > MAX_ENTRY_LIMIT {
            bail!("{name} must be between 1 and {MAX_ENTRY_LIMIT}");
        }
    }
    if args.max_walk_depth == 0 || args.max_walk_depth > 1024 {
        bail!("max-walk-depth must be between 1 and 1024");
    }
    if args.stale_upload_cleanup_max_entries == 0
        || args.stale_upload_cleanup_max_entries > STALE_UPLOAD_CLEANUP_MAX_ENTRIES_HARD_MAX
    {
        bail!(
            "stale-upload-cleanup-max-entries must be between 1 and {STALE_UPLOAD_CLEANUP_MAX_ENTRIES_HARD_MAX}"
        );
    }
    if args.stale_upload_cleanup_max_depth == 0
        || args.stale_upload_cleanup_max_depth > STALE_UPLOAD_CLEANUP_MAX_DEPTH_HARD_MAX
    {
        bail!(
            "stale-upload-cleanup-max-depth must be between 1 and {STALE_UPLOAD_CLEANUP_MAX_DEPTH_HARD_MAX}"
        );
    }
    if args.stale_upload_cleanup_max_deletions == 0
        || args.stale_upload_cleanup_max_deletions > STALE_UPLOAD_CLEANUP_MAX_DELETIONS_HARD_MAX
    {
        bail!(
            "stale-upload-cleanup-max-deletions must be between 1 and {STALE_UPLOAD_CLEANUP_MAX_DELETIONS_HARD_MAX}"
        );
    }
    if args.stale_upload_cleanup_timeout == 0
        || args.stale_upload_cleanup_timeout > STALE_UPLOAD_CLEANUP_TIMEOUT_HARD_MAX_SECS
    {
        bail!(
            "stale-upload-cleanup-timeout must be between 1 and {STALE_UPLOAD_CLEANUP_TIMEOUT_HARD_MAX_SECS} seconds"
        );
    }
    if args.max_webdav_properties == 0 || args.max_webdav_properties > WEBDAV_HARD_MAX_PROPERTIES {
        bail!("max-webdav-properties must be between 1 and {WEBDAV_HARD_MAX_PROPERTIES}");
    }
    let minimum_rendered_properties = args.max_webdav_properties.max(4);
    if args.max_webdav_rendered_properties < minimum_rendered_properties
        || args.max_webdav_rendered_properties > WEBDAV_HARD_MAX_RENDERED_PROPERTIES
    {
        bail!(
            "max-webdav-rendered-properties must be between {minimum_rendered_properties} and {WEBDAV_HARD_MAX_RENDERED_PROPERTIES}"
        );
    }
    if args.max_webdav_response_size < WEBDAV_MIN_RESPONSE_SIZE
        || args.max_webdav_response_size > WEBDAV_HARD_MAX_RESPONSE_SIZE
    {
        bail!(
            "max-webdav-response-size must be between {WEBDAV_MIN_RESPONSE_SIZE} and {WEBDAV_HARD_MAX_RESPONSE_SIZE} bytes"
        );
    }
    if args.max_archive_size == 0 {
        bail!("max-archive-size must be greater than zero");
    }
    if args.max_hash_size == 0 {
        bail!("max-hash-size must be greater than zero");
    }
    if args.max_copy_size == 0 {
        bail!("max-copy-size must be greater than zero");
    }
    if args
        .hsts_max_age
        .is_some_and(|value| value > HSTS_MAX_AGE_HARD_MAX_SECS)
    {
        bail!("hsts-max-age must be between 0 and {HSTS_MAX_AGE_HARD_MAX_SECS} seconds");
    }
    validate_timeout_secs(args.expensive_task_timeout).context("Invalid expensive-task-timeout")?;
    validate_timeout_secs(args.copy_timeout).context("Invalid copy-timeout")?;
    if args.storage_quota_hook_timeout == 0 || args.storage_quota_hook_timeout > 60 {
        bail!("storage-quota-hook-timeout must be between 1 and 60 seconds");
    }
    validate_timeout_secs(args.upload_idle_timeout).context("Invalid upload-idle-timeout")?;
    validate_timeout_secs(args.upload_total_timeout).context("Invalid upload-total-timeout")?;
    validate_timeout_secs(args.stale_upload_cleanup_age)
        .context("Invalid stale-upload-cleanup-age")?;
    Ok(())
}

pub(super) fn normalize_cors_configuration(args: &mut Args) -> Result<()> {
    const MAX_ORIGINS: usize = 64;
    const MAX_HEADERS: usize = 64;

    if args.cors_origins.len() > MAX_ORIGINS {
        bail!("cors-origins accepts at most {MAX_ORIGINS} entries");
    }
    let mut origins = Vec::with_capacity(args.cors_origins.len());
    let mut seen_origins = HashSet::new();
    for configured in args.cors_origins.drain(..) {
        let configured = configured.trim();
        let origin = if configured == "*" {
            "*".to_string()
        } else {
            if configured.len() > 2048 {
                bail!("CORS origin is too long");
            }
            let parsed = url::Url::parse(configured)
                .with_context(|| format!("Invalid CORS origin `{configured}`"))?;
            if !matches!(parsed.scheme(), "http" | "https")
                || parsed.host().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.path() != "/"
                || parsed.query().is_some()
                || parsed.fragment().is_some()
            {
                bail!(
                    "Invalid CORS origin `{configured}`; use an exact http(s) scheme/host/port origin without credentials or a path"
                );
            }
            parsed.origin().ascii_serialization()
        };
        if seen_origins.insert(origin.clone()) {
            origins.push(origin);
        }
    }
    if origins.iter().any(|origin| origin == "*") && origins.len() != 1 {
        bail!("cors-origins wildcard `*` must be the only configured origin");
    }
    if args.enable_cors && origins.is_empty() {
        bail!("enable-cors requires at least one cors-origins entry");
    }
    args.cors_origins = origins;

    let mut methods = Vec::with_capacity(args.cors_methods.len());
    let mut seen_methods = HashSet::new();
    for configured in args.cors_methods.drain(..) {
        let method = configured.trim().to_ascii_uppercase();
        if ResourceMethod::parse_name(&method).is_none() {
            bail!("Unsupported CORS resource method `{configured}`");
        }
        if seen_methods.insert(method.clone()) {
            methods.push(method);
        }
    }
    args.cors_methods = methods;

    if args.cors_headers.len() > MAX_HEADERS {
        bail!("cors-headers accepts at most {MAX_HEADERS} entries");
    }
    let mut headers = Vec::with_capacity(args.cors_headers.len());
    let mut seen_headers = HashSet::new();
    for configured in args.cors_headers.drain(..) {
        let configured = configured.trim();
        if configured == "*" {
            bail!(
                "cors-headers does not accept wildcard `*`; list every request header explicitly"
            );
        }
        let header = hyper::header::HeaderName::from_str(configured)
            .with_context(|| format!("Invalid CORS request header `{configured}`"))?
            .as_str()
            .to_string();
        if seen_headers.insert(header.clone()) {
            headers.push(header);
        }
    }
    args.cors_headers = headers;
    Ok(())
}
