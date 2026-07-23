//! 跨字段、资源预算与 URL 前缀校验。远程输入预算超过硬上限时必须拒绝，
//! 不能截断或转换为宽松默认值。
//!
//! Cross-field, resource-budget and URL-prefix validation.
//!
//! Invariant: remote-input budgets are rejected above hard ceilings; invalid
//! values are never clamped or converted into permissive defaults.

use super::*;
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

pub(super) fn validate_timeout_secs(seconds: u64) -> Result<u64> {
    if seconds == 0 || seconds > 7 * 24 * 60 * 60 {
        bail!("timeout must be between 1 second and 7 days");
    }
    Ok(seconds)
}

pub(super) fn validate_resource_limits(args: &Args) -> Result<()> {
    if args.upload_file_mode > 0o777 || args.upload_dir_mode > 0o777 {
        bail!("upload-file-mode and upload-dir-mode must contain only 0000..0777 bits");
    }
    if args.upload_dir_mode & 0o700 != 0o700 {
        bail!(
            "upload-dir-mode must grant owner read, write, and search permissions (0700); Ram owns created directories and must be able to list, traverse, and update them"
        );
    }
    if args.max_connections == 0 {
        bail!("max-connections must be greater than zero");
    }
    if args.max_connections > tokio::sync::Semaphore::MAX_PERMITS as u64 {
        bail!(
            "max-connections exceeds the runtime limit of {}",
            tokio::sync::Semaphore::MAX_PERMITS
        );
    }
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
    // 中文：密码哈希会占用阻塞线程；预留一个 worker 给非认证请求。
    // English: Password hashing consumes blocking threads; reserve one worker for non-auth requests.
    let minimum_auth_blocking_threads = args.auth.minimum_blocking_threads();
    if args.max_blocking_threads < minimum_auth_blocking_threads {
        bail!(
            "max-blocking-threads must be at least {minimum_auth_blocking_threads} when expensive authentication (password hashing) is configured, reserving one blocking worker for non-authentication requests"
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
    if args.max_archive_size == 0 {
        bail!("max-archive-size must be greater than zero");
    }
    if args.max_upload_size == 0 {
        bail!("max-upload-size must be greater than zero");
    }
    validate_timeout_secs(args.expensive_task_timeout).context("Invalid expensive-task-timeout")?;
    validate_timeout_secs(args.upload_idle_timeout).context("Invalid upload-idle-timeout")?;
    validate_timeout_secs(args.upload_total_timeout).context("Invalid upload-total-timeout")?;
    validate_timeout_secs(args.stale_upload_cleanup_age)
        .context("Invalid stale-upload-cleanup-age")?;
    Ok(())
}
