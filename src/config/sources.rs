//! 配置来源加载与保持优先级的合并：显式 CLI > 环境变量 > YAML > 默认值；敏感文件
//! 通过固定身份消费，绝不重新打开路径名。
//!
//! Configuration source loading and precedence-preserving merge.
//!
//! Invariant: explicit CLI values override environment, which overrides YAML,
//! which overrides defaults. Sensitive source files are consumed by pinned
//! identities rather than reopened pathnames.

use super::*;

/// 仅当布尔值来自 CLI/环境时返回；缺失值不能覆盖 YAML，显式环境 false 也不能被忽略。
/// Return a boolean only when CLI/env supplied it, preserving YAML on absence and explicit false precedence.
pub(super) fn explicit_bool(matches: &ArgMatches, id: &str) -> Option<bool> {
    matches
        .value_source(id)
        .filter(|source| *source != ValueSource::DefaultValue)
        .and_then(|_| matches.get_one::<bool>(id).copied())
}

pub(super) const CAPABILITY_BOOL_IDS: [&str; 6] = [
    "allow-upload",
    "allow-delete",
    "allow-search",
    "allow-symlink",
    "allow-archive",
    "allow-hash",
];

pub(super) fn set_capability(args: &mut Args, id: &str, value: bool) {
    match id {
        "allow-upload" => args.allow_upload = value,
        "allow-delete" => args.allow_delete = value,
        "allow-search" => args.allow_search = value,
        "allow-symlink" => args.allow_symlink = value,
        "allow-archive" => args.allow_archive = value,
        "allow-hash" => args.allow_hash = value,
        _ => unreachable!("unknown capability boolean {id}"),
    }
}

pub(super) fn set_all_capabilities(args: &mut Args, value: bool) {
    for id in CAPABILITY_BOOL_IDS {
        set_capability(args, id, value);
    }
}

pub(super) fn apply_yaml_capability_aggregate(args: &mut Args, yaml_keys: &HashSet<String>) {
    if !yaml_keys.contains("allow-all") {
        return;
    }
    let aggregate = args.allow_all;
    for id in CAPABILITY_BOOL_IDS {
        if !yaml_keys.contains(id) {
            set_capability(args, id, aggregate);
        }
    }
}

impl Args {
    /// YAML 只能由 `--config` 或 `RAM_CONFIG` 显式选择；相对路径以进程 cwd 为基准。
    /// YAML must be selected explicitly with `--config` or `RAM_CONFIG`; relative paths use the process cwd.
    pub fn parse(matches: ArgMatches, purpose: ParsePurpose) -> Result<Args> {
        let cwd = env::current_dir().with_context(|| "Failed to determine current directory")?;
        let config_path = matches
            .get_one::<PathBuf>("config")
            .map(|path| Self::resolve_relative_path(path, &cwd));
        Self::parse_with_config_for(matches, config_path.as_deref(), purpose)
    }

    /// 真正的"配置文件为基底、命令行覆盖"合并逻辑。
    /// 单独拆出来可让单元测试直接覆盖显式 YAML 与命令行的合并规则。
    /// Core file-as-base, CLI-overrides merge, exposed separately for focused unit tests.
    #[cfg(test)]
    pub(super) fn parse_with_config(
        matches: ArgMatches,
        config_path: Option<&Path>,
    ) -> Result<Args> {
        Self::parse_with_config_for(matches, config_path, ParsePurpose::Run)
    }

    pub(super) fn parse_with_config_for(
        matches: ArgMatches,
        config_path: Option<&Path>,
        purpose: ParsePurpose,
    ) -> Result<Args> {
        let mut args = Self::default();
        let mut startup_inputs = Vec::new();
        let cwd = env::current_dir().with_context(|| "Failed to determine current directory")?;
        // 显式 YAML 里写的相对 `serve-path`/`assets`，必须按配置文件自己
        // 所在目录解析，而不是进程工作目录。服务管理器可能把 cwd 设为 `/`；
        // 若按 cwd 解析，可能悄悄暴露运维者完全没打算服务的目录。
        // English: Resolve YAML-relative serve/assets paths against the config
        // directory, not cwd, which service managers may set to an unintended root.
        let config_dir = config_path.and_then(|p| p.parent()).map(Path::to_path_buf);

        if let Some(config_path) = config_path {
            let yaml_keys;
            let config_identity;
            (args, yaml_keys, config_identity) = Self::load_config(config_path)?;
            startup_inputs.push(config_identity);
            apply_yaml_capability_aggregate(&mut args, &yaml_keys);
        }

        let serve_path_from_cli = matches.get_one::<PathBuf>("serve-path").is_some();
        if let Some(path) = matches.get_one::<PathBuf>("serve-path") {
            args.serve_path.clone_from(path)
        }

        let serve_path_base = if serve_path_from_cli {
            &cwd
        } else {
            config_dir.as_deref().unwrap_or(&cwd)
        };
        args.serve_path = Self::sanitize_path(&args.serve_path, serve_path_base)?;

        if let Some(value) = explicit_bool(&matches, "allow-filesystem-root") {
            args.allow_filesystem_root = value;
        }
        if args.serve_path == Path::new("/") {
            if !args.allow_filesystem_root {
                bail!(
                    "Refusing to serve the filesystem root `/`; pass --allow-filesystem-root only after isolating all secrets and system paths"
                );
            }
            eprintln!(
                "WARNING: --allow-filesystem-root exposes the complete filesystem namespace allowed by the service account"
            );
        }

        if let Some(port) = matches.get_one::<u16>("port") {
            args.port = *port
        }

        let bind_from_cli_or_env = matches.get_many::<String>("bind").is_some();
        if let Some(addrs) = matches.get_many::<String>("bind") {
            let addrs: Vec<_> = addrs.map(|v| v.as_str()).collect();
            args.addrs = BindAddr::parse_addrs(&addrs)?;
        }
        if args.addrs.is_empty() {
            bail!("At least one bind address is required");
        }
        let bind_base = if bind_from_cli_or_env {
            &cwd
        } else {
            config_dir.as_deref().unwrap_or(&cwd)
        };
        resolve_pathname_bind_addrs(&mut args.addrs, bind_base)?;

        args.path_is_file = args.serve_path.metadata()?.is_file();
        if args.path_is_file
            && args
                .serve_path
                .file_name()
                .and_then(|name| name.to_str())
                .filter(|name| !name.is_empty())
                .is_none()
        {
            bail!(
                "single-file mode requires a non-empty UTF-8 filename; serve its parent directory and use ZIP export to preserve a non-UTF-8 Linux name"
            );
        }
        if let Some(path_prefix) = matches.get_one::<String>("path-prefix") {
            args.path_prefix.clone_from(path_prefix)
        }
        args.path_prefix = normalize_path_prefix(&args.path_prefix)?;

        args.uri_prefix = if args.path_prefix.is_empty() {
            "/".to_owned()
        } else {
            format!("/{}/", encode_uri(&args.path_prefix))
        };

        if let Some(hidden) = matches.get_many::<String>("hidden") {
            args.hidden = hidden.cloned().collect();
        } else {
            // 中文：展开配置 `hidden: "a,b,c"`；先 swap 取所有权以避免借用冲突。
            // English: Expand comma-form hidden config after swapping ownership to avoid a borrow conflict.
            let mut hidden = vec![];
            std::mem::swap(&mut args.hidden, &mut hidden);
            args.hidden = hidden
                .into_iter()
                .flat_map(|v| v.split(',').map(|v| v.to_string()).collect::<Vec<String>>())
                .collect();
        }

        if let Some(value) = explicit_bool(&matches, "enable-cors") {
            args.enable_cors = value;
        }
        if let Some(values) = matches.get_many::<String>("cors-origins") {
            args.cors_origins = values.cloned().collect();
        }
        if let Some(values) = matches.get_many::<String>("cors-methods") {
            args.cors_methods = values.cloned().collect();
        }
        if let Some(values) = matches.get_many::<String>("cors-headers") {
            args.cors_headers = values.cloned().collect();
        }
        normalize_cors_configuration(&mut args)?;

        let inline_auth_from_cli_env = matches.get_many::<String>("auth").is_some();
        let auth_file_from_cli_env = matches.get_one::<PathBuf>("auth-file").is_some();
        if inline_auth_from_cli_env && args.auth_file.is_some() {
            bail!(
                "auth and auth-file cannot be combined across configuration sources; choose exactly one credential source"
            );
        }
        if auth_file_from_cli_env && args.auth.has_users() {
            bail!(
                "auth and auth-file cannot be combined across configuration sources; choose exactly one credential source"
            );
        }
        if let Some(rules) = matches.get_many::<String>("auth") {
            let rules: Vec<_> = rules.map(|v| v.as_str()).collect();
            args.auth = AccessControl::new(&rules)?;
        }
        if let Some(path) = matches.get_one::<PathBuf>("auth-file") {
            args.auth_file = Some(path.clone());
        }
        if args.auth.has_users() && args.auth_file.is_some() {
            bail!(
                "auth and auth-file are mutually exclusive; choose exactly one credential source"
            );
        }
        if let Some(path) = args.auth_file.clone() {
            let base = if auth_file_from_cli_env {
                &cwd
            } else {
                config_dir.as_deref().unwrap_or(&cwd)
            };
            let path = Self::resolve_relative_path(&path, base);
            let identity = capture_startup_input(
                &path,
                StartupInputKind::AuthenticationFile,
                "authentication file",
                PrivateFileAccess::Secret,
                false,
            )?;
            args.auth = load_auth_file_from_identity(&identity.identity)?;
            startup_inputs.push(identity);
            args.auth_file = Some(path);
        }
        if matches.value_source("auth") == Some(ValueSource::CommandLine) {
            eprintln!(
                "WARNING: --auth exposes reusable credentials through the process argument list; use --auth-file (preferably systemd LoadCredential) in production"
            );
        }

        if let Some(value) = explicit_bool(&matches, "allow-insecure-http") {
            args.allow_insecure_http = value;
        }
        if let Some(value) = explicit_bool(&matches, "allow-active-content-risk") {
            args.allow_active_content_risk = value;
        }
        if let Some(value) = explicit_bool(&matches, "allow-h2c") {
            args.allow_h2c = value;
        }
        if let Some(value) = explicit_bool(&matches, "allow-abstract-unix-socket") {
            args.allow_abstract_unix_socket = value;
        }
        if let Some(value) = matches.get_one::<u32>("unix-socket-mode") {
            args.unix_socket_mode = *value;
        }
        if let Some(value) = matches.get_one::<u32>("unix-socket-uid") {
            args.unix_socket_uid = Some(*value);
        }
        if let Some(value) = matches.get_one::<u32>("unix-socket-gid") {
            args.unix_socket_gid = Some(*value);
        }
        if let Some(values) = matches.get_many::<IpCidr>("trusted-proxy") {
            args.trusted_proxy = values.copied().collect();
        }
        if let Some(value) = matches.get_one::<ForwardedHeader>("trusted-proxy-header") {
            args.trusted_proxy_header = Some(*value);
        }
        if let Some(secret) = matches.get_one::<String>("token-secret") {
            args.token_secret = Some(SecretValue(secret.clone()));
            args.token_secret_file = None;
        }
        if matches.value_source("token-secret") == Some(ValueSource::CommandLine) {
            eprintln!(
                "WARNING: --token-secret exposes token key material through the process argument list; use --token-secret-file (preferably systemd LoadCredential) in production"
            );
        }
        let token_secret_file_from_cli = matches.get_one::<PathBuf>("token-secret-file").is_some();
        if let Some(path) = matches.get_one::<PathBuf>("token-secret-file") {
            args.token_secret_file = Some(path.clone());
            args.token_secret = None;
        }
        if args.token_secret.is_some() && args.token_secret_file.is_some() {
            bail!("token-secret and token-secret-file are mutually exclusive");
        }
        if let Some(audience) = matches.get_one::<String>("token-audience") {
            args.token_audience = Some(audience.clone());
        }
        if let Some(ttl) = matches.get_one::<String>("token-ttl") {
            args.token_ttl =
                parse_duration_secs(ttl).with_context(|| format!("Invalid token-ttl `{ttl}`"))?;
        }
        let revocation_file_from_cli = matches
            .get_one::<PathBuf>("token-revocation-file")
            .is_some();
        if let Some(path) = matches.get_one::<PathBuf>("token-revocation-file") {
            args.token_revocation_file = Some(path.clone());
        }

        if let Some(path) = args.token_secret_file.clone() {
            let base = if token_secret_file_from_cli {
                &cwd
            } else {
                config_dir.as_deref().unwrap_or(&cwd)
            };
            let path = Self::resolve_relative_path(&path, base);
            startup_inputs.push(capture_startup_input(
                &path,
                StartupInputKind::TokenSecret,
                "token secret",
                PrivateFileAccess::Secret,
                false,
            )?);
            args.token_secret_file = Some(path);
        }
        if let Some(path) = args.token_revocation_file.clone() {
            let base = if revocation_file_from_cli {
                &cwd
            } else {
                config_dir.as_deref().unwrap_or(&cwd)
            };
            let path = Self::resolve_relative_path(&path, base);
            validate_private_output_if_exists(&path, "token revocation state")?;
            args.token_revocation_file = Some(path);
        }
        // 中文：先基于已完成优先级合并与路径解析的 persistent secret 派生默认撤销输出，
        // 这样下方早期资源校验即可看到真实昂贵认证拓扑；不能等校验后才补路径。
        // English: Derive the default revocation output from the fully merged and path-resolved
        // persistent secret before early resource validation, so that validation sees the effective
        // expensive-auth topology rather than a path added afterward.
        let persistent_secret = args.token_secret.is_some() || args.token_secret_file.is_some();
        if persistent_secret && args.token_revocation_file.is_none() {
            args.token_revocation_file = Some(match args.token_secret_file.as_ref() {
                Some(path) => {
                    let mut name = path.as_os_str().to_os_string();
                    name.push(".revocations.json");
                    PathBuf::from(name)
                }
                None => config_dir
                    .as_deref()
                    .unwrap_or(&cwd)
                    .join(".ram-token-revocations.json"),
            });
        }

        // 中文：每层先应用总开关，再应用具体操作开关；即使总项来自 CLI、具体项来自环境，具体项仍胜出。
        // English: Apply aggregate gates before operation-specific gates at each layer, so the specific value always wins.
        if let Some(value) = explicit_bool(&matches, "allow-all") {
            args.allow_all = value;
            set_all_capabilities(&mut args, value);
        }
        for id in CAPABILITY_BOOL_IDS {
            if let Some(value) = explicit_bool(&matches, id) {
                set_capability(&mut args, id, value);
            }
        }
        if let Some(value) = explicit_bool(&matches, "render-index") {
            args.render_index = value;
        }

        if let Some(value) = explicit_bool(&matches, "render-try-index") {
            args.render_try_index = value;
        }

        if let Some(value) = explicit_bool(&matches, "render-spa") {
            args.render_spa = value;
        }

        let render_mode_enabled = args.render_index || args.render_try_index || args.render_spa;
        if args.allow_upload && render_mode_enabled && !args.allow_active_content_risk {
            bail!(
                "Refusing to combine uploads with same-origin render modes; separate the content origin or explicitly accept stored active-content risk with --allow-active-content-risk"
            );
        }
        if args.allow_upload && render_mode_enabled {
            eprintln!(
                "WARNING: --allow-active-content-risk permits uploaded site content to execute with this origin's authenticated browser authority"
            );
        }

        let assets_from_cli = matches.get_one::<PathBuf>("assets").is_some();
        if let Some(assets_path) = matches.get_one::<PathBuf>("assets") {
            args.assets = Some(assets_path.clone());
        }

        if let Some(assets_path) = &args.assets {
            let assets_base = if assets_from_cli {
                &cwd
            } else {
                config_dir.as_deref().unwrap_or(&cwd)
            };
            let assets = Args::sanitize_assets_path(assets_path, assets_base)?;
            validate_trusted_directory(&assets, "assets")?;
            args.assets = Some(assets);
        }

        if let Some(assets_path) = &args.assets {
            let p = assets_path.join("404.html");
            if p.exists() {
                args.error_page = Some(p);
            }
        }

        if let Some(log_format) = matches.get_one::<String>("log-format") {
            args.http_logger = log_format.parse()?;
        }

        let log_file_from_cli = matches.get_one::<PathBuf>("log-file").is_some();
        if let Some(log_file) = matches.get_one::<PathBuf>("log-file") {
            args.log_file = Some(log_file.clone());
        }
        if let Some(log_file) = &args.log_file {
            let base = if log_file_from_cli {
                &cwd
            } else {
                config_dir.as_deref().unwrap_or(&cwd)
            };
            args.log_file = Some(Self::resolve_relative_path(log_file, base));
        }

        if let Some(compress) = matches.get_one::<Compress>("compress") {
            args.compress = *compress;
        }

        if let Some(max_connections) = matches.get_one::<u64>("max-connections") {
            args.max_connections = *max_connections;
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

        if let Some(value) = matches.get_one::<u64>("max-concurrent-requests") {
            args.max_concurrent_requests = *value;
        }
        if let Some(value) = matches.get_one::<u64>("max-concurrent-requests-per-source") {
            args.max_concurrent_requests_per_source = *value;
        }
        if let Some(value) = matches.get_one::<u64>("max-concurrent-requests-per-user") {
            args.max_concurrent_requests_per_user = *value;
        }
        if let Some(value) = matches.get_one::<u64>("max-request-queue") {
            args.max_request_queue = *value;
        }
        if let Some(value) = matches.get_one::<String>("request-queue-timeout") {
            args.request_queue_timeout = parse_timeout_secs(value)
                .with_context(|| format!("Invalid request-queue-timeout `{value}`"))?;
        }
        if let Some(value) = matches.get_one::<String>("header-read-timeout") {
            args.header_read_timeout = parse_timeout_secs(value)
                .with_context(|| format!("Invalid header-read-timeout `{value}`"))?;
        }
        if let Some(value) = matches.get_one::<String>("connection-idle-timeout") {
            args.connection_idle_timeout = parse_timeout_secs(value)
                .with_context(|| format!("Invalid connection-idle-timeout `{value}`"))?;
        }
        if let Some(value) = matches.get_one::<String>("connection-max-lifetime") {
            args.connection_max_lifetime = parse_timeout_secs(value)
                .with_context(|| format!("Invalid connection-max-lifetime `{value}`"))?;
        }
        if let Some(value) = matches.get_one::<String>("response-write-idle-timeout") {
            args.response_write_idle_timeout = parse_timeout_secs(value)
                .with_context(|| format!("Invalid response-write-idle-timeout `{value}`"))?;
        }
        if let Some(value) = matches.get_one::<String>("write-lock-timeout") {
            args.write_lock_timeout = parse_timeout_secs(value)
                .with_context(|| format!("Invalid write-lock-timeout `{value}`"))?;
        }
        if let Some(value) = matches.get_one::<u32>("upload-file-mode") {
            args.upload_file_mode = *value;
        }
        if let Some(value) = matches.get_one::<u32>("upload-dir-mode") {
            args.upload_dir_mode = *value;
        }
        if let Some(value) = matches.get_one::<u64>("max-concurrent-uploads") {
            args.max_concurrent_uploads = *value;
        }
        if let Some(value) = matches.get_one::<u64>("max-concurrent-uploads-per-user") {
            args.max_concurrent_uploads_per_user = *value;
        }
        if let Some(value) = matches.get_one::<u64>("max-concurrent-uploads-per-source") {
            args.max_concurrent_uploads_per_source = *value;
        }
        if let Some(value) = matches.get_one::<u32>("h2-max-concurrent-streams") {
            args.h2_max_concurrent_streams = *value;
        }

        if let Some(value) = matches.get_one::<u64>("max-expensive-tasks") {
            args.max_expensive_tasks = *value;
        }
        if let Some(value) = matches.get_one::<u64>("max-blocking-threads") {
            args.max_blocking_threads = *value;
        }
        if let Some(value) = matches.get_one::<u64>("max-walk-entries") {
            args.max_walk_entries = *value;
        }
        if let Some(value) = matches.get_one::<u64>("max-walk-depth") {
            args.max_walk_depth = *value;
        }
        if let Some(value) = matches.get_one::<u64>("max-search-results") {
            args.max_search_results = *value;
        }
        if let Some(value) = matches.get_one::<u64>("max-directory-entries") {
            args.max_directory_entries = *value;
        }
        if let Some(value) = matches.get_one::<u64>("max-webdav-properties") {
            args.max_webdav_properties = *value;
        }
        if let Some(value) = matches.get_one::<u64>("max-webdav-rendered-properties") {
            args.max_webdav_rendered_properties = *value;
        }
        if let Some(value) = matches.get_one::<String>("max-webdav-response-size") {
            args.max_webdav_response_size = parse_size(value)
                .with_context(|| format!("Invalid max-webdav-response-size `{value}`"))?;
        }
        if let Some(value) = matches.get_one::<String>("max-archive-size") {
            args.max_archive_size =
                parse_size(value).with_context(|| format!("Invalid max-archive-size `{value}`"))?;
        }
        if let Some(value) = matches.get_one::<String>("max-hash-size") {
            args.max_hash_size =
                parse_size(value).with_context(|| format!("Invalid max-hash-size `{value}`"))?;
        }
        if let Some(value) = matches.get_one::<String>("expensive-task-timeout") {
            args.expensive_task_timeout = parse_timeout_secs(value)
                .with_context(|| format!("Invalid expensive-task-timeout `{value}`"))?;
        }
        if let Some(value) = matches.get_one::<String>("copy-timeout") {
            args.copy_timeout = parse_timeout_secs(value)
                .with_context(|| format!("Invalid copy-timeout `{value}`"))?;
        }
        if let Some(value) = matches.get_one::<String>("upload-idle-timeout") {
            args.upload_idle_timeout = parse_timeout_secs(value)
                .with_context(|| format!("Invalid upload-idle-timeout `{value}`"))?;
        }
        if let Some(value) = matches.get_one::<String>("upload-total-timeout") {
            args.upload_total_timeout = parse_timeout_secs(value)
                .with_context(|| format!("Invalid upload-total-timeout `{value}`"))?;
        }
        if let Some(value) = matches.get_one::<String>("stale-upload-cleanup-age") {
            args.stale_upload_cleanup_age = parse_timeout_secs(value)
                .with_context(|| format!("Invalid stale-upload-cleanup-age `{value}`"))?;
        }
        if let Some(value) = matches.get_one::<u64>("stale-upload-cleanup-max-entries") {
            args.stale_upload_cleanup_max_entries = *value;
        }
        if let Some(value) = matches.get_one::<u64>("stale-upload-cleanup-max-depth") {
            args.stale_upload_cleanup_max_depth = *value;
        }
        if let Some(value) = matches.get_one::<u64>("stale-upload-cleanup-max-deletions") {
            args.stale_upload_cleanup_max_deletions = *value;
        }
        if let Some(value) = matches.get_one::<String>("stale-upload-cleanup-timeout") {
            args.stale_upload_cleanup_timeout = parse_timeout_secs(value)
                .with_context(|| format!("Invalid stale-upload-cleanup-timeout `{value}`"))?;
        }

        if let Some(max_upload_size) = matches.get_one::<String>("max-upload-size") {
            args.max_upload_size = parse_size(max_upload_size)
                .with_context(|| format!("Invalid max-upload-size `{max_upload_size}`"))?;
        }
        if let Some(max_copy_size) = matches.get_one::<String>("max-copy-size") {
            args.max_copy_size = parse_size(max_copy_size)
                .with_context(|| format!("Invalid max-copy-size `{max_copy_size}`"))?;
        }
        if let Some(value) = explicit_bool(&matches, "storage-space-check") {
            args.storage_space_check = value;
        }
        if let Some(value) = matches.get_one::<String>("storage-reserve") {
            args.storage_reserve =
                parse_size(value).with_context(|| format!("Invalid storage-reserve `{value}`"))?;
        }
        let storage_quota_hook_from_cli =
            matches.get_one::<PathBuf>("storage-quota-hook").is_some();
        if let Some(path) = matches.get_one::<PathBuf>("storage-quota-hook") {
            args.storage_quota_hook = Some(path.clone());
        }
        if let Some(value) = matches.get_one::<String>("storage-quota-hook-timeout") {
            args.storage_quota_hook_timeout = parse_timeout_secs(value)
                .with_context(|| format!("Invalid storage-quota-hook-timeout `{value}`"))?;
        }
        if let Some(path) = args.storage_quota_hook.clone() {
            let base = if storage_quota_hook_from_cli {
                &cwd
            } else {
                config_dir.as_deref().unwrap_or(&cwd)
            };
            let resolved = Self::resolve_relative_path(&path, base);
            startup_inputs.push(capture_startup_input(
                &resolved,
                StartupInputKind::StorageQuotaHook,
                "storage quota hook",
                PrivateFileAccess::IntegrityOnly,
                true,
            )?);
            args.storage_quota_hook = Some(resolved);
        }
        #[cfg(feature = "tls")]
        if let Some(hsts_max_age) = matches.get_one::<u64>("hsts-max-age") {
            args.hsts_max_age = Some(*hsts_max_age);
        }
        validate_resource_limits(&args)?;

        #[cfg(feature = "tls")]
        {
            let tls_cert_from_cli = matches.get_one::<PathBuf>("tls-cert").is_some();
            let tls_key_from_cli = matches.get_one::<PathBuf>("tls-key").is_some();
            if let Some(tls_cert) = matches.get_one::<PathBuf>("tls-cert") {
                args.tls_cert = Some(tls_cert.clone())
            }

            if let Some(tls_key) = matches.get_one::<PathBuf>("tls-key") {
                args.tls_key = Some(tls_key.clone())
            }

            match (&args.tls_cert, &args.tls_key) {
                (Some(_), Some(_)) => {}
                (Some(_), _) => bail!("No tls-key set"),
                (_, Some(_)) => bail!("No tls-cert set"),
                (None, None) => {}
            }
            if args.hsts_max_age.is_some() && args.tls_cert.is_none() {
                bail!("hsts-max-age requires Ram's direct TLS configuration (tls-cert/tls-key)");
            }
            if let Some(tls_cert) = &args.tls_cert {
                let base = if tls_cert_from_cli {
                    &cwd
                } else {
                    config_dir.as_deref().unwrap_or(&cwd)
                };
                let resolved = Self::sanitize_path(tls_cert, base).with_context(|| {
                    format!("Failed to load cert file at `{}`", tls_cert.display())
                })?;
                startup_inputs.push(capture_startup_input(
                    &resolved,
                    StartupInputKind::TlsCertificate,
                    "TLS certificate",
                    PrivateFileAccess::IntegrityOnly,
                    false,
                )?);
                args.tls_cert = Some(resolved);
            }
            if let Some(tls_key) = &args.tls_key {
                let base = if tls_key_from_cli {
                    &cwd
                } else {
                    config_dir.as_deref().unwrap_or(&cwd)
                };
                let resolved = Self::resolve_relative_path(tls_key, base);
                startup_inputs.push(capture_startup_input(
                    &resolved,
                    StartupInputKind::TlsPrivateKey,
                    "TLS private key",
                    PrivateFileAccess::Secret,
                    false,
                )?);
                args.tls_key = Some(Self::sanitize_path(tls_key, base).with_context(|| {
                    format!("Failed to load key file at `{}`", tls_key.display())
                })?);
            }
        }
        #[cfg(not(feature = "tls"))]
        {
            // 中文：无 TLS 特性二进制不能静默忽略 TLS 配置，否则误以为 HTTPS 会暴露 Basic 凭据。
            // English: A no-TLS binary must reject TLS config rather than silently expose Basic credentials over plaintext.
            if args.tls_cert.is_some()
                || args.tls_key.is_some()
                || args.hsts_max_age.is_some()
                || env::var_os("RAM_TLS_CERT").is_some()
                || env::var_os("RAM_TLS_KEY").is_some()
                || env::var_os("RAM_HSTS_MAX_AGE").is_some()
            {
                bail!(
                    "TLS configuration was provided, but this binary was built without the `tls` feature"
                );
            }
        }

        // 中文：无认证用户即拒绝启动，匿名访问被禁用。 / English: Reject startup without a named user; anonymous access is disabled.
        if !args.auth.has_users() {
            bail!("At least one auth user rule is required; anonymous access is disabled");
        }

        // 中文：示例占位密码未经修改等同无密码，拒绝启动。 / English: Reject an unchanged example placeholder password.
        if args.auth.has_placeholder_password() {
            bail!(
                "Refusing to start: an auth rule still uses the placeholder password \
                 `change-me`. Set a real password before running."
            );
        }

        let has_non_loopback_tcp = args
            .addrs
            .iter()
            .any(|addr| matches!(addr, BindAddr::IpAddr(ip) if !ip.is_loopback()));
        if has_non_loopback_tcp && args.tls_cert.is_none() && !args.allow_insecure_http {
            bail!(
                "Refusing authenticated cleartext HTTP on a non-loopback address. Configure TLS, bind only loopback/Unix sockets, or explicitly accept the risk with --allow-insecure-http"
            );
        }
        if has_non_loopback_tcp && args.tls_cert.is_none() {
            eprintln!(
                "WARNING: --allow-insecure-http exposes reusable credentials over cleartext HTTP"
            );
        }

        // 中文：默认撤销路径在合并后才派生，加载/覆盖前必须通过与显式输出相同的末段、链接与 mode 检查。
        // English: The merged default revocation path receives the same final-component/link/mode validation as explicit output.
        if let Some(path) = args.token_revocation_file.as_deref() {
            validate_private_output_if_exists(path, "token revocation state")?;
            let mut lock_name = path.as_os_str().to_os_string();
            lock_name.push(".lock");
            validate_private_output_if_exists(
                &PathBuf::from(lock_name),
                "token revocation instance lock",
            )?;
        }
        if !persistent_secret && args.token_revocation_file.is_some() {
            bail!("token-revocation-file requires a persistent token-secret or token-secret-file");
        }
        // 中文：打开持久 token 状态前捕获一致输入/输出能力集，后续只传描述符，不再打开敏感路径名。
        // English: Capture one coherent capability set before token persistence; later consumers receive descriptors only.
        let mut startup_paths = validate_path_isolation_with_inputs(&args, startup_inputs)?;
        let token_secret = match (&args.token_secret, &args.token_secret_file) {
            (Some(secret), None) => Some(secret.as_bytes().to_vec()),
            (None, Some(_)) => Some(read_token_secret_from_identity(
                startup_paths
                    .input(StartupInputKind::TokenSecret)
                    .ok_or_else(|| anyhow::anyhow!("token secret capability is missing"))?,
            )?),
            (None, None) => None,
            (Some(_), Some(_)) => unreachable!(),
        };
        let revocation_capabilities = startup_paths.token_revocation_capabilities()?;
        if purpose == ParsePurpose::Run {
            args.auth.configure_security(
                token_secret.as_deref(),
                args.token_audience.as_deref(),
                args.token_ttl,
                revocation_capabilities.clone(),
            )?;
        } else {
            args.auth.validate_security_configuration(
                token_secret.as_deref(),
                args.token_audience.as_deref(),
                args.token_ttl,
                revocation_capabilities.as_ref(),
            )?;
        }
        // 中文：安全配置完成后再次校验资源拓扑。Run 检查实际绑定的持久后端；Check 模式
        // 通过上方派生的 effective 输出 hint 得到相同下限，且不会创建状态文件。保留早期
        // 校验可在任何敏感输出 I/O 前拒绝其他无关资源错误，此处负责防止未来顺序回归。
        // English: Revalidate the resource topology after security setup. Run mode sees the bound
        // durable backend; check-config obtains the same minimum from the derived effective output
        // hint without creating files. The earlier validation still rejects unrelated budget errors
        // before sensitive output I/O, while this pass prevents future ordering regressions.
        validate_resource_limits(&args)?;
        // 中文：AccessControl 只保留规范化固定大小 HMAC key；Server 的长期 Args 不保留原配置 secret，避免未来诊断泄露。
        // English: Retain only the normalized HMAC key, not original config secret material in long-lived Args.
        args.token_secret = None;
        if purpose == ParsePurpose::Run {
            let final_revocation_capabilities = args
                .auth
                .finalize_token_revocation_capabilities(revocation_capabilities.as_ref())?;
            startup_paths
                .bind_final_revocation_capabilities(final_revocation_capabilities.as_ref())?;
        }
        args.startup_paths = Some(startup_paths);

        Ok(args)
    }

    pub(super) fn load_config(
        config_path: &Path,
    ) -> Result<(Args, HashSet<String>, StartupExistingIdentity)> {
        let identity = capture_startup_input(
            config_path,
            StartupInputKind::Configuration,
            "configuration file",
            PrivateFileAccess::IntegrityOnly,
            false,
        )?;
        let contents = read_private_file_from_identity(
            &identity.identity,
            "configuration",
            PRIVATE_CONFIG_MAX_BYTES,
            PrivateFileAccess::IntegrityOnly,
        )?;
        let contents = String::from_utf8(contents).with_context(|| {
            format!(
                "Configuration file `{}` is not valid UTF-8",
                config_path.display()
            )
        })?;
        let args: Args = serde_yaml_ng::from_str(&contents)
            .with_context(|| format!("Failed to load config at {}", config_path.display()))?;
        let value: serde_yaml_ng::Value = serde_yaml_ng::from_str(&contents)
            .with_context(|| format!("Failed to inspect config at {}", config_path.display()))?;
        let keys = value
            .as_mapping()
            .map(|mapping| {
                mapping
                    .keys()
                    .filter_map(serde_yaml_ng::Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        Ok((args, keys, identity))
    }

    /// 把 `path` 解析成规范化的绝对路径。相对路径基于 `base` 解析
    /// （由调用方决定：CLI/环境路径用进程 cwd，YAML 内部路径用配置文件
    /// 所在目录），而不是在此处隐式选择 cwd。
    /// Resolve to an absolute normalized path against an explicit base selected by the source, never an implicit cwd.
    pub(super) fn sanitize_path<P: AsRef<Path>>(path: P, base: &Path) -> Result<PathBuf> {
        let path = path.as_ref();
        let full = if path.is_absolute() {
            path.to_path_buf()
        } else {
            base.join(path)
        };
        if !full.exists() {
            bail!("Path `{}` doesn't exist", full.display());
        }

        std::fs::canonicalize(&full)
            .with_context(|| format!("Failed to access path `{}`", full.display()))
    }

    pub(super) fn sanitize_assets_path<P: AsRef<Path>>(path: P, base: &Path) -> Result<PathBuf> {
        let path = Self::sanitize_path(path, base)?;
        if !path.join("index.html").exists() {
            bail!("Path `{}` doesn't contains index.html", path.display());
        }
        Ok(path)
    }

    /// 解析允许尚不存在的输出路径（例如 log-file）。输入文件名保持不变，
    /// 但相对路径始终绑定到明确的配置目录或 cwd，而不依赖启动方式。
    /// Resolve a possibly absent output while binding relative paths to an explicit config directory/cwd.
    pub(super) fn resolve_relative_path(path: &Path, base: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            base.join(path)
        }
    }
}
