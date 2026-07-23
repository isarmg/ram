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

pub(super) const CAPABILITY_BOOL_IDS: [&str; 5] = [
    "allow-upload",
    "allow-delete",
    "allow-search",
    "allow-symlink",
    "allow-archive",
];

pub(super) fn set_capability(args: &mut Args, id: &str, value: bool) {
    match id {
        "allow-upload" => args.allow_upload = value,
        "allow-delete" => args.allow_delete = value,
        "allow-search" => args.allow_search = value,
        "allow-symlink" => args.allow_symlink = value,
        "allow-archive" => args.allow_archive = value,
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
    pub fn parse(matches: ArgMatches) -> Result<Args> {
        let cwd = env::current_dir().with_context(|| "Failed to determine current directory")?;
        let config_path = matches
            .get_one::<PathBuf>("config")
            .map(|path| Self::resolve_relative_path(path, &cwd));
        Self::parse_with_config_for(matches, config_path.as_deref())
    }

    /// 真正的"配置文件为基底、命令行覆盖"合并逻辑。
    /// 单独拆出来可让单元测试直接覆盖显式 YAML 与命令行的合并规则。
    /// Core file-as-base, CLI-overrides merge, exposed separately for focused unit tests.
    #[cfg(test)]
    pub(super) fn parse_with_config(
        matches: ArgMatches,
        config_path: Option<&Path>,
    ) -> Result<Args> {
        Self::parse_with_config_for(matches, config_path)
    }

    pub(super) fn parse_with_config_for(
        matches: ArgMatches,
        config_path: Option<&Path>,
    ) -> Result<Args> {
        let mut args = Self::default();
        let mut startup_inputs = Vec::new();
        let cwd = env::current_dir().with_context(|| "Failed to determine current directory")?;
        // 显式 YAML 里写的相对 `serve-path`，必须按配置文件自己
        // 所在目录解析，而不是进程工作目录。服务管理器可能把 cwd 设为 `/`；
        // 若按 cwd 解析，可能悄悄暴露运维者完全没打算服务的目录。
        // English: Resolve a YAML-relative serve path against the config
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

        if let Some(addrs) = matches.get_many::<String>("bind") {
            let addrs: Vec<_> = addrs.map(|v| v.as_str()).collect();
            args.addrs = BindAddr::parse_addrs(&addrs)?;
        }
        if args.addrs.is_empty() {
            bail!("At least one bind address is required");
        }
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
            let identity =
                capture_startup_input(&path, "authentication file", PrivateFileAccess::Secret)?;
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
        if let Some(log_format) = matches.get_one::<String>("log-format") {
            args.http_logger = log_format.parse()?;
        }

        if let Some(compress) = matches.get_one::<Compress>("compress") {
            args.compress = *compress;
        }

        if let Some(max_connections) = matches.get_one::<u64>("max-connections") {
            args.max_connections = *max_connections;
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
        if let Some(value) = matches.get_one::<String>("max-archive-size") {
            args.max_archive_size =
                parse_size(value).with_context(|| format!("Invalid max-archive-size `{value}`"))?;
        }
        if let Some(value) = matches.get_one::<String>("expensive-task-timeout") {
            args.expensive_task_timeout = parse_timeout_secs(value)
                .with_context(|| format!("Invalid expensive-task-timeout `{value}`"))?;
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
        if let Some(value) = explicit_bool(&matches, "storage-space-check") {
            args.storage_space_check = value;
        }
        if let Some(value) = matches.get_one::<String>("storage-reserve") {
            args.storage_reserve =
                parse_size(value).with_context(|| format!("Invalid storage-reserve `{value}`"))?;
        }
        validate_resource_limits(&args)?;

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
        if has_non_loopback_tcp && !args.allow_insecure_http {
            bail!(
                "Refusing authenticated cleartext HTTP on a non-loopback address. Bind only loopback or explicitly accept the gateway-protected deployment with --allow-insecure-http"
            );
        }
        if has_non_loopback_tcp {
            eprintln!(
                "WARNING: --allow-insecure-http exposes reusable credentials over cleartext HTTP"
            );
        }

        // 中文：捕获一致输入/输出能力集，后续只传描述符，不再打开敏感路径名。
        // English: Capture one coherent capability set; later consumers receive descriptors only.
        let startup_paths = validate_path_isolation_with_inputs(&args, startup_inputs)?;
        // 中文：路径隔离后再次校验资源拓扑，防止未来顺序回归。
        // English: Revalidate the resource topology after path isolation to guard against ordering regressions.
        validate_resource_limits(&args)?;
        args.startup_paths = Some(startup_paths);

        Ok(args)
    }

    pub(super) fn load_config(
        config_path: &Path,
    ) -> Result<(Args, HashSet<String>, StartupExistingIdentity)> {
        let identity = capture_startup_input(
            config_path,
            "configuration file",
            PrivateFileAccess::IntegrityOnly,
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

    /// 解析允许尚不存在的路径；相对路径始终绑定到明确的配置目录或 cwd。
    /// Resolve a possibly absent path against an explicit config directory or cwd.
    pub(super) fn resolve_relative_path(path: &Path, base: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            base.join(path)
        }
    }
}
