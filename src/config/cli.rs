//! 命令行结构与 shell 补全生成。所有 CLI/环境变量标识必须和 `sources` 的合并
//! 逻辑保持一致；新增选项不得产生未被合并的影子值。
//!
//! Command-line schema and shell completion generation.
//!
//! Invariant: every CLI/environment identifier remains aligned with the merge
//! logic in `sources`; adding an option must not create an unmerged shadow value.

use super::*;

fn boolean_switch(id: &'static str, env_name: &'static str, help: &'static str) -> Arg {
    Arg::new(id)
        .env(env_name)
        .hide_env(true)
        .long(id)
        .action(ArgAction::Set)
        .num_args(0..=1)
        .require_equals(true)
        .default_missing_value("true")
        .value_parser(value_parser!(bool))
        .help(help)
}

/// 声明全部命令行参数；每个 `Arg` 同时挂对应的 `RAM_*` 环境变量。
/// Declare every CLI option and attach its matching `RAM_*` environment variable.
pub fn build_cli() -> Command {
    // 中文：库 crate 名为 `ram_fileserver`，但安装后的公开命令和文档调用统一为 `ram`。
    // English: The library crate is `ram_fileserver`, while the installed
    // executable and every documented invocation are named `ram`.
    Command::new("ram")
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(concat!(
            env!("CARGO_PKG_DESCRIPTION"),
            " - ",
            env!("CARGO_PKG_REPOSITORY")
        ))
        .after_help(
            "Resource limits default to the bounded personal-intranet profile. \
             Override advanced controls only after measuring a real bottleneck.",
        )
        .arg(
            Arg::new("config")
                .env("RAM_CONFIG")
                .hide_env(true)
                .long("config")
                .value_parser(value_parser!(PathBuf))
                .value_name("path")
                .help("Load this configuration file (relative paths here use the process cwd)"),
        )
        .arg(
            Arg::new("serve-path")
                .env("RAM_SERVE_PATH")
                .hide_env(true)
                .value_parser(value_parser!(PathBuf))
                .help("Specific path to serve [default: .]"),
        )
        .arg(
            Arg::new("bind")
                .env("RAM_BIND")
                .hide_env(true)
                .short('b')
                .long("bind")
                .help("Specify a TCP IP address")
                .action(ArgAction::Append)
                .value_delimiter(',')
                .value_name("addrs"),
        )
        .arg(
            Arg::new("port")
                .env("RAM_PORT")
                .hide_env(true)
                .short('p')
                .long("port")
                .value_parser(value_parser!(u16))
                .help("Specify port to listen on [default: 5000]")
                .value_name("port"),
        )
        .arg(
            Arg::new("path-prefix")
                .env("RAM_PATH_PREFIX")
                .hide_env(true)
                .long("path-prefix")
                .value_name("path")
                .help("Specify a path prefix"),
        )
        .arg(
            Arg::new("hidden")
                .env("RAM_HIDDEN")
                .hide_env(true)
                .long("hidden")
                .action(ArgAction::Append)
                .value_delimiter(',')
                .help("Hide paths from directory listings, e.g. tmp,*.log,*.lock")
                .value_name("value"),
        )
        .arg(
            Arg::new("auth")
                .env("RAM_AUTH")
                .hide_env(true)
                .short('a')
                .long("auth")
                .conflicts_with("auth-file")
                .help("DEVELOPMENT ONLY: put credentials in argv; production should use --auth-file")
                .action(ArgAction::Append)
                .value_name("rules"),
        )
        .arg(
            Arg::new("auth-file")
                .env("RAM_AUTH_FILE")
                .hide_env(true)
                .long("auth-file")
                .conflicts_with("auth")
                .value_parser(value_parser!(PathBuf))
                .value_name("path")
                .help("Read one auth rule per line from a trusted 0400/0600 private file"),
        )
        .arg(boolean_switch(
            "allow-insecure-http",
            "RAM_ALLOW_INSECURE_HTTP",
            "DANGEROUS: allow authenticated cleartext HTTP on non-loopback TCP",
        ))
        .arg(boolean_switch(
            "allow-filesystem-root",
            "RAM_ALLOW_FILESYSTEM_ROOT",
            "DANGEROUS: explicitly permit serving the filesystem root `/`",
        ))
        .arg(
            boolean_switch("allow-all", "RAM_ALLOW_ALL", "Allow all operations").short('A'),
        )
        .arg(boolean_switch(
            "allow-upload",
            "RAM_ALLOW_UPLOAD",
            "Allow upload files/folders",
        ))
        .arg(boolean_switch(
            "allow-delete",
            "RAM_ALLOW_DELETE",
            "Allow delete files/folders",
        ))
        .arg(boolean_switch(
            "allow-search",
            "RAM_ALLOW_SEARCH",
            "Allow search files/folders",
        ))
        .arg(boolean_switch(
            "allow-symlink",
            "RAM_ALLOW_SYMLINK",
            "Allow following symbolic links (disabled by default for ACL safety)",
        ))
        .arg(boolean_switch(
            "allow-archive",
            "RAM_ALLOW_ARCHIVE",
            "Allow download folders as archive file",
        ))
        .arg(
            Arg::new("log-format")
                .env("RAM_LOG_FORMAT")
                .hide_env(true)
                .long("log-format")
                .value_name("format")
                .help("Customize http log format"),
        )
        .arg(
            Arg::new("compress")
                .env("RAM_COMPRESS")
                .hide_env(true)
                .value_parser(clap::builder::EnumValueParser::<Compress>::new())
                .long("compress")
                .value_name("level")
                .help("Set zip compress level [default: low]")
        )
        .next_help_heading("Advanced personal-intranet resource overrides")
        .arg(
            Arg::new("max-connections")
                .env("RAM_MAX_CONNECTIONS")
                .hide_env(true)
                .long("max-connections")
                .value_parser(value_parser!(u64).range(1..))
                .value_name("number")
                .help("Maximum number of concurrent connections [default: 64]"),
        )
        .arg(
            Arg::new("max-concurrent-requests")
                .env("RAM_MAX_CONCURRENT_REQUESTS")
                .hide_env(true)
                .long("max-concurrent-requests")
                .value_parser(value_parser!(u64).range(1..))
                .value_name("number")
                .help("Maximum requests executing or streaming across all connections [default: 32]"),
        )
        .arg(
            Arg::new("max-concurrent-requests-per-source")
                .env("RAM_MAX_CONCURRENT_REQUESTS_PER_SOURCE")
                .hide_env(true)
                .long("max-concurrent-requests-per-source")
                .value_parser(value_parser!(u64).range(1..))
                .value_name("number")
                .help("Maximum executing or streaming requests per remote IP [default: 32]"),
        )
        .arg(
            Arg::new("max-concurrent-requests-per-user")
                .env("RAM_MAX_CONCURRENT_REQUESTS_PER_USER")
                .hide_env(true)
                .long("max-concurrent-requests-per-user")
                .value_parser(value_parser!(u64).range(1..))
                .value_name("number")
                .help("Maximum executing or streaming requests per authenticated account [default: 32]"),
        )
        .arg(
            Arg::new("max-request-queue")
                .env("RAM_MAX_REQUEST_QUEUE")
                .hide_env(true)
                .long("max-request-queue")
                .value_parser(value_parser!(u64))
                .value_name("number")
                .help("Maximum requests waiting for the global request limit [default: 32; 0 = no waiting]"),
        )
        .arg(
            Arg::new("request-queue-timeout")
                .env("RAM_REQUEST_QUEUE_TIMEOUT")
                .hide_env(true)
                .long("request-queue-timeout")
                .value_name("duration")
                .help("Maximum wait for a request execution slot, e.g. 1s, 30s [default: 5s]"),
        )
        .arg(
            Arg::new("header-read-timeout")
                .env("RAM_HEADER_READ_TIMEOUT")
                .hide_env(true)
                .long("header-read-timeout")
                .value_name("duration")
                .help("Maximum time to receive an HTTP/1 request head [default: 30s]"),
        )
        .arg(
            Arg::new("connection-idle-timeout")
                .env("RAM_CONNECTION_IDLE_TIMEOUT")
                .hide_env(true)
                .long("connection-idle-timeout")
                .value_name("duration")
                .help("Close a connection with no successful network I/O for this long [default: 60s]"),
        )
        .arg(
            Arg::new("connection-max-lifetime")
                .env("RAM_CONNECTION_MAX_LIFETIME")
                .hide_env(true)
                .long("connection-max-lifetime")
                .value_name("duration")
                .help("Hard maximum lifetime of one accepted HTTP connection [default: 1h]"),
        )
        .arg(
            Arg::new("response-write-idle-timeout")
                .env("RAM_RESPONSE_WRITE_IDLE_TIMEOUT")
                .hide_env(true)
                .long("response-write-idle-timeout")
                .value_name("duration")
                .help("Close a connection when its transport write or response body makes no progress [default: 30s]"),
        )
        .arg(
            Arg::new("write-lock-timeout")
                .env("RAM_WRITE_LOCK_TIMEOUT")
                .hide_env(true)
                .long("write-lock-timeout")
                .value_name("duration")
                .help("Maximum wait for conflicting filesystem mutations [default: 5s]"),
        )
        .arg(
            Arg::new("upload-file-mode")
                .env("RAM_UPLOAD_FILE_MODE")
                .hide_env(true)
                .long("upload-file-mode")
                .value_parser(parse_permission_mode)
                .value_name("octal-mode")
                .help("Exact mode for newly published upload files [default: 0600]"),
        )
        .arg(
            Arg::new("upload-dir-mode")
                .env("RAM_UPLOAD_DIR_MODE")
                .hide_env(true)
                .long("upload-dir-mode")
                .value_parser(parse_permission_mode)
                .value_name("octal-mode")
                .help("Exact mode for new upload directories; owner rwx (0700) is required [default: 0700]"),
        )
        .arg(
            Arg::new("max-concurrent-uploads")
                .env("RAM_MAX_CONCURRENT_UPLOADS")
                .hide_env(true)
                .long("max-concurrent-uploads")
                .value_parser(value_parser!(u64).range(1..))
                .value_name("number")
                .help("Maximum PUT bodies staged concurrently [default: 4]"),
        )
        .arg(
            Arg::new("max-concurrent-uploads-per-user")
                .env("RAM_MAX_CONCURRENT_UPLOADS_PER_USER")
                .hide_env(true)
                .long("max-concurrent-uploads-per-user")
                .value_parser(value_parser!(u64).range(1..))
                .value_name("number")
                .help("Maximum staged PUT bodies per authenticated user; hard maximum 1024 [default: 2]"),
        )
        .arg(
            Arg::new("max-concurrent-uploads-per-source")
                .env("RAM_MAX_CONCURRENT_UPLOADS_PER_SOURCE")
                .hide_env(true)
                .long("max-concurrent-uploads-per-source")
                .value_parser(value_parser!(u64).range(1..))
                .value_name("number")
                .help("Maximum staged PUT bodies per remote IP; hard maximum 1024 [default: 3]"),
        )
        .arg(
            Arg::new("max-expensive-tasks")
                .env("RAM_MAX_EXPENSIVE_TASKS")
                .hide_env(true)
                .long("max-expensive-tasks")
                .value_parser(value_parser!(u64).range(1..))
                .value_name("number")
                .help("Shared admission for directory/search/archive and PUT workers [default: 2]"),
        )
        .arg(
            Arg::new("max-blocking-threads")
                .env("RAM_MAX_BLOCKING_THREADS")
                .hide_env(true)
                .long("max-blocking-threads")
                .value_parser(value_parser!(u64).range(1..))
                .value_name("number")
                .help("Hard maximum Tokio blocking-pool threads; 1..256 [default: 12]"),
        )
        .arg(
            Arg::new("max-walk-entries")
                .env("RAM_MAX_WALK_ENTRIES")
                .hide_env(true)
                .long("max-walk-entries")
                .value_parser(value_parser!(u64).range(1..))
                .value_name("number")
                .help("Maximum filesystem entries scanned by one traversal [default: 1000000]"),
        )
        .arg(
            Arg::new("max-walk-depth")
                .env("RAM_MAX_WALK_DEPTH")
                .hide_env(true)
                .long("max-walk-depth")
                .value_parser(value_parser!(u64).range(1..))
                .value_name("number")
                .help("Maximum directory traversal depth [default: 64]"),
        )
        .arg(
            Arg::new("max-search-results")
                .env("RAM_MAX_SEARCH_RESULTS")
                .hide_env(true)
                .long("max-search-results")
                .value_parser(value_parser!(u64).range(1..))
                .value_name("number")
                .help("Maximum results returned by one search [default: 5000]"),
        )
        .arg(
            Arg::new("max-directory-entries")
                .env("RAM_MAX_DIRECTORY_ENTRIES")
                .hide_env(true)
                .long("max-directory-entries")
                .value_parser(value_parser!(u64).range(1..))
                .value_name("number")
                .help("Maximum entries returned by one directory listing [default: 10000]"),
        )
        .arg(
            Arg::new("max-archive-size")
                .env("RAM_MAX_ARCHIVE_SIZE")
                .hide_env(true)
                .long("max-archive-size")
                .value_name("size")
                .help("Maximum uncompressed bytes in one archive, e.g. 512M, 4G [default: 4G]"),
        )
        .arg(
            Arg::new("expensive-task-timeout")
                .env("RAM_EXPENSIVE_TASK_TIMEOUT")
                .hide_env(true)
                .long("expensive-task-timeout")
                .value_name("duration")
                .help("Timeout for search/archive and local mutation workers, e.g. 30s, 5m [default: 5m]"),
        )
        .arg(
            Arg::new("upload-idle-timeout")
                .env("RAM_UPLOAD_IDLE_TIMEOUT")
                .hide_env(true)
                .long("upload-idle-timeout")
                .value_name("duration")
                .help("Abort an upload after no body data arrives for this long [default: 30s]"),
        )
        .arg(
            Arg::new("upload-total-timeout")
                .env("RAM_UPLOAD_TOTAL_TIMEOUT")
                .hide_env(true)
                .long("upload-total-timeout")
                .value_name("duration")
                .help("Maximum staging time for one PUT upload [default: 15m]"),
        )
        .arg(
            Arg::new("stale-upload-cleanup-age")
                .env("RAM_STALE_UPLOAD_CLEANUP_AGE")
                .hide_env(true)
                .long("stale-upload-cleanup-age")
                .value_name("duration")
                .help("Minimum age of an unlocked private upload candidate before startup/periodic cleanup [default: 24h]"),
        )
        .arg(
            Arg::new("stale-upload-cleanup-max-entries")
                .env("RAM_STALE_UPLOAD_CLEANUP_MAX_ENTRIES")
                .hide_env(true)
                .long("stale-upload-cleanup-max-entries")
                .value_parser(value_parser!(u64).range(1..))
                .value_name("number")
                .help("Maximum entries inspected by each upload cleanup pass; hard maximum 1000000 [default: 100000]"),
        )
        .arg(
            Arg::new("stale-upload-cleanup-max-depth")
                .env("RAM_STALE_UPLOAD_CLEANUP_MAX_DEPTH")
                .hide_env(true)
                .long("stale-upload-cleanup-max-depth")
                .value_parser(value_parser!(u64).range(1..))
                .value_name("number")
                .help("Maximum directory depth inspected by each upload cleanup pass; hard maximum 256 [default: 64]"),
        )
        .arg(
            Arg::new("stale-upload-cleanup-max-deletions")
                .env("RAM_STALE_UPLOAD_CLEANUP_MAX_DELETIONS")
                .hide_env(true)
                .long("stale-upload-cleanup-max-deletions")
                .value_parser(value_parser!(u64).range(1..))
                .value_name("number")
                .help("Maximum stale candidates removed by each cleanup pass; hard maximum 100000 [default: 1000]"),
        )
        .arg(
            Arg::new("stale-upload-cleanup-timeout")
                .env("RAM_STALE_UPLOAD_CLEANUP_TIMEOUT")
                .hide_env(true)
                .long("stale-upload-cleanup-timeout")
                .value_name("duration")
                .help("Cooperative deadline for each startup/periodic upload-cleanup pass; hard maximum 60s [default: 5s]"),
        )
        .arg(
            Arg::new("max-upload-size")
                .env("RAM_MAX_UPLOAD_SIZE")
                .hide_env(true)
                .long("max-upload-size")
                .value_name("size")
                .help("Maximum size of a single upload, e.g. 512M, 4G [default: 4G]"),
        )
        .arg(boolean_switch(
            "storage-space-check",
            "RAM_STORAGE_SPACE_CHECK",
            "Preflight target statvfs space/inode availability before PUT",
        ))
        .arg(
            Arg::new("storage-reserve")
                .env("RAM_STORAGE_RESERVE")
                .hide_env(true)
                .long("storage-reserve")
                .value_name("size")
                .help("Free bytes retained by storage-space-check [default: 5G]"),
        )
        .next_help_heading("Other")
        .arg(
            Arg::new("check-config")
                .long("check-config")
                .action(ArgAction::SetTrue)
                .conflicts_with("completions")
                .help("Validate the effective configuration without starting the server"),
        )
        .arg(
            Arg::new("completions")
                .long("completions")
                .value_name("shell")
                .value_parser(value_parser!(Shell))
                .help("Print shell completion script for <shell>"),
        )
}

pub fn print_completions<G: Generator>(generator: G, cmd: &mut Command) {
    generate(
        generator,
        cmd,
        cmd.get_name().to_string(),
        &mut std::io::stdout(),
    );
}
