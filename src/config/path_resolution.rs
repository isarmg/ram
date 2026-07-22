//! 启动路径解析与文件系统能力捕获。敏感输入/输出只解析一次，经可信属主与隔离检查后
//! 以固定身份交给运行时；任何消费者都不得退回到重新打开配置路径名。
//!
//! Startup path resolution and filesystem capability capture.
//!
//! Invariant: sensitive inputs/outputs are resolved once, checked for trusted
//! ownership and isolation, then handed to runtime code as pinned identities.
//! No consumer may fall back to reopening a configured pathname.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(feature = "tls"), allow(dead_code))]
pub(crate) enum StartupInputKind {
    Configuration,
    TlsCertificate,
    TlsPrivateKey,
    AuthenticationFile,
    TokenSecret,
    StorageQuotaHook,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StartupOutputKind {
    TokenRevocationState,
    TokenRevocationLock,
    AccessLog,
    /// 日志轮转会 unlink/rename 的派生槽。 / Derived slot that log rotation may unlink or rename over.
    AccessLogBackup(usize),
    /// pathname Unix listener 的可达名称；abstract socket 没有文件系统槽。
    /// Reachability name of a pathname Unix listener; abstract sockets have no filesystem slot.
    ListenerSocket(usize),
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct StartupExistingIdentity {
    pub(super) kind: StartupInputKind,
    pub(super) label: &'static str,
    pub(super) identity: PathIdentity,
    pub(super) access: PrivateFileAccess,
    pub(super) require_executable: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct StartupOutputIdentity {
    kind: StartupOutputKind,
    label: &'static str,
    identity: OutputPathIdentity,
}

/// 所有路径源解析后才捕获的文件系统权限快照，直接交给 `Server::init`，不再规范化原字符串。
/// Filesystem authorities captured after all sources resolve and carried into `Server::init` without recanonicalizing configured strings.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct StartupPathIdentities {
    served: ServedPathIdentity,
    assets: Option<ServedPathIdentity>,
    existing: Vec<StartupExistingIdentity>,
    outputs: Vec<StartupOutputIdentity>,
}

impl StartupPathIdentities {
    pub(crate) fn served(&self) -> &ServedPathIdentity {
        &self.served
    }

    pub(crate) fn assets(&self) -> Option<&ServedPathIdentity> {
        self.assets.as_ref()
    }

    pub(crate) fn input(&self, kind: StartupInputKind) -> Option<&PathIdentity> {
        self.existing
            .iter()
            .find(|entry| entry.kind == kind)
            .map(|entry| &entry.identity)
    }

    pub(crate) fn output(&self, kind: StartupOutputKind) -> Option<&OutputPathIdentity> {
        self.outputs
            .iter()
            .find(|entry| entry.kind == kind)
            .map(|entry| &entry.identity)
    }

    pub(crate) fn log_file(&self) -> Option<&OutputPathIdentity> {
        self.output(StartupOutputKind::AccessLog)
    }

    pub(crate) fn storage_quota_hook(&self) -> Option<&PathIdentity> {
        self.input(StartupInputKind::StorageQuotaHook)
    }

    pub(crate) fn token_revocation_capabilities(
        &self,
    ) -> Result<Option<TokenRevocationCapabilities>> {
        match (
            self.output(StartupOutputKind::TokenRevocationState),
            self.output(StartupOutputKind::TokenRevocationLock),
        ) {
            (None, None) => Ok(None),
            (Some(state), Some(lock)) => Ok(Some(TokenRevocationCapabilities::new(
                state.clone(),
                lock.clone(),
            )?)),
            _ => bail!("token revocation state and lock capabilities are incomplete"),
        }
    }

    /// 保存认证后端实际绑定的身份；共享状态可在同一固定父目录下原子替换，既有锁必须精确不变，缺失锁只能变为后端创建的精确 inode。
    /// Store identities actually bound by auth: replaceable state stays below the pinned parent, while the lock must remain or become the exact backend inode.
    pub(super) fn bind_final_revocation_capabilities(
        &mut self,
        final_capabilities: Option<&TokenRevocationCapabilities>,
    ) -> Result<()> {
        let initial = self.token_revocation_capabilities()?;
        match (initial.as_ref(), final_capabilities) {
            (None, None) => return Ok(()),
            (Some(initial), Some(final_capabilities)) => {
                if final_capabilities.state().expected_object().is_none() {
                    bail!("token revocation state was not created during security setup");
                }
                if final_capabilities.lock().expected_object().is_none() {
                    bail!("token revocation instance lock was not created during security setup");
                }
                if initial.lock().expected_object().is_some()
                    && initial.lock().expected_object()
                        != final_capabilities.lock().expected_object()
                {
                    bail!(
                        "existing token revocation instance lock changed identity during security setup"
                    );
                }
            }
            _ => bail!("token revocation capabilities changed during security setup"),
        }
        let Some(final_capabilities) = final_capabilities else {
            return Ok(());
        };
        for output in &mut self.outputs {
            match output.kind {
                StartupOutputKind::TokenRevocationState => {
                    output.identity = final_capabilities.state().clone();
                }
                StartupOutputKind::TokenRevocationLock => {
                    output.identity = final_capabilities.lock().clone();
                }
                StartupOutputKind::AccessLog
                | StartupOutputKind::AccessLogBackup(_)
                | StartupOutputKind::ListenerSocket(_) => {}
            }
        }
        Ok(())
    }

    pub(crate) fn verify_sensitive_for_server_init(&self) -> Result<()> {
        for expected in &self.existing {
            let file = expected.identity.open_metadata_pinned().with_context(|| {
                format!(
                    "{} identity changed before server initialization",
                    expected.label
                )
            })?;
            let metadata = file.metadata()?;
            validate_private_metadata(
                &metadata,
                expected.identity.canonical(),
                expected.label,
                expected.access,
            )?;
            if expected.require_executable && metadata.mode() & 0o111 == 0 {
                bail!(
                    "{} is no longer executable: `{}`",
                    expected.label,
                    expected.identity.canonical().display()
                );
            }
        }
        Ok(())
    }
}

pub(super) fn resolve_pathname_bind_addrs(addrs: &mut [BindAddr], base: &Path) -> Result<()> {
    for address in addrs {
        let BindAddr::SocketPath(path) = address else {
            continue;
        };
        // 中文：Linux abstract 名是独立命名空间的字节串而非文件路径；加 cwd/config_dir
        // 会把危险 opt-in 静默变成无关 pathname socket。
        // English: Abstract names are byte strings in another namespace, not
        // paths; prefixing a base would silently change the requested socket kind.
        if path.starts_with('@') || Path::new(path).is_absolute() {
            continue;
        }
        let configured = path.clone();
        let resolved = Args::resolve_relative_path(Path::new(path), base);
        *path = resolved.into_os_string().into_string().map_err(|_| {
            anyhow::anyhow!(
                "Relative Unix socket path `{configured}` resolves through a non-UTF-8 base directory"
            )
        })?;
    }
    Ok(())
}

pub(super) fn validate_private_input_file(path: &Path, label: &str) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("Failed to inspect {label} file `{}`", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("Refusing {label} file symlink `{}`", path.display());
    }
    if !metadata.is_file() {
        bail!("{label} path must be a regular file: `{}`", path.display());
    }
    if metadata.nlink() != 1 {
        bail!(
            "{label} file must not have hard-link aliases: `{}`",
            path.display()
        );
    }
    if !is_trusted_file_owner(metadata.uid()) {
        bail!("{label} file has an untrusted owner: `{}`", path.display());
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        bail!(
            "{label} file must not be writable by group or other users: `{}`",
            path.display()
        );
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PrivateFileAccess {
    IntegrityOnly,
    Secret,
}

pub(super) fn capture_startup_input(
    path: &Path,
    kind: StartupInputKind,
    label: &'static str,
    access: PrivateFileAccess,
    require_executable: bool,
) -> Result<StartupExistingIdentity> {
    let namespace_metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("Failed to inspect {label} file `{}`", path.display()))?;
    if namespace_metadata.file_type().is_symlink() {
        bail!("Refusing {label} file symlink `{}`", path.display());
    }
    let identity = PathIdentity::capture(path)
        .with_context(|| format!("Failed to capture {label} path `{}`", path.display()))?;
    let metadata = identity
        .open_metadata_pinned()
        .with_context(|| format!("Failed to inspect pinned {label} file `{}`", path.display()))?
        .metadata()?;
    validate_private_metadata(&metadata, identity.canonical(), label, access)?;
    if require_executable && metadata.permissions().mode() & 0o111 == 0 {
        bail!(
            "{label} is not executable: `{}`",
            identity.canonical().display()
        );
    }
    Ok(StartupExistingIdentity {
        kind,
        label,
        identity,
        access,
        require_executable,
    })
}

#[cfg(test)]
pub(super) fn read_private_file_with<F>(
    path: &Path,
    label: &str,
    max_bytes: u64,
    access: PrivateFileAccess,
    before_read: F,
) -> Result<Vec<u8>>
where
    F: FnOnce(),
{
    let identity = PathIdentity::capture(path)
        .with_context(|| format!("Failed to capture {label} file `{}`", path.display()))?;
    read_private_file_from_identity_with(&identity, label, max_bytes, access, before_read)
}

pub(super) fn read_private_file_from_identity(
    identity: &PathIdentity,
    label: &str,
    max_bytes: u64,
    access: PrivateFileAccess,
) -> Result<Vec<u8>> {
    read_private_file_from_identity_with(identity, label, max_bytes, access, || {})
}

pub(super) fn read_private_file_from_identity_with<F>(
    identity: &PathIdentity,
    label: &str,
    max_bytes: u64,
    access: PrivateFileAccess,
    before_read: F,
) -> Result<Vec<u8>>
where
    F: FnOnce(),
{
    // 中文：重新打开启动时固定的对象而非路径名，并保留 O_NONBLOCK，使非普通对象在 fstat
    // 拒绝前也不能卡住启动。
    // English: Reopen the pinned object, not its pathname, with O_NONBLOCK so a non-regular object cannot stall before fstat rejection.
    let mut file = identity.open_regular_file_pinned().with_context(|| {
        format!(
            "Failed to open pinned {label} file `{}`",
            identity.canonical().display()
        )
    })?;
    let path = identity.canonical();
    let metadata = file
        .metadata()
        .with_context(|| format!("Failed to inspect {label} file `{}`", path.display()))?;
    validate_private_metadata(&metadata, path, label, access)?;
    let fingerprint = PrivateFileFingerprint::from_metadata(&metadata);
    if metadata.len() > max_bytes {
        bail!(
            "{label} file exceeds the {max_bytes}-byte size limit: `{}`",
            path.display()
        );
    }

    let capacity = usize::try_from(metadata.len().min(max_bytes)).unwrap_or(0);
    let mut contents = Vec::with_capacity(capacity);
    before_read();
    file.by_ref()
        .take(max_bytes + 1)
        .read_to_end(&mut contents)
        .with_context(|| format!("Failed to read {label} file `{}`", path.display()))?;
    if contents.len() as u64 > max_bytes {
        bail!(
            "{label} file exceeds the {max_bytes}-byte size limit: `{}`",
            path.display()
        );
    }
    let after = file
        .metadata()
        .with_context(|| format!("Failed to re-inspect {label} file `{}`", path.display()))?;
    validate_private_metadata(&after, path, label, access)?;
    if PrivateFileFingerprint::from_metadata(&after) != fingerprint
        || contents.len() as u64 != fingerprint.len
    {
        bail!(
            "{label} file changed while it was being read; refusing an unstable credential snapshot: `{}`",
            path.display()
        );
    }
    Ok(contents)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PrivateFileFingerprint {
    dev: u64,
    ino: u64,
    len: u64,
    mode: u32,
    uid: u32,
    nlink: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

impl PrivateFileFingerprint {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            len: metadata.len(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            nlink: metadata.nlink(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }
}

pub(super) fn validate_private_metadata(
    metadata: &std::fs::Metadata,
    path: &Path,
    label: &str,
    access: PrivateFileAccess,
) -> Result<()> {
    if !metadata.is_file() {
        bail!("{label} path must be a regular file: `{}`", path.display());
    }
    if metadata.nlink() != 1 {
        bail!(
            "{label} file must not have hard-link aliases: `{}`",
            path.display()
        );
    }
    if !is_trusted_file_owner(metadata.uid()) {
        bail!("{label} file has an untrusted owner: `{}`", path.display());
    }
    // 中文：secret 输入要求精确普通文件权限；只屏蔽 rwx 会误收 04600 等 setid/sticky
    // 变体，而运维契约明确只允许 0400/0600。
    // English: Secret inputs require exact ordinary-file modes; masking rwx alone would incorrectly accept setid/sticky variants.
    let mode = metadata.permissions().mode() & 0o7777;
    if access == PrivateFileAccess::Secret {
        if !matches!(mode, 0o400 | 0o600) {
            bail!(
                "{label} file contains reusable secret material and must use mode 0400 or 0600 (found {mode:04o}): `{}`",
                path.display()
            );
        }
    } else if mode & 0o022 != 0 {
        bail!(
            "{label} file must not be writable by group or other users: `{}`",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn load_auth_file(path: &Path) -> Result<AccessControl> {
    let identity = capture_startup_input(
        path,
        StartupInputKind::AuthenticationFile,
        "authentication file",
        PrivateFileAccess::Secret,
        false,
    )?;
    load_auth_file_from_identity(&identity.identity)
}

pub(super) fn load_auth_file_from_identity(identity: &PathIdentity) -> Result<AccessControl> {
    let path = identity.canonical();
    let contents = read_private_file_from_identity(
        identity,
        "authentication",
        AUTH_FILE_MAX_BYTES,
        PrivateFileAccess::Secret,
    )?;
    let contents = String::from_utf8(contents).with_context(|| {
        format!(
            "Authentication file `{}` is not valid UTF-8",
            path.display()
        )
    })?;
    let mut rules = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        if index >= AUTH_FILE_MAX_LINES {
            bail!(
                "Authentication file exceeds the {AUTH_FILE_MAX_LINES}-line limit: `{}`",
                path.display()
            );
        }
        if line.len() > AUTH_FILE_MAX_LINE_BYTES {
            bail!(
                "Authentication file line {} exceeds the {AUTH_FILE_MAX_LINE_BYTES}-byte limit: `{}`",
                index + 1,
                path.display()
            );
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if line != trimmed {
            bail!(
                "Authentication file rule line {} has leading or trailing whitespace; refusing to change credential bytes: `{}`",
                index + 1,
                path.display()
            );
        }
        rules.push(line.to_owned());
    }
    if rules.is_empty() {
        bail!(
            "Authentication file contains no user rules: `{}`",
            path.display()
        );
    }
    let refs: Vec<&str> = rules.iter().map(String::as_str).collect();
    AccessControl::new(&refs).with_context(|| {
        format!(
            "Failed to load authentication rules from `{}`; credential values were not logged",
            path.display()
        )
    })
}

pub(super) fn validate_private_output_if_exists(path: &Path, label: &str) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => validate_private_input_file(path, label),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => {
            Err(err).with_context(|| format!("Failed to inspect {label} file `{}`", path.display()))
        }
    }
}

pub(super) fn validate_trusted_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("Failed to inspect {label} directory `{}`", path.display()))?;
    if !metadata.is_dir() {
        bail!("{label} path must be a directory: `{}`", path.display());
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        bail!(
            "{label} directory must not be writable by group or other users: `{}`",
            path.display()
        );
    }
    Ok(())
}

/// 校验并保留一个会被进程创建、截断、unlink、rename 或 bind 的输出槽。
///
/// 已存在对象按固定 inode 与所有敏感输入/输出比较；即使双方都不存在，也按固定父目录
/// 身份加 basename 比较 namespace 槽。两层检查分别覆盖硬链接别名和“启动后谁先创建”的
/// 冲突，不能退化为易受 symlink/bind-mount 影响的路径字符串比较。
/// Validate and retain a slot the process may create, truncate, unlink, rename, or bind.
/// Existing objects are compared by pinned inode against every sensitive input/output, while even
/// absent objects are compared by pinned-parent identity plus basename. These layers cover hard-link
/// aliases and create-after-validation conflicts without falling back to mutable pathname strings.
fn retain_startup_output(
    outputs: &mut Vec<StartupOutputIdentity>,
    existing: &[StartupExistingIdentity],
    served: &ServedPathIdentity,
    assets: Option<&ServedPathIdentity>,
    serve_path: &Path,
    output: StartupOutputIdentity,
) -> Result<()> {
    let label = output.label;
    let identity = &output.identity;
    if served.exposes_output(identity) {
        bail!(
            "Refusing to expose {label} `{}` through the served path `{}`",
            identity.display_path().display(),
            serve_path.display()
        );
    }
    if assets.is_some_and(|assets_identity| assets_identity.exposes_output(identity)) {
        bail!(
            "Refusing to expose {label} `{}` through unauthenticated custom assets",
            identity.display_path().display()
        );
    }

    if let Some(candidate) = identity.existing() {
        for input in existing {
            if candidate.same_object(&input.identity) {
                bail!(
                    "Refusing {label} `{}` because it shares a filesystem object with {input_label} `{}`",
                    identity.display_path().display(),
                    input.identity.canonical().display(),
                    input_label = input.label,
                );
            }
        }
    }

    for prior in outputs.iter() {
        let same_namespace_slot = identity.parent().same_object(prior.identity.parent())
            && identity.basename() == prior.identity.basename();
        let same_existing_object = identity.existing().is_some_and(|candidate| {
            prior
                .identity
                .existing()
                .is_some_and(|previous| candidate.same_object(previous))
        });
        if same_namespace_slot || same_existing_object {
            let collision = if same_namespace_slot {
                "namespace slot"
            } else {
                "filesystem object"
            };
            bail!(
                "Refusing {label} `{}` because it shares a {collision} with {prior_label} `{}`",
                identity.display_path().display(),
                prior.identity.display_path().display(),
                prior_label = prior.label,
            );
        }
    }

    outputs.push(output);
    Ok(())
}

/// 拒绝把认证文件变成公开 assets 或经服务能力树暴露本地 secret 的布局；规范名只用于诊断，包含关系由从 `/` 打开的完整 `(dev,ino,type)` 祖先链判断。
/// Reject layouts exposing protected files via assets/serve trees; containment uses complete opened identity chains, not canonical-name strings.
pub(super) fn validate_path_isolation_with_inputs(
    args: &Args,
    existing: Vec<StartupExistingIdentity>,
) -> Result<StartupPathIdentities> {
    let served = ServedPathIdentity::capture(&args.serve_path, args.path_is_file)
        .context("Failed to capture served path identity")?;
    let assets = args
        .assets
        .as_deref()
        .map(|path| ServedPathIdentity::capture(path, false))
        .transpose()
        .context("Failed to capture custom-assets identity")?;
    let revocation_lock_path = args.token_revocation_file.as_ref().map(|path| {
        let mut name = path.as_os_str().to_os_string();
        name.push(".lock");
        PathBuf::from(name)
    });
    let mut outputs = Vec::with_capacity(
        args.addrs.len()
            + usize::from(args.token_revocation_file.is_some()) * 2
            + usize::from(args.log_file.is_some())
                * (crate::logging::DEFAULT_ROTATE_BACKUPS.saturating_add(1)),
    );

    if let (Some(assets_path), Some(assets_identity)) = (args.assets.as_deref(), assets.as_ref()) {
        let assets_directory = assets_identity.exposed_identity();
        // 中文：assets 若包含 serve 根，未认证 assets 路由可寻址普通服务文件；专用 assets 子目录仅在网络写关闭时安全。
        // English: If assets contains serve root, unauthenticated routing reaches served files; a dedicated child is safe only without network mutation.
        if assets_directory.contains(served.exposed_identity()) {
            bail!(
                "Refusing assets directory `{}` because it contains the served path and would bypass authentication",
                assets_path.display()
            );
        }
        if served.contains_directory(assets_directory) && (args.allow_upload || args.allow_delete) {
            bail!(
                "Refusing writable assets directory `{}` inside the served path; place management assets outside the writable tree",
                assets_path.display()
            );
        }
    }

    // 中文：pathname socket 是实时可达能力；unlink 不断开既有连接，却阻止所有新客户端，
    // 因而必须位于远程可写 serve 路径和未认证 assets 之外。abstract socket 由独立风险策略处理。
    // English: A pathname socket is reachability authority and must stay
    // outside mutable/unauthenticated trees; abstract sockets have a separate explicit-risk policy.
    for (listener_index, address) in args.addrs.iter().enumerate() {
        let BindAddr::SocketPath(path) = address else {
            continue;
        };
        if path.starts_with('@') {
            continue;
        }
        let identity = OutputPathIdentity::capture_no_symlinks(Path::new(path))
            .with_context(|| format!("Failed to validate Unix socket path `{path}`"))?;
        retain_startup_output(
            &mut outputs,
            &existing,
            &served,
            assets.as_ref(),
            &args.serve_path,
            StartupOutputIdentity {
                kind: StartupOutputKind::ListenerSocket(listener_index),
                label: "Unix socket listener",
                identity,
            },
        )?;
    }

    for expected in &existing {
        if served.exposes_existing(&expected.identity) {
            bail!(
                "Refusing to expose {label} `{}` through the served path `{}`",
                expected.identity.canonical().display(),
                args.serve_path.display(),
                label = expected.label
            );
        }
        if assets.as_ref().is_some_and(|assets_identity| {
            assets_identity
                .exposed_identity()
                .contains(&expected.identity)
        }) {
            bail!(
                "Refusing to expose {label} `{}` through unauthenticated custom assets",
                expected.identity.canonical().display(),
                label = expected.label
            );
        }
    }

    let mut output_specs: Vec<(StartupOutputKind, &'static str, PathBuf)> = Vec::new();
    if let Some(path) = args.token_revocation_file.as_deref() {
        // 中文：其他 Ram 实例通过原子 rename 发布此文件，inode 可合法变化，但 parent+basename 权限保持固定。
        // English: Other instances atomically replace this file, so inode may change while parent+basename authority remains fixed.
        output_specs.push((
            StartupOutputKind::TokenRevocationState,
            "token revocation state",
            path.to_path_buf(),
        ));
    }
    if let Some(path) = revocation_lock_path {
        output_specs.push((
            StartupOutputKind::TokenRevocationLock,
            "token revocation instance lock",
            path,
        ));
    }
    if let Some(path) = args.log_file.as_deref() {
        output_specs.push((
            StartupOutputKind::AccessLog,
            "access log",
            path.to_path_buf(),
        ));
        // 中文：轮转会覆盖 `.1`…`.5`；即使当前不存在，也必须在创建任何能力前保留槽。
        // English: Rotation overwrites `.1`…`.5`; reserve every slot before any capability is created, even when absent.
        for index in 1..=crate::logging::DEFAULT_ROTATE_BACKUPS {
            output_specs.push((
                StartupOutputKind::AccessLogBackup(index),
                "access log rotation backup",
                crate::logging::rotated_path(path, index),
            ));
        }
    }

    for (kind, label, path) in output_specs {
        let identity = OutputPathIdentity::capture(&path)
            .with_context(|| format!("Failed to validate {label} path `{}`", path.display()))?;
        retain_startup_output(
            &mut outputs,
            &existing,
            &served,
            assets.as_ref(),
            &args.serve_path,
            StartupOutputIdentity {
                kind,
                label,
                identity,
            },
        )?;
    }

    Ok(StartupPathIdentities {
        served,
        assets,
        existing,
        outputs,
    })
}

#[cfg(test)]
pub(super) fn validate_path_isolation(
    args: &Args,
    config_path: Option<&Path>,
) -> Result<StartupPathIdentities> {
    let mut existing_specs = Vec::new();
    if let Some(path) = config_path {
        existing_specs.push((
            path,
            StartupInputKind::Configuration,
            "configuration file",
            PrivateFileAccess::IntegrityOnly,
            false,
        ));
    }
    if let Some(path) = args.tls_cert.as_deref() {
        existing_specs.push((
            path,
            StartupInputKind::TlsCertificate,
            "TLS certificate",
            PrivateFileAccess::IntegrityOnly,
            false,
        ));
    }
    if let Some(path) = args.tls_key.as_deref() {
        existing_specs.push((
            path,
            StartupInputKind::TlsPrivateKey,
            "TLS private key",
            PrivateFileAccess::Secret,
            false,
        ));
    }
    if let Some(path) = args.auth_file.as_deref() {
        existing_specs.push((
            path,
            StartupInputKind::AuthenticationFile,
            "authentication file",
            PrivateFileAccess::Secret,
            false,
        ));
    }
    if let Some(path) = args.token_secret_file.as_deref() {
        existing_specs.push((
            path,
            StartupInputKind::TokenSecret,
            "token secret",
            PrivateFileAccess::Secret,
            false,
        ));
    }
    if let Some(path) = args.storage_quota_hook.as_deref() {
        existing_specs.push((
            path,
            StartupInputKind::StorageQuotaHook,
            "storage quota hook",
            PrivateFileAccess::IntegrityOnly,
            true,
        ));
    }
    let existing = existing_specs
        .into_iter()
        .map(|(path, kind, label, access, require_executable)| {
            capture_startup_input(path, kind, label, access, require_executable)
        })
        .collect::<Result<Vec<_>>>()?;
    validate_path_isolation_with_inputs(args, existing)
}

pub(super) fn read_token_secret_from_identity(identity: &PathIdentity) -> Result<Vec<u8>> {
    let mut secret = read_private_file_from_identity(
        identity,
        "token secret",
        TOKEN_SECRET_FILE_MAX_BYTES,
        PrivateFileAccess::Secret,
    )?;
    while matches!(secret.last(), Some(b'\n' | b'\r')) {
        secret.pop();
    }
    Ok(secret)
}
