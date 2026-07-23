//! 启动路径解析与文件系统能力捕获。敏感输入只解析一次，经可信属主与隔离检查后
//! 以固定身份交给运行时；任何消费者都不得退回到重新打开配置路径名。
//!
//! Startup path resolution and filesystem capability capture.
//!
//! Invariant: sensitive inputs are resolved once, checked for trusted
//! ownership and isolation, then handed to runtime code as pinned identities.
//! No consumer may fall back to reopening a configured pathname.

use super::*;

#[derive(Clone, Debug, PartialEq)]
pub(super) struct StartupExistingIdentity {
    pub(super) label: &'static str,
    pub(super) identity: PathIdentity,
    pub(super) access: PrivateFileAccess,
}

/// 所有路径源解析后才捕获的文件系统权限快照，直接交给 `Server::init`，不再规范化原字符串。
/// Filesystem authorities captured after all sources resolve and carried into `Server::init` without recanonicalizing configured strings.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct StartupPathIdentities {
    served: ServedPathIdentity,
    existing: Vec<StartupExistingIdentity>,
}

impl StartupPathIdentities {
    pub(crate) fn served(&self) -> &ServedPathIdentity {
        &self.served
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
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PrivateFileAccess {
    IntegrityOnly,
    Secret,
}

pub(super) fn capture_startup_input(
    path: &Path,
    label: &'static str,
    access: PrivateFileAccess,
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
    Ok(StartupExistingIdentity {
        label,
        identity,
        access,
    })
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
    let identity = capture_startup_input(path, "authentication file", PrivateFileAccess::Secret)?;
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

/// 拒绝经服务能力树暴露认证或配置文件；包含关系由固定的文件系统身份判断。
/// Reject layouts exposing authentication or configuration inputs through the served capability.
pub(super) fn validate_path_isolation_with_inputs(
    args: &Args,
    existing: Vec<StartupExistingIdentity>,
) -> Result<StartupPathIdentities> {
    let served = ServedPathIdentity::capture(&args.serve_path, args.path_is_file)
        .context("Failed to capture served path identity")?;

    for expected in &existing {
        if served.exposes_existing(&expected.identity) {
            bail!(
                "Refusing to expose {label} `{}` through the served path `{}`",
                expected.identity.canonical().display(),
                args.serve_path.display(),
                label = expected.label
            );
        }
    }

    Ok(StartupPathIdentities { served, existing })
}

#[cfg(test)]
pub(super) fn validate_path_isolation(
    args: &Args,
    config_path: Option<&Path>,
) -> Result<StartupPathIdentities> {
    let mut existing_specs = Vec::new();
    if let Some(path) = config_path {
        existing_specs.push((path, "configuration file", PrivateFileAccess::IntegrityOnly));
    }
    if let Some(path) = args.auth_file.as_deref() {
        existing_specs.push((path, "authentication file", PrivateFileAccess::Secret));
    }
    let existing = existing_specs
        .into_iter()
        .map(|(path, label, access)| capture_startup_input(path, label, access))
        .collect::<Result<Vec<_>>>()?;
    validate_path_isolation_with_inputs(args, existing)
}
