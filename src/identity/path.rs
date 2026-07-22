//! 启动校验使用的稳定 Linux 命名空间身份。规范路径只用于诊断而非权限；模块通过固定
//! 目录描述符捕获从 `/` 到目标的每个 `(dev,ino,type)`，并把同一描述符交给能力消费者，
//! 避免 bind mount、硬链接、别名与 rename 竞态破坏字符串前缀判断。
//!
//! Stable Linux filesystem namespace identities used by startup validation.
//! A canonical pathname is useful for diagnostics, but it is not an authority:
//! bind mounts, hard links, aliases and rename races can make textual prefix
//! checks disagree with the objects a server eventually opens.  This module
//! captures every component from `/` to a target through pinned directory
//! descriptors and records its `(st_dev, st_ino, file-type)` identity.  The
//! same retained descriptors are handed directly to each capability consumer.

use anyhow::{Context, Result, anyhow, bail};
use rustix::fs::{self, Mode, OFlags, ResolveFlags};
use rustix::io::Errno;
use std::ffi::{OsStr, OsString};
use std::fs::{File, Metadata};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

#[cfg(test)]
use crate::utils::is_trusted_file_owner;

const IDENTITY_CAPTURE_RETRIES: usize = 3;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum ObjectKind {
    Directory,
    RegularFile,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ObjectIdentity {
    dev: u64,
    ino: u64,
    kind: ObjectKind,
}

impl ObjectIdentity {
    pub(crate) fn from_metadata(metadata: &Metadata) -> Self {
        let kind = if metadata.is_dir() {
            ObjectKind::Directory
        } else if metadata.is_file() {
            ObjectKind::RegularFile
        } else {
            ObjectKind::Other
        };
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            kind,
        }
    }
}

/// 已存在对象及通向它的全部命名空间祖先。 / An existing object and every namespace ancestor leading to it.
///
/// 首项为 `/`、末项为目标；完整链让包含关系使用对象身份而非 starts_with，并能检测任一祖先替换。
/// The chain runs from `/` to target, enabling identity containment and replacement detection for every ancestor.
#[derive(Clone)]
pub(crate) struct PathIdentity {
    canonical: PathBuf,
    ancestors: Vec<ObjectIdentity>,
    pinned: Vec<Arc<File>>,
}

impl std::fmt::Debug for PathIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PathIdentity")
            .field("canonical", &self.canonical)
            .field("ancestors", &self.ancestors)
            .field("pinned_depth", &self.pinned.len())
            .finish()
    }
}

impl PartialEq for PathIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.canonical == other.canonical && self.ancestors == other.ancestors
    }
}

impl Eq for PathIdentity {}

impl PathIdentity {
    pub(crate) fn capture(path: &Path) -> Result<Self> {
        let mut last_error = None;
        for _ in 0..IDENTITY_CAPTURE_RETRIES {
            let before = std::fs::canonicalize(path)
                .with_context(|| format!("failed to canonicalize `{}`", path.display()))?;
            let first = match open_identity_chain(&before, identity_open_flags()) {
                Ok((chain, _)) => chain,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
            let middle = std::fs::canonicalize(path)
                .with_context(|| format!("failed to recanonicalize `{}`", path.display()))?;
            if middle != before {
                last_error = Some(anyhow!(
                    "canonical namespace changed while capturing identity"
                ));
                continue;
            }
            let (second, pinned) = match open_identity_chain(&middle, identity_open_flags()) {
                Ok(captured) => captured,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
            let after = std::fs::canonicalize(path)
                .with_context(|| format!("failed to recanonicalize `{}`", path.display()))?;
            if after == before && first == second {
                return Ok(Self {
                    canonical: before,
                    ancestors: first,
                    pinned: pinned.into_iter().map(Arc::new).collect(),
                });
            }
            last_error = Some(anyhow!(
                "filesystem namespace changed while capturing path identity"
            ));
        }
        Err(last_error.unwrap_or_else(|| anyhow!("failed to capture path identity")))
            .with_context(|| format!("unstable filesystem identity for `{}`", path.display()))
    }

    /// 捕获词法规范化绝对路径且不跟随任何符号链接组件。 / Capture an absolute normalized path without following symlinks.
    ///
    /// 此严格形式用于 pathname Unix socket，其配置拼写本身是可达能力；只校验 canonical 目标会把可变 symlink 别名留在固定祖先链外。
    /// This strict form protects pathname sockets whose configured spelling is itself reachability authority.
    pub(crate) fn capture_no_symlinks(path: &Path) -> Result<Self> {
        let components = normal_components(path).with_context(|| {
            format!(
                "Unix socket path `{}` must be normalized and absolute",
                path.display()
            )
        })?;
        let normalized = components
            .iter()
            .fold(PathBuf::from("/"), |path, component| path.join(component));
        let mut last_error = None;
        for _ in 0..IDENTITY_CAPTURE_RETRIES {
            // 中文：这里每段都应为祖先目录；除 NOFOLLOW 外还需 DIRECTORY，因为 Linux 可用
            // O_PATH|O_NOFOLLOW 打开 symlink 自身，虽随后安全失败却丢失明确诊断。
            // English: Ancestors require DIRECTORY as well as NOFOLLOW; O_PATH
            // could otherwise open the symlink object and lose this API's explicit diagnostic.
            let first = match open_identity_chain(&normalized, directory_walk_flags()) {
                Ok((chain, _)) => chain,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
            let (second, pinned) = match open_identity_chain(&normalized, directory_walk_flags()) {
                Ok(captured) => captured,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
            if first == second {
                return Ok(Self {
                    canonical: normalized,
                    ancestors: second,
                    pinned: pinned.into_iter().map(Arc::new).collect(),
                });
            }
            last_error = Some(anyhow!(
                "filesystem namespace changed while capturing path identity"
            ));
        }
        Err(last_error.unwrap_or_else(|| anyhow!("failed to capture path identity"))).with_context(
            || {
                format!(
                    "Unix socket path `{}` must not contain symbolic-link components",
                    path.display()
                )
            },
        )
    }

    pub(crate) fn canonical(&self) -> &Path {
        &self.canonical
    }

    pub(crate) fn object(&self) -> ObjectIdentity {
        *self
            .ancestors
            .last()
            .expect("an absolute identity always includes filesystem root")
    }

    pub(crate) fn parent(&self) -> Option<Self> {
        let parent = self.canonical.parent()?;
        if self.ancestors.len() <= 1 {
            return None;
        }
        Some(Self {
            canonical: parent.to_path_buf(),
            ancestors: self.ancestors[..self.ancestors.len() - 1].to_vec(),
            pinned: self.pinned[..self.pinned.len() - 1].to_vec(),
        })
    }

    /// 此目录对象在捕获命名空间中是否为 other 祖先；别名按身份相等，不按拼写。
    /// Whether this directory identity is an ancestor of `other`; aliases compare equal by identity.
    pub(crate) fn contains(&self, other: &Self) -> bool {
        self.object().kind == ObjectKind::Directory
            && other
                .ancestors
                .iter()
                .any(|identity| *identity == self.object())
    }

    pub(crate) fn same_object(&self, other: &Self) -> bool {
        self.object() == other.object()
    }

    pub(crate) fn open_directory_pinned(&self) -> Result<File> {
        if self.object().kind != ObjectKind::Directory {
            bail!(
                "identity does not name a directory: `{}`",
                self.canonical.display()
            );
        }
        self.reopen_pinned(OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC)
    }

    pub(crate) fn open_metadata_pinned(&self) -> Result<File> {
        self.pinned_file()?.try_clone().map_err(Into::into)
    }

    /// 从捕获时固定描述符读取每个祖先元数据；返回路径仅为诊断标签，不经可变路径空间重开。
    /// Read ancestor metadata from pinned descriptors; returned paths are diagnostic labels only.
    pub(crate) fn pinned_ancestor_metadata(&self) -> Result<Vec<(PathBuf, Metadata)>> {
        let mut paths = self
            .canonical
            .ancestors()
            .map(Path::to_path_buf)
            .collect::<Vec<_>>();
        paths.reverse();
        if paths.len() != self.pinned.len() || self.pinned.len() != self.ancestors.len() {
            bail!(
                "pinned ancestor chain length changed for `{}`",
                self.canonical.display()
            );
        }

        paths
            .into_iter()
            .zip(self.pinned.iter())
            .zip(self.ancestors.iter())
            .map(|((path, pinned), expected)| {
                let metadata = pinned.metadata()?;
                if ObjectIdentity::from_metadata(&metadata) != *expected {
                    bail!("pinned ancestor identity changed for `{}`", path.display());
                }
                Ok((path, metadata))
            })
            .collect()
    }

    pub(crate) fn open_regular_file_pinned(&self) -> Result<File> {
        if self.object().kind != ObjectKind::RegularFile {
            bail!(
                "identity does not name a regular file: `{}`",
                self.canonical.display()
            );
        }
        self.reopen_pinned(OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK)
    }

    pub(crate) fn open_regular_file_pinned_read_write(&self) -> Result<File> {
        if self.object().kind != ObjectKind::RegularFile {
            bail!(
                "identity does not name a regular file: `{}`",
                self.canonical.display()
            );
        }
        self.reopen_pinned(OFlags::RDWR | OFlags::CLOEXEC | OFlags::NONBLOCK)
    }

    pub(crate) fn open_regular_file_pinned_append(&self) -> Result<File> {
        if self.object().kind != ObjectKind::RegularFile {
            bail!(
                "identity does not name a regular file: `{}`",
                self.canonical.display()
            );
        }
        self.reopen_pinned(OFlags::WRONLY | OFlags::APPEND | OFlags::CLOEXEC | OFlags::NONBLOCK)
    }

    pub(crate) fn proc_fd_path(&self) -> Result<PathBuf> {
        Ok(PathBuf::from(format!(
            "/proc/self/fd/{}",
            self.pinned_file()?.as_raw_fd()
        )))
    }

    pub(crate) fn verify_namespace(&self) -> Result<()> {
        self.open_namespace_verified(identity_open_flags())
            .map(drop)
    }

    fn pinned_file(&self) -> Result<&File> {
        self.pinned
            .last()
            .map(Arc::as_ref)
            .ok_or_else(|| anyhow!("path identity has no pinned descriptor"))
    }

    fn child_from_opened(&self, basename: &OsStr, file: File) -> Result<Self> {
        if self.object().kind != ObjectKind::Directory {
            bail!(
                "cannot bind child below a non-directory identity: `{}`",
                self.canonical.display()
            );
        }
        let mut ancestors = self.ancestors.clone();
        ancestors.push(ObjectIdentity::from_metadata(&file.metadata()?));
        let mut pinned = self.pinned.clone();
        pinned.push(Arc::new(file));
        Ok(Self {
            canonical: self.canonical.join(basename),
            ancestors,
            pinned,
        })
    }

    fn reopen_pinned(&self, flags: OFlags) -> Result<File> {
        let path = self.proc_fd_path()?;
        let reopened: File = fs::open(&path, flags, Mode::empty())
            .with_context(|| {
                format!(
                    "failed to reopen pinned descriptor for `{}`",
                    self.canonical.display()
                )
            })?
            .into();
        if ObjectIdentity::from_metadata(&reopened.metadata()?) != self.object() {
            bail!(
                "pinned descriptor changed object identity for `{}`",
                self.canonical.display()
            );
        }
        Ok(reopened)
    }

    fn open_namespace_verified(&self, final_flags: OFlags) -> Result<File> {
        let (actual, mut opened) =
            open_identity_chain(&self.canonical, final_flags).with_context(|| {
                format!(
                    "failed to reopen `{}` by namespace identity",
                    self.canonical.display()
                )
            })?;
        if actual != self.ancestors {
            bail!(
                "filesystem identity changed for `{}` between validation and use",
                self.canonical.display()
            );
        }
        opened
            .pop()
            .ok_or_else(|| anyhow!("reopened identity chain is empty"))
    }
}

/// 可尚不存在输出的身份：可信位置是已验证父目录加单一 basename；若已存在也保留精确对象身份。
/// Identity for a possibly absent output, authorized by a verified parent and basename plus exact existing identity when present.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OutputPathIdentity {
    parent: PathIdentity,
    basename: OsString,
    existing: Option<PathIdentity>,
}

impl OutputPathIdentity {
    pub(crate) fn capture(path: &Path) -> Result<Self> {
        let basename = validated_basename(path)?;
        let parent_path = path.parent().unwrap_or_else(|| Path::new("."));
        let parent = PathIdentity::capture(parent_path)?;
        let existing = open_output_child(&parent, &basename)?
            .map(|file| parent.child_from_opened(&basename, file))
            .transpose()?;
        Ok(Self {
            parent,
            basename,
            existing,
        })
    }

    /// 捕获尚未创建输出并拒绝配置路径中的所有 symlink。 / Capture a not-yet-created output while rejecting every symlink component.
    pub(crate) fn capture_no_symlinks(path: &Path) -> Result<Self> {
        let basename = validated_basename(path)?;
        let parent_path = path.parent().unwrap_or_else(|| Path::new("."));
        let parent = PathIdentity::capture_no_symlinks(parent_path)?;
        let existing = open_output_child(&parent, &basename)?
            .map(|file| parent.child_from_opened(&basename, file))
            .transpose()?;
        Ok(Self {
            parent,
            basename,
            existing,
        })
    }

    pub(crate) fn parent(&self) -> &PathIdentity {
        &self.parent
    }

    pub(crate) fn basename(&self) -> &OsStr {
        &self.basename
    }

    pub(crate) fn existing(&self) -> Option<&PathIdentity> {
        self.existing.as_ref()
    }

    pub(crate) fn expected_object(&self) -> Option<ObjectIdentity> {
        self.existing.as_ref().map(PathIdentity::object)
    }

    pub(crate) fn open_parent_pinned(&self) -> Result<File> {
        self.parent.open_directory_pinned()
    }

    pub(crate) fn with_current_expectation(&self) -> Result<Self> {
        let existing = open_output_child(&self.parent, &self.basename)?
            .map(|file| self.parent.child_from_opened(&self.basename, file))
            .transpose()?;
        Ok(Self {
            parent: self.parent.clone(),
            basename: self.basename.clone(),
            existing,
        })
    }

    #[cfg(test)]
    pub(crate) fn verify(&self) -> Result<()> {
        let parent = self.open_parent_pinned()?;
        match &self.existing {
            Some(expected) => {
                let opened: File = fs::openat2(
                    &parent,
                    &self.basename,
                    identity_open_flags(),
                    Mode::empty(),
                    component_resolve_flags(false),
                )?
                .into();
                let actual = ObjectIdentity::from_metadata(&opened.metadata()?);
                if actual != expected.object() {
                    bail!(
                        "existing output object changed for `{}`",
                        self.display_path().display()
                    );
                }
            }
            None => match fs::statat(&parent, &self.basename, fs::AtFlags::SYMLINK_NOFOLLOW) {
                Err(Errno::NOENT) => {}
                Ok(_) => bail!(
                    "previously absent output object appeared at `{}`",
                    self.display_path().display()
                ),
                Err(error) => return Err(error.into()),
            },
        }
        Ok(())
    }

    /// 服务能力可达前重新校验输出；配置时缺失者可被 logger/撤销锁合法创建，但必须仍在同一固定父目录下且为可信单链接普通文件；稳定输出需 inode 连续，除非显式允许原子替换。
    /// Revalidate before reachability, permitting legitimate creation below the same parent while requiring trusted file identity and caller-approved replacement semantics.
    #[cfg(test)]
    pub(crate) fn verify_for_server_init(&self, allow_atomic_replacement: bool) -> Result<()> {
        let parent = self.open_parent_pinned()?;
        let current = match fs::openat2(
            &parent,
            &self.basename,
            identity_open_flags(),
            Mode::empty(),
            component_resolve_flags(false),
        ) {
            Ok(fd) => Some(File::from(fd)),
            Err(Errno::NOENT) => None,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to securely reopen output `{}`",
                        self.display_path().display()
                    )
                });
            }
        };

        match (self.existing.as_ref(), current) {
            (None, None) => Ok(()),
            (Some(_), None) => bail!(
                "existing output disappeared between configuration and server initialization: `{}`",
                self.display_path().display()
            ),
            (expected, Some(file)) => {
                let metadata = file.metadata()?;
                validate_trusted_output_metadata(&metadata, &self.display_path())?;
                if let Some(expected) = expected
                    && !allow_atomic_replacement
                    && ObjectIdentity::from_metadata(&metadata) != expected.object()
                {
                    bail!(
                        "existing output changed identity between configuration and server initialization: `{}`",
                        self.display_path().display()
                    );
                }
                Ok(())
            }
        }
    }

    pub(crate) fn display_path(&self) -> PathBuf {
        self.parent.canonical.join(&self.basename)
    }
}

/// 服务目录或文件在配置时的精确身份。 / Exact configuration-time identity of a served directory or file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ServedPathIdentity {
    Directory(PathIdentity),
    SingleFile {
        parent: PathIdentity,
        file: PathIdentity,
        basename: OsString,
    },
}

pub(crate) struct OpenedServeRoot {
    pub(crate) root: File,
    pub(crate) single_file: Option<OpenedSingleFile>,
}

pub(crate) struct OpenedSingleFile {
    pub(crate) name: OsString,
    pub(crate) file: File,
}

impl ServedPathIdentity {
    pub(crate) fn capture(path: &Path, path_is_file: bool) -> Result<Self> {
        let identity = PathIdentity::capture(path)?;
        if path_is_file {
            if identity.object().kind != ObjectKind::RegularFile {
                bail!(
                    "served single-file path is not a regular file: `{}`",
                    path.display()
                );
            }
            let parent = identity.parent().ok_or_else(|| {
                anyhow!("served file has no parent directory: `{}`", path.display())
            })?;
            let basename = identity
                .canonical
                .file_name()
                .ok_or_else(|| anyhow!("served file has no basename"))?
                .to_os_string();
            Ok(Self::SingleFile {
                parent,
                file: identity,
                basename,
            })
        } else {
            if identity.object().kind != ObjectKind::Directory {
                bail!("served path is not a directory: `{}`", path.display());
            }
            Ok(Self::Directory(identity))
        }
    }

    pub(crate) fn exposed_identity(&self) -> &PathIdentity {
        match self {
            Self::Directory(root) => root,
            Self::SingleFile { file, .. } => file,
        }
    }

    pub(crate) fn exposes_existing(&self, sensitive: &PathIdentity) -> bool {
        match self {
            Self::Directory(root) => root.contains(sensitive),
            Self::SingleFile { file, .. } => file.same_object(sensitive),
        }
    }

    pub(crate) fn exposes_output(&self, sensitive: &OutputPathIdentity) -> bool {
        match self {
            Self::Directory(root) => {
                root.contains(sensitive.parent())
                    || sensitive
                        .existing()
                        .is_some_and(|existing| root.contains(existing))
            }
            Self::SingleFile {
                parent,
                file,
                basename,
            } => {
                (parent.same_object(sensitive.parent()) && basename == sensitive.basename())
                    || sensitive
                        .existing()
                        .is_some_and(|existing| file.same_object(existing))
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn overlaps_directory(&self, directory: &PathIdentity) -> bool {
        match self {
            Self::Directory(root) => root.contains(directory) || directory.contains(root),
            Self::SingleFile { file, .. } => directory.contains(file),
        }
    }

    pub(crate) fn contains_directory(&self, directory: &PathIdentity) -> bool {
        match self {
            Self::Directory(root) => root.contains(directory),
            Self::SingleFile { .. } => false,
        }
    }

    /// 重开完整 canonical 链并要求每个祖先及目标保留启动身份；请求服务仍用固定描述符，此检查只用于 readiness 观察。
    /// Reopen the full chain for readiness and require startup identity continuity; serving remains descriptor-pinned.
    pub(crate) fn verify_namespace(&self) -> Result<()> {
        match self {
            Self::Directory(root) => root.verify_namespace(),
            Self::SingleFile { file, .. } => file.verify_namespace(),
        }
    }

    /// 为 RootFs 克隆保留描述符，交接中不再解析命名空间路径。 / Clone retained descriptors for RootFs without resolving a path again.
    pub(crate) fn open_root_verified(&self) -> Result<OpenedServeRoot> {
        match self {
            Self::Directory(root) => Ok(OpenedServeRoot {
                root: root.open_directory_pinned()?,
                single_file: None,
            }),
            Self::SingleFile {
                parent,
                file,
                basename,
            } => {
                let root = parent.open_directory_pinned()?;
                // 中文：用完整链定位配置能力本身且不设 NO_XDEV；单文件根也可自身为挂载点，
                // NO_XDEV 只在已建立根之下遍历时执行。
                // English: Locate the configured root across mounts; enforce NO_XDEV only beneath the established capability.
                let opened = file.open_regular_file_pinned()?;
                Ok(OpenedServeRoot {
                    root,
                    single_file: Some(OpenedSingleFile {
                        name: basename.clone(),
                        file: opened,
                    }),
                })
            }
        }
    }
}

pub(crate) fn component_resolve_flags(allow_cross_filesystems: bool) -> ResolveFlags {
    let flags = ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS;
    if allow_cross_filesystems {
        flags
    } else {
        flags | ResolveFlags::NO_XDEV
    }
}

fn identity_capture_resolve_flags() -> ResolveFlags {
    // 中文：捕获显式根可合法从 `/` 跨到其文件系统；NO_XDEV 只约束服务能力之下，不约束定位能力本身。
    // English: Capturing an explicit root may cross filesystems; NO_XDEV applies only beneath that established capability.
    ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS
}

fn identity_open_flags() -> OFlags {
    OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW
}

fn directory_walk_flags() -> OFlags {
    OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW
}

fn open_identity_chain(
    path: &Path,
    final_flags: OFlags,
) -> Result<(Vec<ObjectIdentity>, Vec<File>)> {
    if !path.is_absolute() {
        bail!("identity path must be absolute: `{}`", path.display());
    }
    let components = normal_components(path)?;
    let root_flags = if components.is_empty() {
        final_flags
    } else {
        directory_walk_flags()
    };
    let root: File = fs::open(Path::new("/"), root_flags, Mode::empty())?.into();
    let mut identities = vec![ObjectIdentity::from_metadata(&root.metadata()?)];
    let mut pinned = vec![root];
    for (index, component) in components.iter().enumerate() {
        let last = index + 1 == components.len();
        let flags = if last {
            final_flags
        } else {
            directory_walk_flags()
        };
        let next: File = fs::openat2(
            pinned
                .last()
                .expect("identity chain always retains its current directory"),
            component,
            flags,
            Mode::empty(),
            identity_capture_resolve_flags(),
        )?
        .into();
        identities.push(ObjectIdentity::from_metadata(&next.metadata()?));
        pinned.push(next);
    }
    Ok((identities, pinned))
}

fn normal_components(path: &Path) -> Result<Vec<OsString>> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => components.push(name.to_os_string()),
            _ => bail!(
                "identity path is not a normalized absolute path: `{}`",
                path.display()
            ),
        }
    }
    Ok(components)
}

fn validated_basename(path: &Path) -> Result<OsString> {
    let name = path
        .file_name()
        .ok_or_else(|| anyhow!("path has no basename: `{}`", path.display()))?;
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes == b"."
        || bytes == b".."
        || bytes.contains(&0)
        || bytes.contains(&b'/')
    {
        bail!("path has an invalid basename: `{}`", path.display());
    }
    Ok(name.to_os_string())
}

fn open_output_child(parent: &PathIdentity, basename: &OsStr) -> Result<Option<File>> {
    let parent_fd = parent.open_directory_pinned()?;
    match fs::openat2(
        &parent_fd,
        basename,
        identity_open_flags(),
        Mode::empty(),
        component_resolve_flags(false),
    ) {
        Ok(fd) => Ok(Some(File::from(fd))),
        Err(Errno::NOENT) => Ok(None),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to securely inspect output `{}`",
                parent.canonical().join(basename).display()
            )
        }),
    }
}

#[cfg(test)]
fn validate_trusted_output_metadata(metadata: &Metadata, path: &Path) -> Result<()> {
    if !metadata.is_file() {
        bail!("output path is not a regular file: `{}`", path.display());
    }
    if metadata.nlink() != 1 {
        bail!(
            "output file acquired a hard-link alias: `{}`",
            path.display()
        );
    }
    if !is_trusted_file_owner(metadata.uid()) {
        bail!("output file has an untrusted owner: `{}`", path.display());
    }
    if metadata.mode() & 0o022 != 0 {
        bail!(
            "output file became writable by group or other users: `{}`",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_fs::TempDir;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn containment_uses_ancestor_identity_not_text_prefixes() -> Result<()> {
        let temp = TempDir::new()?;
        let served = temp.path().join("share");
        let sibling = temp.path().join("share-other");
        std::fs::create_dir(&served)?;
        std::fs::create_dir(&sibling)?;
        let nested = served.join("nested");
        std::fs::create_dir(&nested)?;

        let served = PathIdentity::capture(&served)?;
        let nested = PathIdentity::capture(&nested)?;
        let sibling = PathIdentity::capture(&sibling)?;
        assert!(served.contains(&nested));
        assert!(!served.contains(&sibling));
        Ok(())
    }

    #[test]
    fn hard_link_aliases_have_the_same_exact_object_identity() -> Result<()> {
        let temp = TempDir::new()?;
        let original = temp.path().join("secret");
        let alias = temp.path().join("served");
        std::fs::write(&original, b"secret")?;
        std::fs::hard_link(&original, &alias)?;

        let original = PathIdentity::capture(&original)?;
        let alias = PathIdentity::capture(&alias)?;
        assert!(original.same_object(&alias));
        Ok(())
    }

    #[test]
    fn verified_identity_rejects_ancestor_replacement() -> Result<()> {
        let temp = TempDir::new()?;
        let parent = temp.path().join("parent");
        let moved = temp.path().join("moved");
        std::fs::create_dir(&parent)?;
        let child = parent.join("child");
        std::fs::create_dir(&child)?;
        let expected = PathIdentity::capture(&child)?;

        std::fs::rename(&parent, &moved)?;
        std::fs::create_dir(&parent)?;
        std::fs::create_dir(parent.join("child"))?;
        assert!(expected.verify_namespace().is_err());
        Ok(())
    }

    #[test]
    fn output_identity_pins_parent_and_absence() -> Result<()> {
        let temp = TempDir::new()?;
        let parent = temp.path().join("state");
        let moved = temp.path().join("old-state");
        std::fs::create_dir(&parent)?;
        let output = parent.join("revocations.json");
        let expected = OutputPathIdentity::capture(&output)?;
        expected.verify()?;

        std::fs::rename(&parent, &moved)?;
        std::fs::create_dir(&parent)?;
        std::fs::write(&output, b"decoy")?;
        // 中文：能力刻意绑定原目录对象，同名替换命名空间必须不可见。
        // English: Capability binds the original directory object; a same-spelled replacement must remain invisible.
        expected.verify()?;
        assert_eq!(expected.with_current_expectation()?.expected_object(), None);
        assert_eq!(std::fs::read(&output)?, b"decoy");
        Ok(())
    }

    #[test]
    fn strict_output_identity_rejects_every_symlink_component() -> Result<()> {
        let temp = TempDir::new()?;
        let real_parent = temp.path().join("real-parent");
        let alias_parent = temp.path().join("alias-parent");
        std::fs::create_dir(&real_parent)?;
        symlink(&real_parent, &alias_parent)?;

        let aliased_output = alias_parent.join("ram.sock");
        let error = OutputPathIdentity::capture_no_symlinks(&aliased_output).unwrap_err();
        assert!(
            format!("{error:#}").contains("must not contain symbolic-link components"),
            "unexpected strict-capture error: {error:#}"
        );

        let direct_output = real_parent.join("ram.sock");
        OutputPathIdentity::capture_no_symlinks(&direct_output)?;
        Ok(())
    }

    #[test]
    fn absent_output_may_be_created_but_stable_existing_output_cannot_be_replaced() -> Result<()> {
        let temp = TempDir::new()?;
        let output = temp.path().join("access.log");
        let absent = OutputPathIdentity::capture(&output)?;
        std::fs::write(&output, b"created by startup consumer")?;
        std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o600))?;
        absent.verify_for_server_init(false)?;

        let stable = OutputPathIdentity::capture(&output)?;
        let old = temp.path().join("old.log");
        std::fs::rename(&output, &old)?;
        std::fs::write(&output, b"replacement")?;
        std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o600))?;
        assert!(stable.verify_for_server_init(false).is_err());
        stable.verify_for_server_init(true)?;
        Ok(())
    }

    #[test]
    fn single_file_exposure_detects_a_hard_link_alias() -> Result<()> {
        let temp = TempDir::new()?;
        let served_path = temp.path().join("public-name");
        let secret_path = temp.path().join("secret-name");
        std::fs::write(&served_path, b"same inode")?;
        std::fs::hard_link(&served_path, &secret_path)?;

        let served = ServedPathIdentity::capture(&served_path, true)?;
        let secret = PathIdentity::capture(&secret_path)?;
        assert!(served.exposes_existing(&secret));
        Ok(())
    }

    #[test]
    fn assets_overlap_is_bidirectional_by_directory_identity() -> Result<()> {
        let temp = TempDir::new()?;
        let outer = temp.path().join("outer");
        let inner = outer.join("inner");
        std::fs::create_dir_all(&inner)?;

        let served_outer = ServedPathIdentity::capture(&outer, false)?;
        let inner_identity = PathIdentity::capture(&inner)?;
        assert!(served_outer.overlaps_directory(&inner_identity));

        let served_inner = ServedPathIdentity::capture(&inner, false)?;
        let outer_identity = PathIdentity::capture(&outer)?;
        assert!(served_inner.overlaps_directory(&outer_identity));
        Ok(())
    }

    #[test]
    fn output_exposure_uses_parent_basename_and_exact_existing_inode() -> Result<()> {
        let temp = TempDir::new()?;
        let served = temp.path().join("served.txt");
        let hard_link = temp.path().join("state.json");
        std::fs::write(&served, b"same inode")?;
        std::fs::hard_link(&served, &hard_link)?;

        let served = ServedPathIdentity::capture(&served, true)?;
        let output = OutputPathIdentity::capture(&hard_link)?;
        assert!(served.exposes_output(&output));
        Ok(())
    }

    #[test]
    fn no_xdev_is_default_and_compatibility_is_explicit() {
        assert!(component_resolve_flags(false).contains(ResolveFlags::NO_XDEV));
        assert!(!component_resolve_flags(true).contains(ResolveFlags::NO_XDEV));
    }
}
