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
use std::ffi::OsString;
use std::fs::{File, Metadata};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

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

    pub(crate) fn open_regular_file_pinned(&self) -> Result<File> {
        if self.object().kind != ObjectKind::RegularFile {
            bail!(
                "identity does not name a regular file: `{}`",
                self.canonical.display()
            );
        }
        self.reopen_pinned(OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK)
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

    pub(crate) fn exposes_existing(&self, sensitive: &PathIdentity) -> bool {
        match self {
            Self::Directory(root) => root.contains(sensitive),
            Self::SingleFile { file, .. } => file.same_object(sensitive),
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

#[cfg(test)]
mod tests {
    use super::*;
    use assert_fs::TempDir;

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
}
