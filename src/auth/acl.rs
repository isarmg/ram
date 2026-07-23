//! 分层路径授权与 HTTP 方法权限策略。权限只从最近的非 IndexOnly 祖先继承；
//! 写方法（含 MOVE 目标）要求 ReadWrite；遍历入口只能暴露明确可读的后代。
//!
//! Hierarchical path authorization and HTTP-method permission policy.
//!
//! Security invariants:
//! - path permissions inherit only from the nearest non-index-only ancestor;
//! - write-capable methods require read-write permission, including a separate
//!   destination check for MOVE;
//! - traversal roots never expose an index-only subtree outside explicitly
//!   readable descendants.

use super::*;
use crate::http::ResourceMethod;

#[derive(Debug)]
struct ValidatedAccessPath {
    components: Vec<String>,
    perm: AccessPerm,
}

/// 所有账号共享的输入复杂度预算；整条逗号分隔规则验证成功后才提交计数，
/// 因而拒绝项既不消耗预算，也不会部分修改授权树。
/// Aggregate input-complexity budget shared by all accounts. Counts commit only
/// after a complete comma-separated rule validates, preventing partial mutation.
#[derive(Debug, Default)]
pub(super) struct AccessPathBudget {
    path_rules: usize,
    components: usize,
}

/// 权限树：每个节点是一个路径段，携带该子树的权限级别。
///
/// 例：规则 `/dir1:rw,/dir2/sub:ro` 构成
/// ```text
/// (root: IndexOnly)
/// ├── dir1 (ReadWrite)
/// └── dir2 (IndexOnly)      ← 中间节点只允许"看见"，不能读内容
///     └── sub (ReadOnly)
/// ```
/// IndexOnly 的含义：用户能在列表里看到这个目录名（否则没法导航到
/// 有权限的深层目录），但看不到其真实内容。
///
/// Each node is one path segment with a subtree permission. IndexOnly exposes
/// a navigation name but not contents, allowing access to explicitly readable descendants.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AccessPaths {
    pub(super) perm: AccessPerm,
    pub(super) children: IndexMap<String, AccessPaths>,
}

impl AccessPaths {
    pub fn new(perm: AccessPerm) -> Self {
        Self {
            perm,
            ..Default::default()
        }
    }

    pub fn perm(&self) -> AccessPerm {
        self.perm
    }

    pub fn set_perm(&mut self, perm: AccessPerm) {
        if !perm.indexonly() {
            self.perm = perm;
        }
    }

    /// 把一条规则的路径部分（`/dir1:rw,/dir2`）合并进树；
    /// 不带 `:ro`/`:rw` 后缀的路径默认只读。
    /// Merge one rule's paths into the tree; entries without a suffix default to read-only.
    #[cfg(test)]
    pub(super) fn merge(&mut self, paths: &str) -> Option<()> {
        self.merge_with_budget(paths, &mut AccessPathBudget::default())
            .ok()
    }

    pub(super) fn merge_with_budget(
        &mut self,
        paths: &str,
        budget: &mut AccessPathBudget,
    ) -> Result<()> {
        let validated = validate_access_paths(paths, budget)?;
        for entry in validated {
            self.add_components(&entry.components, entry.perm);
        }
        Ok(())
    }

    /// 在树中查找 `path`，写方法还要求 ReadWrite；`None` 表示拒绝。
    /// Authorize `path`; write methods require ReadWrite and `None` means denied.
    pub fn guard(&self, path: &str, method: &Method) -> Option<Self> {
        let target = self.find(path)?;
        if !is_readonly_method(method) && !target.perm().readwrite() {
            return None;
        }
        Some(target)
    }

    /// 与 `guard` 类似，但无论 HTTP 方法一律要求读写权限。
    /// MOVE 的 `Destination` 总是被写入，因此使用此入口。
    /// Require ReadWrite regardless of method for a MOVE destination.
    pub fn guard_write(&self, path: &str) -> Option<Self> {
        let target = self.find(path)?;
        if !target.perm().readwrite() {
            return None;
        }
        Some(target)
    }

    fn add_components(&mut self, components: &[String], perm: AccessPerm) {
        let mut current = self;
        for component in components {
            current = current.children.entry(component.clone()).or_default();
        }
        current.set_perm(perm);
    }

    /// 查询 `path` 的有效权限：沿路径段下行，权限继承自最近的
    /// 非 IndexOnly 祖先；走出树后沿用继承到的权限。
    /// 返回 `None` = 这条路径完全不可见。
    /// Resolve effective permission from the nearest non-IndexOnly ancestor;
    /// leaving the explicit tree retains inherited permission, while `None` is invisible.
    pub fn find(&self, path: &str) -> Option<AccessPaths> {
        let mut current = self;
        let mut inherited = self.perm;
        for part in path
            .trim_matches('/')
            .split('/')
            .filter(|value| !value.is_empty())
        {
            if !current.perm.indexonly() {
                inherited = current.perm;
            }
            let Some(child) = current.children.get(part) else {
                return (!inherited.indexonly()).then(|| AccessPaths::new(inherited));
            };
            current = child;
        }
        if !current.perm.indexonly() {
            inherited = current.perm;
        }
        if inherited.indexonly() {
            Some(current.clone())
        } else {
            Some(AccessPaths::new(inherited))
        }
    }

    pub fn child_names(&self) -> Vec<&String> {
        self.children.keys().collect()
    }

    pub(super) fn has_write_access(&self) -> bool {
        let mut pending = vec![(self, AccessPerm::IndexOnly)];
        while let Some((current, inherited)) = pending.pop() {
            let effective = if current.perm.indexonly() {
                inherited
            } else {
                current.perm
            };
            if effective.readwrite() {
                return true;
            }
            pending.extend(current.children.values().map(|child| (child, effective)));
        }
        false
    }

    /// 供遍历（搜索/打包）使用：返回"真正有读取权限"的子树根列表。
    /// 权限是 IndexOnly 时不能从 `base` 全树遍历，只能从授权过的
    /// 分支开始。
    /// Return readable subtree roots for search/archive; IndexOnly starts only at explicitly authorized branches.
    pub fn entry_paths(&self, base: &Path) -> Vec<PathBuf> {
        if !self.perm().indexonly() {
            return vec![base.to_path_buf()];
        }
        let mut output = vec![];
        let mut pending = Vec::with_capacity(self.children.len());
        for (name, child) in self.children.iter().rev() {
            pending.push((child, base.join(name)));
        }
        while let Some((child, path)) = pending.pop() {
            if child.perm().indexonly() {
                for (name, descendant) in child.children.iter().rev() {
                    pending.push((descendant, path.join(name)));
                }
            } else {
                output.push(path);
            }
        }
        output
    }
}

fn validate_access_paths(
    paths: &str,
    budget: &mut AccessPathBudget,
) -> Result<Vec<ValidatedAccessPath>> {
    let mut next_path_rules = budget.path_rules;
    let mut next_components = budget.components;
    let mut validated = Vec::new();

    for item in paths.split(',') {
        if item.is_empty() {
            bail!("ACL path list contains an empty entry");
        }
        if next_path_rules >= AUTH_ACL_PATH_RULE_MAX_COUNT {
            bail!("Authentication ACL exceeds the {AUTH_ACL_PATH_RULE_MAX_COUNT}-path-rule limit");
        }
        next_path_rules += 1;

        let (path, perm) = match item.split_once(':') {
            None => (item, AccessPerm::ReadOnly),
            Some((path, "ro")) => (path, AccessPerm::ReadOnly),
            Some((path, "rw")) => (path, AccessPerm::ReadWrite),
            _ => bail!("ACL path entry has an invalid permission suffix"),
        };
        if path.is_empty() {
            bail!("ACL path entry has an empty path");
        }
        if !path.starts_with('/') {
            bail!("ACL paths must be absolute and begin with `/`");
        }

        let path = path.trim_matches('/');
        let components = if path.is_empty() {
            Vec::new()
        } else {
            let mut components = Vec::new();
            for component in path.split('/') {
                if component.is_empty() {
                    bail!("ACL paths must not contain empty components");
                }
                if matches!(component, "." | "..") || component.contains('\0') {
                    bail!("ACL path contains an invalid component");
                }
                if components.len() >= AUTH_ACL_PATH_MAX_DEPTH {
                    bail!("ACL path exceeds the {AUTH_ACL_PATH_MAX_DEPTH}-component depth limit");
                }
                if next_components >= AUTH_ACL_COMPONENT_MAX_TOTAL {
                    bail!(
                        "Authentication ACL exceeds the {AUTH_ACL_COMPONENT_MAX_TOTAL}-component limit"
                    );
                }
                components.push(component.to_string());
                next_components += 1;
            }
            components
        };
        validated.push(ValidatedAccessPath { components, perm });
    }

    budget.path_rules = next_path_rules;
    budget.components = next_components;
    Ok(validated)
}

/// 三级权限，可比较为 IndexOnly < ReadOnly < ReadWrite。 / Three ordered permission levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum AccessPerm {
    /// 仅为导航可见，内容不可读。 / Visible for navigation only; contents are unreadable.
    #[default]
    IndexOnly,
    /// 可读。 / Readable.
    ReadOnly,
    /// 可读写。 / Readable and writable.
    ReadWrite,
}

impl AccessPerm {
    pub fn indexonly(&self) -> bool {
        self == &AccessPerm::IndexOnly
    }

    pub fn readwrite(&self) -> bool {
        self == &AccessPerm::ReadWrite
    }
}

/// 方法对请求路径本身是否只读，用于判断 ReadOnly 是否足够。 / Whether the method is read-only for its request path.
pub(super) fn is_readonly_method(method: &Method) -> bool {
    ResourceMethod::parse(method).is_some_and(ResourceMethod::readonly_source)
}
