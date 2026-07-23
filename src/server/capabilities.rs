//! Ram 所实现资源方法的唯一权威描述。路由器通过 [`ResourceMethod`] 解析方法，而
//! `Allow`、`OPTIONS` 与 405 响应都渲染经过筛选的
//! [`ResourceCapabilities`] 值。把两者集中在这里，可防止协议声明偏离分派表。
//!
//! The one authoritative description of the resource methods Ram implements. The router parses
//! methods through [`ResourceMethod`], while `Allow`, `OPTIONS`, and 405 responses
//! render a filtered [`ResourceCapabilities`] value. Keeping both pieces here prevents protocol
//! advertisements from drifting away from the dispatch table.

use crate::http::ResourceMethod;

/// 用于收窄方法能力的已选文件系统对象类型。 / Selected filesystem object type used to narrow method capabilities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ResourceTarget {
    Missing,
    EmptyFile,
    File,
    RootCollection,
    Collection,
    Other,
    SingleFile,
}

/// 对特定目标与调用方有意义的方法集合。 / Methods meaningful for one selected target and caller.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct ResourceCapabilities(u16);

impl ResourceCapabilities {
    pub(super) fn for_target(
        target: ResourceTarget,
        readable: bool,
        writable: bool,
        allow_upload: bool,
        allow_delete: bool,
    ) -> Self {
        if target == ResourceTarget::SingleFile {
            let mut capabilities = Self::default();
            if readable {
                capabilities.insert(ResourceMethod::Get);
                capabilities.insert(ResourceMethod::Head);
            }
            capabilities.insert(ResourceMethod::Options);
            return capabilities;
        }

        let mut capabilities = Self::default();
        capabilities.insert(ResourceMethod::Options);
        capabilities.insert(ResourceMethod::Checkauth);
        capabilities.insert(ResourceMethod::Logout);

        // 中文：查找方法也能路由缺失名称并返回 404 而非 405；保留它们可让同一表驱动
        // 分派而不破坏这一区别。
        // English: Lookup methods route missing names to 404 rather than 405;
        // retaining them lets one table drive dispatch without changing that distinction.
        let exists = target != ResourceTarget::Missing;
        // 特殊文件系统节点没有可选择的 HTTP 表示，但查找方法仍需路由并返回 404；
        // DELETE/MOVE 可操作其命名空间项。
        // Special filesystem nodes have no selectable HTTP representation, but lookup methods
        // still route to 404; DELETE/MOVE may operate on the namespace entry.
        if readable {
            capabilities.insert(ResourceMethod::Get);
            capabilities.insert(ResourceMethod::Head);
        }

        if writable && exists {
            // 固定服务根在服务能力内没有父目录槽位，因此根本身不能
            // DELETE 或 MOVE。
            // The pinned service root has no parent slot in the served capability and therefore
            // cannot itself be deleted or moved.
            if allow_delete && target != ResourceTarget::RootCollection {
                capabilities.insert(ResourceMethod::Delete);
            }
            if allow_upload && allow_delete && target != ResourceTarget::RootCollection {
                capabilities.insert(ResourceMethod::Move);
            }
        }

        match target {
            ResourceTarget::Missing if writable && allow_upload => {
                capabilities.insert(ResourceMethod::Put);
                capabilities.insert(ResourceMethod::Mkcol);
            }
            ResourceTarget::EmptyFile if writable && allow_upload => {
                capabilities.insert(ResourceMethod::Put);
            }
            ResourceTarget::File if writable && allow_upload && allow_delete => {
                // 替换非空表示会删除旧字节，因此还需要删除权限。
                // Replacing a non-empty representation deletes old bytes and also requires delete permission.
                capabilities.insert(ResourceMethod::Put);
            }
            _ => {}
        }

        capabilities
    }

    pub(super) fn contains(self, method: ResourceMethod) -> bool {
        self.0 & method.bit() != 0
    }

    pub(super) fn names(self) -> impl Iterator<Item = &'static str> {
        ResourceMethod::ALL
            .into_iter()
            .filter(move |method| self.contains(*method))
            .map(ResourceMethod::as_str)
    }

    pub(super) fn allow_header(self) -> String {
        self.names().collect::<Vec<_>>().join(", ")
    }

    pub(super) fn insert(&mut self, method: ResourceMethod) {
        self.0 |= method.bit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_collection_does_not_advertise_mutations() {
        let capabilities =
            ResourceCapabilities::for_target(ResourceTarget::Collection, true, false, true, true);
        assert_eq!(
            capabilities.allow_header(),
            "GET, HEAD, OPTIONS, CHECKAUTH, LOGOUT"
        );
    }

    #[test]
    fn file_and_collection_capabilities_follow_real_handler_limits() {
        let file = ResourceCapabilities::for_target(ResourceTarget::File, true, true, true, true);
        assert!(!file.contains(ResourceMethod::Mkcol));

        let collection =
            ResourceCapabilities::for_target(ResourceTarget::Collection, true, true, true, true);
        assert!(collection.contains(ResourceMethod::Move));

        let root = ResourceCapabilities::for_target(
            ResourceTarget::RootCollection,
            true,
            true,
            true,
            true,
        );
        assert!(!root.contains(ResourceMethod::Delete));
        assert!(!root.contains(ResourceMethod::Move));

        let special =
            ResourceCapabilities::for_target(ResourceTarget::Other, true, true, true, true);
        assert_eq!(
            special.allow_header(),
            "GET, HEAD, OPTIONS, DELETE, MOVE, CHECKAUTH, LOGOUT"
        );
    }

    #[test]
    fn missing_target_only_advertises_creation_when_writable() {
        // 中文：真实 ACL 的 ReadWrite 包含读取；传递两个有效维度，不构造不可能的只写主体。
        // English: Real ACL ReadWrite includes read permission; pass both facets instead of inventing a write-only principal.
        let writable =
            ResourceCapabilities::for_target(ResourceTarget::Missing, true, true, true, false);
        assert!(writable.contains(ResourceMethod::Put));
        assert!(writable.contains(ResourceMethod::Mkcol));
        // 中文：查找方法对缺失名称仍可路由并返回 404，不能误归类为 405。
        // English: Lookup methods stay routable and return 404 for a missing name, not unsupported 405.
        assert!(writable.contains(ResourceMethod::Get));
        assert!(writable.contains(ResourceMethod::Head));

        let readonly =
            ResourceCapabilities::for_target(ResourceTarget::Missing, false, false, true, true);
        assert!(!readonly.contains(ResourceMethod::Put));
        assert!(!readonly.contains(ResourceMethod::Mkcol));
    }
}
