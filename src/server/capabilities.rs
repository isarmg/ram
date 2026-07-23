//! Ram 所实现资源方法的唯一权威描述。路由器通过 [`ResourceMethod`] 解析方法，而
//! `Allow`、`OPTIONS`、405 响应与 CORS 预检都渲染经过筛选的
//! [`ResourceCapabilities`] 值。把两者集中在这里，可防止协议声明偏离分派表。
//!
//! The one authoritative description of the resource methods Ram implements. The router parses
//! methods through [`ResourceMethod`], while `Allow`, `OPTIONS`, 405 responses, and CORS preflights
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

/// CORS 公共包络附带的最大目标能力；预检不携带后续凭据，故先受目标/全局开关限制，
/// 再与运维 CORS 列表取交集，实际请求仍必须经过 ACL。
/// Maximum target capability for the CORS envelope. Preflights lack request
/// credentials, so target/global gates and the operator allowlist bound it;
/// the actual request still passes ACL enforcement.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct CorsPreflightCapabilities(pub(super) ResourceCapabilities);

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
        // 特殊文件系统节点没有可选择的 HTTP/DAV 表示，但查找方法仍需路由并返回 404，
        // 与缺失名称保持一致；属性变更继续在下方排除。DELETE/MOVE 可操作其命名空间项。
        // Special filesystem nodes have no selectable HTTP/DAV representation, but lookup methods
        // still route to 404 just like missing names. Property mutation remains excluded below,
        // while DELETE/MOVE may operate on the namespace entry.
        if readable {
            capabilities.insert(ResourceMethod::Get);
            capabilities.insert(ResourceMethod::Head);
            capabilities.insert(ResourceMethod::Propfind);
        }

        if writable && exists {
            // 中文：Ram 解析 PROPPATCH 并逐属性拒绝不支持的 dead-property 存储；
            // 因而只向可在该资源执行非安全方法的调用方声明。
            // English: Ram parses PROPPATCH and rejects unsupported dead
            // properties individually, so only unsafe-method-capable callers see it.
            if target != ResourceTarget::Other {
                capabilities.insert(ResourceMethod::Proppatch);
            }
            // 固定服务根是可读 DAV 集合，但在服务能力内没有父目录槽位，因此根本身不能
            // DELETE 或 MOVE。
            // The pinned service root is a readable DAV collection, but it has no parent slot in
            // the served capability and therefore cannot itself be deleted or moved.
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
                capabilities.insert(ResourceMethod::Patch);
            }
            ResourceTarget::File if writable && allow_upload => {
                // 中文：替换非空表示也会删除旧字节；仅追加 PATCH 仍不要求 DELETE。
                // English: Replacing a non-empty representation deletes old bytes; append-only PATCH remains possible without DELETE.
                if allow_delete {
                    capabilities.insert(ResourceMethod::Put);
                }
                capabilities.insert(ResourceMethod::Patch);
            }
            _ => {}
        }

        if readable
            && allow_upload
            && matches!(target, ResourceTarget::EmptyFile | ResourceTarget::File)
        {
            // 中文：COPY 只读取源；解析 Destination 后再评估目标 ACL 与覆盖策略。
            // English: COPY reads this source; destination ACL and overwrite policy are evaluated after parsing Destination.
            capabilities.insert(ResourceMethod::Copy);
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

    pub(super) fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    pub(super) fn from_method_names<'a>(methods: impl IntoIterator<Item = &'a str>) -> Self {
        let mut capabilities = Self::default();
        for method in methods {
            if let Some(method) = ResourceMethod::parse_name(method) {
                capabilities.insert(method);
            }
        }
        capabilities
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
            "GET, HEAD, OPTIONS, PROPFIND, CHECKAUTH, LOGOUT"
        );
    }

    #[test]
    fn file_and_collection_capabilities_follow_real_handler_limits() {
        let file = ResourceCapabilities::for_target(ResourceTarget::File, true, true, true, true);
        assert!(file.contains(ResourceMethod::Copy));
        assert!(!file.contains(ResourceMethod::Mkcol));

        let collection =
            ResourceCapabilities::for_target(ResourceTarget::Collection, true, true, true, true);
        assert!(!collection.contains(ResourceMethod::Copy));
        assert!(collection.contains(ResourceMethod::Move));

        let root = ResourceCapabilities::for_target(
            ResourceTarget::RootCollection,
            true,
            true,
            true,
            true,
        );
        assert!(root.contains(ResourceMethod::Proppatch));
        assert!(!root.contains(ResourceMethod::Delete));
        assert!(!root.contains(ResourceMethod::Move));

        let special =
            ResourceCapabilities::for_target(ResourceTarget::Other, true, true, true, true);
        assert_eq!(
            special.allow_header(),
            "GET, HEAD, OPTIONS, DELETE, PROPFIND, MOVE, CHECKAUTH, LOGOUT"
        );
        assert!(!special.contains(ResourceMethod::Proppatch));
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
        assert!(writable.contains(ResourceMethod::Propfind));

        let readonly =
            ResourceCapabilities::for_target(ResourceTarget::Missing, false, false, true, true);
        assert!(!readonly.contains(ResourceMethod::Put));
        assert!(!readonly.contains(ResourceMethod::Mkcol));
    }
}
