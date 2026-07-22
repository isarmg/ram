//! 这是资源路由器所处理方法的权威模型：线名只声明一次，源路径授权和条件头准入
//! 都是注册表元数据，未知方法永远不会凭空获得能力。
//!
//! Authoritative model for methods handled by the resource router.
//!
//! Security invariants:
//! - every resource-method wire name is declared exactly once, in
//!   [`RESOURCE_METHODS`];
//! - source-path authorization and conditional-header admission are metadata,
//!   not independent string matches in authentication and routing code;
//! - parsing an unknown method never invents capabilities for it.

use hyper::Method;

/// 认证后负责该方法的路由族。 / The route family that owns the method after authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResourceRoute {
    Read,
    Write,
    Dav,
    Control,
}

/// 普通文件/目录资源路由器实现的全部方法。 / Every method implemented by the ordinary file/directory router.
///
/// `POST` 刻意不在其中：它只属于显式 token 端点，不是资源能力。
/// `POST` is intentionally absent: it belongs only to the token endpoint and is not a resource capability.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub(crate) enum ResourceMethod {
    Get,
    Head,
    Options,
    Put,
    Delete,
    Patch,
    Propfind,
    Proppatch,
    Mkcol,
    Copy,
    Move,
    Checkauth,
    Logout,
}

/// 方法注册表中的一条不可变记录。 / One immutable row in the method registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResourceMethodDescriptor {
    pub(crate) method: ResourceMethod,
    pub(crate) name: &'static str,
    /// 源路径是否只需只读 ACL；COPY 的源只读，目标则独立按写操作授权。
    /// Whether read-only ACL is sufficient for the source; COPY authorizes its destination independently as a write.
    pub(crate) readonly_source: bool,
    /// 认证后是否解析条件请求字段。 / Whether conditional request fields are parsed after authentication.
    pub(crate) uses_preconditions: bool,
    pub(crate) route: ResourceRoute,
}

const fn descriptor(
    method: ResourceMethod,
    name: &'static str,
    readonly_source: bool,
    uses_preconditions: bool,
    route: ResourceRoute,
) -> ResourceMethodDescriptor {
    ResourceMethodDescriptor {
        method,
        name,
        readonly_source,
        uses_preconditions,
        route,
    }
}

/// 资源方法线名与策略的唯一声明位置。 / The sole declaration site for resource-method wire names and policy.
pub(crate) const RESOURCE_METHODS: [ResourceMethodDescriptor; 13] = [
    descriptor(ResourceMethod::Get, "GET", true, true, ResourceRoute::Read),
    descriptor(
        ResourceMethod::Head,
        "HEAD",
        true,
        true,
        ResourceRoute::Read,
    ),
    descriptor(
        ResourceMethod::Options,
        "OPTIONS",
        true,
        false,
        ResourceRoute::Control,
    ),
    descriptor(
        ResourceMethod::Put,
        "PUT",
        false,
        true,
        ResourceRoute::Write,
    ),
    descriptor(
        ResourceMethod::Delete,
        "DELETE",
        false,
        true,
        ResourceRoute::Write,
    ),
    descriptor(
        ResourceMethod::Patch,
        "PATCH",
        false,
        true,
        ResourceRoute::Write,
    ),
    descriptor(
        ResourceMethod::Propfind,
        "PROPFIND",
        true,
        false,
        ResourceRoute::Dav,
    ),
    descriptor(
        ResourceMethod::Proppatch,
        "PROPPATCH",
        false,
        true,
        ResourceRoute::Dav,
    ),
    descriptor(
        ResourceMethod::Mkcol,
        "MKCOL",
        false,
        true,
        ResourceRoute::Dav,
    ),
    descriptor(ResourceMethod::Copy, "COPY", true, true, ResourceRoute::Dav),
    descriptor(
        ResourceMethod::Move,
        "MOVE",
        false,
        true,
        ResourceRoute::Dav,
    ),
    descriptor(
        ResourceMethod::Checkauth,
        "CHECKAUTH",
        true,
        false,
        ResourceRoute::Control,
    ),
    descriptor(
        ResourceMethod::Logout,
        "LOGOUT",
        true,
        false,
        ResourceRoute::Control,
    ),
];

impl ResourceMethod {
    pub(crate) const ALL: [Self; 13] = [
        Self::Get,
        Self::Head,
        Self::Options,
        Self::Put,
        Self::Delete,
        Self::Patch,
        Self::Propfind,
        Self::Proppatch,
        Self::Mkcol,
        Self::Copy,
        Self::Move,
        Self::Checkauth,
        Self::Logout,
    ];

    pub(crate) fn parse(method: &Method) -> Option<Self> {
        Self::parse_name(method.as_str())
    }

    pub(crate) fn parse_name(name: &str) -> Option<Self> {
        RESOURCE_METHODS
            .iter()
            .find(|descriptor| descriptor.name == name)
            .map(|descriptor| descriptor.method)
    }

    pub(crate) const fn descriptor(self) -> &'static ResourceMethodDescriptor {
        &RESOURCE_METHODS[self as usize]
    }

    pub(crate) const fn as_str(self) -> &'static str {
        self.descriptor().name
    }

    pub(crate) const fn readonly_source(self) -> bool {
        self.descriptor().readonly_source
    }

    pub(crate) const fn uses_preconditions(self) -> bool {
        self.descriptor().uses_preconditions
    }

    pub(crate) const fn route(self) -> ResourceRoute {
        self.descriptor().route
    }

    pub(crate) const fn bit(self) -> u16 {
        1 << self as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn registry_is_total_unique_and_index_aligned() {
        assert_eq!(RESOURCE_METHODS.len(), ResourceMethod::ALL.len());
        let mut names = HashSet::new();
        for (index, method) in ResourceMethod::ALL.into_iter().enumerate() {
            let descriptor = method.descriptor();
            assert_eq!(descriptor.method, method);
            assert_eq!(descriptor, &RESOURCE_METHODS[index]);
            assert!(names.insert(descriptor.name));
            assert_eq!(ResourceMethod::parse_name(descriptor.name), Some(method));
        }
    }

    #[test]
    fn registry_captures_security_policy_instead_of_route_string_matches() {
        assert!(ResourceMethod::Copy.readonly_source());
        assert!(!ResourceMethod::Move.readonly_source());
        assert!(ResourceMethod::Proppatch.uses_preconditions());
        assert!(!ResourceMethod::Propfind.uses_preconditions());
        assert_eq!(ResourceMethod::Get.route(), ResourceRoute::Read);
        assert_eq!(ResourceMethod::Put.route(), ResourceRoute::Write);
    }
}
