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
    Control,
}

/// 普通文件/目录资源路由器实现的全部方法。 / Every method implemented by the ordinary file/directory router.
///
/// `POST` 刻意不在其中：本项目不提供表单提交式资源端点。
/// `POST` is intentionally absent because this server exposes no form-style resource endpoint.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub(crate) enum ResourceMethod {
    Get,
    Head,
    Options,
    Put,
    Delete,
    Mkcol,
    Move,
    Checkauth,
    Logout,
}

/// 方法注册表中的一条不可变记录。 / One immutable row in the method registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResourceMethodDescriptor {
    pub(crate) method: ResourceMethod,
    pub(crate) name: &'static str,
    /// 源路径是否只需只读 ACL。 / Whether read-only ACL is sufficient for the source.
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
pub(crate) const RESOURCE_METHODS: [ResourceMethodDescriptor; 9] = [
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
        ResourceMethod::Mkcol,
        "MKCOL",
        false,
        true,
        ResourceRoute::Write,
    ),
    descriptor(
        ResourceMethod::Move,
        "MOVE",
        false,
        true,
        ResourceRoute::Write,
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
    pub(crate) const ALL: [Self; 9] = [
        Self::Get,
        Self::Head,
        Self::Options,
        Self::Put,
        Self::Delete,
        Self::Mkcol,
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
        assert!(!ResourceMethod::Move.readonly_source());
        assert_eq!(ResourceMethod::Get.route(), ResourceRoute::Read);
        assert_eq!(ResourceMethod::Put.route(), ResourceRoute::Write);
        assert_eq!(ResourceMethod::Move.route(), ResourceRoute::Write);
    }
}
