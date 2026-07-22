//! 已认证路由处理器共享的类型化请求状态转换。
//!
//! 安全不变量：
//! - 只有完成 URI 规范化和 ACL 路径规范化后才能创建 `NormalizedRequestPath`；
//! - 只有认证成功并消费该规范化状态后才能生成 `AuthenticatedRequest`；
//! - 只有描述符的真实能力相对路径再次授权后才返回 `OpenedRequestTarget`，路由代码不能从
//!   路径字符串构造它。
//!
//! Typed request-state transitions shared by authenticated route handlers.
//!
//! Security invariants:
//! - `NormalizedRequestPath` is created only after URI normalization and ACL path canonicalization;
//! - `AuthenticatedRequest` can only be produced by consuming that normalized state after
//!   authentication succeeds;
//! - `OpenedRequestTarget` is returned only after the descriptor's real capability-relative path
//!   is re-authorized. Route code cannot construct it from a path string.

use super::*;
use std::ops::{Deref, DerefMut};

/// 路径规范化后的 URI 与授权身份。 / URI and authorization identities after path normalization.
pub(crate) struct NormalizedRequestPath {
    authorization_path: String,
    authorization_method: Method,
}

impl NormalizedRequestPath {
    pub(crate) fn new(authorization_path: String, authorization_method: Method) -> Self {
        debug_assert!(!Path::new(&authorization_path).is_absolute());
        Self {
            authorization_path,
            authorization_method,
        }
    }

    /// 仅在认证层返回有效主体与路径权限后消费规范化状态。
    /// Consume normalized state only after authentication returns the effective principal and permissions.
    pub(crate) fn authenticate(
        self,
        user: Option<String>,
        access_paths: AccessPaths,
    ) -> AuthenticatedRequest {
        AuthenticatedRequest {
            normalized: self,
            user,
            access_paths,
        }
    }
}

/// 已通过认证和初始 ACL 检查的规范化请求。 / A normalized request that passed authentication and initial ACL checks.
pub(crate) struct AuthenticatedRequest {
    normalized: NormalizedRequestPath,
    user: Option<String>,
    access_paths: AccessPaths,
}

/// 仅在认证后可用的共享不可变请求数据。 / Shared immutable request data available only after authentication.
pub(crate) struct RequestContext<'a> {
    pub(crate) query_params: HashMap<String, String>,
    pub(crate) headers: &'a hyper::HeaderMap,
    pub(crate) preconditions: ParsedPreconditions,
    pub(crate) head_only: bool,
    pub(crate) user: Option<String>,
    pub(crate) access_paths: AccessPaths,
    pub(crate) authorization_path: String,
    pub(crate) authorization_method: Method,
}

impl<'a> RequestContext<'a> {
    pub(crate) fn from_authenticated(
        query_params: HashMap<String, String>,
        headers: &'a hyper::HeaderMap,
        preconditions: ParsedPreconditions,
        head_only: bool,
        authenticated: AuthenticatedRequest,
    ) -> Self {
        Self {
            query_params,
            headers,
            preconditions,
            head_only,
            user: authenticated.user,
            access_paths: authenticated.access_paths,
            authorization_path: authenticated.normalized.authorization_path,
            authorization_method: authenticated.normalized.authorization_method,
        }
    }

    /// 重新授权从已打开 fd 获取的对象身份。 / Re-authorize an object identity obtained from an already-open fd.
    pub(crate) fn allows_actual(&self, actual: &Path, method: &Method) -> bool {
        let base = Path::new(&self.authorization_path);
        let Ok(suffix) = actual.strip_prefix(base) else {
            return false;
        };
        let Some(suffix) = suffix.to_str() else {
            return false;
        };
        self.access_paths.guard(suffix, method).is_some()
    }

    /// 只有检查真实能力相对身份后，才把描述符转换为路由可见的已打开状态。
    /// Convert an opened descriptor into route-visible state only after checking its real capability-relative identity.
    pub(crate) fn authorize_opened(&self, opened: OpenedNode) -> Option<OpenedRequestTarget> {
        self.allows_actual(&opened.real_rel, &self.authorization_method)
            .then_some(OpenedRequestTarget(opened))
    }
}

/// 真实路径已按认证请求检查的描述符；私有元组字段防止伪造。
/// An opened descriptor whose real path was checked against the authenticated request; its private field prevents fabrication.
pub(super) struct OpenedRequestTarget(OpenedNode);

impl OpenedRequestTarget {
    pub(super) fn into_inner(self) -> OpenedNode {
        self.0
    }

    pub(super) fn as_node_mut(&mut self) -> &mut OpenedNode {
        &mut self.0
    }
}

impl Deref for OpenedRequestTarget {
    type Target = OpenedNode;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for OpenedRequestTarget {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
