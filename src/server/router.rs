//! 已认证资源的路由与有界请求准备。
//! Authenticated resource routing and bounded request preparation.
//!
//! 路由只消费已经规范化并完成身份认证的请求状态；打开的文件系统对象必须先以
//! 描述符推导出的真实身份通过第二次 ACL 检查，才会暴露给处理器。方法归属统一
//! 来自中央资源方法注册表，避免在各处重复比较线上方法名。
//! Routing consumes the normalized/authenticated request state and refuses to expose an opened
//! filesystem object until its descriptor-derived identity has passed the second ACL check.
//! Method ownership comes from the central resource-method registry rather than duplicated
//! wire-name comparisons.

use super::*;

/// `IndexOnly` 只是为了让调用方穿过中间集合导航到明确授权的后代。
/// ACL 初次检查时还不知道路径是文件还是目录，所以只读方法必须先暂时
/// 通过；在描述符已经确认目标不是集合后，GET/HEAD/PROPFIND/COPY 都会读取
/// 文件内容或元数据，必须在分派前拒绝。
///
/// `IndexOnly` exists only so a caller can navigate through intermediate
/// collections to explicitly authorized descendants. The first ACL pass does
/// not yet know whether a path is a file or directory, so read-only methods
/// provisionally pass. Once descriptor metadata proves a non-collection
/// target, methods that consume source contents or metadata must be denied.
fn index_only_forbids_target(
    access_paths: &AccessPaths,
    target: ResourceTarget,
    method: ResourceMethod,
) -> bool {
    access_paths.perm().indexonly()
        && matches!(
            target,
            ResourceTarget::EmptyFile
                | ResourceTarget::File
                | ResourceTarget::Other
                | ResourceTarget::SingleFile
        )
        && matches!(
            method,
            ResourceMethod::Get
                | ResourceMethod::Head
                | ResourceMethod::Propfind
                | ResourceMethod::Copy
        )
}

impl Server {
    /// 解码并规范化配置 URL 前缀下的请求路径。进入文件系统路由前会拒绝点段、
    /// 绝对路径组件、非 UTF-8 名称、NUL 和内部上传候选名称。
    /// Decode and normalize a request path beneath the configured URL prefix. Dot segments,
    /// absolute components, non-UTF-8 names, NULs, and private upload-candidate names are rejected
    /// before filesystem routing.
    pub(super) fn resolve_path(&self, path: &str) -> Option<String> {
        normalize_request_path(path, &self.args.path_prefix)
    }

    fn join_path(&self, path: &str) -> Option<PathBuf> {
        if path.is_empty() {
            Some(self.args.serve_path.clone())
        } else {
            Some(self.args.serve_path.join(path))
        }
    }

    /// 请求路由器：按"路径解析 → 内置端点 → 认证鉴权 → 特殊方法 →
    /// 按 HTTP 方法分发"的顺序处理。每个阶段一旦能确定响应就提前
    /// `return Ok(res)`（"早退"风格，避免深层嵌套）。
    /// Request router: process path resolution, built-in endpoints, authentication/authorization,
    /// special methods, and HTTP-method dispatch in order. Each stage returns as soon as it can
    /// determine the response, keeping control flow shallow.
    pub(super) async fn handle(
        self: Arc<Self>,
        req: Request,
        source: SourceIdentity,
        admission: &mut RequestAdmission,
    ) -> Result<Response> {
        let mut res = Response::default();

        // URI 和请求头与流式请求体分开保存。这样，已认证的 DAV 处理器可以消费其有界
        // XML 请求体，而请求上下文仍可借用不可变的请求头快照。
        // Keep the URI and headers independently from the streaming body so authenticated DAV
        // handlers can consume their bounded XML body while the context borrows immutable headers.
        let uri = req.uri().clone();
        let req_path = uri.path();
        let headers = req.headers().clone();
        let method = req.method().clone();
        let resource_method = ResourceMethod::parse(&method);

        // 阶段一：把 URL 路径解码、规范化成服务根下的相对路径。
        // 含 `..` 等越界成分的路径在这里直接被拒（返回 400）。
        // Stage 1: decode the URL path and normalize it below the service root. Reject escaping
        // components such as `..` here with a 400 response.
        let relative_path = match self.resolve_path(req_path) {
            Some(v) => v,
            None => {
                status_bad_request(&mut res, "Invalid Path");
                return Ok(res);
            }
        };
        // 单文件模式对同一物理文件暴露 `/`、无尾斜杠前缀和
        // `/<filename>` 等别名。先记住是否命中，后面所有别名都会映射到
        // 唯一规范虚拟文件路径做授权，避免根节点 IndexOnly 被误当成
        // “可读文件内容”。
        // Single-file mode exposes `/`, the prefix without a trailing slash, and `/<filename>` as
        // aliases of one physical file. Record a match now; all aliases are later authorized as the
        // one canonical virtual file path so root IndexOnly never implies readable file contents.
        let single_file_request = self.args.path_is_file
            && self
                .single_file_req_paths
                .iter()
                .any(|candidate| candidate == req_path);

        // 阶段二：内置端点（前端 js/css/favicon、健康检查）。
        // 它们不需要认证——资源文件本身不含敏感数据，而登录页也要用它们。
        // Stage 2: built-in endpoints (frontend JS/CSS/favicon and health check). They are public
        // because the assets contain no sensitive data and the login page needs them.
        if matches!(method, Method::GET | Method::HEAD)
            && self
                .handle_internal(&relative_path, &headers, method == Method::HEAD, &mut res)
                .await?
        {
            return Ok(res);
        }

        // Authorization 是安全关键且不可逗号合并的字段；认证层绝不能从多份凭据中静默挑选。
        // Authorization is security-critical and not a comma-combinable field. Never let the
        // authentication layer silently choose one of multiple credentials.
        let mut authorization_values = headers.get_all(AUTHORIZATION).iter();
        let authorization = authorization_values.next();
        if authorization_values.next().is_some() {
            status_bad_request(&mut res, "Duplicate Authorization header");
            return Ok(res);
        }

        // 把查询串（?a=1&b=2）解析成 HashMap，后面各功能按参数名取用。
        // Parse the query string (`?a=1&b=2`) into a map for later named-parameter lookup.
        let query = uri.query().unwrap_or_default();
        let query_params: HashMap<String, String> = form_urlencoded::parse(query.as_bytes())
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let is_tokengen = has_query_flag(&query_params, "tokengen");
        let mut revoke_values = headers.get_all("x-ram-revoke-token").iter();
        let revoke_token = match revoke_values.next() {
            Some(value) => match value.to_str() {
                Ok(value) => Some(value),
                Err(_) => {
                    status_bad_request(&mut res, "Invalid X-Ram-Revoke-Token header");
                    return Ok(res);
                }
            },
            None => None,
        };
        if revoke_values.next().is_some() {
            status_bad_request(&mut res, "Duplicate X-Ram-Revoke-Token header");
            return Ok(res);
        }

        // 令牌签发是明确的 GET/POST 端点，不再由“查询参数在方法
        // 分发之前处理”意外地接受 OPTIONS/PUT/DELETE 等任意方法。
        // Token issuance is an explicit GET/POST endpoint; handling a query flag before dispatch
        // must not accidentally accept OPTIONS, PUT, DELETE, or another arbitrary method.
        if is_tokengen && method != Method::GET && method != Method::POST {
            status_method_not_allowed(&mut res, TOKENGEN_ALLOW);
            return Ok(res);
        }
        if revoke_token.is_some() && method != Method::POST {
            status_method_not_allowed(&mut res, TOKEN_REVOKE_ALLOW);
            return Ok(res);
        }
        if is_tokengen && revoke_token.is_some() {
            status_bad_request(
                &mut res,
                "Token generation and revocation are mutually exclusive",
            );
            return Ok(res);
        }

        // 原始请求目标（与 Digest 客户端签名时使用的完全一致），
        // 用于把 Digest Authorization 头绑定到"这一个"具体请求上，
        // 防止截获的认证头被重放到其他路径（详见 auth 模块）。
        // Preserve the exact request target signed by a Digest client. This binds the Digest
        // Authorization header to this request and prevents replay against another path.
        let request_target = match uri.query() {
            Some(query) => format!("{req_path}?{query}"),
            None => req_path.to_string(),
        };

        // POST ?tokengen 与令牌撤销针对 GET 所指向的表示。资源路由前先计算这个有效授权
        // 方法，让 SPA 回退在签发、使用和撤销时选中同一个索引对象；下方 Digest 校验仍
        // 接收原始 `method`，因此签名并校验真实的 POST。
        // POST ?tokengen and token revocation operate on the representation a GET would address.
        // Compute that effective authorization method before resource routing so SPA fallback picks
        // the same index object for issuance, use, and revocation. Digest still verifies real POST.
        let authorization_method = if is_tokengen || revoke_token.is_some() {
            Method::GET
        } else {
            method.clone()
        };

        // 授权使用的资源身份必须与最终打开的文件一致：
        // - 单文件的全部 URL 别名统一映射到真实文件名；
        // - 显式允许 symlink 时，根内链接按其真实根内相对路径鉴权。
        // Authorization identity must match the file eventually opened: all single-file URL aliases
        // map to the real filename, and explicitly permitted in-root symlinks are authorized by their
        // real root-relative path.
        let requested_authorization_path = if single_file_request {
            single_file_authorization_path(&self.args.serve_path)
        } else {
            match self.canonical_authorization_path(&relative_path).await {
                Ok(path) => path,
                Err(error) if canonical_authorization_path_is_unavailable(&error) => {
                    // 初次 ACL 选择发生在认证前，因此所有客户端可造成的不可用命名空间状态
                    // 必须得到相同的 404；真正的后端/worker 故障仍沿错误链映射为 500。
                    // Initial ACL selection precedes authentication, so every client-induced
                    // unavailable namespace state gets the same 404. Genuine backend/worker
                    // failures still retain their error chain and map to 500.
                    status_not_found(&mut res);
                    return Ok(res);
                }
                Err(error) => return Err(error),
            }
        };
        // SPA 回退提供的文件系统对象不同于请求中缺失的路由。认证前先通过能力探测决定
        // 该映射，然后对实际的索引对象本身进行认证。
        // SPA fallback serves a different filesystem object from the missing route. Decide that
        // mapping with a capability probe before authentication, then authenticate the actual index.
        let spa_fallback = if !self.args.path_is_file
            && self.args.render_spa
            && matches!(authorization_method, Method::GET | Method::HEAD)
            && Path::new(&relative_path).extension().is_none()
        {
            classify_open_result(
                self.fs_root
                    .open(PathBuf::from(&requested_authorization_path), NodeKind::Any)
                    .await,
                "probing requested path for SPA fallback",
                OpenErrorPolicy::HideUnavailable,
            )?
            .is_none()
        } else {
            false
        };
        let authorization_path = if spa_fallback {
            self.canonical_authorization_path("index.html").await?
        } else {
            requested_authorization_path
        };

        // 阶段三：认证与鉴权，一次完成。
        // 返回 (用户名, 可访问路径集)：
        //   (None, None)      → 没有有效凭据，回 401 要求登录；
        //   (Some, None)      → 身份有效但对该路径/方法无权限，回 403；
        //   (user, Some(paths)) → 放行，同时拿到该用户的权限树。
        // Stage 3 authenticates and authorizes together. `(None, None)` means no valid credentials
        // (401), `(Some, None)` means authenticated but forbidden (403), and `(user, Some(paths))`
        // permits the request while carrying the user's accessible-path tree.
        let guard = self
            .args
            .auth
            .guard(AuthRequest {
                path: &authorization_path,
                method: &method,
                authorization_method: &authorization_method,
                authorization,
                // 分享下载 token 不得再签发新 token，否则短期过期
                // 可被无限续期。tokengen 必须回到 Basic/Digest 原始凭据。
                // A shared download token cannot mint another token, which would renew a short-lived
                // credential indefinitely. Token generation requires original Basic/Digest credentials.
                request_target: &request_target,
                source: Some(source),
                allow_token_auth: !is_tokengen && revoke_token.is_none(),
            })
            .await;

        let (user, access_paths) = match guard {
            AuthDecision::Unauthorized => {
                self.auth_reject(&mut res)?;
                return Ok(res);
            }
            AuthDecision::RateLimited { retry_after_secs } => {
                *res.status_mut() = StatusCode::TOO_MANY_REQUESTS;
                res.headers_mut().insert(
                    RETRY_AFTER,
                    HeaderValue::from_str(&retry_after_secs.to_string())?,
                );
                return Ok(res);
            }
            AuthDecision::ServiceUnavailable { retry_after_secs } => {
                *res.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
                res.headers_mut().insert(
                    RETRY_AFTER,
                    HeaderValue::from_str(&retry_after_secs.to_string())?,
                );
                return Ok(res);
            }
            AuthDecision::Forbidden {
                user,
                source: auth_source,
            } => {
                if !self.acquire_account_request(&user, admission, &mut res) {
                    return Ok(res);
                }
                res.extensions_mut().insert(AuthenticatedUser(user.clone()));
                if auth_source == AuthSource::Token {
                    res.extensions_mut().insert(TokenAuthenticated);
                }
                status_forbid(&mut res);
                return Ok(res);
            }
            AuthDecision::Allowed {
                user,
                access_paths,
                source: auth_source,
            } => {
                if let Some(user) = user.as_ref() {
                    if !self.acquire_account_request(user, admission, &mut res) {
                        return Ok(res);
                    }
                    res.extensions_mut().insert(AuthenticatedUser(user.clone()));
                }
                if auth_source == AuthSource::Token {
                    res.extensions_mut().insert(TokenAuthenticated);
                }
                (user, access_paths)
            }
        };

        // 条件请求语法只在认证成功后检查，避免畸形验证器取代 401/403 或泄露受保护名称
        // 是否存在。自此以后，对下方表示方法而言，该检查先于任何目标存在性响应、上传
        // 请求体暂存和命名空间副作用。
        // Check conditional syntax only after authentication so a malformed validator cannot replace
        // 401/403 or reveal a protected name. It then precedes existence responses, upload staging,
        // and namespace side effects for representation methods.
        let preconditions = if !is_tokengen
            && revoke_token.is_none()
            && resource_method.is_some_and(method_uses_preconditions)
        {
            match ParsedPreconditions::parse(&headers) {
                Ok(parsed) => parsed,
                Err(error) => {
                    warn!("Rejected invalid conditional request header: {error:#}");
                    status_bad_request(&mut res, "Invalid conditional request header");
                    return Ok(res);
                }
            }
        } else {
            ParsedPreconditions::default()
        };

        // 鉴权通过：把后续处理函数共同需要的请求侧数据收进上下文，
        // 之后一律传 `&ctx` 而不是逐个散参数。
        // Authorization succeeded: collect shared request data into a context and pass `&ctx`
        // instead of a growing list of independent parameters.
        let authenticated =
            NormalizedRequestPath::new(authorization_path.clone(), authorization_method.clone())
                .authenticate(user, access_paths);
        let ctx = RequestContext::from_authenticated(
            query_params,
            &headers,
            preconditions,
            // HEAD 请求：走与 GET 完全相同的逻辑，但只发响应头不发响应体。
            // HEAD follows exactly the GET path but emits headers without a response body.
            method == Method::HEAD,
            authenticated,
        );

        if let Some(token) = revoke_token {
            match ctx.user.as_deref() {
                Some(user) => {
                    match self
                        .args
                        .auth
                        .revoke_token(token, user, &authorization_path, Some(source))
                        .await
                    {
                        Ok(()) => *res.status_mut() = StatusCode::NO_CONTENT,
                        Err(TokenRevokeError::Invalid(_)) => {
                            status_bad_request(&mut res, "Invalid token revocation request");
                        }
                        Err(TokenRevokeError::RateLimited { retry_after_secs }) => {
                            *res.status_mut() = StatusCode::TOO_MANY_REQUESTS;
                            res.headers_mut().insert(
                                RETRY_AFTER,
                                HeaderValue::from_str(&retry_after_secs.to_string())?,
                            );
                        }
                        Err(TokenRevokeError::Infrastructure(err)) => {
                            warn!("Token revocation infrastructure unavailable: {err:#}");
                            *res.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
                            res.headers_mut()
                                .insert(RETRY_AFTER, HeaderValue::from_static("1"));
                        }
                    }
                    res.headers_mut()
                        .typed_insert(CacheControl::new().with_no_store());
                }
                None => self.auth_reject(&mut res)?,
            }
            return Ok(res);
        }

        // 阶段四：本项目自定义的两个"伪 HTTP 方法"，供前端登录逻辑使用。
        // CHECKAUTH 询问"我登录了吗"，LOGOUT 通过回 401 让浏览器丢弃凭据。
        // Stage 4 handles two custom pseudo-methods used by the login UI: CHECKAUTH asks whether the
        // caller is logged in, and LOGOUT returns 401 so the browser discards cached credentials.
        if resource_method == Some(ResourceMethod::Checkauth) {
            // 禁用匿名后，鉴权阶段只会以 (Some(user), Some(paths)) 放行
            // 非 OPTIONS 请求，走到这里的 CHECKAUTH 必然已认证；
            // None 分支仅作防御性兜底。
            // With anonymous access disabled, only `(Some(user), Some(paths))` passes a non-OPTIONS
            // request. CHECKAUTH is therefore authenticated here; `None` is defensive fallback only.
            match ctx.user.clone() {
                Some(user) => {
                    *res.body_mut() = body_full(user);
                }
                None => self.auth_reject(&mut res)?,
            }
            return Ok(res);
        } else if resource_method == Some(ResourceMethod::Logout) {
            self.auth_reject(&mut res)?;
            return Ok(res);
        }

        if is_tokengen {
            // 令牌代表读取表示，不是目录导航。不允许 IndexOnly 主体签发一个随后
            // 只会在文件路径上失败的 Bearer 凭据，也避免未来令牌路径绕过对象类型检查。
            // A token represents a readable representation, not collection
            // navigation. Refuse IndexOnly issuance so a future token path
            // cannot bypass descriptor-type authorization.
            match (ctx.user.as_deref(), ctx.access_paths.perm().indexonly()) {
                (_, true) => status_forbid(&mut res),
                (Some(user), false) => {
                    self.handle_tokengen(&authorization_path, user, &mut res)
                        .await?;
                }
                (None, false) => self.auth_reject(&mut res)?,
            }
            return Ok(res);
        }

        // 单文件模式：serve 的路径本身是一个文件，只响应固定几种路径。
        // In single-file mode the served path is itself a file and only fixed aliases are accepted.
        if self.args.path_is_file {
            if single_file_request {
                let readable = !ctx.access_paths.perm().indexonly();
                let caller_capabilities = ResourceCapabilities::for_target(
                    ResourceTarget::SingleFile,
                    readable,
                    false,
                    false,
                    false,
                );
                let cors_capabilities = ResourceCapabilities::for_target(
                    ResourceTarget::SingleFile,
                    true,
                    false,
                    false,
                    false,
                );
                res.extensions_mut()
                    .insert(CorsPreflightCapabilities(cors_capabilities));
                if resource_method.is_some_and(|method| {
                    index_only_forbids_target(&ctx.access_paths, ResourceTarget::SingleFile, method)
                }) {
                    status_forbid(&mut res);
                    return Ok(res);
                }
                match resource_method {
                    Some(ResourceMethod::Get | ResourceMethod::Head) => {
                        let Some(rel) = self.fs_root.single_file_rel() else {
                            status_not_found(&mut res);
                            return Ok(res);
                        };
                        match classify_open_result(
                            self.fs_root.open(rel, NodeKind::File).await,
                            "opening the configured single file",
                            OpenErrorPolicy::HideUnavailable,
                        )? {
                            Some(opened)
                                if ctx
                                    .allows_actual(&opened.real_rel, &ctx.authorization_method) =>
                            {
                                self.handle_send_opened_cap_file(
                                    opened,
                                    &self.args.serve_path,
                                    &ctx,
                                    &mut res,
                                )
                                .await?;
                            }
                            Some(_) | None
                                if ctx.preconditions.requires_existing_representation() =>
                            {
                                *res.status_mut() = StatusCode::PRECONDITION_FAILED;
                            }
                            Some(_) | None => status_not_found(&mut res),
                        }
                    }
                    Some(ResourceMethod::Options) => {
                        set_resource_headers(&mut res, caller_capabilities)
                    }
                    _ => status_resource_method_not_allowed(&mut res, caller_capabilities),
                }
            } else {
                self.handle_not_found(&ctx, &mut res).await?;
            }
            return Ok(res);
        }
        let path = match self.join_path(&relative_path) {
            Some(v) => v,
            None => {
                status_forbid(&mut res);
                return Ok(res);
            }
        };

        let path = path.as_path();

        let allow_upload = self.args.allow_upload;
        let allow_delete = self.args.allow_delete;
        let capability_path = Path::new(&authorization_path);
        let mut request = Some(req);

        // 服务根在当前能力内没有父目录项；无论请求头如何，都在解析 Destination、暂存正文或
        // 获取变更锁之前拒绝根 DELETE/MOVE。
        // The served root has no parent entry inside this capability. Reject root DELETE/MOVE before
        // Destination parsing, body staging, or mutation-lock acquisition, regardless of request headers.
        if capability_path.as_os_str().is_empty()
            && matches!(
                resource_method,
                Some(ResourceMethod::Delete | ResourceMethod::Move)
            )
        {
            status_forbid(&mut res);
            return Ok(res);
        }

        // 中文：纯配置能力拒绝不需要读取正文、解析 Destination、打开对象或取得路径锁。
        // 尤其不能先进入 mutation-version 事务：否则只有读取权限的已认证客户端也能用
        // 必然返回 403 的写请求持续推进全局 revision，使所有管理 UI 列表快照失效。
        // `allow_delete` 对 PUT/PATCH/COPY 的覆盖语义仍取决于锁内看到的目标形状，因此这里只
        // 提前判断每个方法无条件需要的静态开关。
        //
        // English: A configuration-only capability denial needs no body read, Destination parsing,
        // object open, or path lock. In particular it must not enter the mutation-version transaction:
        // otherwise an authenticated read-only client could repeatedly advance the global revision
        // with writes guaranteed to return 403, invalidating every manager listing. DELETE permission
        // for PUT/PATCH/COPY replacement still depends on the target observed under lock, so this
        // early gate checks only the static flag unconditionally required by each method.
        let disabled_by_configuration = match resource_method {
            Some(
                ResourceMethod::Put
                | ResourceMethod::Patch
                | ResourceMethod::Mkcol
                | ResourceMethod::Copy,
            ) => !allow_upload,
            Some(ResourceMethod::Delete) => !allow_delete,
            Some(ResourceMethod::Move) => !allow_upload || !allow_delete,
            _ => false,
        };
        if disabled_by_configuration {
            status_forbid(&mut res);
            return Ok(res);
        }

        // 列表页只为其危险的 DELETE/MOVE 操作发送该条件头。它不是可逗号合并字段：
        // 重复值、非 UTF-8、非规范 UUID/revision 都在取得锁或触碰文件系统前以 400 拒绝。
        // Listing pages send this condition only for destructive DELETE/MOVE actions. It is not a
        // comma-combinable field: duplicates, non-UTF-8, and non-canonical UUID/revision spellings
        // are rejected with 400 before lock admission or filesystem mutation.
        let expected_mutation_version = if matches!(
            resource_method,
            Some(ResourceMethod::Delete | ResourceMethod::Move)
        ) {
            match mutation_version::parse_mutation_version_header(&headers) {
                Ok(version) => version,
                Err(error) => {
                    debug!("Rejected mutation-version condition: {error}");
                    status_bad_request(&mut res, "Invalid X-Ram-If-Mutation-Version header");
                    return Ok(res);
                }
            }
        } else {
            None
        };

        // PUT/PATCH 网络请求体会在获取变更锁之前暂存。乐观探测先拒绝明显失败；获取下方
        // 有界提交事务锁后，再权威地核验描述符、ACL 和前置条件。
        // Stage PUT/PATCH network bodies before acquiring any mutation lock. An optimistic probe
        // rejects obvious failures; descriptor identity, ACL, and preconditions are checked again
        // after acquiring the bounded commit-transaction lock.
        let mut staged_upload = None;
        if matches!(
            resource_method,
            Some(ResourceMethod::Put | ResourceMethod::Patch)
        ) && allow_upload
        {
            let initial_intent = MutationIntent::write(capability_path);
            let initial_upload_guard = match self
                .acquire_write_guards(std::slice::from_ref(&initial_intent), &mut res)
                .await?
            {
                Some(guard) => guard,
                None => return Ok(res),
            };
            let mut probe = match classify_open_result(
                self.fs_root
                    .open(PathBuf::from(&authorization_path), NodeKind::Any)
                    .await,
                "probing an upload target",
                OpenErrorPolicy::HideUnavailable,
            )? {
                Some(opened) if ctx.allows_actual(&opened.real_rel, &ctx.authorization_method) => {
                    Some(opened)
                }
                Some(_) | None => None,
            };
            let (probe_missing, probe_is_file, probe_size) = match probe.as_ref() {
                Some(opened) => (false, opened.metadata.is_file(), opened.metadata.len()),
                None => (true, false, 0),
            };
            let upload_projection;
            if resource_method == Some(ResourceMethod::Put) {
                upload_projection = UploadProjection::put();
                if (!probe_missing && !probe_is_file) || (!allow_delete && probe_size > 0) {
                    status_forbid(&mut res);
                    return Ok(res);
                }
                if !write_precondition_passes(probe.as_mut(), &ctx.preconditions, &mut res).await? {
                    return Ok(res);
                }
            } else {
                if !write_precondition_passes(probe.as_mut(), &ctx.preconditions, &mut res).await? {
                    return Ok(res);
                }
                if probe_missing {
                    status_not_found(&mut res);
                    return Ok(res);
                }
                if !probe_is_file {
                    status_forbid(&mut res);
                    return Ok(res);
                }
                let offset = match parse_upload_offset(ctx.headers, probe_size) {
                    Ok(Some(offset)) => offset,
                    Ok(None) => {
                        status_bad_request(&mut res, "Missing X-Update-Range header");
                        return Ok(res);
                    }
                    Err(err) => {
                        warn!("Rejected invalid X-Update-Range header: {err:#}");
                        status_bad_request(&mut res, "Invalid X-Update-Range header");
                        return Ok(res);
                    }
                };
                upload_projection = UploadProjection::patch(probe_size, offset);
                if offset < probe_size && !allow_delete {
                    status_forbid(&mut res);
                    return Ok(res);
                }
            }
            drop(initial_upload_guard);
            drop(probe);
            let upload_request = request
                .take()
                .ok_or_else(|| anyhow::anyhow!("upload request body was already consumed"))?;
            staged_upload = self
                .stage_upload(
                    capability_path,
                    upload_request,
                    upload_projection,
                    ctx.user.as_deref(),
                    source,
                    &mut res,
                )
                .await?;
            if staged_upload.is_none() {
                return Ok(res);
            }
        }

        // 基础 MKCOL 没有请求实体格式。获取命名空间变更锁之前先消费并校验请求体，避免
        // 被拒绝或缓慢的实体创建目录或长期独占事务临界区。
        // Base MKCOL has no request-entity format. Consume and validate its body before acquiring a
        // namespace mutation lock so a rejected or slow entity cannot mutate or monopolize the lock.
        if resource_method == Some(ResourceMethod::Mkcol) && allow_upload {
            let mkcol_request = request
                .take()
                .ok_or_else(|| anyhow::anyhow!("MKCOL request body was already consumed"))?;
            if !validate_mkcol_empty_body(mkcol_request, &mut res).await {
                return Ok(res);
            }
        }

        // 目标解析和初始 ACL 选择不会修改文件系统，因此 COPY/MOVE 可以在进入有界最终
        // 变更事务前完成请求校验。
        // Destination parsing and initial ACL selection do not mutate the filesystem, so COPY/MOVE
        // can finish request validation before entering the bounded final-mutation transaction.
        let needs_destination = (resource_method == Some(ResourceMethod::Copy) && allow_upload)
            || (resource_method == Some(ResourceMethod::Move) && allow_upload && allow_delete);
        let prepared_destination = if needs_destination {
            let request = request
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("DAV request body was already consumed"))?;
            match self
                .prepare_destination(request, ctx.user.as_deref(), &mut res)
                .await?
            {
                Some(destination) => Some(destination),
                None => return Ok(res),
            }
        } else {
            None
        };

        let mutation_intents = match resource_method {
            Some(
                ResourceMethod::Put
                | ResourceMethod::Patch
                | ResourceMethod::Delete
                | ResourceMethod::Mkcol,
            ) => {
                vec![MutationIntent::write(capability_path)]
            }
            Some(ResourceMethod::Copy) => prepared_destination
                .as_deref()
                .map(|destination| {
                    vec![
                        MutationIntent::read(capability_path),
                        MutationIntent::write(destination),
                    ]
                })
                .unwrap_or_default(),
            Some(ResourceMethod::Move) => prepared_destination
                .as_deref()
                .map(|destination| {
                    vec![
                        MutationIntent::write(capability_path),
                        MutationIntent::write(destination),
                    ]
                })
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        let mut mutation_guards = if mutation_intents.is_empty() {
            None
        } else {
            match self
                .acquire_write_guards(&mutation_intents, &mut res)
                .await?
            {
                Some(guards) => Some(guards),
                None => return Ok(res),
            }
        };
        if let Some(guards) = mutation_guards.as_mut() {
            // 所有相关路径锁已经持有，且下面的权威 open/检查尚未产生最终副作用。原子比较
            // 与 active+revision 转换封闭“检查成功后另一事务先启动”的竞态。
            // Every relevant path lock is now held and no final side effect has occurred. The atomic
            // compare plus active/revision transition closes the race where another transaction
            // could otherwise start immediately after a successful comparison.
            match guards.activate(&self.mutation_versions, expected_mutation_version.as_ref()) {
                Ok(()) => {}
                Err(MutationVersionBeginError::Stale) => {
                    *res.status_mut() = StatusCode::PRECONDITION_FAILED;
                    res.headers_mut()
                        .insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
                    res.headers_mut()
                        .typed_insert(CacheControl::new().with_no_store());
                    return Ok(res);
                }
                Err(error) => {
                    return Err(anyhow::Error::new(error)
                        .context("entering the final filesystem mutation transaction"));
                }
            }
        }

        // 分发元数据和对象身份来自同一个 openat2 描述符。再次对描述符的真实根相对路径
        // 授权；认证完成后不再信任路径字符串本身。
        // Dispatch metadata and object identity come from one openat2 descriptor. Re-authorize its
        // real root-relative path; path strings are not trusted after authentication.
        let mut opened_node = match classify_open_result(
            self.fs_root
                .open(PathBuf::from(&authorization_path), NodeKind::Any)
                .await,
            "opening a request target",
            OpenErrorPolicy::HideUnavailable,
        )? {
            Some(opened) => ctx.authorize_opened(opened),
            None => None,
        };
        let (is_miss, is_dir, is_file, size) = match opened_node.as_ref() {
            Some(opened) => (
                false,
                opened.metadata.is_dir(),
                opened.metadata.is_file(),
                opened.metadata.len(),
            ),
            None => (true, false, false, 0),
        };
        if is_miss
            && matches!(method, Method::GET | Method::HEAD)
            && ctx.preconditions.requires_existing_representation()
        {
            *res.status_mut() = StatusCode::PRECONDITION_FAILED;
            return Ok(res);
        }
        let target = if is_miss {
            ResourceTarget::Missing
        } else if is_dir && capability_path.as_os_str().is_empty() {
            ResourceTarget::RootCollection
        } else if is_dir {
            ResourceTarget::Collection
        } else if is_file && size == 0 {
            ResourceTarget::EmptyFile
        } else if is_file {
            ResourceTarget::File
        } else {
            ResourceTarget::Other
        };
        if resource_method
            .is_some_and(|method| index_only_forbids_target(&ctx.access_paths, target, method))
        {
            status_forbid(&mut res);
            return Ok(res);
        }
        let readable = !ctx.access_paths.perm().indexonly();
        let writable = ctx.access_paths.perm().readwrite();
        let caller_can_create_destination = ctx
            .user
            .as_deref()
            .is_some_and(|user| self.args.auth.user_has_write_access(user));
        let caller_capabilities = ResourceCapabilities::for_target(
            target,
            readable,
            writable,
            allow_upload && caller_can_create_destination,
            allow_delete,
        );
        let cors_capabilities =
            ResourceCapabilities::for_target(target, true, true, allow_upload, allow_delete);
        res.extensions_mut()
            .insert(CorsPreflightCapabilities(cors_capabilities));

        // 不适用于目标的方法和未知方法与 OPTIONS/Allow 共用能力表。缺失名称及没有公开
        // 表示的特殊节点查找已包含在表中，仍交给处理器返回 404。
        // Target-inapplicable and unknown methods share the OPTIONS/Allow capability table. Lookups
        // of missing names and special nodes without a public representation remain in that table
        // and reach their handlers for a 404 response.
        let structural_capabilities =
            ResourceCapabilities::for_target(target, true, true, true, true);
        if resource_method
            .is_none_or(|method| !is_miss && !structural_capabilities.contains(method))
        {
            status_resource_method_not_allowed(&mut res, caller_capabilities);
            return Ok(res);
        }

        // 阶段五：按中央方法注册表解析后的枚举分发。未知方法已在
        // 上方使用同一能力表返回 405，因此这里不再比较方法字符串。
        // Stage 5 dispatches the enum parsed by the central method registry. Unknown methods already
        // returned 405 through the same capability table, so no wire-name comparison remains here.
        let changed_status = if ctx.preconditions.if_match.is_some()
            || ctx.preconditions.if_unmodified_since.is_some()
            || ctx.preconditions.if_none_match.is_some()
        {
            ChangedStatus::PreconditionFailed
        } else {
            ChangedStatus::Conflict
        };
        let method = resource_method.expect("resource method was validated above");
        match method.route() {
            ResourceRoute::Read => {
                self.dispatch_read_route(
                    method,
                    path,
                    req_path,
                    spa_fallback,
                    &mut opened_node,
                    &ctx,
                    target,
                    allow_upload,
                    &mut res,
                )
                .await?;
            }
            ResourceRoute::Write => {
                self.dispatch_write_route(
                    method,
                    capability_path,
                    &mut opened_node,
                    &ctx,
                    &mut staged_upload,
                    &mut mutation_guards,
                    changed_status,
                    is_miss,
                    is_file,
                    size,
                    allow_upload,
                    allow_delete,
                    &mut res,
                )
                .await?;
            }
            ResourceRoute::Dav => {
                self.dispatch_dav_route(
                    method,
                    path,
                    req_path,
                    capability_path,
                    &mut opened_node,
                    &ctx,
                    &mut request,
                    &mut mutation_guards,
                    prepared_destination.as_deref(),
                    changed_status,
                    caller_capabilities,
                    is_miss,
                    is_dir,
                    is_file,
                    allow_upload,
                    allow_delete,
                    &mut res,
                )
                .await?;
            }
            ResourceRoute::Control => match method {
                ResourceMethod::Options => set_resource_headers(&mut res, caller_capabilities),
                ResourceMethod::Checkauth | ResourceMethod::Logout => {
                    unreachable!("control methods returned before filesystem routing")
                }
                _ => unreachable!("method registry assigned an invalid control route"),
            },
        }
        Ok(res)
    }
}
