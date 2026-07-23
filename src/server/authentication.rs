//! 认证响应与规范授权路径中间件。认证先选择逻辑 ACL 路径，但文件访问始终描述符相对，
//! 已打开对象真实路径必须二次授权；symlink canonicalization 绝不成为访问能力。
//!
//! Authentication-response and canonical authorization-path middleware. Authentication selects a
//! logical ACL path before routing, but filesystem access remains descriptor-relative and every
//! opened object's real path is re-authorized. Symlink canonicalization never becomes an access
//! capability.

use super::*;

impl Server {
    /// 返回不暴露认证细节的有界 401 challenge。 / Return a bounded 401 challenge without exposing auth details.
    pub(super) fn auth_reject(&self, res: &mut Response) -> Result<()> {
        www_authenticate(res, &self.args)?;
        *res.status_mut() = StatusCode::UNAUTHORIZED;
        Ok(())
    }

    /// 显式开启 `allow-symlink` 时，把根内链接的请求路径转成它实际
    /// 指向的根内相对路径，供 ACL 在打开文件**之前**重新授权。
    ///
    /// 待创建文件不能整体 canonicalize，因此逐级回退到最近存在
    /// 祖先，解析它之后再拼回缺失后缀。此结果只用于初次 ACL 选择；
    /// 真正的边界与二次授权由 RootFs 打开的 fd 决定。
    /// With symlinks enabled, canonicalize to the real in-root ACL path before
    /// opening; for absent targets resolve the nearest ancestor. RootFs fd identity remains authoritative.
    pub(super) async fn canonical_authorization_path(&self, relative_path: &str) -> Result<String> {
        if !self.args.allow_symlink {
            return Ok(relative_path.to_string());
        }
        canonicalize_authorization_path(&self.fs_root, &self.args.serve_path, relative_path).await
    }
}

pub(super) async fn canonicalize_authorization_path(
    root: &RootFs,
    served_root: &Path,
    relative_path: &str,
) -> Result<String> {
    let served_root = served_root.to_path_buf();
    let relative_path = relative_path.to_owned();
    root.run_short_blocking(move || {
        canonicalize_authorization_path_sync(&served_root, &relative_path)
    })
    .await
}

/// 整个逐祖先 canonicalize 在一个已准入 worker 内完成，避免每个缺失组件分别向 Tokio
/// blocking queue 提交任务，也确保请求取消后 lease 留到最后一个真实 syscall 返回。
/// Resolve the complete ancestor fallback in one admitted worker, avoiding one Tokio queue entry per
/// missing component and retaining the lease until the final real syscall returns after cancellation.
fn canonicalize_authorization_path_sync(served_root: &Path, relative_path: &str) -> Result<String> {
    let canonical_root = std::fs::canonicalize(served_root).map_err(|error| {
        anyhow::Error::new(FsError::io(
            "canonicalizing the served root for authorization",
            error,
        ))
    })?;
    let mut existing = canonical_root.join(relative_path);
    let mut missing = Vec::new();
    let canonical = loop {
        match std::fs::canonicalize(&existing) {
            Ok(path) => break path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if existing == canonical_root {
                    return Err(anyhow::Error::new(FsError::io(
                        "canonicalizing an authorization path",
                        error,
                    )));
                }
                let name = existing.file_name().map(ToOwned::to_owned).ok_or_else(|| {
                    anyhow::Error::new(FsError::io(
                        "canonicalizing an authorization path",
                        anyhow::anyhow!("missing path component had no basename"),
                    ))
                })?;
                if !existing.pop() || !existing.starts_with(&canonical_root) {
                    return Err(anyhow::Error::new(FsError::outside_root(
                        "canonicalizing an authorization path",
                        anyhow::anyhow!("missing path ancestor escaped the served root"),
                    )));
                }
                missing.push(name);
            }
            Err(error) => {
                // ELOOP 表示客户端所选命名空间条目不可用，而非存储后端故障。与 ENOTDIR
                // 一样归入封闭的冲突类别，使请求边界可统一隐藏，避免坏链接变成公开 500。
                // ELOOP describes an unavailable client-selected namespace entry, not a failed
                // storage backend. Keep it in the same closed conflict class as ENOTDIR so the
                // request boundary can hide both without turning a bad symlink into a public 500.
                let error = if error.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error())
                {
                    FsError::conflict("canonicalizing an authorization path", error)
                } else {
                    FsError::from_anyhow(
                        "canonicalizing an authorization path",
                        anyhow::Error::new(error),
                    )
                };
                return Err(anyhow::Error::new(error));
            }
        }
    };

    let mut resolved = canonical;
    for component in missing.iter().rev() {
        resolved.push(component);
    }
    let resolved = resolved.strip_prefix(&canonical_root).map_err(|_| {
        anyhow::Error::new(FsError::outside_root(
            "canonicalizing an authorization path",
            anyhow::anyhow!("resolved authorization path is outside the served root"),
        ))
    })?;
    // 中文：有损或空回退可能意外选择更宽 ACL。 / English: A lossy or empty fallback could select a broader ACL.
    resolved.to_str().map(ToOwned::to_owned).ok_or_else(|| {
        anyhow::Error::new(FsError::outside_root(
            "canonicalizing an authorization path",
            anyhow::anyhow!("resolved authorization path is not valid UTF-8"),
        ))
    })
}

/// 仅识别请求路由应隐藏为未命中的客户端命名空间状态；后端/运行时故障不在此集合中，继续保留
/// 类型化 500 映射。
/// Return true only for client-selected namespace states that request routing deliberately hides as
/// a miss. Backend/runtime failures remain outside this set and retain their typed 500 mapping.
pub(super) fn canonical_authorization_path_is_unavailable(error: &anyhow::Error) -> bool {
    matches!(
        FsError::in_anyhow_chain(error),
        Some(
            FsError::NotFound { .. }
                | FsError::Forbidden { .. }
                | FsError::Conflict { .. }
                | FsError::OutsideRoot { .. }
        )
    )
}

impl Server {
    /// 每个 HTTP 请求的入口（由 runtime 模块的 `service_fn` 调用）。
    ///
    /// 职责是给 `handle` 包一层"外壳"：
    /// - 记录访问日志（成功与失败都记）；
    /// - 把 `handle` 返回的内部错误兜住，转成 500 响应——所以这个函数
    ///   自身永远返回 `Ok`，连接不会因业务错误而断开；
    /// - 统一补上安全响应头。
    ///
    /// 注意接收者写法 `self: Arc<Self>`：调用方传入的是 Arc 智能指针
    /// 本身（而非 `&self` 借用），因为异步任务需要拥有状态的所有权。
    /// Per-request outer middleware records terminal access logs, maps internal
    /// errors to bounded responses, and applies security headers. Arc ownership supports async task lifetime.
    pub async fn call(
        self: Arc<Self>,
        req: Request,
        peer: PeerIdentity,
    ) -> Result<Response, hyper::Error> {
        let request_started = Instant::now();
        let uri = req.uri().clone();
        let request_method = req.method().clone();
        let mut http_log_data = self.args.http_logger.data(&req);
        http_log_data.insert(
            "request_id".to_string(),
            Uuid::new_v4().simple().to_string(),
        );
        let source = peer.direct_source();
        // 日志和所有按来源预算只使用监听器从内核取得的直连身份。
        http_log_data.insert("remote_addr".to_string(), source.to_string());
        let skip_successful_asset = self.is_embedded_asset_request(uri.path());
        let mut response_context = CallResponseContext {
            request_method,
            http_log_data,
            request_started,
            skip_successful_asset,
        };
        let mut admission = RequestAdmission::default();

        match self.request_source_limit.try_acquire(&source) {
            Ok(Some(permit)) => admission.hold(permit),
            Ok(None) => {
                let res = request_admission_rejection(AdmissionError::queue_full(
                    AdmissionResource::Requests,
                    QueueScope::PerSource,
                    self.args.max_concurrent_requests_per_source,
                ));
                return Ok(self.finish_call_response(
                    res,
                    Some("per-source request admission limit reached".to_string()),
                    admission,
                    response_context,
                ));
            }
            Err(error) => {
                let res = request_admission_rejection(AdmissionError::cancelled(
                    AdmissionResource::Requests,
                ));
                return Ok(self.finish_call_response(
                    res,
                    Some(error.to_string()),
                    admission,
                    response_context,
                ));
            }
        }

        match self.request_limit.clone().try_acquire_owned() {
            Ok(permit) => admission.hold(permit),
            Err(_) => {
                let queue_permit = match self.request_queue_limit.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        let res = request_admission_rejection(AdmissionError::queue_full(
                            AdmissionResource::Requests,
                            QueueScope::Global,
                            self.args.max_request_queue,
                        ));
                        return Ok(self.finish_call_response(
                            res,
                            Some("global request admission queue is full".to_string()),
                            admission,
                            response_context,
                        ));
                    }
                };
                let waited = Duration::from_secs(self.args.request_queue_timeout);
                let acquired =
                    tokio::time::timeout(waited, self.request_limit.clone().acquire_owned()).await;
                drop(queue_permit);
                match acquired {
                    Ok(Ok(permit)) => admission.hold(permit),
                    Ok(Err(_)) => {
                        let res = request_admission_rejection(AdmissionError::cancelled(
                            AdmissionResource::Requests,
                        ));
                        return Ok(self.finish_call_response(
                            res,
                            Some("request admission closed during shutdown".to_string()),
                            admission,
                            response_context,
                        ));
                    }
                    Err(_) => {
                        let res = request_admission_rejection(AdmissionError::queue_timeout(
                            AdmissionResource::Requests,
                            QueueScope::Global,
                            waited,
                        ));
                        return Ok(self.finish_call_response(
                            res,
                            Some("global request admission queue timed out".to_string()),
                            admission,
                            response_context,
                        ));
                    }
                }
            }
        }

        let (res, handler_error) = match self.clone().handle(req, source, &mut admission).await {
            Ok(res) => {
                if let Some(user) = res.extensions().get::<AuthenticatedUser>() {
                    self.args
                        .http_logger
                        .set_authenticated_user(&mut response_context.http_log_data, &user.0);
                }
                (res, None)
            }
            Err(err) => {
                let mut res = Response::default();
                apply_anyhow_or_internal(&mut res, &err, ChangedStatus::Conflict);
                // 中文：终态日志保留 anyhow 完整因果链；公开响应只用审阅过的类型映射，原始失败固定无细节 500。
                // English: Logs retain the cause chain; public responses use reviewed typed mappings or a fixed detail-free 500.
                (res, Some(format!("{err:#}")))
            }
        };
        Ok(self.finish_call_response(res, handler_error, admission, response_context))
    }

    fn finish_call_response(
        &self,
        mut res: Response,
        handler_error: Option<String>,
        admission: RequestAdmission,
        context: CallResponseContext,
    ) -> Response {
        if res.extensions().get::<AuthenticatedUser>().is_some()
            && !res.headers().contains_key("cache-control")
        {
            // 中文：认证下载只允许用户私有缓存且必须 revalidate；敏感动态/API handler 自行设更严 private,no-store。
            // English: Authenticated downloads are private/revalidated; sensitive dynamic/API handlers set private,no-store.
            res.headers_mut()
                .typed_insert(CacheControl::new().with_private().with_no_cache());
        }

        add_security_headers(&mut res);
        observe_response_completion(
            &mut res,
            &context.request_method,
            admission.into_permits(),
            self.args.http_logger.clone(),
            context.http_log_data,
            context.request_started,
            context.request_started.elapsed(),
            handler_error,
            context.skip_successful_asset,
        );
        res
    }

    pub(super) fn acquire_account_request(
        &self,
        user: &str,
        admission: &mut RequestAdmission,
        response: &mut Response,
    ) -> bool {
        match self.request_user_limit.try_acquire(&user.to_owned()) {
            Ok(Some(permit)) => {
                admission.hold(permit);
                true
            }
            Ok(None) => {
                ResponseError::admission(AdmissionError::queue_full(
                    AdmissionResource::Requests,
                    QueueScope::PerAccount,
                    self.args.max_concurrent_requests_per_user,
                ))
                .apply(response);
                false
            }
            Err(error) => {
                warn!("Authenticated-account admission state failed: {error}");
                ResponseError::admission(AdmissionError::cancelled(AdmissionResource::Requests))
                    .apply(response);
                false
            }
        }
    }
}
