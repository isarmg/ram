//! 已认证 WebDAV 路由分派。路由器在有界正文和锁准入下准备源描述符与目标路径；
//! 本模块只负责方法语义，不重复声明 HTTP 线名或能力策略。
//!
//! Authenticated WebDAV route dispatch. Source descriptors and destination paths are prepared by
//! the router under bounded request-body and lock admission. This module owns the method-level DAV
//! semantics without duplicating HTTP wire names or capability policy.

use super::*;

impl Server {
    /// 分派已经完整准备的 DAV 事务。PROPFIND/PROPPATCH 只消费有界 XML 正文；MKCOL/COPY/MOVE
    /// 还必须取得路由器预先排序的路径锁集合。源描述符、正文和 guard 都用 `Option::take`
    /// 转移给唯一分支，使前置条件失败或能力拒绝时不会意外启动 worker，也不会重用事务资源。
    ///
    /// Dispatch a fully prepared DAV transaction. PROPFIND/PROPPATCH consume only their bounded XML
    /// body; MKCOL/COPY/MOVE also require the router's deterministically ordered path-lock set.
    /// Source descriptors, bodies, and guards move through `Option::take` into one branch, preventing
    /// worker launch on precondition/capability failure and preventing transaction-resource reuse.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn dispatch_dav_route(
        &self,
        method: ResourceMethod,
        path: &Path,
        req_path: &str,
        capability_path: &Path,
        opened_target: &mut Option<OpenedRequestTarget>,
        ctx: &RequestContext<'_>,
        request: &mut Option<Request>,
        mutation_guards: &mut Option<MutationGuards>,
        prepared_destination: Option<&Path>,
        changed_status: ChangedStatus,
        caller_capabilities: ResourceCapabilities,
        is_miss: bool,
        is_dir: bool,
        is_file: bool,
        allow_upload: bool,
        allow_delete: bool,
        res: &mut Response,
    ) -> Result<()> {
        debug_assert_eq!(method.route(), ResourceRoute::Dav);
        match method {
            ResourceMethod::Propfind => {
                let request = request
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("PROPFIND request body was already consumed"))?;
                if is_dir {
                    let opened = opened_target.take().ok_or_else(|| {
                        anyhow::anyhow!("opened directory capability disappeared")
                    })?;
                    self.handle_propfind_dir(request, path, opened.into_inner(), ctx, res)
                        .await?;
                } else if is_file {
                    let opened = opened_target
                        .take()
                        .ok_or_else(|| anyhow::anyhow!("opened file capability disappeared"))?;
                    self.handle_propfind_file(request, path, opened.into_inner(), ctx, res)
                        .await?;
                } else {
                    status_not_found(res);
                }
            }
            ResourceMethod::Proppatch => {
                if write_precondition_passes(
                    opened_target.as_mut().map(OpenedRequestTarget::as_node_mut),
                    &ctx.preconditions,
                    res,
                )
                .await?
                {
                    if is_file || is_dir {
                        self.handle_proppatch(
                            request.take().ok_or_else(|| {
                                anyhow::anyhow!("PROPPATCH request body was already consumed")
                            })?,
                            req_path,
                            res,
                        )
                        .await?;
                    } else {
                        status_not_found(res);
                    }
                }
            }
            ResourceMethod::Mkcol => {
                if !allow_upload {
                    status_forbid(res);
                } else if write_precondition_passes(
                    opened_target.as_mut().map(OpenedRequestTarget::as_node_mut),
                    &ctx.preconditions,
                    res,
                )
                .await?
                {
                    if !is_miss {
                        status_resource_method_not_allowed(res, caller_capabilities);
                        *res.body_mut() = body_full("Already exists");
                    } else {
                        self.handle_mkcol(
                            capability_path,
                            mutation_guards.take().ok_or_else(|| {
                                anyhow::anyhow!("MKCOL mutation lock was not held")
                            })?,
                            changed_status,
                            res,
                        )
                        .await?;
                    }
                }
            }
            ResourceMethod::Copy => {
                if !allow_upload {
                    status_forbid(res);
                } else if write_precondition_passes(
                    opened_target.as_mut().map(OpenedRequestTarget::as_node_mut),
                    &ctx.preconditions,
                    res,
                )
                .await?
                {
                    if is_miss {
                        status_not_found(res);
                    } else {
                        let destination = prepared_destination
                            .ok_or_else(|| anyhow::anyhow!("COPY destination was not prepared"))?;
                        self.handle_copy(
                            opened_target
                                .take()
                                .map(OpenedRequestTarget::into_inner)
                                .ok_or_else(|| {
                                    anyhow::anyhow!("COPY source capability disappeared")
                                })?,
                            destination,
                            ctx.headers,
                            ctx.user.as_deref(),
                            mutation_guards.take().ok_or_else(|| {
                                anyhow::anyhow!("COPY mutation locks were not held")
                            })?,
                            changed_status,
                            res,
                        )
                        .await?;
                    }
                }
            }
            ResourceMethod::Move => {
                if !allow_upload || !allow_delete {
                    status_forbid(res);
                } else if write_precondition_passes(
                    opened_target.as_mut().map(OpenedRequestTarget::as_node_mut),
                    &ctx.preconditions,
                    res,
                )
                .await?
                {
                    if is_miss {
                        status_not_found(res);
                    } else {
                        let destination = prepared_destination
                            .ok_or_else(|| anyhow::anyhow!("MOVE destination was not prepared"))?;
                        self.handle_move(
                            capability_path,
                            opened_target
                                .take()
                                .map(OpenedRequestTarget::into_inner)
                                .ok_or_else(|| {
                                    anyhow::anyhow!("MOVE source capability disappeared")
                                })?,
                            destination,
                            ctx.headers,
                            ctx.user.as_deref(),
                            mutation_guards.take().ok_or_else(|| {
                                anyhow::anyhow!("MOVE mutation locks were not held")
                            })?,
                            changed_status,
                            res,
                        )
                        .await?;
                    }
                }
            }
            _ => unreachable!("DAV route received a non-DAV method"),
        }
        Ok(())
    }
}
