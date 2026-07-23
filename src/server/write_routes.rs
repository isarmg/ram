//! 已认证 PUT、DELETE、MKCOL 与 MOVE 路由分派。上传正文先暂存，最终事务持锁后针对已打开
//! 描述符重新校验，因此乐观探测不能授权最终发布。
//!
//! Authenticated PUT, DELETE, MKCOL, and MOVE route dispatch. Upload bodies are staged before this module
//! is entered. Every mutation is revalidated against the descriptor opened while its transaction
//! lock is held, so an optimistic probe can never authorize the final publication.

use super::*;
use crate::http::IncomingStream;
use futures_util::StreamExt;

const MKCOL_BODY_TIMEOUT: Duration = Duration::from_secs(5);

/// 基础 MKCOL 不接受请求实体。读取到第一个非空数据块即返回 415；空分块编码正文允许通过。
/// Base MKCOL accepts no request entity. The first non-empty data chunk yields 415, while an empty
/// chunked body is accepted.
pub(super) async fn validate_mkcol_empty_body(req: Request, res: &mut Response) -> bool {
    if req
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > 0)
    {
        *res.status_mut() = StatusCode::UNSUPPORTED_MEDIA_TYPE;
        *res.body_mut() = body_full("MKCOL request entities are not supported");
        return false;
    }

    let read = async move {
        let mut stream = IncomingStream::new(req.into_body());
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(chunk) if chunk.is_empty() => {}
                Ok(_) => return Ok::<_, anyhow::Error>(false),
                Err(error) => return Err(error),
            }
        }
        Ok(true)
    };
    match tokio::time::timeout(MKCOL_BODY_TIMEOUT, read).await {
        Ok(Ok(true)) => true,
        Ok(Ok(false)) => {
            *res.status_mut() = StatusCode::UNSUPPORTED_MEDIA_TYPE;
            *res.body_mut() = body_full("MKCOL request entities are not supported");
            false
        }
        Ok(Err(error)) => {
            warn!("Invalid MKCOL request transport: {error:#}");
            status_bad_request(res, "Invalid MKCOL request body");
            false
        }
        Err(_) => {
            *res.status_mut() = StatusCode::REQUEST_TIMEOUT;
            *res.body_mut() = body_full("MKCOL request body timed out");
            false
        }
    }
}

impl Server {
    /// 消费路由器准备的一次性写事务资源。PUT 正文已在锁外进入私有候选文件；
    /// `mutation_guards` 同时拥有全部路径锁与变更活动 guard，并随最终阻塞 worker 存活。
    /// 对这些 `Option` 使用 `take` 可在类型层面阻止同一正文、fd 或锁被二次提交。
    ///
    /// Consume single-use write-transaction resources prepared by the router. PUT bodies are
    /// already staged into private candidates outside the lock; `mutation_guards` owns every path
    /// lock plus the mutation-activity guard for the real blocking worker's lifetime. Taking these
    /// options prevents a body, fd, or lock set from being committed twice.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn dispatch_write_route(
        &self,
        method: ResourceMethod,
        capability_path: &Path,
        opened_target: &mut Option<OpenedRequestTarget>,
        ctx: &RequestContext<'_>,
        staged_upload: &mut Option<StagedUpload>,
        mutation_guards: &mut Option<MutationGuards>,
        prepared_destination: Option<&Path>,
        changed_status: ChangedStatus,
        caller_capabilities: ResourceCapabilities,
        is_miss: bool,
        is_file: bool,
        size: u64,
        allow_upload: bool,
        allow_delete: bool,
        res: &mut Response,
    ) -> Result<()> {
        debug_assert_eq!(method.route(), ResourceRoute::Write);
        match method {
            ResourceMethod::Put => {
                // 中文：替换非空文件会移除旧内容，因此除上传外还需要删除权限。
                // English: Replacing a non-empty file removes old contents and therefore requires delete as well as upload permission.
                if (!is_miss && !is_file) || !allow_upload || (!allow_delete && size > 0) {
                    status_forbid(res);
                } else if write_precondition_passes(
                    opened_target.as_mut().map(OpenedRequestTarget::as_node_mut),
                    &ctx.preconditions,
                    res,
                )
                .await?
                {
                    let staged = staged_upload
                        .take()
                        .ok_or_else(|| anyhow::anyhow!("PUT body was not staged"))?;
                    self.handle_upload(
                        capability_path,
                        UploadCommit {
                            original: opened_target.take().map(OpenedRequestTarget::into_inner),
                            staged,
                            mutation_guards: mutation_guards
                                .take()
                                .ok_or_else(|| anyhow::anyhow!("PUT mutation lock was not held"))?,
                            changed_status,
                        },
                        res,
                    )
                    .await?;
                }
            }
            ResourceMethod::Delete => {
                if !allow_delete {
                    status_forbid(res);
                } else if !write_precondition_passes(
                    opened_target.as_mut().map(OpenedRequestTarget::as_node_mut),
                    &ctx.preconditions,
                    res,
                )
                .await?
                {
                    // 中文：前置条件失败，目标保持不变。 / English: Preconditions failed; the target remains untouched.
                } else if is_miss {
                    status_not_found(res);
                } else {
                    self.handle_delete(
                        capability_path,
                        opened_target
                            .take()
                            .map(OpenedRequestTarget::into_inner)
                            .ok_or_else(|| {
                                anyhow::anyhow!("DELETE target capability disappeared")
                            })?,
                        mutation_guards
                            .take()
                            .ok_or_else(|| anyhow::anyhow!("DELETE mutation lock was not held"))?,
                        changed_status,
                        res,
                    )
                    .await?;
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
            _ => unreachable!("write route received a non-write method"),
        }
        Ok(())
    }
}
