//! 已认证 PUT、PATCH 与 DELETE 路由分派。上传正文先暂存，最终事务持锁后针对已打开
//! 描述符重新校验，因此乐观探测不能授权最终发布。
//!
//! Authenticated PUT, PATCH, and DELETE route dispatch. Upload bodies are staged before this module
//! is entered. Every mutation is revalidated against the descriptor opened while its transaction
//! lock is held, so an optimistic probe can never authorize the final publication.

use super::*;

impl Server {
    /// 消费路由器准备的一次性写事务资源。PUT/PATCH 正文已在锁外进入私有候选文件；
    /// `mutation_guards` 同时拥有全部路径锁与变更活动 guard，并随最终阻塞 worker 存活。
    /// 对这些 `Option` 使用 `take` 可在类型层面阻止同一正文、fd 或锁被二次提交。
    ///
    /// Consume single-use write-transaction resources prepared by the router. PUT/PATCH bodies are
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
        changed_status: ChangedStatus,
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
                            upload_offset: None,
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
            ResourceMethod::Patch => {
                if !allow_upload {
                    status_forbid(res);
                } else if !write_precondition_passes(
                    opened_target.as_mut().map(OpenedRequestTarget::as_node_mut),
                    &ctx.preconditions,
                    res,
                )
                .await?
                {
                    // 中文：请求暂存期间所选表示已变化，必须保持它不变。
                    // English: The selected representation changed during staging; leave it untouched.
                } else if is_miss {
                    status_not_found(res);
                } else if !is_file {
                    status_forbid(res);
                } else {
                    let offset = match parse_upload_offset(ctx.headers, size) {
                        Ok(Some(offset)) => offset,
                        Ok(None) => {
                            status_bad_request(res, "Missing X-Update-Range header");
                            return Ok(());
                        }
                        Err(error) => {
                            warn!("Rejected invalid X-Update-Range header: {error:#}");
                            status_bad_request(res, "Invalid X-Update-Range header");
                            return Ok(());
                        }
                    };
                    // 中文：原位范围会覆盖旧字节；仅追加 PATCH 不需要删除权限。
                    // English: An in-place range overwrites bytes; append-only PATCH does not require delete permission.
                    if offset < size && !allow_delete {
                        status_forbid(res);
                        return Ok(());
                    }
                    self.handle_upload(
                        capability_path,
                        UploadCommit {
                            upload_offset: Some(offset),
                            original: Some(
                                opened_target
                                    .take()
                                    .map(OpenedRequestTarget::into_inner)
                                    .ok_or_else(|| {
                                        anyhow::anyhow!(
                                            "PATCH source capability disappeared before commit"
                                        )
                                    })?,
                            ),
                            staged: staged_upload
                                .take()
                                .ok_or_else(|| anyhow::anyhow!("PATCH body was not staged"))?,
                            mutation_guards: mutation_guards.take().ok_or_else(|| {
                                anyhow::anyhow!("PATCH mutation lock was not held")
                            })?,
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
            _ => unreachable!("write route received a non-write method"),
        }
        Ok(())
    }
}
