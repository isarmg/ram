//! 针对已打开文件/目录能力的 GET/HEAD 分派。调用方已完成规范化和授权；这里不重新
//! 打开不可信绝对路径，并持续使用路由器选择的描述符支持对象。
//!
//! Authenticated GET/HEAD dispatch for opened file and directory capabilities. The caller has
//! already normalized and authorized the path. These helpers never reopen an untrusted absolute
//! path and continue using the descriptor-backed `OpenedNode` selected by the router.

use super::*;

impl Server {
    /// 在路由器已完成逻辑 ACL 与描述符真实路径二次 ACL 后分派 GET/HEAD。
    /// `opened_target` 是一次性能力：文件路径会 `take` 并把同一 fd 交给 metadata、
    /// 条件请求、Range 与响应流，目录路径则保留由 `RootFs` 打开的根能力。
    ///
    /// Dispatch GET/HEAD after both logical-path and descriptor-real-path ACL checks. The
    /// `opened_target` option is a single-use capability: file branches take the same fd through
    /// metadata, preconditions, Range, and streaming, while directory branches continue from the
    /// pinned `RootFs` capability.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn dispatch_read_route(
        &self,
        method: ResourceMethod,
        path: &Path,
        req_path: &str,
        opened_target: &mut Option<OpenedRequestTarget>,
        ctx: &RequestContext<'_>,
        target: ResourceTarget,
        allow_upload: bool,
        res: &mut Response,
    ) -> Result<()> {
        debug_assert_eq!(method.route(), ResourceRoute::Read);
        debug_assert!(matches!(method, ResourceMethod::Get | ResourceMethod::Head));
        match target {
            ResourceTarget::RootCollection | ResourceTarget::Collection => {
                self.handle_get_dir(path, ctx, res).await?;
            }
            ResourceTarget::EmptyFile | ResourceTarget::File => {
                let opened = opened_target
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("opened file capability disappeared"))?;
                self.handle_get_file(path, opened.into_inner(), ctx, res)
                    .await?;
            }
            ResourceTarget::Missing if allow_upload && req_path.ends_with('/') => {
                self.handle_ls_dir(path, false, ctx, res).await?;
            }
            ResourceTarget::Missing | ResourceTarget::Other => {
                self.handle_not_found(ctx, res).await?;
            }
            ResourceTarget::SingleFile => {
                unreachable!("single-file requests return before generic read dispatch")
            }
        }
        Ok(())
    }

    /// GET/HEAD 访问目录：按需打包、搜索，或返回普通目录列表。
    pub(super) async fn handle_get_dir(
        &self,
        path: &Path,
        ctx: &RequestContext<'_>,
        res: &mut Response,
    ) -> Result<()> {
        let allow_search = self.args.allow_search;
        let allow_archive = self.args.allow_archive;
        if has_query_flag(&ctx.query_params, "zip") {
            if !allow_archive {
                status_not_found(res);
                return Ok(());
            }
            self.handle_zip_dir(path, ctx, res).await?;
        } else if allow_search && ctx.query_params.contains_key("q") {
            self.handle_search_dir(path, ctx, res).await?;
        } else {
            self.handle_ls_dir(path, true, ctx, res).await?;
        }
        Ok(())
    }

    /// GET/HEAD 访问已存在文件：只读查看或默认下载。
    pub(super) async fn handle_get_file(
        &self,
        path: &Path,
        opened: OpenedNode,
        ctx: &RequestContext<'_>,
        res: &mut Response,
    ) -> Result<()> {
        if has_query_flag(&ctx.query_params, "view") {
            self.handle_view_file(path, opened, ctx, res).await?;
        } else {
            self.handle_send_opened_cap_file(opened, path, ctx, res)
                .await?;
        }
        Ok(())
    }
}
