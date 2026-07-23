//! 针对已打开文件/目录能力的 GET/HEAD 分派。调用方已完成规范化和授权；这里不重新
//! 打开不可信绝对路径，并持续使用路由器选择的描述符支持对象。
//!
//! Authenticated GET/HEAD dispatch for opened file and directory capabilities. The caller has
//! already normalized and authorized the path. These helpers never reopen an untrusted absolute
//! path and continue using the descriptor-backed `OpenedNode` selected by the router.

use super::*;

impl Server {
    /// 在路由器已完成逻辑 ACL 与描述符真实路径二次 ACL 后分派 GET/HEAD。
    /// `opened_target` 是一次性能力：文件路径或 SPA 索引分支会 `take` 并把同一 fd 交给
    /// metadata、条件请求、Range 与响应流，目录路径则保留由 `RootFs` 打开的根能力。
    ///
    /// Dispatch GET/HEAD after both logical-path and descriptor-real-path ACL checks. The
    /// `opened_target` option is a single-use capability: file and SPA-index branches take the same
    /// fd through metadata, preconditions, Range, and streaming, while directory branches continue
    /// from the pinned `RootFs` capability.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn dispatch_read_route(
        &self,
        method: ResourceMethod,
        path: &Path,
        req_path: &str,
        spa_fallback: bool,
        opened_target: &mut Option<OpenedRequestTarget>,
        ctx: &RequestContext<'_>,
        target: ResourceTarget,
        allow_upload: bool,
        res: &mut Response,
    ) -> Result<()> {
        debug_assert_eq!(method.route(), ResourceRoute::Read);
        debug_assert!(matches!(method, ResourceMethod::Get | ResourceMethod::Head));
        if spa_fallback {
            if let Some(opened) = opened_target.take().filter(|opened| {
                opened.metadata.is_file()
                    && ctx.allows_actual(&opened.real_rel, &ctx.authorization_method)
            }) {
                let index_path = self.args.serve_path.join("index.html");
                self.handle_send_trusted_opened_cap_file(
                    opened.into_inner(),
                    &index_path,
                    ctx,
                    res,
                )
                .await?;
            } else {
                self.handle_not_found(ctx, res).await?;
            }
        } else {
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
        }
        Ok(())
    }

    /// GET/HEAD 访问一个已存在的目录：可能是 `?zip` 打包下载、`?q` 搜索、
    /// index 页渲染（`--render-*` 系列开关）、或普通的目录列表。
    ///
    /// 注意几种模式的差异是**有意**保留的：
    /// - `--render-try-index` 下，`?zip` 请求在未开 `--allow-archive` 时
    ///   回退到渲染 index 页；
    /// - 无任何 render 模式时，同样的请求则回 404；
    /// - `--render-index`/`--render-spa` 完全忽略 `?zip`/`?q` 参数。
    ///
    /// Handle GET/HEAD for an existing directory: ZIP, search, configured
    /// index rendering, or a normal listing. The documented render-mode
    /// differences are intentional and must remain stable.
    pub(super) async fn handle_get_dir(
        &self,
        path: &Path,
        ctx: &RequestContext<'_>,
        res: &mut Response,
    ) -> Result<()> {
        let allow_search = self.args.allow_search;
        let allow_archive = self.args.allow_archive;
        if self.args.render_try_index {
            if allow_archive && has_query_flag(&ctx.query_params, "zip") {
                self.handle_zip_dir(path, ctx, res).await?;
            } else if allow_search && ctx.query_params.contains_key("q") {
                self.handle_search_dir(path, ctx, res).await?;
            } else {
                self.handle_render_index(path, ctx, res).await?;
            }
        } else if self.args.render_index || self.args.render_spa {
            self.handle_render_index(path, ctx, res).await?;
        } else if has_query_flag(&ctx.query_params, "zip") {
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

    /// GET/HEAD 访问已存在文件：`?json`（元数据）、`?edit`、`?view`、`?hash`
    /// 等视图，或默认下载。 / Handle GET/HEAD for an existing file: metadata,
    /// edit/view/hash views, or the default download.
    pub(super) async fn handle_get_file(
        &self,
        path: &Path,
        opened: OpenedNode,
        ctx: &RequestContext<'_>,
        res: &mut Response,
    ) -> Result<()> {
        if has_query_flag(&ctx.query_params, "json") {
            self.handle_file_json(path, opened, ctx, res).await?;
        } else if has_query_flag(&ctx.query_params, "edit") {
            self.handle_edit_file(path, opened, DataKind::Edit, ctx, res)
                .await?;
        } else if has_query_flag(&ctx.query_params, "view") {
            self.handle_edit_file(path, opened, DataKind::View, ctx, res)
                .await?;
        } else if has_query_flag(&ctx.query_params, "hash") {
            if self.args.allow_hash {
                self.handle_hash_file(opened, ctx, res).await?;
            } else {
                status_forbid(res);
            }
        } else {
            self.handle_send_opened_cap_file(opened, path, ctx, res)
                .await?;
        }
        Ok(())
    }
}
