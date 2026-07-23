//! 目录浏览：目录列表、文件名搜索、index 页渲染
//! （`--render-index`/`--render-try-index`/`--render-spa`）、404 错误页，
//! 以及把文件系统条目转换成 [`PathItem`] 视图模型。
//!
//! ## 本模块的 Rust 知识点
//! - **`spawn_blocking`**：基于 dirfd 的目录树遍历是同步（阻塞）IO，
//!   不能占用异步工作线程，所以丢到专门的阻塞线程池。
//!   注意闭包是 `move` 的——所有数据必须转移所有权或用 `Arc` 共享。
//! - **装饰-排序-还原（decorate-sort-undecorate）**：`sort_paths_by_name`
//!   先为每项算一次小写键再排序，避免比较器里重复分配字符串。
//! - **`StreamExt::buffered`**：目录条目的元数据读取按固定窗口并发，
//!   既降低大目录延迟，也避免无界任务把磁盘或 Tokio 阻塞池打满。
//!
//! Directory browsing: directory listings, filename search, index-page rendering
//! (`--render-index`/`--render-try-index`/`--render-spa`), 404 pages, and conversion of filesystem
//! entries into the [`PathItem`] view model.
//!
//! ## Rust concepts in this module
//! - **`spawn_blocking`**: dirfd-based directory-tree traversal is synchronous (blocking) I/O and
//!   must not occupy an async worker thread, so it runs in the dedicated blocking pool. Its closure
//!   is `move`, requiring every value to transfer ownership or be shared with `Arc`.
//! - **Decorate-sort-undecorate**: `sort_paths_by_name` computes one lowercase key per item before
//!   sorting, avoiding repeated allocation inside the comparator.
//! - **`StreamExt::buffered`**: directory-entry metadata reads use a fixed concurrency window,
//!   reducing large-directory latency without unbounded tasks saturating the disk or Tokio's
//!   blocking pool.

use super::content::{
    OpenFileResponseOptions, apply_generated_preconditions, apply_read_precondition_outcome,
};
use super::error::{
    AdmissionError, AdmissionResource, ChangedStatus, FsError, QueueScope, ResponseError,
};
use super::filesystem::{NodeKind, validate_opened_trusted_asset};
use super::model::{DataKind, IndexData, PathItem, PathType};
use super::mutation_version::MUTATION_VERSION_HEADER;
use super::preconditions::{ParsedPreconditions, ReadPreconditionOutcome};
use super::reply::{set_content_disposition, status_not_found};
use super::security_headers::add_management_ui_csp;
use super::walk::{
    CapabilityWalkAction, RequestCancellation, is_blocking_deadline,
    run_guarded_cancellable_blocking, walk_dir_entries,
};
use super::{
    OpenErrorPolicy, RequestContext, Response, Server, classify_open_result, has_query_flag,
    is_internal_temp_name, normalize_path, to_timestamp,
};
use crate::http::body_full;
use crate::utils::get_file_name;

use anyhow::{Result, anyhow};
use headers::{CacheControl, ContentLength, ContentType, HeaderMapExt};
use hyper::{StatusCode, header::HeaderValue};
use std::cmp::Ordering;
use std::path::{Path, PathBuf};
use std::time::Duration;

const INDEX_NAME: &str = "index.html";
#[derive(Clone)]
struct ListingOptions {
    exist: bool,
    content_length_known: bool,
    representation_complete: bool,
    truncated: bool,
    omitted_non_utf8: bool,
    /// 仅在扫描两端都确认全局变更状态静止时存在。
    /// Present only when both ends of the scan prove globally quiescent mutation state.
    mutation_version: Option<String>,
}

pub(super) struct DirectoryListing {
    pub(super) paths: Vec<PathItem>,
    pub(super) truncated: bool,
    pub(super) omitted_non_utf8: bool,
}

impl Server {
    /// 普通目录列表（`GET /some/dir/`）。
    /// `exist` 为 false 时表示目录不存在但仍渲染空列表页
    /// （用于"可上传但尚未创建"的目录）。
    /// Render a normal listing; an absent but uploadable directory is shown as an empty not-yet-created page.
    pub(super) async fn handle_ls_dir(
        &self,
        path: &Path,
        exist: bool,
        ctx: &RequestContext<'_>,
        res: &mut Response,
    ) -> Result<()> {
        let mut paths = vec![];
        let mut truncated = false;
        let mut omitted_non_utf8 = false;
        let head_outcome = ctx
            .head_only
            .then(|| ctx.preconditions.evaluate_generated_head_without_body())
            .flatten();
        let representation_complete = !ctx.head_only || head_outcome.is_none();
        if let Some(outcome) = head_outcome
            && outcome != ReadPreconditionOutcome::Proceed
        {
            res.headers_mut()
                .typed_insert(CacheControl::new().with_private().with_no_store());
            apply_read_precondition_outcome(outcome, res);
            return Ok(());
        }
        // 快照起点故意位于实际扫描之前。等待昂贵任务准入也包含在稳定窗口内：这会保守
        // 省略令牌，却绝不会给跨越变更的列表错误签名，且不进行可能饥饿的重试。
        // The snapshot deliberately starts before the real scan. Expensive-task admission wait is
        // part of the stability window: this may conservatively omit a token, but never signs a
        // listing spanning a mutation and never retries into starvation.
        let mutation_scan = (exist && representation_complete)
            .then(|| self.mutation_versions.begin_scan())
            .flatten();
        if exist && representation_complete {
            let listing = match self.list_dir(path, path, ctx, None).await {
                Ok(listing) => listing,
                Err(error) => {
                    if error.status().is_server_error() {
                        warn!("Directory listing response failed: error={error:#}");
                    } else {
                        debug!("Directory listing rejected: error={error:#}");
                    }
                    error.apply(res);
                    return Ok(());
                }
            };
            paths = listing.paths;
            truncated = listing.truncated;
            omitted_non_utf8 = listing.omitted_non_utf8;
        }
        let mutation_version =
            mutation_scan.and_then(|snapshot| self.mutation_versions.finish_scan(snapshot));
        self.send_index(
            path,
            paths,
            ctx,
            ListingOptions {
                exist,
                content_length_known: representation_complete,
                representation_complete,
                truncated,
                omitted_non_utf8,
                mutation_version,
            },
            res,
        )
    }

    /// 文件名搜索（`GET /some/dir/?q=关键词`）：
    /// 在阻塞线程池里递归遍历目录树，按小写子串匹配文件名。
    /// Search recursively on the blocking pool using case-folded substring matching.
    pub(super) async fn handle_search_dir(
        &self,
        path: &Path,
        ctx: &RequestContext<'_>,
        res: &mut Response,
    ) -> Result<()> {
        let mut paths: Vec<PathItem> = vec![];
        let mut truncated = false;
        let mut omitted_non_utf8 = false;
        let search = ctx
            .query_params
            .get("q")
            .ok_or_else(|| anyhow!("invalid q"))?
            .to_lowercase();
        if search.is_empty() {
            return self.handle_ls_dir(path, true, ctx, res).await;
        }

        let head_outcome = ctx
            .head_only
            .then(|| ctx.preconditions.evaluate_generated_head_without_body())
            .flatten();
        let representation_complete = !ctx.head_only || head_outcome.is_none();
        if let Some(outcome) = head_outcome
            && outcome != ReadPreconditionOutcome::Proceed
        {
            res.headers_mut()
                .typed_insert(CacheControl::new().with_private().with_no_store());
            apply_read_precondition_outcome(outcome, res);
            return Ok(());
        }

        let mutation_scan = representation_complete
            .then(|| self.mutation_versions.begin_scan())
            .flatten();
        if representation_complete {
            // 搜索会遍历整棵目录树并做大量 metadata IO，与
            // hash/zip 共用有界的“昂贵任务”配额，避免多个
            // 请求同时打满磁盘和 blocking pool。
            // English: Search shares bounded expensive-task admission with hash/ZIP to prevent concurrent disk/blocking-pool exhaustion.
            let operation_timeout = Duration::from_secs(self.args.expensive_task_timeout);
            let deadline = tokio::time::Instant::now() + operation_timeout;
            let permit = match tokio::time::timeout_at(
                deadline,
                self.expensive_task_limit.clone().acquire_owned(),
            )
            .await
            {
                Ok(Ok(permit)) => permit,
                Err(_) => {
                    let error = ResponseError::admission(AdmissionError::queue_timeout(
                        AdmissionResource::ExpensiveTasks,
                        QueueScope::WorkerPool,
                        operation_timeout,
                    ));
                    warn!("Search admission failed: error={error:#}");
                    error.apply(res);
                    return Ok(());
                }
                Ok(Err(_)) => {
                    let error = ResponseError::admission(AdmissionError::cancelled(
                        AdmissionResource::ExpensiveTasks,
                    ));
                    warn!("Search admission failed: error={error:#}");
                    error.apply(res);
                    return Ok(());
                }
            };
            // spawn_blocking 的闭包要求 'static（可能比本函数活得久），
            // 所以先把需要的数据克隆成拥有所有权的副本；
            // hidden/running 是 Arc，克隆只是引用计数 +1，很廉价。
            // English: `spawn_blocking` requires owned `'static` data; clone values, while Arc clones only increment reference counts.
            let base_rel = PathBuf::from(&ctx.authorization_path);
            let hidden = self.hidden.clone();
            let search_access_paths = ctx.access_paths.clone();
            let running = self.running.clone();
            let fs_root = self.fs_root.clone();
            let max_walk_entries = self.args.max_walk_entries as usize;
            let max_walk_depth = self.args.max_walk_depth as usize;
            let max_search_results = self.args.max_search_results as usize;

            let search_result = run_guarded_cancellable_blocking(
                deadline,
                self.running.clone(),
                permit,
                move |cancellation: RequestCancellation| {
                    let mut paths = Vec::new();
                    let mut result_limit_hit = false;
                    let mut path_error = None;
                    let walk_result = walk_dir_entries(
                        fs_root,
                        search_access_paths,
                        running,
                        cancellation,
                        max_walk_entries,
                        max_walk_depth,
                        base_rel.clone(),
                        hidden,
                        |entry| {
                            let Some(entry_name) = entry.name.to_str() else {
                                omitted_non_utf8 = true;
                                return if entry.metadata.is_dir() {
                                    CapabilityWalkAction::SkipDirectory
                                } else {
                                    CapabilityWalkAction::Continue
                                };
                            };
                            if entry.display_rel.to_str().is_none()
                                || entry.real_rel.to_str().is_none()
                            {
                                omitted_non_utf8 = true;
                                return if entry.metadata.is_dir() {
                                    CapabilityWalkAction::SkipDirectory
                                } else {
                                    CapabilityWalkAction::Continue
                                };
                            }
                            let name_matches = entry_name.to_lowercase().contains(&search);
                            if !name_matches {
                                return CapabilityWalkAction::Continue;
                            }
                            if paths.len() >= max_search_results {
                                result_limit_hit = true;
                                return CapabilityWalkAction::Stop;
                            }
                            let is_dir = entry.metadata.is_dir();
                            let path_type = match (entry.is_symlink, is_dir) {
                                (true, true) => PathType::SymlinkDir,
                                (false, true) => PathType::Dir,
                                (true, false) => PathType::SymlinkFile,
                                (false, false) => PathType::File,
                            };
                            let mtime = entry
                                .metadata
                                .modified()
                                .ok()
                                .or_else(|| entry.metadata.created().ok())
                                .map(|time| to_timestamp(&time))
                                .unwrap_or_default();
                            let name = match entry.display_rel.strip_prefix(&base_rel) {
                                Ok(relative) => match relative.to_str() {
                                    Some(relative) => relative.to_owned(),
                                    None => {
                                        omitted_non_utf8 = true;
                                        return if is_dir {
                                            CapabilityWalkAction::SkipDirectory
                                        } else {
                                            CapabilityWalkAction::Continue
                                        };
                                    }
                                },
                                Err(error) => {
                                    path_error = Some(anyhow!(
                                        "walked search path escaped its display root: {error}"
                                    ));
                                    return CapabilityWalkAction::Stop;
                                }
                            };
                            paths.push(PathItem {
                                path_type,
                                name,
                                mtime,
                                size: if is_dir { 0 } else { entry.metadata.len() },
                                size_known: !is_dir,
                            });
                            CapabilityWalkAction::Continue
                        },
                    );
                    if let Some(error) = path_error {
                        return Err(error);
                    }
                    let walk_outcome = walk_result?;
                    omitted_non_utf8 |= walk_outcome.omitted_non_utf8;
                    Ok((paths, result_limit_hit, omitted_non_utf8))
                },
            )
            .await;
            let (search_paths, traversal_truncated, search_omitted_non_utf8) = match search_result {
                Ok(result) => result,
                Err(error) => {
                    let error = map_blocking_operation_error(
                        error,
                        "searching directory tree",
                        operation_timeout,
                    );
                    if error.status().is_server_error() {
                        warn!("Search execution response failed: error={error:#}");
                    } else {
                        debug!("Search execution rejected: error={error:#}");
                    }
                    error.apply(res);
                    return Ok(());
                }
            };
            truncated = traversal_truncated;
            omitted_non_utf8 = search_omitted_non_utf8;
            paths = search_paths;
        }
        let mutation_version =
            mutation_scan.and_then(|snapshot| self.mutation_versions.finish_scan(snapshot));
        // 普通/通配符 HEAD 不遍历；携带具体 ETag 的 HEAD 才生成与 GET 相同的搜索表示。
        // 该必要遍历仍受昂贵任务并发、深度、条目数和总执行时间共同约束。
        // Ordinary/wildcard HEAD avoids traversal. A concrete-tag HEAD alone generates GET's exact
        // search representation, still bounded by expensive-task, depth, entry, and time limits.
        self.send_index(
            path,
            paths,
            ctx,
            ListingOptions {
                exist: true,
                content_length_known: representation_complete,
                representation_complete,
                truncated,
                omitted_non_utf8,
                mutation_version,
            },
            res,
        )
    }

    /// `--render-index`/`--render-try-index` 模式：请求目录时改为发送
    /// 目录下的 index.html（静态网站托管场景）。
    /// Serve directory `index.html` under render-index/try-index site-hosting modes.
    pub(super) async fn handle_render_index(
        &self,
        path: &Path,
        ctx: &RequestContext<'_>,
        res: &mut Response,
    ) -> Result<()> {
        let index_path = path.join(INDEX_NAME);
        let requested_rel = Path::new(&ctx.authorization_path).join(INDEX_NAME);
        let open_rel = self
            .canonical_authorization_path(&normalize_path(&requested_rel)?)
            .await?;
        let opened = classify_open_result(
            self.fs_root
                .open(PathBuf::from(open_rel), NodeKind::Any)
                .await,
            "opening a rendered directory index",
            OpenErrorPolicy::HideUnavailable,
        )?
        .filter(|opened| opened.metadata.is_file())
        .filter(|opened| ctx.allows_actual(&opened.real_rel, &ctx.authorization_method));
        if let Some(opened) = opened {
            self.handle_send_trusted_opened_cap_file(opened, &index_path, ctx, res)
                .await?;
        } else if self.args.render_try_index {
            self.handle_ls_dir(path, true, ctx, res).await?;
        } else {
            self.handle_not_found(ctx, res).await?;
        }
        Ok(())
    }

    /// 404 处理：配置了自定义错误页（assets 目录下的 404.html）就发它，
    /// 否则回简单的 "Not Found" 文本。
    /// Serve a configured assets/404.html or a simple Not Found response.
    pub(super) async fn handle_not_found(
        &self,
        ctx: &RequestContext<'_>,
        res: &mut Response,
    ) -> Result<()> {
        if let Some(error_page) = &self.args.error_page {
            // 中文：Range/条件头针对原缺失资源，不能继承给 404.html，否则会产生部分或空 404。
            // English: Do not apply missing-resource Range/conditions to the error page.
            let error_headers = headers::HeaderMap::new();
            let opened = self
                .args
                .assets
                .as_deref()
                .and_then(|assets| error_page.strip_prefix(assets).ok())
                .and_then(|rel| {
                    self.assets_root
                        .as_ref()
                        .map(|root| (root.clone(), rel.to_path_buf()))
                });
            let Some((root, rel)) = opened else {
                status_not_found(res);
                return Ok(());
            };
            let Some(opened) = classify_open_result(
                root.open(rel, NodeKind::Any).await,
                "opening the configured internal error page",
                OpenErrorPolicy::TrustedInternalAsset,
            )?
            else {
                status_not_found(res);
                return Ok(());
            };
            validate_opened_trusted_asset(&opened.metadata, error_page).map_err(|error| {
                anyhow::Error::new(FsError::io(
                    "validating the configured internal error page",
                    error,
                ))
            })?;
            let empty_preconditions = ParsedPreconditions::default();
            self.handle_send_open_file(
                opened.file,
                opened.metadata,
                error_page,
                OpenFileResponseOptions {
                    headers: &error_headers,
                    preconditions: &empty_preconditions,
                    head_only: ctx.head_only,
                    allow_active_inline: true,
                },
                res,
            )
            .await?;
            // 中文：自定义错误页内联显示但 sandbox，不能获得文件管理器同源权限。
            // English: Display custom errors inline but sandbox them away from file-manager same-origin authority.
            set_content_disposition(res, true, get_file_name(error_page))?;
            res.headers_mut().insert(
                "content-security-policy",
                HeaderValue::from_static(
                    "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:",
                ),
            );
            *res.status_mut() = StatusCode::NOT_FOUND;
            return Ok(());
        }
        status_not_found(res);
        Ok(())
    }

    /// 把条目列表渲染成响应，是所有目录页的汇聚点。
    /// 依据查询参数支持三种输出：`?simple`（纯文本一行一个名字）、
    /// `?json`（结构化数据）和默认的现代 Web 界面。
    /// 排序参数为 `?sort=` + `?order=desc`。
    /// Converged listing renderer for simple text, JSON, or modern UI with sort/order parameters.
    fn send_index(
        &self,
        path: &Path,
        mut paths: Vec<PathItem>,
        ctx: &RequestContext<'_>,
        options: ListingOptions,
        res: &mut Response,
    ) -> Result<()> {
        // 中文：目录列表暴露 ACL 过滤名称与管理状态，含 ?simple 在内都不能跨登出/ACL 变化被浏览器或共享缓存持久化。
        // English: Listings expose ACL-filtered state and must never persist across logout or ACL changes.
        res.headers_mut()
            .typed_insert(CacheControl::new().with_private().with_no_store());
        if let Some(version) = options.mutation_version.as_deref() {
            // 同时放入响应头便于非 HTML 客户端消费；IndexData 仍是浏览器的权威来源。
            // Also expose it as a response header for non-HTML clients; IndexData remains the
            // browser's authoritative source.
            res.headers_mut()
                .insert(MUTATION_VERSION_HEADER, HeaderValue::from_str(version)?);
        }
        if let Some(sort) = ctx.query_params.get("sort") {
            if sort == "name" {
                sort_paths_by_name(&mut paths)
            } else if sort == "mtime" {
                paths.sort_by(|v1, v2| v1.sort_by_mtime(v2))
            } else if sort == "size" {
                paths.sort_by(|v1, v2| v1.sort_by_size(v2))
            }
            if ctx
                .query_params
                .get("order")
                .map(|v| v == "desc")
                .unwrap_or_default()
            {
                paths.reverse()
            }
        } else {
            sort_paths_by_name(&mut paths)
        }
        if has_query_flag(&ctx.query_params, "simple") {
            let output = paths
                .into_iter()
                .map(|v| {
                    if v.is_dir() {
                        format!("{}/\n", v.name)
                    } else {
                        format!("{}\n", v.name)
                    }
                })
                .collect::<String>();
            res.headers_mut()
                .typed_insert(ContentType::from(mime_guess::mime::TEXT_PLAIN_UTF_8));
            if options.content_length_known {
                res.headers_mut()
                    .typed_insert(ContentLength(output.len() as u64));
            }
            set_listing_truncated_header(res, options.truncated);
            set_listing_omitted_header(res, options.omitted_non_utf8);
            if options.representation_complete
                && !apply_generated_preconditions(output.as_bytes(), &ctx.preconditions, res)?
                || ctx.head_only
            {
                return Ok(());
            }
            *res.body_mut() = body_full(output);
            return Ok(());
        }
        let href = format!(
            "/{}",
            normalize_path(path.strip_prefix(&self.args.serve_path)?)?
        );
        let readwrite = ctx.access_paths.perm().readwrite();
        let data = IndexData {
            kind: DataKind::Index,
            href,
            uri_prefix: self.args.uri_prefix.clone(),
            allow_upload: self.args.allow_upload && readwrite,
            allow_delete: self.args.allow_delete && readwrite,
            allow_search: self.args.allow_search,
            allow_archive: self.args.allow_archive,
            dir_exists: options.exist,
            user: ctx.user.clone(),
            truncated: options.truncated,
            omitted_non_utf8: options.omitted_non_utf8,
            mutation_version: options.mutation_version,
            paths,
        };
        let output = if has_query_flag(&ctx.query_params, "json") {
            res.headers_mut()
                .typed_insert(ContentType::from(mime_guess::mime::APPLICATION_JSON));
            serde_json::to_string_pretty(&data)?
        } else {
            res.headers_mut()
                .typed_insert(ContentType::from(mime_guess::mime::TEXT_HTML_UTF_8));
            add_management_ui_csp(res);

            self.render_page(&data)?
        };
        if options.content_length_known {
            res.headers_mut()
                .typed_insert(ContentLength(output.len() as u64));
        }
        res.headers_mut().insert(
            "x-content-type-options",
            HeaderValue::from_static("nosniff"),
        );
        set_listing_truncated_header(res, options.truncated);
        set_listing_omitted_header(res, options.omitted_non_utf8);
        if options.representation_complete
            && !apply_generated_preconditions(output.as_bytes(), &ctx.preconditions, res)?
            || ctx.head_only
        {
            return Ok(());
        }
        *res.body_mut() = body_full(output);
        Ok(())
    }

    /// 列出目录的直接子条目。权限为"仅索引"（indexonly）的用户只能
    /// 看到权限树里授权过的那几个名字，而不是真实的完整目录内容。
    /// List direct children; IndexOnly callers see only explicitly authorized names, never the real full directory.
    pub(super) async fn list_dir(
        &self,
        entry_path: &Path,
        base_path: &Path,
        ctx: &RequestContext<'_>,
        result_limit: Option<usize>,
    ) -> std::result::Result<DirectoryListing, ResponseError> {
        let rel = PathBuf::from(&ctx.authorization_path);
        let visible_children = ctx.access_paths.perm().indexonly().then(|| {
            ctx.access_paths
                .child_names()
                .into_iter()
                .cloned()
                .collect::<Vec<_>>()
        });
        let access_paths = ctx.access_paths.clone();
        let authorization_path = PathBuf::from(&ctx.authorization_path);
        let authorization_method = ctx.authorization_method.clone();
        let fs_root = self.fs_root.clone();
        let running = self.running.clone();
        let hidden = self.hidden.clone();
        let entry_path = entry_path.to_owned();
        let base_path = base_path.to_owned();
        let max_walk_entries = self.args.max_walk_entries as usize;
        let max_directory_entries = result_limit
            .map(|limit| limit.min(self.args.max_directory_entries as usize))
            .unwrap_or(self.args.max_directory_entries as usize);
        let operation_timeout = Duration::from_secs(self.args.expensive_task_timeout);
        let deadline = tokio::time::Instant::now() + operation_timeout;
        // 中文：平面列表仍执行阻塞 readdir/stat 且最多访问 max-walk-entries；与搜索/hash/archive 共用准入，防 H2 扇出无界 worker。
        // English: Flat scans still consume bounded blocking work and share admission with search/hash/archive.
        let permit = match tokio::time::timeout_at(
            deadline,
            self.expensive_task_limit.clone().acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => permit,
            Err(_) => {
                return Err(ResponseError::admission(AdmissionError::queue_timeout(
                    AdmissionResource::ExpensiveTasks,
                    QueueScope::WorkerPool,
                    operation_timeout,
                )));
            }
            Ok(Err(_)) => {
                return Err(ResponseError::admission(AdmissionError::cancelled(
                    AdmissionResource::ExpensiveTasks,
                )));
            }
        };

        run_guarded_cancellable_blocking(
            deadline,
            self.running.clone(),
            permit,
            move |cancellation| {
                let mut paths = Vec::new();
                let mut omitted_non_utf8 = false;
                let scan_result = fs_root.visit_dir(
                    &rel,
                    &running,
                    cancellation.flag(),
                    max_walk_entries,
                    |entry| {
                        let Some(base_name) = entry.name.to_str() else {
                            // 中文：IndexOnly 用户不能得知无关原始字节名存在；非 UTF-8 名不可能匹配显式 UTF-8 子项，
                            // 因而只有可读目录暴露 omission 信号。
                            // English: IndexOnly must not learn unrelated raw-byte names; only readable directories expose omission.
                            if visible_children.is_none() {
                                omitted_non_utf8 = true;
                            }
                            return Ok(true);
                        };
                        if is_internal_temp_name(base_name) {
                            return Ok(true);
                        }
                        // 中文：IndexOnly 仅显式命名子项可导航。 / English: Only explicitly named children are navigable under IndexOnly.
                        if visible_children.as_ref().is_some_and(|children| {
                            !children.iter().any(|name| name.as_str() == base_name)
                        }) {
                            return Ok(true);
                        }
                        if entry.real_rel.to_str().is_none() {
                            // 中文：可见 UTF-8 symlink 可指向原始字节目标；省略而不发布误导 URL，但向有权 alias 调用方标记损失。
                            // English: Omit a UTF-8 alias resolving to a raw-byte target, while reporting the authorized loss.
                            omitted_non_utf8 = true;
                            return Ok(true);
                        }
                        if !allows_actual_path(
                            &access_paths,
                            &authorization_path,
                            &entry.real_rel,
                            &authorization_method,
                        ) {
                            return Ok(true);
                        }
                        let is_dir = entry.metadata.is_dir();
                        if hidden.is_hidden(base_name, is_dir) {
                            return Ok(true);
                        }
                        if paths.len() >= max_directory_entries {
                            return Ok(false);
                        }
                        let path_type = match (entry.is_symlink, is_dir) {
                            (true, true) => PathType::SymlinkDir,
                            (false, true) => PathType::Dir,
                            (true, false) => PathType::SymlinkFile,
                            (false, false) => PathType::File,
                        };
                        let mtime = entry
                            .metadata
                            .modified()
                            .ok()
                            .or_else(|| entry.metadata.created().ok())
                            .map(|time| to_timestamp(&time))
                            .unwrap_or_default();
                        let display_path = entry_path.join(&entry.name);
                        let name = normalize_path(display_path.strip_prefix(&base_path)?)?;
                        paths.push(PathItem {
                            path_type,
                            name,
                            mtime,
                            size: if is_dir { 0 } else { entry.metadata.len() },
                            size_known: !is_dir,
                        });
                        Ok(true)
                    },
                );
                if cancellation.is_cancelled() {
                    return Err(anyhow::Error::new(AdmissionError::cancelled(
                        AdmissionResource::WalkEntries,
                    ))
                    .context("directory listing was cancelled"));
                }
                let (real_dir, scan_truncated) = scan_result?;
                if !allows_actual_path(
                    &access_paths,
                    &authorization_path,
                    &real_dir,
                    &authorization_method,
                ) {
                    return Err(anyhow::Error::new(FsError::outside_root(
                        "listing directory",
                        anyhow!("opened directory is outside the request ACL"),
                    )));
                }
                Ok(DirectoryListing {
                    paths,
                    truncated: scan_truncated,
                    omitted_non_utf8,
                })
            },
        )
        .await
        .map_err(|error| {
            map_blocking_operation_error(error, "listing directory", operation_timeout)
        })
    }
}

fn map_blocking_operation_error(
    error: anyhow::Error,
    operation: &'static str,
    operation_timeout: Duration,
) -> ResponseError {
    if is_blocking_deadline(&error) {
        warn!(
            "Blocking filesystem deadline exceeded: operation={operation} timeout={operation_timeout:?} error={error:#}"
        );
    }
    let internal_error = format!("{error:#}");
    let response_error =
        ResponseError::from_anyhow_or_filesystem(operation, error, ChangedStatus::Conflict);
    if response_error.status().is_server_error() {
        error!(
            "Blocking filesystem operation failed: operation={operation} error={internal_error}"
        );
    } else {
        debug!(
            "Blocking filesystem operation rejected: operation={operation} error={internal_error}"
        );
    }
    response_error
}

fn allows_actual_path(
    access_paths: &crate::auth::AccessPaths,
    authorization_path: &Path,
    actual: &Path,
    method: &hyper::Method,
) -> bool {
    let Ok(suffix) = actual.strip_prefix(authorization_path) else {
        return false;
    };
    suffix
        .to_str()
        .and_then(|suffix| access_paths.guard(suffix, method))
        .is_some()
}

pub(super) fn set_listing_truncated_header(res: &mut Response, truncated: bool) {
    if truncated {
        res.headers_mut()
            .insert("x-ram-list-truncated", HeaderValue::from_static("true"));
    }
}

pub(super) fn set_listing_omitted_header(res: &mut Response, omitted_non_utf8: bool) {
    if omitted_non_utf8 {
        res.headers_mut()
            .insert("x-ram-list-omitted", HeaderValue::from_static("non-utf8"));
    }
}

/// 排序规则：目录在前，同类内按名称做"不区分大小写的自然排序"
/// （alphanumeric：`a2 < a10`，比纯字典序更符合直觉）。
/// 小写键每项只算一次（O(n) 次分配），而不是在比较器里每次比较算两次
/// （O(n log n) 次）——目录很大时差距明显。
/// Sort directories first, then case-insensitive natural names; decorate once to avoid O(n log n) key allocations.
fn sort_paths_by_name(paths: &mut Vec<PathItem>) {
    let mut keyed: Vec<(String, PathItem)> = std::mem::take(paths)
        .into_iter()
        .map(|v| (v.name.to_lowercase(), v))
        .collect();
    keyed.sort_by(|(k1, v1), (k2, v2)| {
        match v1.path_type.sort_group().cmp(&v2.path_type.sort_group()) {
            Ordering::Equal => alphanumeric_sort::compare_str(k1, k2),
            v => v,
        }
    });
    paths.extend(keyed.into_iter().map(|(_, v)| v));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::error::LimitKind;

    #[test]
    fn listing_budget_and_encoding_loss_signals_can_coexist() {
        let mut response = Response::default();
        set_listing_truncated_header(&mut response, true);
        set_listing_omitted_header(&mut response, true);
        assert_eq!(response.headers()["x-ram-list-truncated"], "true");
        assert_eq!(response.headers()["x-ram-list-omitted"], "non-utf8");
    }

    #[test]
    fn blocking_mapper_preserves_typed_cause_buried_under_context() {
        let source = anyhow::Error::new(AdmissionError::limit_exceeded(
            AdmissionResource::WalkEntries,
            LimitKind::Semantic,
            100,
            Some(101),
        ))
        .context("walking one authorized root");
        let response =
            map_blocking_operation_error(source, "searching directories", Duration::from_secs(5));

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn blocking_mapper_classifies_untyped_io_once_at_boundary() {
        let source = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
            .context("private traversal detail");
        let response =
            map_blocking_operation_error(source, "listing directory", Duration::from_secs(5));
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
