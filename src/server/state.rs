//! 服务构造、保留能力状态与生命周期设置。接受请求前，启动验证身份转为固定文件系统
//! 能力；可变恢复只在初始化执行，随后 handler 共享不可变状态。
//!
//! Server construction, retained capability state, and lifecycle settings. Every filesystem root
//! is converted from a startup-verified identity into a pinned capability before requests are
//! accepted. Mutable recovery runs only during initialization; request handlers subsequently share
//! immutable state.

use super::*;

impl Server {
    /// 执行信任服务根/自定义 assets 所需的全部只读校验；与 init 不同，不清理 stale 候选或构造可变运行态。
    /// Perform all read-only root/assets validation without stale cleanup or mutable runtime construction.
    pub(crate) fn validate_static_configuration(args: &Args) -> Result<()> {
        let startup_paths = args.startup_paths.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "configuration did not retain verified filesystem identities; refusing pathname-only validation"
            )
        })?;
        startup_paths
            .verify_sensitive_for_server_init()
            .context("A sensitive startup path changed after configuration validation")?;
        let _served_root =
            RootFs::from_verified_identity(startup_paths.served(), args.allow_symlink, false)
                .context("Failed to establish the served filesystem capability")?;
        if args.assets.is_some() != startup_paths.assets().is_some() {
            bail!("custom-assets path and its verified identity are inconsistent");
        }
        if let Some(identity) = startup_paths.assets() {
            let assets_root = RootFs::from_verified_identity(identity, false, false)
                .context("Failed to establish the custom-assets filesystem capability")?;
            assets_root
                .validate_trusted_asset_tree(
                    args.max_walk_entries as usize,
                    args.max_walk_depth as usize,
                )
                .context("Custom assets contain an untrusted file or directory")?;
            assets_root
                .read_to_string_limited("index.html", CUSTOM_ASSET_INDEX_MAX_BYTES)
                .context("Custom asset index escapes the assets root or cannot be read securely")?;
        }
        Ok(())
    }

    /// 由解析完的启动参数构建服务器状态。所有"每个请求都要用、
    /// 但每次都一样"的东西（模板切分、隐藏规则编译、资源前缀）都在
    /// 这里一次性算好——这是常见的性能手法：把工作从热路径挪到启动期。
    /// Build server state once, precomputing invariant templates, hidden rules, and prefixes outside request hot paths.
    pub fn init(args: Args, running: Arc<AtomicBool>) -> Result<Self> {
        const ROOT_WARNING: &str = "Ram is running as root: atomically published files will be root-owned and kernel filesystem authority is unnecessarily broad; use a dedicated unprivileged service account";
        const WRITE_MODE_WARNING: &str = "RAM WRITE MODE IS ENABLED: only one writable Ram process is supported; in-process locks do not coordinate external writers or another Ram instance, so stop Ram before any external filesystem write";
        if rustix::process::geteuid().is_root() {
            eprintln!("WARNING: {ROOT_WARNING}");
            warn!("{ROOT_WARNING}");
        }
        if args.allow_upload || args.allow_delete {
            eprintln!("WARNING: {WRITE_MODE_WARNING}");
            warn!("{WRITE_MODE_WARNING}");
        }
        let startup_paths = args.startup_paths.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "configuration did not retain verified filesystem identities; refusing pathname-only initialization"
            )
        })?;
        startup_paths
            .verify_sensitive_for_server_init()
            .context("A sensitive startup path changed after configuration validation")?;
        let revocation_capabilities = startup_paths.token_revocation_capabilities()?;
        args.auth
            .verify_token_revocation_capabilities(revocation_capabilities.as_ref())
            .context("Token revocation capabilities changed before server initialization")?;
        // 中文：服务根、自定义资源、readiness 与 allow-symlink canonicalize 必须共享同一
        // spawn 前准入；分别建 semaphore 会把总 blocking queue 上限悄悄乘以根数量。
        // English: Served/assets roots, readiness, and symlink canonicalization share one
        // pre-spawn admission; separate semaphores would multiply the process-wide queue bound.
        let filesystem_blocking_admission = FilesystemBlockingAdmission::new(
            args.max_blocking_threads as usize,
            Duration::from_secs(args.request_queue_timeout),
        );
        let fs_root = RootFs::from_verified_identity_with_candidate_cleanup_and_admission(
            startup_paths.served(),
            args.allow_symlink,
            false,
            args.stale_upload_cleanup_max_depth as usize,
            filesystem_blocking_admission.clone(),
        )
        .context("Failed to establish the served filesystem capability")?;
        if !args.path_is_file {
            handle_startup_stale_cleanup(
                fs_root.cleanup_stale_uploads(StaleUploadCleanupLimits {
                    min_age: Duration::from_secs(args.stale_upload_cleanup_age),
                    max_entries: args.stale_upload_cleanup_max_entries as usize,
                    max_depth: args.stale_upload_cleanup_max_depth as usize,
                    max_deletions: args.stale_upload_cleanup_max_deletions as usize,
                    timeout: Duration::from_secs(args.stale_upload_cleanup_timeout),
                }),
                args.allow_upload || args.allow_delete,
            )?;
        }
        if args.assets.is_some() != startup_paths.assets().is_some() {
            bail!("custom-assets path and its verified identity are inconsistent");
        }
        let assets_root = startup_paths
            .assets()
            .map(|identity| {
                RootFs::from_verified_identity_with_candidate_cleanup_and_admission(
                    identity,
                    false,
                    false,
                    usize::MAX,
                    filesystem_blocking_admission.clone(),
                )
            })
            .transpose()
            .context("Failed to establish the custom-assets filesystem capability")?;
        if let Some(root) = assets_root.as_ref() {
            root.validate_trusted_asset_tree(
                args.max_walk_entries as usize,
                args.max_walk_depth as usize,
            )
            .context("Custom assets contain an untrusted file or directory")?;
        }
        // 内置资源的 URL 包含构建版本，可以安全地 immutable 缓存。
        // 自定义资源可在不升级二进制的情况下改变，必须使用独立
        // 命名空间；否则浏览器会用“上次启动的内置 immutable JS”遮蔽
        // 本次启动的自定义文件，连 no-cache 响应都不会请求到。
        // English: Versioned embedded assets are immutable. Custom assets need
        // a separate namespace and revalidation so a prior immutable cache cannot shadow this startup.
        let assets_prefix = if assets_root.is_some() {
            "__ram_custom_assets__/".to_string()
        } else {
            format!("__ram_v{}__/", env!("CARGO_PKG_VERSION"))
        };
        let assets_uri = format!("{}{}", args.uri_prefix, assets_prefix);
        let single_file_req_paths = if args.path_is_file {
            vec![
                args.uri_prefix.to_string(),
                args.uri_prefix[0..args.uri_prefix.len() - 1].to_string(),
                encode_uri(&format!(
                    "{}{}",
                    args.uri_prefix,
                    get_file_name(&args.serve_path)
                )),
            ]
        } else {
            vec![]
        };
        let html = match assets_root.as_ref() {
            Some(root) => root
                .read_to_string_limited("index.html", CUSTOM_ASSET_INDEX_MAX_BYTES)
                .context("Custom asset index escapes the assets root or cannot be read securely")?,
            None => INDEX_HTML.to_string(),
        };
        let html = html.replace("__ASSETS_PREFIX__", &assets_uri);
        let (html_head, html_tail) = match html.split_once("__INDEX_DATA__") {
            Some((head, tail)) => (head.to_string(), Some(tail.to_string())),
            None => (html, None),
        };
        let hidden = Arc::new(HiddenRules::compile(&args.hidden));
        let expensive_task_limit = Arc::new(Semaphore::new(args.max_expensive_tasks as usize));
        let upload_limit = Arc::new(Semaphore::new(args.max_concurrent_uploads as usize));
        let upload_user_limit = KeyedLimit::new(
            args.max_concurrent_uploads_per_user
                .min(args.max_concurrent_uploads) as usize,
        );
        let upload_source_limit = KeyedLimit::new(
            args.max_concurrent_uploads_per_source
                .min(args.max_concurrent_uploads) as usize,
        );
        let request_limit = Arc::new(Semaphore::new(args.max_concurrent_requests as usize));
        let request_queue_limit = Arc::new(Semaphore::new(args.max_request_queue as usize));
        let request_source_limit = KeyedLimit::new(
            args.max_concurrent_requests_per_source
                .min(args.max_concurrent_requests) as usize,
        );
        let request_user_limit = KeyedLimit::new(
            args.max_concurrent_requests_per_user
                .min(args.max_concurrent_requests) as usize,
        );
        let trusted_proxy_policy =
            TrustedProxyPolicy::new(args.trusted_proxy.clone(), args.trusted_proxy_header)?;
        Ok(Self {
            args,
            fs_root,
            assets_root,
            running,
            expensive_task_limit,
            upload_limit,
            upload_user_limit,
            upload_source_limit,
            request_limit,
            request_queue_limit,
            request_source_limit,
            request_user_limit,
            trusted_proxy_policy,
            write_locks: WriteLockTable::new(),
            mutation_versions: MutationVersionState::new(),
            single_file_req_paths,
            assets_prefix,
            assets_uri,
            html_head,
            html_tail,
            hidden,
        })
    }

    /// 每连接 HTTP/2 流上限；进程请求上限仍为额外约束，不能降低全局值却留下单连接大队列。
    /// Per-connection H2 stream ceiling additionally bounded by the process-wide request limit.
    pub(crate) fn h2_max_concurrent_streams(&self) -> u32 {
        let process_limit = self.args.max_concurrent_requests.min(u32::MAX as u64) as u32;
        self.args.h2_max_concurrent_streams.min(process_limit)
    }

    pub(crate) fn allow_h2c(&self) -> bool {
        self.args.allow_h2c
    }

    pub(crate) fn header_read_timeout(&self) -> Duration {
        Duration::from_secs(self.args.header_read_timeout)
    }

    pub(crate) fn connection_idle_timeout(&self) -> Duration {
        Duration::from_secs(self.args.connection_idle_timeout)
    }

    pub(crate) fn connection_max_lifetime(&self) -> Duration {
        Duration::from_secs(self.args.connection_max_lifetime)
    }

    pub(crate) fn response_write_idle_timeout(&self) -> Duration {
        Duration::from_secs(self.args.response_write_idle_timeout)
    }

    pub(crate) fn close_request_admission(&self) {
        self.request_queue_limit.close();
        self.request_limit.close();
    }

    pub(crate) fn spawn_stale_upload_maintenance(
        self: &Arc<Self>,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        if self.args.path_is_file {
            return None;
        }
        let root = self.fs_root.clone();
        let limits = StaleUploadCleanupLimits {
            min_age: Duration::from_secs(self.args.stale_upload_cleanup_age),
            max_entries: self.args.stale_upload_cleanup_max_entries as usize,
            max_depth: self.args.stale_upload_cleanup_max_depth as usize,
            max_deletions: self.args.stale_upload_cleanup_max_deletions as usize,
            timeout: Duration::from_secs(self.args.stale_upload_cleanup_timeout),
        };
        // 中文：候选首次成熟时重访，同时限制删除/条目批次延迟；age=0 仍用适度频率防 busy loop。
        // English: Revisit at first maturity while bounding batch delay; zero age still uses a modest cadence.
        let interval = if limits.min_age.is_zero() {
            Duration::from_secs(60)
        } else {
            limits
                .min_age
                .min(Duration::from_secs(60 * 60))
                .max(Duration::from_secs(1))
        };
        Some(tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {}
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            return;
                        }
                        continue;
                    }
                }
                let admission_root = root.clone();
                let cleanup_root = root.clone();
                // 中文：周期扫描本身每个 Server 至多一个，并且也先经过共享 FS 准入；这样
                // max_blocking_threads=1 时不会在唯一 worker 后额外留下一个未计数队列项。
                // English: Each Server has at most one periodic scan, and it also enters shared FS
                // admission before submission, avoiding an extra unaccounted queue node with one worker.
                let worker = async move {
                    admission_root
                        .run_short_blocking(move || cleanup_root.cleanup_stale_uploads(limits))
                        .await
                };
                let Some(result) = wait_stale_cleanup_or_shutdown(worker, &mut shutdown_rx).await
                else {
                    return;
                };
                match result {
                    Ok(report) => log_stale_upload_cleanup(report),
                    Err(error) => {
                        warn!("Periodic stale upload cleanup failed: {error:#}");
                    }
                }
            }
        }))
    }

    pub(super) async fn acquire_write_guards(
        &self,
        intents: &[MutationIntent],
        res: &mut Response,
    ) -> Result<Option<MutationGuards>> {
        let timeout = Duration::from_secs(self.args.write_lock_timeout);
        match self
            .write_locks
            .acquire(&self.fs_root, intents, timeout)
            .await
        {
            Ok(guards) => Ok(Some(guards)),
            Err(error)
                if matches!(
                    FsError::in_anyhow_chain(&error),
                    Some(FsError::OutsideRoot { .. })
                ) =>
            {
                warn!("Rejected mutation path outside capability: error={error:#}");
                ResponseError::bad_request(error).apply(res);
                Ok(None)
            }
            Err(error) => {
                if let Some(response) =
                    ResponseErrorRef::from_anyhow_typed(&error, ChangedStatus::Conflict)
                {
                    if response.status().is_server_error() {
                        warn!("Filesystem mutation lock admission failed: error={error:#}");
                    } else {
                        debug!("Rejected filesystem mutation lock request: error={error:#}");
                    }
                    response.apply(res);
                    Ok(None)
                } else {
                    Err(error)
                }
            }
        }
    }

    /// 渲染 Web 界面页面：把 `data` 序列化成 JSON、base64 编码后，
    /// 拼进预先切分好的模板中间。目录列表页和编辑器页共用此函数。
    /// `T: Serialize` 是泛型约束——任何能被 serde 序列化的类型都可以传。
    /// Render UI by inserting base64(JSON) into the pre-split template for any serializable page data.
    pub(crate) fn render_page<T: Serialize>(&self, data: &T) -> Result<String> {
        let tail = match self.html_tail.as_deref() {
            Some(tail) => tail,
            None => return Ok(self.html_head.clone()),
        };
        let index_data = STANDARD.encode(serde_json::to_string(data)?);
        let mut output =
            String::with_capacity(self.html_head.len() + index_data.len() + tail.len());
        output.push_str(&self.html_head);
        output.push_str(&index_data);
        output.push_str(tail);
        Ok(output)
    }
}

/// 等待一次周期 stale 扫描而不让关停依赖不可中断 syscall。关停分支会立即丢弃 admitted
/// future：尚未取得许可的等待被取消，已提交任务的 `AbortOnDropBlocking` 防止排队执行；若
/// syscall 已运行，真实闭包仍持 RootFs 与许可并在后台退出。通知前请求准入已关闭。
/// Wait for periodic cleanup without coupling graceful shutdown to an uninterruptible syscall.
/// Dropping the admitted future cancels permit waiters and aborts queued work; an already-running
/// closure remains detached with its RootFs and permit until real exit.
async fn wait_stale_cleanup_or_shutdown<T, F>(
    worker: F,
    shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
) -> Option<T>
where
    F: std::future::Future<Output = T>,
{
    tokio::pin!(worker);
    if *shutdown_rx.borrow() {
        return None;
    }

    loop {
        tokio::select! {
            biased;
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    // 中文：返回会同步丢弃 pinned admitted future，触发其内部 AbortOnDrop。
                    // English: Returning synchronously drops the pinned admitted future and triggers its AbortOnDrop.
                    return None;
                }
            }
            result = &mut worker => return Some(result),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::wait_stale_cleanup_or_shutdown;
    use crate::server::filesystem::RootFs;
    use anyhow::Result;
    use assert_fs::TempDir;
    use std::{sync::mpsc, time::Duration};
    use tokio::sync::{oneshot, watch};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn running_stale_cleanup_does_not_hold_shutdown_open() -> Result<()> {
        let directory = TempDir::new()?;
        let root = RootFs::new(directory.path(), false, false)?;
        let worker_root = root.clone();
        let (release_tx, release_rx) = mpsc::channel();
        let (started_tx, started_rx) = oneshot::channel();
        let (finished_tx, mut finished_rx) = oneshot::channel();
        let worker = async move {
            worker_root
                .run_short_blocking(move || {
                    let _ = started_tx.send(());
                    release_rx
                        .recv()
                        .expect("test must release the simulated filesystem syscall");
                    let _ = finished_tx.send(());
                    Ok(7_u8)
                })
                .await
        };
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let waiter =
            tokio::spawn(
                async move { wait_stale_cleanup_or_shutdown(worker, &mut shutdown_rx).await },
            );
        started_rx
            .await
            .expect("simulated filesystem worker did not start");

        shutdown_tx
            .send(true)
            .expect("maintenance shutdown receiver disappeared");

        let result = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("maintenance waited for an uninterruptible blocking worker")
            .expect("maintenance waiter task failed");
        assert!(result.is_none(), "shutdown must detach the blocking worker");
        assert_eq!(root.blocking_admission().available_permits(), 31);
        assert!(
            matches!(
                finished_rx.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            ),
            "the running blocking worker was unexpectedly cancelled"
        );

        release_tx
            .send(())
            .expect("simulated filesystem worker disappeared");
        tokio::time::timeout(Duration::from_secs(2), &mut finished_rx)
            .await
            .expect("detached filesystem worker did not finish after release")
            .expect("detached filesystem worker dropped its completion signal");
        tokio::time::timeout(Duration::from_secs(2), async {
            while root.blocking_admission().available_permits() != 32 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok(())
    }
}
