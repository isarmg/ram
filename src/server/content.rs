//! 单个资源的内容响应：流式文件下载（支持条件请求与 Range 断点续传）、
//! JSON 元数据视图、编辑器页面、文件哈希、下载令牌生成，
//! 以及内置前端资源和健康检查端点。
//!
//! ## 本模块的 Rust 知识点
//! - **流式响应体**：大文件不整体读入内存。`GuardedBlockingFile` 在每次 read/seek 前
//!   获取共享文件系统准入，`LengthLimitedStream`/multipart 状态机让 Hyper 边读边发；
//!   每个真实阻塞闭包返回后立即释放许可，网络背压期间不占 worker 容量。
//! - **`include_bytes!`/`include_str!`**：前端 js/css/图标在编译期嵌入
//!   二进制。
//! - **HTTP 缓存协商**：`If-None-Match`/`If-Modified-Since` → 304，
//!   `If-Match`/`If-Unmodified-Since` → 412，`If-Range` 决定 Range
//!   是否还有效——这是一套标准的条件请求状态机，值得对照 RFC 细读。
//!
//! 同一个经能力目录打开的描述符同时提供 metadata、内容嗅探、缓存验证器、Range 与响应体
//! 字节，路径名并发替换不能把不同对象的属性和内容拼进同一响应。
//!
//! Content responses for one resource: streaming file downloads with conditional requests and
//! resumable Range support, JSON metadata views, editor pages, file hashing, download-token
//! issuance, embedded frontend assets, and the health-check endpoint.
//!
//! ## Rust concepts in this module
//! - **Streaming response bodies**: large files are never loaded completely into memory.
//!   `GuardedBlockingFile` acquires shared filesystem admission before each read/seek, while
//!   `LengthLimitedStream` and the multipart state machine let Hyper read and send incrementally.
//!   Each real blocking closure releases its permit immediately on return, so network backpressure
//!   does not occupy worker capacity.
//! - **`include_bytes!`/`include_str!`**: frontend JavaScript, CSS, and icons are embedded into the
//!   binary at compile time.
//! - **HTTP cache negotiation**: `If-None-Match`/`If-Modified-Since` select 304,
//!   `If-Match`/`If-Unmodified-Since` select 412, and `If-Range` decides whether a Range remains
//!   valid. Together these form the standard conditional-request state machine described by the
//!   RFCs.
//!
//! One descriptor opened through the filesystem capability supplies metadata, content sniffing,
//! cache validators, Range data, and response bytes, so concurrent pathname replacement cannot mix
//! the attributes of one object with the contents of another.

use super::error::{
    AdmissionError, AdmissionResource, ChangedStatus, FsError, LimitKind, QueueScope,
    ResponseError, ResponseErrorRef,
};
use super::filesystem::{GuardedBlockingFile, OpenedNode, validate_opened_trusted_asset};
use super::model::{DataKind, EditData, PathItem, PathType};
use super::preconditions::{ParsedPreconditions, ReadPreconditionOutcome};
use super::range::{multipart_body, multipart_content_length, multipart_ranges_exceed_limits};
use super::reply::{set_content_disposition, status_bad_request, status_not_found};
use super::security_headers::add_management_ui_csp;
use super::walk::{RequestCancellation, run_guarded_cancellable_blocking};
use super::{
    BUF_SIZE, OpenErrorPolicy, RequestContext, Response, Server, classify_open_result,
    extract_cache_headers, normalize_path, to_timestamp,
};
use crate::http::{LengthLimitedStream, body_full};
use crate::utils::{ByteRangeParse, parse_http_range, try_get_file_name};

use anyhow::Result;
use futures_util::TryStreamExt;
use headers::{
    AcceptRanges, CacheControl, ContentLength, ContentType, ETag, HeaderMap, HeaderMapExt,
};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use hyper::{
    Method, StatusCode,
    header::{CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, HeaderValue, RANGE},
};
use sha2::{Digest, Sha256};
use std::io::{Read as _, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use uuid::Uuid;

const INDEX_CSS: &str = include_str!("../../web/index.css");
const INDEX_JS: &str = include_str!("../../web/index.js");
const API_JS: &str = include_str!("../../web/api.js");
const APP_UTILS_JS: &str = include_str!("../../web/app-utils.js");
const EDITOR_JS: &str = include_str!("../../web/editor.js");
const FILE_OPERATIONS_JS: &str = include_str!("../../web/file-operations.js");
const ICONS_JS: &str = include_str!("../../web/icons.js");
const PAGE_INIT_JS: &str = include_str!("../../web/page-init.js");
const UI_STATE_JS: &str = include_str!("../../web/ui-state.js");
const UPLOAD_SCHEDULER_JS: &str = include_str!("../../web/upload-scheduler.js");
const FAVICON_ICO: &[u8] = include_bytes!("../../web/favicon.ico");
// 4 MiB 可编辑文本上限；读取时还会用实际收到的字节数再次执行同一硬限制。
// 4 MiB editable-text ceiling; the received byte count is checked against the same hard limit again.
const EDITABLE_TEXT_MAX_SIZE: u64 = 4 * 1024 * 1024;
const HEALTH_CHECK_PATH: &str = "__ram__/health";

/// 解析一个编译期前端资源并集中构造响应；返回字节同时是其强 ETag 的权威输入。
/// Resolve one compile-time frontend asset without duplicating response construction. The returned
/// bytes are also the authoritative input to its strong ETag.
fn embedded_asset(name: &str) -> Option<(&'static [u8], &'static str)> {
    const JAVASCRIPT: &str = "application/javascript; charset=UTF-8";
    match name {
        "index.js" => Some((INDEX_JS.as_bytes(), JAVASCRIPT)),
        "api.js" => Some((API_JS.as_bytes(), JAVASCRIPT)),
        "app-utils.js" => Some((APP_UTILS_JS.as_bytes(), JAVASCRIPT)),
        "editor.js" => Some((EDITOR_JS.as_bytes(), JAVASCRIPT)),
        "file-operations.js" => Some((FILE_OPERATIONS_JS.as_bytes(), JAVASCRIPT)),
        "icons.js" => Some((ICONS_JS.as_bytes(), JAVASCRIPT)),
        "page-init.js" => Some((PAGE_INIT_JS.as_bytes(), JAVASCRIPT)),
        "ui-state.js" => Some((UI_STATE_JS.as_bytes(), JAVASCRIPT)),
        "upload-scheduler.js" => Some((UPLOAD_SCHEDULER_JS.as_bytes(), JAVASCRIPT)),
        "index.css" => Some((INDEX_CSS.as_bytes(), "text/css; charset=UTF-8")),
        "favicon.ico" => Some((FAVICON_ICO, "image/x-icon")),
        _ => None,
    }
}

pub(super) struct OpenFileResponseOptions<'a> {
    pub(super) headers: &'a HeaderMap<HeaderValue>,
    pub(super) preconditions: &'a ParsedPreconditions,
    pub(super) head_only: bool,
    pub(super) allow_active_inline: bool,
}

/// 为已经完整生成的表示附加强验证器，并针对完全相同的字节求值 GET/HEAD 条件。调用方让
/// GET 与 HEAD 生成同一字节序列，因此任一方法返回的验证器都精确描述另一方法所选择的表示。
///
/// Attach a strong validator for a fully generated representation and evaluate GET/HEAD conditions
/// against exactly those bytes. Callers use the same generated byte sequence for GET and HEAD, so a
/// validator learned from either method always describes the other method's selected representation.
pub(super) fn apply_generated_preconditions(
    output: &[u8],
    preconditions: &ParsedPreconditions,
    res: &mut Response,
) -> Result<bool> {
    let etag = format!("\"sha256:{}\"", hex::encode(Sha256::digest(output))).parse::<ETag>()?;
    res.headers_mut().typed_insert(etag.clone());
    Ok(apply_read_precondition_outcome(
        preconditions.evaluate_read(&etag, None),
        res,
    ))
}

/// 应用已经求值的读取条件。304 可以保留所选表示的 Content-Length；Ram 的 412 没有错误
/// 表示，因此必须明确声明零字节，不能遗留动态表示的长度。
/// Apply a previously evaluated read condition. A 304 may retain the selected representation's
/// Content-Length, but Ram's 412 response has no error representation and therefore must explicitly
/// advertise zero bytes rather than leaking the generated representation length.
pub(super) fn apply_read_precondition_outcome(
    outcome: ReadPreconditionOutcome,
    res: &mut Response,
) -> bool {
    match outcome {
        ReadPreconditionOutcome::Proceed => true,
        ReadPreconditionOutcome::NotModified => {
            *res.status_mut() = StatusCode::NOT_MODIFIED;
            false
        }
        ReadPreconditionOutcome::PreconditionFailed => {
            *res.status_mut() = StatusCode::PRECONDITION_FAILED;
            res.headers_mut().typed_insert(ContentLength(0));
            false
        }
    }
}

impl Server {
    /// 发送经根 dirfd 能力打开的文件；同一描述符交给流之前立即按其真实根相对路径重验 ACL。
    /// Send a root-capability-opened file after re-authorizing the fd's real relative path.
    pub(super) async fn handle_send_opened_cap_file(
        &self,
        opened: OpenedNode,
        display_path: &Path,
        ctx: &RequestContext<'_>,
        res: &mut Response,
    ) -> Result<()> {
        self.handle_send_opened_cap_file_with_policy(opened, display_path, ctx, false, res)
            .await
    }

    /// 只把显式可信站点入口（render mode 选中的 index.html）作为站点内容；其他文件仍下载，上传 HTML 不会被提升为同源可执行内容。
    /// Serve only an explicitly trusted site entry point as active content; all other files remain downloads.
    pub(super) async fn handle_send_trusted_opened_cap_file(
        &self,
        opened: OpenedNode,
        display_path: &Path,
        ctx: &RequestContext<'_>,
        res: &mut Response,
    ) -> Result<()> {
        self.handle_send_opened_cap_file_with_policy(opened, display_path, ctx, true, res)
            .await
    }

    async fn handle_send_opened_cap_file_with_policy(
        &self,
        opened: OpenedNode,
        display_path: &Path,
        ctx: &RequestContext<'_>,
        allow_active_inline: bool,
        res: &mut Response,
    ) -> Result<()> {
        if !opened.metadata.is_file()
            || !ctx.allows_actual(&opened.real_rel, &ctx.authorization_method)
        {
            status_not_found(res);
            return Ok(());
        }
        self.handle_send_open_file(
            opened.file,
            opened.metadata,
            display_path,
            OpenFileResponseOptions {
                headers: ctx.headers,
                preconditions: &ctx.preconditions,
                head_only: ctx.head_only,
                allow_active_inline,
            },
            res,
        )
        .await
    }

    /// 内置端点分发：`__ram_v*__/` 前缀的前端资源（js/css/favicon，
    /// 可被 `--assets` 目录覆盖）和 `__ram__/health` 健康检查。
    /// 返回 `Ok(true)` 表示"这是内置请求且已处理"，调用方直接返回；
    /// `Ok(false)` 表示不是，继续走正常路由。
    /// Dispatch versioned frontend assets and health; true means handled, false continues normal routing.
    pub(super) async fn handle_internal(
        &self,
        req_path: &str,
        headers: &HeaderMap<HeaderValue>,
        head_only: bool,
        res: &mut Response,
    ) -> Result<bool> {
        if let Some(name) = req_path.strip_prefix(&self.assets_prefix) {
            let preconditions = match ParsedPreconditions::parse(headers) {
                Ok(preconditions) => preconditions,
                Err(error) => {
                    warn!("Rejected malformed asset conditional header: {error}");
                    status_bad_request(res, "Invalid conditional request header");
                    return Ok(true);
                }
            };
            let custom_assets = self.args.assets.is_some();
            match self.args.assets.as_ref() {
                Some(assets_path) => {
                    let opened = match self.assets_root.as_ref() {
                        Some(root) => classify_open_result(
                            root.open(PathBuf::from(name), super::filesystem::NodeKind::Any)
                                .await,
                            "opening a trusted internal asset",
                            OpenErrorPolicy::TrustedInternalAsset,
                        )?,
                        None => None,
                    };
                    match opened {
                        Some(opened) => {
                            validate_opened_trusted_asset(&opened.metadata, Path::new(name))
                                .map_err(|error| {
                                    anyhow::Error::new(FsError::io(
                                        "validating a trusted internal asset",
                                        error,
                                    ))
                                })?;
                            let display_path = assets_path.join(name);
                            self.handle_send_open_file(
                                opened.file,
                                opened.metadata,
                                &display_path,
                                OpenFileResponseOptions {
                                    headers,
                                    preconditions: &preconditions,
                                    head_only,
                                    allow_active_inline: true,
                                },
                                res,
                            )
                            .await?;
                        }
                        None => {
                            status_not_found(res);
                        }
                    }
                }
                None => {
                    if let Some((body, content_type)) = embedded_asset(name) {
                        res.headers_mut()
                            .typed_insert(ContentLength(body.len() as u64));
                        res.headers_mut()
                            .insert("content-type", HeaderValue::from_static(content_type));
                        if apply_generated_preconditions(body, &preconditions, res)? && !head_only {
                            *res.body_mut() = body_full(bytes::Bytes::from_static(body));
                        }
                    } else {
                        status_not_found(res);
                    }
                }
            }
            // 中文：内置资源只随 URL 中二进制版本变化，可 immutable；自定义 assets 可独立变化且 URL 不变，
            // 必须 revalidate，不能缓存旧 UI/404 一年。
            // English: Versioned embedded resources are immutable; custom assets retain URLs and must revalidate.
            let cache_control = if custom_assets {
                HeaderValue::from_static("no-cache")
            } else {
                HeaderValue::from_static("public, max-age=31536000, immutable")
            };
            res.headers_mut().insert("cache-control", cache_control);
            res.headers_mut().insert(
                "x-content-type-options",
                HeaderValue::from_static("nosniff"),
            );
            Ok(true)
        } else if req_path == HEALTH_CHECK_PATH {
            res.headers_mut()
                .typed_insert(ContentType::from(mime_guess::mime::APPLICATION_JSON));
            res.headers_mut()
                .typed_insert(CacheControl::new().with_no_store());
            const HEALTH_BODY: &str = r#"{"status":"OK"}"#;
            const UNAVAILABLE_BODY: &str = r#"{"status":"UNAVAILABLE"}"#;
            let body = if self.serve_root_ready().await {
                HEALTH_BODY
            } else {
                *res.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
                UNAVAILABLE_BODY
            };
            res.headers_mut()
                .typed_insert(ContentLength(body.len() as u64));
            if !head_only {
                *res.body_mut() = body_full(body);
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// 健康端点的 readiness 检查：配置的服务根必须仍能打开，
    /// 且对象身份与启动时一致。正常读取继续使用固定的能力 fd；
    /// readiness 单独检查当前命名空间，避免路径被删除或替换后仍
    /// 被误报为 ready。
    /// Readiness reopens the configured namespace and verifies startup identity while normal serving remains descriptor-pinned.
    async fn serve_root_ready(&self) -> bool {
        let Some(identity) = self
            .args
            .startup_paths
            .as_ref()
            .map(|paths| paths.served().clone())
        else {
            return false;
        };
        matches!(
            self.fs_root
                .run_short_blocking(move || identity.verify_namespace())
                .await,
            Ok(())
        )
    }

    /// 使用调用方已安全打开的文件句柄生成响应。所有
    /// metadata、MIME 嗅探、Range 和正文都复用该句柄，
    /// 避免安全检查后再按路径打开的竞态。
    /// Build metadata, MIME, Range, and body from one safely opened handle to avoid post-check path reopen races.
    pub(super) async fn handle_send_open_file(
        &self,
        mut file: GuardedBlockingFile,
        meta: std::fs::Metadata,
        path: &Path,
        options: OpenFileResponseOptions<'_>,
        res: &mut Response,
    ) -> Result<()> {
        let OpenFileResponseOptions {
            headers,
            preconditions,
            head_only,
            allow_active_inline,
        } = options;
        // 中文：metadata 与文件由 RootFs 同一已准入 open worker 返回；不再调用 tokio::fs 的
        // 隐式 spawn_blocking，否则请求取消会让内部 JoinHandle 脱离共享准入。
        // English: RootFs returns metadata and the file from one admitted open worker. Avoid
        // tokio::fs's implicit spawn_blocking, whose hidden JoinHandle would escape admission on cancellation.
        if !meta.is_file() {
            status_not_found(res);
            return Ok(());
        }
        let size = meta.len();
        // 中文：RFC 9110 只为 GET 定义 Range；HEAD 返回无 Range GET 的表示头但无正文。
        // English: Range applies to GET only; HEAD mirrors a non-Range GET representation without a body.
        let mut use_range = !head_only && headers.contains_key(RANGE);
        // 中文：编辑器大小文件用内容强 ETag，大文件用 metadata 弱 ETag，避免 HEAD/Range 触发无界二次读取。
        // English: Small files use content-strong ETags; large files use metadata-weak ETags to avoid a second full read.
        let validators = extract_cache_headers(&mut file, &meta).await?;
        let etag = validators.etag;
        let last_modified = validators.last_modified;
        let etag_is_strong = validators.strong;
        // 304/412 也需要携带当前的 validator，因此必须在任何条件请求
        // 的提前返回之前插入。ETag 来自已打开文件的版本属性，即使某个
        // 特殊文件系统不能提供修改时间，也不能因此丢失校验器。
        // English: Insert the current validator before early 304/412; the opened-file version still supplies an ETag when mtime is unavailable.
        res.headers_mut()
            .typed_insert(CacheControl::new().with_private().with_no_cache());
        if let Some(last_modified) = last_modified {
            res.headers_mut().typed_insert(last_modified);
        }
        res.headers_mut().typed_insert(etag.clone());

        // 条件请求评估遵循 RFC 9110 §13.2.2：先写前置条件（412）再
        // 缓存新鲜度（304）；且 ETag 校验头优先于时间戳校验头——
        // If-Match 存在时必须忽略 If-Unmodified-Since，If-None-Match
        // 存在时必须忽略 If-Modified-Since。时间戳只有秒级精度，
        // 同一秒内的多次修改只有 ETag 能区分；两者同时出现时看时间戳
        // 会得出与 ETag 矛盾的结论（例如错误地回 304）。
        // English: Follow RFC 9110 §13.2.2: write preconditions before freshness,
        // and ETags suppress second-resolution dates to avoid contradictory results.
        match preconditions.evaluate_read(&etag, last_modified) {
            ReadPreconditionOutcome::Proceed => {}
            ReadPreconditionOutcome::NotModified => {
                *res.status_mut() = StatusCode::NOT_MODIFIED;
                return Ok(());
            }
            ReadPreconditionOutcome::PreconditionFailed => {
                *res.status_mut() = StatusCode::PRECONDITION_FAILED;
                return Ok(());
            }
        }

        if use_range {
            // 中文：If-Range 只在未变时发区间，否则全量；缺失 validator 时正常处理 Range。
            // English: If-Range sends the range only when unchanged; without it, process Range normally.
            use_range = preconditions.if_range_matches(&etag, etag_is_strong);
        }

        let ranges = if use_range {
            let mut values = headers.get_all(RANGE).iter();
            let range = values.next();
            if values.next().is_some() {
                *res.status_mut() = StatusCode::BAD_REQUEST;
                res.headers_mut().typed_insert(ContentLength(0));
                return Ok(());
            }
            range.map(|range| match range.to_str() {
                Ok(range) => parse_http_range(range, size),
                Err(_) => ByteRangeParse::Invalid,
            })
        } else {
            None
        };

        // 中文：未知 unit 按 RFC 忽略，无效 bytes 语法为 400，只有合法但全不可满足为 416。
        // English: Ignore unknown units, map invalid bytes syntax to 400, and reserve 416 for valid wholly unsatisfiable ranges.
        let ranges = match ranges {
            Some(ByteRangeParse::UnsupportedUnit) | None => None,
            Some(ByteRangeParse::Invalid) => {
                *res.status_mut() = StatusCode::BAD_REQUEST;
                res.headers_mut().typed_insert(ContentLength(0));
                return Ok(());
            }
            Some(ByteRangeParse::Unsatisfiable) => {
                *res.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
                res.headers_mut().typed_insert(AcceptRanges::bytes());
                res.headers_mut()
                    .insert(CONTENT_RANGE, format!("bytes */{size}").parse()?);
                res.headers_mut().typed_insert(ContentLength(0));
                return Ok(());
            }
            Some(ByteRangeParse::Satisfiable(ranges)) => Some(ranges),
        };

        let content_type = sniff_content_type(&mut file, path).await?;
        res.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_str(&content_type)?);

        let filename = try_get_file_name(path)?;
        let active_content = is_browser_active_content(&content_type);
        set_content_disposition(res, !active_content || allow_active_inline, filename)?;
        if active_content && !allow_active_inline {
            res.headers_mut().insert(
                "content-security-policy",
                HeaderValue::from_static(
                    "sandbox; default-src 'none'; base-uri 'none'; form-action 'none'",
                ),
            );
        }

        res.headers_mut().typed_insert(AcceptRanges::bytes());

        if let Some(ranges) = ranges {
            if ranges.len() == 1 {
                let (start, end) = ranges[0];
                file.seek(SeekFrom::Start(start)).await?;
                let range_size = end - start + 1;
                *res.status_mut() = StatusCode::PARTIAL_CONTENT;
                let content_range = format!("bytes {start}-{end}/{size}");
                res.headers_mut()
                    .insert(CONTENT_RANGE, content_range.parse()?);
                res.headers_mut()
                    .insert(CONTENT_LENGTH, format!("{range_size}").parse()?);
                if head_only {
                    return Ok(());
                }

                let stream_body = StreamBody::new(
                    LengthLimitedStream::new(file, range_size)
                        .map_ok(Frame::data)
                        .map_err(anyhow::Error::new),
                );
                let boxed_body = stream_body.boxed();
                *res.body_mut() = boxed_body;
            } else {
                if multipart_ranges_exceed_limits(&ranges) {
                    *res.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
                    res.headers_mut()
                        .insert(CONTENT_RANGE, format!("bytes */{size}").parse()?);
                    return Ok(());
                }
                *res.status_mut() = StatusCode::PARTIAL_CONTENT;
                let boundary = Uuid::new_v4().to_string();
                res.headers_mut().insert(
                    CONTENT_TYPE,
                    format!("multipart/byteranges; boundary={boundary}").parse()?,
                );
                let content_length =
                    multipart_content_length(&ranges, &boundary, &content_type, size);
                res.headers_mut()
                    .insert(CONTENT_LENGTH, format!("{content_length}").parse()?);
                if head_only {
                    return Ok(());
                }
                let stream_body =
                    StreamBody::new(multipart_body(file, ranges, boundary, content_type, size));
                let boxed_body = stream_body.boxed();
                *res.body_mut() = boxed_body;
            }
        } else {
            res.headers_mut()
                .insert(CONTENT_LENGTH, format!("{size}").parse()?);
            if head_only {
                return Ok(());
            }

            let stream_body = StreamBody::new(
                LengthLimitedStream::new(file, size)
                    .map_ok(Frame::data)
                    .map_err(anyhow::Error::new),
            );
            let boxed_body = stream_body.boxed();
            *res.body_mut() = boxed_body;
        }
        Ok(())
    }

    /// `?json` 返回类型、大小与修改时间。 / Return file type, size, and mtime as JSON.
    pub(super) async fn handle_file_json(
        &self,
        path: &Path,
        opened: OpenedNode,
        ctx: &RequestContext<'_>,
        res: &mut Response,
    ) -> Result<()> {
        if !opened.metadata.is_file()
            || !ctx.allows_actual(&opened.real_rel, &ctx.authorization_method)
        {
            status_not_found(res);
            return Ok(());
        }
        let meta = opened.metadata;
        let requested_rel = path.strip_prefix(&self.args.serve_path)?;
        let is_symlink = requested_rel != opened.real_rel;
        let pathitem = PathItem {
            path_type: if is_symlink {
                PathType::SymlinkFile
            } else {
                PathType::File
            },
            name: normalize_path(path.strip_prefix(&self.args.serve_path)?)?,
            mtime: meta
                .modified()
                .ok()
                .or_else(|| meta.created().ok())
                .map(|time| to_timestamp(&time))
                .unwrap_or_default(),
            size: meta.len(),
            size_known: true,
        };
        let output = serde_json::to_string_pretty(&pathitem)?;
        res.headers_mut()
            .typed_insert(ContentType::from(mime_guess::mime::APPLICATION_JSON));
        res.headers_mut()
            .typed_insert(ContentLength(output.len() as u64));
        res.headers_mut()
            .typed_insert(CacheControl::new().with_private().with_no_store());
        if !apply_generated_preconditions(output.as_bytes(), &ctx.preconditions, res)?
            || ctx.head_only
        {
            return Ok(());
        }
        *res.body_mut() = body_full(output);
        Ok(())
    }

    /// `?edit`/`?view`：返回编辑器/查看器页面（页面本身，不含文件内容；
    /// 内容由前端再发一次普通 GET 拉取）。
    /// 通过读文件头 1KB 判断是否文本、大小是否超限，决定"可编辑"标志。
    /// Return editor/viewer shell; the frontend fetches content separately. Sniff 1 KiB and size to decide editability.
    pub(super) async fn handle_edit_file(
        &self,
        path: &Path,
        opened: OpenedNode,
        kind: DataKind,
        ctx: &RequestContext<'_>,
        res: &mut Response,
    ) -> Result<()> {
        if !opened.metadata.is_file()
            || !ctx.allows_actual(&opened.real_rel, &ctx.authorization_method)
        {
            status_not_found(res);
            return Ok(());
        }
        // 中文：按根能力打开身份评估有效 ACL，再与各全局开关组合；UI 只接收能力，不接收原始进程开关。
        // English: Evaluate ACL on the opened identity and combine with global gates; expose effective capabilities only.
        let acl_allows_write = ctx.allows_actual(&opened.real_rel, &Method::PUT);
        let can_save = self.args.allow_upload && acl_allows_write;
        let can_delete = self.args.allow_delete && acl_allows_write;
        let can_move = self.args.allow_upload && self.args.allow_delete && acl_allows_write;
        let meta = opened.metadata;
        let file = opened.file;
        let href = format!(
            "/{}",
            normalize_path(path.strip_prefix(&self.args.serve_path)?)?
        );
        let mut buffer: Vec<u8> = vec![];
        file.take(1024).read_to_end(&mut buffer).await?;
        let editable =
            meta.len() <= EDITABLE_TEXT_MAX_SIZE && content_inspector::inspect(&buffer).is_text();
        let data = EditData {
            href,
            kind,
            uri_prefix: self.args.uri_prefix.clone(),
            allow_upload: can_save,
            allow_delete: can_delete,
            can_save,
            can_delete,
            can_move,
            user: ctx.user.clone(),
            editable,
        };
        res.headers_mut()
            .typed_insert(ContentType::from(mime_guess::mime::TEXT_HTML_UTF_8));
        add_management_ui_csp(res);
        let output = self.render_page(&data)?;
        res.headers_mut()
            .typed_insert(ContentLength(output.len() as u64));
        res.headers_mut()
            .typed_insert(CacheControl::new().with_private().with_no_store());
        if !apply_generated_preconditions(output.as_bytes(), &ctx.preconditions, res)?
            || ctx.head_only
        {
            return Ok(());
        }
        *res.body_mut() = body_full(output);
        Ok(())
    }

    /// `?hash` 流式计算 SHA-256 十六进制。 / Stream SHA-256 and return hexadecimal text.
    pub(super) async fn handle_hash_file(
        &self,
        opened: OpenedNode,
        ctx: &RequestContext<'_>,
        res: &mut Response,
    ) -> Result<()> {
        res.headers_mut()
            .typed_insert(ContentType::from(mime_guess::mime::TEXT_PLAIN_UTF_8));
        res.headers_mut()
            .typed_insert(CacheControl::new().with_private().with_no_store());
        // SHA-256 hex 固定 64 字节。只有携带具体 ETag 条件的 HEAD 才需要生成表示；普通 HEAD
        // 可按规范省略生成成本高的 ETag，但一旦返回 ETag，它与 GET 精确相同。
        // SHA-256 hex is always 64 bytes. Only HEAD with a concrete tag condition must generate the
        // representation; an ordinary HEAD may omit an expensive ETag, but any emitted tag exactly
        // matches GET.
        res.headers_mut().typed_insert(ContentLength(64));
        if !opened.metadata.is_file()
            || !ctx.allows_actual(&opened.real_rel, &ctx.authorization_method)
        {
            status_not_found(res);
            return Ok(());
        }
        if opened.metadata.len() > self.args.max_hash_size {
            ResponseError::admission(AdmissionError::limit_exceeded(
                AdmissionResource::HashBytes,
                LimitKind::Payload,
                self.args.max_hash_size,
                Some(opened.metadata.len()),
            ))
            .apply(res);
            return Ok(());
        }
        // 无条件 HEAD 与通配符实体标签只需知道表示存在，不能把它们变成全文件哈希原语；
        // 具体标签仍在下方生成精确哈希表示，并与其字节派生 ETag 比较。
        // Unconditional HEAD and wildcard entity-tag conditions only need representation existence;
        // avoid turning them into a full-file hashing primitive. Concrete tags still generate the
        // exact hash representation below and compare against its byte-derived ETag.
        if ctx.head_only
            && let Some(outcome) = ctx.preconditions.evaluate_generated_head_without_body()
        {
            apply_read_precondition_outcome(outcome, res);
            return Ok(());
        }
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
                warn!("Hash admission failed: error={error:#}");
                error.apply(res);
                return Ok(());
            }
            Ok(Err(_)) => {
                let error = ResponseError::admission(AdmissionError::cancelled(
                    AdmissionResource::ExpensiveTasks,
                ));
                warn!("Hash admission failed: error={error:#}");
                error.apply(res);
                return Ok(());
            }
        };
        let file = opened.file.into_std()?;
        let output = match run_guarded_cancellable_blocking(
            deadline,
            self.running.clone(),
            permit,
            move |cancellation| sha256_file(file, &cancellation),
        )
        .await
        {
            Ok(output) => output,
            Err(error) => {
                if super::walk::is_blocking_deadline(&error) {
                    warn!(
                        "Hash execution deadline exceeded: timeout={operation_timeout:?} error={error:#}"
                    );
                } else {
                    error!("Hash execution failed: error={error:#}");
                }
                if let Some(response_error) =
                    ResponseErrorRef::from_anyhow_typed(&error, ChangedStatus::Conflict)
                {
                    response_error.apply(res);
                } else {
                    ResponseError::filesystem(
                        FsError::io("hashing file", error),
                        ChangedStatus::Conflict,
                    )
                    .apply(res);
                }
                return Ok(());
            }
        };
        if !apply_generated_preconditions(output.as_bytes(), &ctx.preconditions, res)?
            || ctx.head_only
        {
            return Ok(());
        }
        *res.body_mut() = body_full(output);
        Ok(())
    }

    /// `?tokengen`：为当前用户和该路径签发一个下载令牌（见 auth 模块），
    /// 之后必须通过 `Authorization: Bearer ...` 携带。
    /// Issue a path/user download token that must later be sent in Authorization.
    pub(super) async fn handle_tokengen(
        &self,
        relative_path: &str,
        user: &str,
        res: &mut Response,
    ) -> Result<()> {
        let output = self.args.auth.generate_token(relative_path, user)?;
        res.headers_mut()
            .typed_insert(ContentType::from(mime_guess::mime::TEXT_PLAIN_UTF_8));
        res.headers_mut()
            .typed_insert(ContentLength(output.len() as u64));
        // 中文：token 是 bearer 凭据，缓存/历史不得持久化。 / English: Tokens are bearer credentials and must never persist in cache/history.
        res.headers_mut()
            .typed_insert(CacheControl::new().with_private().with_no_store());
        *res.body_mut() = body_full(output);
        Ok(())
    }
}

/// 在普通文件管理 origin 上内联展示这些类型会执行脚本、
/// 外链或 XSLT，因此默认按下载处理。
/// Treat active types as downloads because inline rendering on the manager origin could execute scripts, links, or XSLT.
fn is_browser_active_content(content_type: &str) -> bool {
    let mime = content_type
        .split_once(';')
        .map(|(mime, _)| mime)
        .unwrap_or(content_type)
        .trim()
        .to_ascii_lowercase();
    matches!(
        mime.as_str(),
        "text/html" | "application/xhtml+xml" | "image/svg+xml" | "application/xml" | "text/xml"
    ) || mime.ends_with("+xml")
}

/// 综合"扩展名猜测 + 头 1KiB 内容嗅探"确定 Content-Type：
/// 文本文件还会用 chardetng 探测字符编码（GBK/UTF-8 等），拼进 charset。
/// 直接读已打开的 `file` 再把读取位置拨回开头，省去对同一路径的二次 open。
/// Combine extension and 1 KiB sniffing, detect text charset, then rewind the same opened file.
async fn sniff_content_type(file: &mut GuardedBlockingFile, path: &Path) -> Result<String> {
    let mut buffer: Vec<u8> = vec![];
    (&mut *file).take(1024).read_to_end(&mut buffer).await?;
    file.seek(SeekFrom::Start(0)).await?;
    let mime = mime_guess::from_path(path).first();
    let is_text = content_inspector::inspect(&buffer).is_text();
    let content_type = if is_text {
        let mut detector = chardetng::EncodingDetector::new(chardetng::Iso2022JpDetection::Allow);
        detector.feed(&buffer, buffer.len() < 1024);
        let enc = detector.guess(None, chardetng::Utf8Detection::Allow);
        let charset = format!("; charset={}", enc.name());
        match mime {
            Some(m) => format!("{m}{charset}"),
            None => format!("text/plain{charset}"),
        }
    } else {
        match mime {
            Some(m) => m.to_string(),
            None => "application/octet-stream".into(),
        }
    };
    Ok(content_type)
}

/// 按 64 KiB 块流式哈希，内存恒定。 / Hash in 64 KiB chunks with constant memory.
fn sha256_file(mut file: std::fs::File, cancellation: &RequestCancellation) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; BUF_SIZE];

    loop {
        if cancellation.is_cancelled() {
            return Err(anyhow::Error::new(AdmissionError::cancelled(
                AdmissionResource::HashBytes,
            ))
            .context("hash request cancelled"));
        }
        let bytes_read = file.read(&mut buffer)?;
        if cancellation.is_cancelled() {
            return Err(anyhow::Error::new(AdmissionError::cancelled(
                AdmissionResource::HashBytes,
            ))
            .context("hash request cancelled"));
        }
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let result = hasher.finalize();
    Ok(hex::encode(result))
}
