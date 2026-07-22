//! WebDAV 专属处理：PROPFIND（列属性）/PROPPATCH（改属性）以及
//! 有界 DAV 请求体语义。动态 `Allow`/OPTIONS 由 capabilities 模块统一生成；
//! 本项目不宣告并未完整实现的数字 DAV compliance class。
//!
//! DAV XML 来自不可信客户端。本模块限制请求体大小、读取时间、属性数量
//! 与扩展名字节数，使用不会解析外部实体的事件流解析器，并明确拒绝 DTD、
//! 实体引用和非法结构。PROPFIND 的“目录项 × 属性”以及最终 Multi-Status
//! 字节数也有独立硬预算，避免 XXE、实体膨胀和请求到响应的资源放大。
//!
//! WebDAV-specific handling for PROPFIND/PROPPATCH and bounded DAV request-body semantics.
//! Dynamic `Allow`/OPTIONS comes from the capabilities module; the server does not advertise a
//! numeric DAV compliance class that it does not fully implement.
//!
//! DAV XML is untrusted. This module bounds body size, read time, property count, and expanded-name
//! bytes; uses an event parser that does not resolve external entities; and explicitly rejects DTDs,
//! entity references, and malformed structure. Independent “directory items × properties” and final
//! Multi-Status byte budgets prevent XXE, entity expansion, and request-to-response amplification.

use super::browse::{set_listing_omitted_header, set_listing_truncated_header};
use super::error::{
    AdmissionError, AdmissionResource, HttpError, LimitKind, PublicErrorBody, ResponseError,
};
use super::filesystem::OpenedNode;
use super::model::{PathItem, PathType};
use super::reply::{res_multistatus, status_bad_request, status_not_found};
use super::{Request, RequestContext, Response, Server, normalize_path, to_timestamp};
#[cfg(any(test, feature = "fuzzing"))]
use crate::config::{
    WEBDAV_HARD_MAX_PROPERTIES, WEBDAV_HARD_MAX_RENDERED_PROPERTIES, WEBDAV_HARD_MAX_RESPONSE_SIZE,
};
use crate::http::{IncomingStream, body_full};
use crate::utils::{encode_uri, escape_xml, is_xml_10_char};

use anyhow::{Result, anyhow};
use chrono::{LocalResult, TimeZone, Utc};
use futures_util::StreamExt;
use headers::{CacheControl, HeaderMapExt};
use hyper::StatusCode;
use hyper::header::CONTENT_LENGTH;
use quick_xml::events::Event;
use quick_xml::name::ResolveResult;
use quick_xml::reader::NsReader;
use std::collections::HashSet;
use std::fmt::{self, Write as _};
use std::io::Cursor;
use std::path::Path;
use std::str;
use std::sync::Arc;
use std::time::Duration;

const DAV_NAMESPACE: &str = "DAV:";
/// DAV 正文同时受 64 KiB 字节上限与五秒读取截止时间约束；XML 树另限 64 层、4,096 个
/// 元素，使小正文也不能用极深嵌套或大量空元素放大解析器栈与驻留节点。
/// DAV bodies have both a 64 KiB byte limit and a five-second read deadline. The XML tree is
/// separately limited to 64 levels and 4,096 elements so a small body cannot amplify parser-stack
/// or resident-node usage through deep nesting or many empty elements.
const DAV_BODY_LIMIT: usize = 64 * 1024;
const DAV_BODY_TIMEOUT: Duration = Duration::from_secs(5);
const DAV_XML_MAX_DEPTH: usize = 64;
const DAV_XML_MAX_ELEMENTS: usize = 4096;
/// 限制从不可信 XML 保留并随后插入响应的名称。总预算按唯一扩展属性名（`namespace` +
/// `local_name`）计费。
/// Bounds names retained from untrusted XML and later interpolated into a response. The aggregate
/// budget is charged per unique expanded property name (`namespace` + `local_name`).
const DAV_MAX_NAMESPACE_BYTES: usize = 256;
const DAV_MAX_LOCAL_NAME_BYTES: usize = 128;
const DAV_MAX_PROPERTY_NAME_BYTES: usize = 16 * 1024;
/// 成功的 DAV XML 会先缓冲，这样预算失败仍能在发送 207 响应头前返回 507。预算包括整个
/// XML 外壳，而不只是各个 `<D:response>` 元素。
/// Successful DAV XML is buffered so a budget failure can return 507 before 207 headers are sent.
/// The limit includes the XML envelope, not only individual `<D:response>` elements.
const DAV_MULTISTATUS_PREFIX: &str =
    "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n<D:multistatus xmlns:D=\"DAV:\">\n";
const DAV_MULTISTATUS_SUFFIX: &str = "\n</D:multistatus>";
const KNOWN_PROPERTY_NAMES: [&str; 4] = [
    "displayname",
    "getcontentlength",
    "getlastmodified",
    "resourcetype",
];

/// 启动校验后的进程级 WebDAV 预算。运维人员可以调低，但 `config` 会拒绝超过编译期安全
/// 上限的值。同一值对象贯穿解析、预检和渲染，防止 allprop、propname、显式属性和
/// PROPPATCH 形成不一致的资源契约。
/// Per-process WebDAV budgets after startup validation. Operators may lower them, while `config`
/// rejects values above compile-time ceilings. One value object spans parsing, preflight, and
/// rendering so allprop/propname/explicit/PROPPATCH share one resource contract.
#[derive(Clone, Copy, Debug)]
struct DavLimits {
    max_properties: usize,
    max_rendered_properties: usize,
    max_response_size: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DavDepth {
    Zero,
    One,
    Infinity,
}

impl DavLimits {
    fn for_server(server: &Server) -> Self {
        Self {
            max_properties: server.args.max_webdav_properties as usize,
            max_rendered_properties: server.args.max_webdav_rendered_properties as usize,
            max_response_size: server.args.max_webdav_response_size as usize,
        }
    }

    #[cfg(any(test, feature = "fuzzing"))]
    fn hard_maximum() -> Self {
        Self {
            max_properties: WEBDAV_HARD_MAX_PROPERTIES as usize,
            max_rendered_properties: WEBDAV_HARD_MAX_RENDERED_PROPERTIES as usize,
            max_response_size: WEBDAV_HARD_MAX_RESPONSE_SIZE as usize,
        }
    }

    fn response_content_limit(self) -> usize {
        // 启动校验保证 max_response_size 至少为 1 KiB，远大于固定外壳；saturating_sub 也
        // 能在未来限制构造变化时确保仅 fuzz 调用方保持全函数语义。
        // Startup validation keeps max_response_size at least 1 KiB, above the fixed envelope;
        // saturating_sub also keeps fuzz-only callers total if limit construction changes.
        self.max_response_size
            .saturating_sub(DAV_MULTISTATUS_PREFIX.len() + DAV_MULTISTATUS_SUFFIX.len())
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct DavProperty {
    namespace: Arc<str>,
    local_name: Arc<str>,
}

impl DavProperty {
    fn is_dav(&self, local_name: &str) -> bool {
        self.namespace.as_ref() == DAV_NAMESPACE && self.local_name.as_ref() == local_name
    }
}

#[derive(Debug)]
struct XmlNode {
    name: DavProperty,
    children: Vec<XmlNode>,
    has_text: bool,
}

impl XmlNode {
    fn new(name: DavProperty) -> Self {
        Self {
            name,
            children: Vec::new(),
            has_text: false,
        }
    }

    fn is_empty(&self) -> bool {
        self.children.is_empty() && !self.has_text
    }
}

#[derive(Debug)]
enum PropFindRequest {
    AllProp,
    PropName,
    Explicit(Vec<DavProperty>),
}

#[derive(Debug)]
struct PropertyUpdate {
    property: DavProperty,
    _operation: PatchOperation,
}

#[derive(Clone, Copy, Debug)]
enum PatchOperation {
    Set,
    Remove,
}

#[derive(Debug)]
enum DavRequestError {
    BodyTooLarge(DavBudgetExceeded),
    BudgetExceeded(DavBudgetExceeded),
    Timeout,
    Transport(anyhow::Error),
    InvalidXml,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DavBudgetExceeded {
    resource: AdmissionResource,
    limit: u64,
    observed: Option<u64>,
}

impl DavBudgetExceeded {
    const fn new(resource: AdmissionResource, limit: u64, observed: Option<u64>) -> Self {
        Self {
            resource,
            limit,
            observed,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum DavResponseError {
    BudgetExceeded(DavBudgetExceeded),
}

/// 在单次解析生命周期内驻留扩展 XML 名称。继承命名空间通常在每个属性元素上重复；使用
/// `Arc<str>` 可避免为每个 XML 节点重复分配大型共享命名空间。
/// Intern expanded XML names for one parse. Inherited namespaces commonly repeat on every property
/// element; `Arc<str>` avoids allocating a large shared namespace once per XML node.
#[derive(Default)]
struct DavNameInterner {
    namespaces: HashSet<Arc<str>>,
    local_names: HashSet<Arc<str>>,
}

impl DavNameInterner {
    fn namespace(&mut self, value: &str) -> Arc<str> {
        intern_name(&mut self.namespaces, value)
    }

    fn local_name(&mut self, value: &str) -> Arc<str> {
        intern_name(&mut self.local_names, value)
    }
}

fn intern_name(values: &mut HashSet<Arc<str>>, value: &str) -> Arc<str> {
    if let Some(value) = values.get(value) {
        return Arc::clone(value);
    }
    let value: Arc<str> = Arc::from(value);
    values.insert(Arc::clone(&value));
    value
}

/// 永不增长到成功 DAV 响应预算之外的 `fmt::Write` 实现。格式化可能在写入前缀后失败，
/// 但此时会丢弃整个构建器并返回小型 507 响应。
/// A `fmt::Write` implementation that never exceeds the successful DAV response budget. Formatting
/// may fail after a prefix, but the whole builder is discarded and a small 507 is returned.
struct DavXmlWriter {
    output: String,
    content_limit: usize,
    response_limit: usize,
    last_observed_response_size: Option<u64>,
}

impl DavXmlWriter {
    fn new(limits: DavLimits) -> Self {
        Self {
            output: String::with_capacity(4096.min(limits.response_content_limit())),
            content_limit: limits.response_content_limit(),
            response_limit: limits.max_response_size,
            last_observed_response_size: None,
        }
    }

    fn push(&mut self, value: &str) -> Result<(), DavResponseError> {
        if self.write_str(value).is_err() {
            Err(self.response_budget_error())
        } else {
            Ok(())
        }
    }

    fn push_fmt(&mut self, args: fmt::Arguments<'_>) -> Result<(), DavResponseError> {
        if self.write_fmt(args).is_err() {
            Err(self.response_budget_error())
        } else {
            Ok(())
        }
    }

    fn finish(self) -> String {
        self.output
    }

    fn response_budget_error(&self) -> DavResponseError {
        DavResponseError::BudgetExceeded(DavBudgetExceeded::new(
            AdmissionResource::WebDavResponseBytes,
            self.response_limit as u64,
            self.last_observed_response_size,
        ))
    }
}

impl fmt::Write for DavXmlWriter {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let content_length = self.output.len().checked_add(value.len());
        if content_length.is_none_or(|length| length > self.content_limit) {
            let envelope_length = DAV_MULTISTATUS_PREFIX.len() + DAV_MULTISTATUS_SUFFIX.len();
            self.last_observed_response_size = content_length
                .and_then(|length| length.checked_add(envelope_length))
                .map(|length| length as u64);
            return Err(fmt::Error);
        }
        self.output.push_str(value);
        Ok(())
    }
}

struct DavPropertyBudget {
    unique: HashSet<DavProperty>,
    unique_name_bytes: usize,
    update_count: usize,
    max_properties: usize,
}

impl DavPropertyBudget {
    fn new(limits: DavLimits) -> Self {
        Self {
            unique: HashSet::new(),
            unique_name_bytes: 0,
            update_count: 0,
            max_properties: limits.max_properties,
        }
    }

    /// 若扩展属性名尚未出现则加入。返回值让 PROPFIND 去重并保留首次出现顺序。
    /// Add an expanded property name if new. The return value lets PROPFIND deduplicate while
    /// retaining first-occurrence order.
    fn insert_unique(&mut self, property: &DavProperty) -> Result<bool, DavRequestError> {
        if self.unique.contains(property) {
            return Ok(false);
        }
        if self.unique.len() >= self.max_properties {
            return Err(DavRequestError::BudgetExceeded(DavBudgetExceeded::new(
                AdmissionResource::WebDavProperties,
                self.max_properties as u64,
                self.unique
                    .len()
                    .checked_add(1)
                    .map(|observed| observed as u64),
            )));
        }
        self.charge_unique_name(property)?;
        self.unique.insert(property.clone());
        Ok(true)
    }

    /// PROPPATCH 顺序具有语义，因此保留重复操作。重复项仍计入同一个 64 属性出现次数上限；
    /// 名称总字节预算则按每个扩展名只计费一次。
    /// PROPPATCH order is semantic, so duplicate operations remain. They count toward the same
    /// 64-property occurrence limit; aggregate name bytes are charged once per expanded name.
    fn observe_update(&mut self, property: &DavProperty) -> Result<(), DavRequestError> {
        self.update_count = self.update_count.checked_add(1).ok_or_else(|| {
            DavRequestError::BudgetExceeded(DavBudgetExceeded::new(
                AdmissionResource::WebDavProperties,
                self.max_properties as u64,
                None,
            ))
        })?;
        if self.update_count > self.max_properties {
            return Err(DavRequestError::BudgetExceeded(DavBudgetExceeded::new(
                AdmissionResource::WebDavProperties,
                self.max_properties as u64,
                Some(self.update_count as u64),
            )));
        }
        if !self.unique.contains(property) {
            self.charge_unique_name(property)?;
            self.unique.insert(property.clone());
        }
        Ok(())
    }

    fn charge_unique_name(&mut self, property: &DavProperty) -> Result<(), DavRequestError> {
        let bytes = property
            .namespace
            .len()
            .checked_add(property.local_name.len())
            .ok_or_else(|| {
                DavRequestError::BudgetExceeded(DavBudgetExceeded::new(
                    AdmissionResource::WebDavPropertyNameBytes,
                    DAV_MAX_PROPERTY_NAME_BYTES as u64,
                    None,
                ))
            })?;
        self.unique_name_bytes = self.unique_name_bytes.checked_add(bytes).ok_or_else(|| {
            DavRequestError::BudgetExceeded(DavBudgetExceeded::new(
                AdmissionResource::WebDavPropertyNameBytes,
                DAV_MAX_PROPERTY_NAME_BYTES as u64,
                None,
            ))
        })?;
        if self.unique_name_bytes > DAV_MAX_PROPERTY_NAME_BYTES {
            return Err(DavRequestError::BudgetExceeded(DavBudgetExceeded::new(
                AdmissionResource::WebDavPropertyNameBytes,
                DAV_MAX_PROPERTY_NAME_BYTES as u64,
                Some(self.unique_name_bytes as u64),
            )));
        }
        Ok(())
    }
}

impl Server {
    /// PROPFIND 目录：按 `Depth` 头返回自身（0）或自身加直接子条目（1）。
    /// 无限深度（infinity）被拒绝，避免一次请求递归扫描整个服务树。
    /// PROPFIND a directory: `Depth: 0` returns itself and `Depth: 1` adds direct children. Infinity
    /// is rejected so one request cannot recursively scan the entire served tree.
    pub(super) async fn handle_propfind_dir(
        &self,
        req: Request,
        path: &Path,
        opened: OpenedNode,
        ctx: &RequestContext<'_>,
        res: &mut Response,
    ) -> Result<()> {
        res.headers_mut()
            .typed_insert(CacheControl::new().with_private().with_no_store());
        let depth = match propfind_depth(ctx.headers, res) {
            Some(depth) => depth,
            None => return Ok(()),
        };
        let limits = DavLimits::for_server(self);
        let request = match read_and_parse_propfind(req, limits).await {
            Ok(request) => request,
            Err(err) => {
                reject_dav_request(res, err);
                return Ok(());
            }
        };
        let Some(pathitem) = opened_pathitem(self, path, opened, ctx) else {
            status_not_found(res);
            return Ok(());
        };
        let mut paths = vec![pathitem];
        let mut listing_truncated = false;
        let mut listing_omitted_non_utf8 = false;
        if depth == DavDepth::One {
            let property_count = propfind_property_count(&request);
            // 比最大可表示响应多保留一个子项，以便将超大目录识别为 507；同时在高属性数
            // 请求可能保留配置的数百万条目前停止扫描。`paths` 中根项已占乘法预算的一项。
            // Include one child beyond the largest representable response to detect an oversized
            // directory as 507, while stopping before retaining a multi-million configured maximum.
            // The root already in `paths` consumes one multiplication-budget item.
            let result_probe_limit = Some(propfind_child_probe_limit(limits, property_count));
            match self
                .list_dir(path, &self.args.serve_path, ctx, result_probe_limit)
                .await
            {
                Ok(child) => {
                    listing_truncated = child.truncated;
                    listing_omitted_non_utf8 = child.omitted_non_utf8;
                    paths.extend(child.paths);
                }
                Err(error) => {
                    if error.status().is_server_error() {
                        warn!("WebDAV directory listing response failed: error={error:#}");
                    } else {
                        debug!("WebDAV directory listing rejected: error={error:#}");
                    }
                    error.apply(res);
                    return Ok(());
                }
            }
        }
        match render_propfind_response(&paths, self.args.uri_prefix.as_str(), &request, limits) {
            Ok(output) => {
                set_listing_truncated_header(res, listing_truncated);
                set_listing_omitted_header(res, listing_omitted_non_utf8);
                set_multistatus_response(res, output);
            }
            Err(err) => reject_dav_response(res, err),
        }
        Ok(())
    }

    /// PROPFIND 单个文件：按请求选择返回属性 XML。
    /// PROPFIND one file and return the XML properties selected by the request.
    pub(super) async fn handle_propfind_file(
        &self,
        req: Request,
        path: &Path,
        opened: OpenedNode,
        ctx: &RequestContext<'_>,
        res: &mut Response,
    ) -> Result<()> {
        res.headers_mut()
            .typed_insert(CacheControl::new().with_private().with_no_store());
        if propfind_depth(ctx.headers, res).is_none() {
            return Ok(());
        }
        let limits = DavLimits::for_server(self);
        let request = match read_and_parse_propfind(req, limits).await {
            Ok(request) => request,
            Err(err) => {
                reject_dav_request(res, err);
                return Ok(());
            }
        };
        if let Some(pathitem) = opened_pathitem(self, path, opened, ctx) {
            match render_propfind_response(
                std::slice::from_ref(&pathitem),
                self.args.uri_prefix.as_str(),
                &request,
                limits,
            ) {
                Ok(output) => set_multistatus_response(res, output),
                Err(err) => reject_dav_response(res, err),
            }
        } else {
            status_not_found(res);
        }
        Ok(())
    }

    /// PROPPATCH 请求会完整解析 `set`/`remove` 和其中的每个属性，但本
    /// 服务器不存储 dead properties，因此逐项以 403 propstat 明确拒绝。
    /// Fully parse PROPPATCH `set`/`remove` and every contained property. The server stores no dead
    /// properties, so it explicitly rejects each one with a 403 propstat.
    pub(super) async fn handle_proppatch(
        &self,
        req: Request,
        req_path: &str,
        res: &mut Response,
    ) -> Result<()> {
        res.headers_mut()
            .typed_insert(CacheControl::new().with_private().with_no_store());
        let limits = DavLimits::for_server(self);
        let updates = match read_and_parse_proppatch(req, limits).await {
            Ok(updates) => updates,
            Err(err) => {
                reject_dav_request(res, err);
                return Ok(());
            }
        };
        match render_proppatch_response(req_path, &updates, limits) {
            Ok(output) => set_multistatus_response(res, output),
            Err(err) => reject_dav_response(res, err),
        }
        Ok(())
    }
}

/// RFC 4918 将缺失的 PROPFIND Depth 定义为 `infinity`。Ram 刻意只实现有界 Depth 0/1，
/// 因此显式和隐式 infinity 都会以标准有限深度 DAV 前置条件失败。
/// RFC 4918 defines a missing PROPFIND Depth as `infinity`. Ram implements only bounded Depth 0/1,
/// so explicit and implicit infinity fail with the standard finite-depth DAV precondition.
fn propfind_depth(headers: &hyper::HeaderMap, res: &mut Response) -> Option<DavDepth> {
    let values: Vec<_> = headers.get_all("depth").iter().collect();
    let depth = match values.as_slice() {
        [] => DavDepth::Infinity,
        [value] => match value.to_str().ok().map(str::trim) {
            Some("0") => DavDepth::Zero,
            Some("1") => DavDepth::One,
            Some(value) if value.eq_ignore_ascii_case("infinity") => DavDepth::Infinity,
            _ => {
                status_bad_request(res, "Invalid Depth header: expected 0, 1, or infinity");
                return None;
            }
        },
        _ => {
            status_bad_request(res, "Invalid Depth header: expected one value");
            return None;
        }
    };
    if depth == DavDepth::Infinity {
        ResponseError::http(HttpError::forbidden(anyhow!(
            "unbounded PROPFIND depth is disabled"
        )))
        .apply_with_body(
            res,
            PublicErrorBody::xml(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:error xmlns:D=\"DAV:\"><D:propfind-finite-depth/></D:error>",
            ),
        );
        None
    } else {
        Some(depth)
    }
}

/// 获取变更锁之前消费 MKCOL 请求体。基础 MKCOL 没有可扩展请求实体格式，因而任何字节都
/// 返回 415，且文件系统必须保持不变。
/// Consume MKCOL's body before acquiring a mutation lock. Base MKCOL has no extensible request-entity
/// format, so any byte yields 415 and the filesystem must remain untouched.
pub(super) async fn validate_mkcol_empty_body(req: Request, res: &mut Response) -> bool {
    match read_dav_body(req).await {
        Ok(body) if body.is_empty() => true,
        Ok(_) | Err(DavRequestError::BodyTooLarge(_)) => {
            *res.status_mut() = StatusCode::UNSUPPORTED_MEDIA_TYPE;
            *res.body_mut() = body_full("MKCOL request entities are not supported");
            false
        }
        Err(DavRequestError::Timeout) => {
            *res.status_mut() = StatusCode::REQUEST_TIMEOUT;
            *res.body_mut() = body_full("MKCOL request body timed out");
            false
        }
        Err(DavRequestError::Transport(error)) => {
            warn!("Invalid MKCOL request transport: {error:#}");
            status_bad_request(res, "Invalid MKCOL request body");
            false
        }
        Err(DavRequestError::BudgetExceeded(_) | DavRequestError::InvalidXml) => {
            unreachable!("MKCOL body validation does not parse XML")
        }
    }
}

async fn read_and_parse_propfind(
    req: Request,
    limits: DavLimits,
) -> Result<PropFindRequest, DavRequestError> {
    let body = read_dav_body(req).await?;
    parse_propfind_body(&body, limits)
}

fn parse_propfind_body(body: &[u8], limits: DavLimits) -> Result<PropFindRequest, DavRequestError> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(PropFindRequest::AllProp);
    }
    let root = parse_xml(body)?;
    if !root.name.is_dav("propfind") || root.has_text || root.children.len() != 1 {
        return Err(DavRequestError::InvalidXml);
    }
    let selector = &root.children[0];
    if selector.name.is_dav("allprop") && selector.is_empty() {
        Ok(PropFindRequest::AllProp)
    } else if selector.name.is_dav("propname") && selector.is_empty() {
        Ok(PropFindRequest::PropName)
    } else if selector.name.is_dav("prop")
        && !selector.has_text
        && !selector.children.is_empty()
        && selector.children.iter().all(XmlNode::is_empty)
    {
        let mut budget = DavPropertyBudget::new(limits);
        let mut properties = Vec::new();
        for node in &selector.children {
            if budget.insert_unique(&node.name)? {
                properties.push(node.name.clone());
            }
        }
        Ok(PropFindRequest::Explicit(properties))
    } else {
        Err(DavRequestError::InvalidXml)
    }
}

async fn read_and_parse_proppatch(
    req: Request,
    limits: DavLimits,
) -> Result<Vec<PropertyUpdate>, DavRequestError> {
    let body = read_dav_body(req).await?;
    parse_proppatch_body(&body, limits)
}

fn parse_proppatch_body(
    body: &[u8],
    limits: DavLimits,
) -> Result<Vec<PropertyUpdate>, DavRequestError> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Err(DavRequestError::InvalidXml);
    }
    let root = parse_xml(body)?;
    if !root.name.is_dav("propertyupdate") || root.has_text || root.children.is_empty() {
        return Err(DavRequestError::InvalidXml);
    }
    let mut updates = Vec::new();
    let mut budget = DavPropertyBudget::new(limits);
    for action in &root.children {
        let operation = if action.name.is_dav("set") {
            PatchOperation::Set
        } else if action.name.is_dav("remove") {
            PatchOperation::Remove
        } else {
            return Err(DavRequestError::InvalidXml);
        };
        if action.has_text || action.children.len() != 1 {
            return Err(DavRequestError::InvalidXml);
        }
        let prop = &action.children[0];
        if !prop.name.is_dav("prop") || prop.has_text || prop.children.is_empty() {
            return Err(DavRequestError::InvalidXml);
        }
        for node in &prop.children {
            budget.observe_update(&node.name)?;
            updates.push(PropertyUpdate {
                property: node.name.clone(),
                _operation: operation,
            });
        }
    }
    if updates.is_empty() {
        return Err(DavRequestError::InvalidXml);
    }
    Ok(updates)
}

async fn read_dav_body(req: Request) -> Result<Vec<u8>, DavRequestError> {
    if req
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > DAV_BODY_LIMIT as u64)
    {
        let observed = req
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        return Err(DavRequestError::BodyTooLarge(DavBudgetExceeded::new(
            AdmissionResource::RequestBodyBytes,
            DAV_BODY_LIMIT as u64,
            observed,
        )));
    }

    let read = async move {
        let mut stream = IncomingStream::new(req.into_body());
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(DavRequestError::Transport)?;
            let observed = body.len().checked_add(chunk.len());
            if observed.is_none_or(|observed| observed > DAV_BODY_LIMIT) {
                return Err(DavRequestError::BodyTooLarge(DavBudgetExceeded::new(
                    AdmissionResource::RequestBodyBytes,
                    DAV_BODY_LIMIT as u64,
                    observed.map(|observed| observed as u64),
                )));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    };
    tokio::time::timeout(DAV_BODY_TIMEOUT, read)
        .await
        .map_err(|_| DavRequestError::Timeout)?
}

/// 只保留元素扩展名和树结构。quick-xml 不解析/获取外部实体；DTD 与
/// GeneralRef 事件仍在这里显式拒绝，因而既不会访问 URI，也不会进行
/// “billion laughs” 一类实体展开。
/// Retain only expanded element names and tree structure. quick-xml does not resolve or fetch
/// external entities; this layer still rejects DTD and GeneralRef events explicitly, so it neither
/// accesses a URI nor performs entity expansion such as “billion laughs.”
fn parse_xml(body: &[u8]) -> Result<XmlNode, DavRequestError> {
    let mut reader = NsReader::from_reader(Cursor::new(body));
    reader.config_mut().enable_all_checks(true);
    let mut buffer = Vec::new();
    let mut stack = Vec::<XmlNode>::new();
    let mut root = None;
    let mut element_count = 0usize;
    let mut seen_declaration = false;
    let mut names = DavNameInterner::default();

    loop {
        let (namespace, event) = reader
            .read_resolved_event_into(&mut buffer)
            .map_err(|_| DavRequestError::InvalidXml)?;
        match event {
            Event::Start(element) => {
                element_count = element_count.checked_add(1).ok_or_else(|| {
                    DavRequestError::BudgetExceeded(DavBudgetExceeded::new(
                        AdmissionResource::WebDavXmlElements,
                        DAV_XML_MAX_ELEMENTS as u64,
                        None,
                    ))
                })?;
                if element_count > DAV_XML_MAX_ELEMENTS {
                    return Err(DavRequestError::BudgetExceeded(DavBudgetExceeded::new(
                        AdmissionResource::WebDavXmlElements,
                        DAV_XML_MAX_ELEMENTS as u64,
                        Some(element_count as u64),
                    )));
                }
                if stack.len() >= DAV_XML_MAX_DEPTH {
                    return Err(DavRequestError::BudgetExceeded(DavBudgetExceeded::new(
                        AdmissionResource::WebDavXmlDepth,
                        DAV_XML_MAX_DEPTH as u64,
                        stack.len().checked_add(1).map(|observed| observed as u64),
                    )));
                }
                let name = resolved_name(namespace, element.local_name().as_ref(), &mut names)?;
                stack.push(XmlNode::new(name));
            }
            Event::Empty(element) => {
                element_count = element_count.checked_add(1).ok_or_else(|| {
                    DavRequestError::BudgetExceeded(DavBudgetExceeded::new(
                        AdmissionResource::WebDavXmlElements,
                        DAV_XML_MAX_ELEMENTS as u64,
                        None,
                    ))
                })?;
                if element_count > DAV_XML_MAX_ELEMENTS {
                    return Err(DavRequestError::BudgetExceeded(DavBudgetExceeded::new(
                        AdmissionResource::WebDavXmlElements,
                        DAV_XML_MAX_ELEMENTS as u64,
                        Some(element_count as u64),
                    )));
                }
                if stack.len() >= DAV_XML_MAX_DEPTH {
                    return Err(DavRequestError::BudgetExceeded(DavBudgetExceeded::new(
                        AdmissionResource::WebDavXmlDepth,
                        DAV_XML_MAX_DEPTH as u64,
                        stack.len().checked_add(1).map(|observed| observed as u64),
                    )));
                }
                let name = resolved_name(namespace, element.local_name().as_ref(), &mut names)?;
                attach_node(XmlNode::new(name), &mut stack, &mut root)?;
            }
            Event::End(_) => {
                let node = stack.pop().ok_or(DavRequestError::InvalidXml)?;
                attach_node(node, &mut stack, &mut root)?;
            }
            Event::Text(text) => {
                if contains_non_whitespace(text.as_ref()) {
                    stack
                        .last_mut()
                        .ok_or(DavRequestError::InvalidXml)?
                        .has_text = true;
                }
            }
            Event::CData(data) => {
                if contains_non_whitespace(data.as_ref()) {
                    stack
                        .last_mut()
                        .ok_or(DavRequestError::InvalidXml)?
                        .has_text = true;
                }
            }
            Event::Decl(_)
                if !seen_declaration
                    && element_count == 0
                    && root.is_none()
                    && stack.is_empty() =>
            {
                seen_declaration = true;
            }
            Event::Decl(_) => return Err(DavRequestError::InvalidXml),
            Event::Comment(_) => {}
            Event::DocType(_) | Event::GeneralRef(_) | Event::PI(_) => {
                return Err(DavRequestError::InvalidXml);
            }
            Event::Eof => break,
        }
        buffer.clear();
    }

    if !stack.is_empty() {
        return Err(DavRequestError::InvalidXml);
    }
    root.ok_or(DavRequestError::InvalidXml)
}

fn contains_non_whitespace(value: &[u8]) -> bool {
    value.iter().any(|byte| !byte.is_ascii_whitespace())
}

fn resolved_name(
    namespace: ResolveResult<'_>,
    local_name: &[u8],
    names: &mut DavNameInterner,
) -> Result<DavProperty, DavRequestError> {
    let namespace = match namespace {
        ResolveResult::Bound(namespace) => {
            // NsReader 会有意暴露原始 xmlns 属性值。只规范化 XML 预定义/数字引用；未知实体
            // 仍为错误，并且 DTD 声明已在上方拒绝。
            // NsReader intentionally exposes the raw xmlns value. Normalize only predefined/numeric
            // XML references; unknown entities remain errors and DTD declarations are rejected above.
            let raw =
                str::from_utf8(namespace.as_ref()).map_err(|_| DavRequestError::InvalidXml)?;
            let value =
                quick_xml::escape::unescape(raw).map_err(|_| DavRequestError::InvalidXml)?;
            if !value.chars().all(is_xml_10_char) {
                return Err(DavRequestError::InvalidXml);
            }
            if value.len() > DAV_MAX_NAMESPACE_BYTES {
                return Err(DavRequestError::BudgetExceeded(DavBudgetExceeded::new(
                    AdmissionResource::WebDavNamespaceBytes,
                    DAV_MAX_NAMESPACE_BYTES as u64,
                    Some(value.len() as u64),
                )));
            }
            names.namespace(value.as_ref())
        }
        ResolveResult::Unbound => names.namespace(""),
        ResolveResult::Unknown(_) => return Err(DavRequestError::InvalidXml),
    };
    let local_name = str::from_utf8(local_name).map_err(|_| DavRequestError::InvalidXml)?;
    if local_name.len() > DAV_MAX_LOCAL_NAME_BYTES {
        return Err(DavRequestError::BudgetExceeded(DavBudgetExceeded::new(
            AdmissionResource::WebDavLocalNameBytes,
            DAV_MAX_LOCAL_NAME_BYTES as u64,
            Some(local_name.len() as u64),
        )));
    }
    if !is_safe_xml_local_name(local_name) {
        return Err(DavRequestError::InvalidXml);
    }
    Ok(DavProperty {
        namespace,
        local_name: names.local_name(local_name),
    })
}

/// quick-xml 刻意专注于快速分词，而非完整验证 XML Name 产生式。由于属性名会插入响应，
/// 这里只接受保守的 NCName 子集，拒绝可能生成畸形标记的内容；DAV 和常见自定义属性均为
/// ASCII。
/// quick-xml focuses on tokenization rather than the complete XML Name production. Because property
/// names enter the response, accept a conservative NCName subset and reject malformed-markup risks.
/// DAV and common custom properties are ASCII.
fn is_safe_xml_local_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
}

fn attach_node(
    node: XmlNode,
    stack: &mut [XmlNode],
    root: &mut Option<XmlNode>,
) -> Result<(), DavRequestError> {
    if let Some(parent) = stack.last_mut() {
        parent.children.push(node);
    } else if root.replace(node).is_some() {
        return Err(DavRequestError::InvalidXml);
    }
    Ok(())
}

fn reject_dav_request(res: &mut Response, error: DavRequestError) {
    match error {
        DavRequestError::BodyTooLarge(budget) => {
            ResponseError::admission(AdmissionError::limit_exceeded(
                budget.resource,
                LimitKind::Payload,
                budget.limit,
                budget.observed,
            ))
            .apply_with_body(
                res,
                PublicErrorBody::plain("WebDAV XML body exceeds 65536 bytes"),
            );
        }
        DavRequestError::BudgetExceeded(budget) => {
            let response_error = ResponseError::admission(AdmissionError::limit_exceeded(
                budget.resource,
                LimitKind::Semantic,
                budget.limit,
                budget.observed,
            ));
            warn!("Rejected WebDAV request: error={response_error:#}");
            let public_body = match budget.resource {
                AdmissionResource::WebDavXmlElements | AdmissionResource::WebDavXmlDepth => {
                    "WebDAV XML complexity budget exceeded"
                }
                _ => "WebDAV property budget exceeded",
            };
            response_error.apply_with_body(res, PublicErrorBody::plain(public_body));
        }
        DavRequestError::Timeout => {
            *res.status_mut() = StatusCode::REQUEST_TIMEOUT;
            *res.body_mut() = body_full("WebDAV XML body timed out");
        }
        DavRequestError::Transport(source) => {
            let error = ResponseError::bad_request(source.context("reading WebDAV XML body"));
            warn!("Rejected WebDAV request: {error:?}");
            error.apply_with_body(res, PublicErrorBody::plain("Invalid WebDAV XML body"));
        }
        DavRequestError::InvalidXml => {
            ResponseError::bad_request(anyhow!("invalid WebDAV XML request"))
                .apply_with_body(res, PublicErrorBody::plain("Invalid WebDAV XML body"));
        }
    }
}

fn reject_dav_response(res: &mut Response, error: DavResponseError) {
    match error {
        DavResponseError::BudgetExceeded(budget) => {
            let response_error = ResponseError::admission(AdmissionError::limit_exceeded(
                budget.resource,
                LimitKind::Storage,
                budget.limit,
                budget.observed,
            ));
            warn!("Rejected WebDAV response: error={response_error:#}");
            response_error.apply_with_body(
                res,
                PublicErrorBody::plain("WebDAV response budget exceeded"),
            );
        }
    }
}

fn is_known_property(property: &DavProperty) -> bool {
    property.namespace.as_ref() == DAV_NAMESPACE
        && KNOWN_PROPERTY_NAMES.contains(&property.local_name.as_ref())
}

fn set_multistatus_response(res: &mut Response, output: String) {
    res_multistatus(res, &output);
}

fn render_propfind_response(
    items: &[PathItem],
    prefix: &str,
    request: &PropFindRequest,
    limits: DavLimits,
) -> Result<String, DavResponseError> {
    let property_count = propfind_property_count(request);
    ensure_propfind_complexity(items.len(), property_count, limits)?;

    let mut output = DavXmlWriter::new(limits);
    for item in items {
        render_propfind_item(&mut output, item, prefix, request)?;
    }
    Ok(output.finish())
}

fn propfind_property_count(request: &PropFindRequest) -> usize {
    match request {
        PropFindRequest::AllProp | PropFindRequest::PropName => KNOWN_PROPERTY_NAMES.len(),
        PropFindRequest::Explicit(properties) => properties.len(),
    }
}

fn ensure_propfind_complexity(
    item_count: usize,
    property_count: usize,
    limits: DavLimits,
) -> Result<(), DavResponseError> {
    match item_count.checked_mul(property_count) {
        Some(count) if count <= limits.max_rendered_properties => Ok(()),
        observed => Err(DavResponseError::BudgetExceeded(DavBudgetExceeded::new(
            AdmissionResource::WebDavRenderedProperties,
            limits.max_rendered_properties as u64,
            observed.map(|count| count as u64),
        ))),
    }
}

/// 探测 Depth: 1 请求时最多保留的子项数。
/// Maximum number of children retained while probing a Depth: 1 request.
///
/// 返回的子项上限刻意包含一个拒绝哨兵：根资源单独保留，因此填满的子向量会令
/// `items = floor(rendered/property) + 1`，使上方预检返回 507。由此保留的 PathItem 数量
/// 确定地受“此值加一”限制，与物理目录大小无关。
/// The returned child limit deliberately includes one rejection sentinel. The root is retained
/// separately, so a full child vector makes `items = floor(rendered/property) + 1` and preflight
/// returns 507. Retained PathItems are therefore bounded by this value plus one regardless of disk.
fn propfind_child_probe_limit(limits: DavLimits, property_count: usize) -> usize {
    debug_assert!(property_count > 0);
    limits.max_rendered_properties / property_count
}

fn render_propfind_item(
    output: &mut DavXmlWriter,
    item: &PathItem,
    prefix: &str,
    request: &PropFindRequest,
) -> Result<(), DavResponseError> {
    output.push_fmt(format_args!(
        "<D:response>\n<D:href>{}</D:href>\n",
        render_href(item, prefix)
    ))?;

    match request {
        PropFindRequest::AllProp | PropFindRequest::PropName => {
            output.push("<D:propstat>\n<D:prop>\n")?;
            for local_name in KNOWN_PROPERTY_NAMES {
                if matches!(request, PropFindRequest::PropName) {
                    output.push_fmt(format_args!("<D:{local_name}/>\n"))?;
                } else {
                    output.push(&render_known_property(item, local_name))?;
                    output.push("\n")?;
                }
            }
            output.push("</D:prop>\n<D:status>HTTP/1.1 200 OK</D:status>\n</D:propstat>\n")?;
        }
        PropFindRequest::Explicit(properties) => {
            if properties.iter().any(is_known_property) {
                output.push("<D:propstat>\n<D:prop>\n")?;
                for property in properties
                    .iter()
                    .filter(|property| is_known_property(property))
                {
                    output.push(&render_known_property(item, property.local_name.as_ref()))?;
                    output.push("\n")?;
                }
                output.push("</D:prop>\n<D:status>HTTP/1.1 200 OK</D:status>\n</D:propstat>\n")?;
            }

            if properties
                .iter()
                .any(|property| !is_known_property(property))
            {
                output.push("<D:propstat>\n<D:prop>\n")?;
                for (index, property) in properties
                    .iter()
                    .filter(|property| !is_known_property(property))
                    .enumerate()
                {
                    output.push(&render_empty_property(property, index))?;
                    output.push("\n")?;
                }
                output.push(
                    "</D:prop>\n<D:status>HTTP/1.1 404 Not Found</D:status>\n</D:propstat>\n",
                )?;
            }
        }
    }
    output.push("</D:response>")
}

fn render_proppatch_response(
    req_path: &str,
    updates: &[PropertyUpdate],
    limits: DavLimits,
) -> Result<String, DavResponseError> {
    ensure_propfind_complexity(1, updates.len(), limits)?;
    let mut output = DavXmlWriter::new(limits);
    output.push_fmt(format_args!(
        "<D:response>\n<D:href>{}</D:href>\n",
        escape_xml(req_path)
    ))?;
    for (index, update) in updates.iter().enumerate() {
        output.push("<D:propstat>\n<D:prop>\n")?;
        output.push(&render_empty_property(&update.property, index))?;
        output.push("\n</D:prop>\n<D:status>HTTP/1.1 403 Forbidden</D:status>\n</D:propstat>\n")?;
    }
    output.push("</D:response>")?;
    Ok(output.finish())
}

fn render_href(item: &PathItem, prefix: &str) -> String {
    // `Args::uri_prefix` 已在配置时完成百分号编码。再次编码组合字符串会把 Unicode 或保留
    // 字符前缀中的每个 `%XX` 变成 `%25XX`，从而产生不同路由。
    // `Args::uri_prefix` is already percent-encoded during configuration. Re-encoding the combined
    // string would turn `%XX` into `%25XX` and produce a different route.
    let mut href = format!("{}{}", prefix, encode_uri(&item.name));
    if item.is_dir() && !href.ends_with('/') {
        href.push('/');
    }
    escape_xml(&href).into_owned()
}

fn render_known_property(item: &PathItem, local_name: &str) -> String {
    match local_name {
        "displayname" => format!(
            "<D:displayname>{}</D:displayname>",
            escape_xml(item.base_name())
        ),
        "getcontentlength" => format!("<D:getcontentlength>{}</D:getcontentlength>", item.size),
        "getlastmodified" => {
            let value = match Utc.timestamp_millis_opt(item.mtime as i64) {
                LocalResult::Single(value) => {
                    format!("{}", value.format("%a, %d %b %Y %H:%M:%S GMT"))
                }
                _ => String::new(),
            };
            format!("<D:getlastmodified>{value}</D:getlastmodified>")
        }
        "resourcetype" if item.is_dir() => {
            "<D:resourcetype><D:collection/></D:resourcetype>".to_string()
        }
        "resourcetype" => "<D:resourcetype></D:resourcetype>".to_string(),
        _ => unreachable!("only known DAV properties are rendered here"),
    }
}

fn render_empty_property(property: &DavProperty, index: usize) -> String {
    if property.namespace.as_ref() == DAV_NAMESPACE {
        format!("<D:{}/>", property.local_name)
    } else if property.namespace.is_empty() {
        format!("<{}/>", property.local_name)
    } else {
        format!(
            "<P{index}:{} xmlns:P{index}=\"{}\"/>",
            property.local_name,
            quick_xml::escape::escape(property.namespace.as_ref())
        )
    }
}

fn opened_pathitem(
    server: &Server,
    path: &Path,
    opened: OpenedNode,
    ctx: &RequestContext<'_>,
) -> Option<PathItem> {
    if !ctx.allows_actual(&opened.real_rel, &ctx.authorization_method) {
        return None;
    }
    let requested_rel = path.strip_prefix(&server.args.serve_path).ok()?;
    let is_symlink = requested_rel != opened.real_rel;
    let is_dir = opened.metadata.is_dir();
    let path_type = match (is_symlink, is_dir) {
        (true, true) => PathType::SymlinkDir,
        (false, true) => PathType::Dir,
        (true, false) => PathType::SymlinkFile,
        (false, false) => PathType::File,
    };
    let mtime = opened
        .metadata
        .modified()
        .ok()
        .or_else(|| opened.metadata.created().ok())
        .map(|time| to_timestamp(&time))
        .unwrap_or_default();
    Some(PathItem {
        path_type,
        name: normalize_path(requested_rel).ok()?,
        mtime,
        size: if is_dir { 0 } else { opened.metadata.len() },
        size_known: !is_dir,
    })
}

/// cargo-fuzz 钩子由显式特性保护，生产请求 API 无需暴露解析器内部细节。成功解析的内容会
/// 在 DAV 命名空间外壳中渲染并再次解析，因此畸形生成 XML 与解析器 panic 一样会成为可
/// 重现的模糊测试失败。
/// The cargo-fuzz hook sits behind an explicit feature so production APIs do not expose parser
/// internals. Successful parses are rendered and parsed again in the DAV envelope, making malformed
/// generated XML a reproducible fuzz failure just like a parser panic.
#[cfg(feature = "fuzzing")]
pub fn fuzz_webdav_xml(data: &[u8]) {
    if data.len() > DAV_BODY_LIMIT {
        return;
    }
    let limits = DavLimits::hard_maximum();
    let item = PathItem {
        path_type: PathType::File,
        name: "fuzz-item".to_string(),
        mtime: 0,
        size: data.len() as u64,
        size_known: true,
    };

    if let Ok(request) = parse_propfind_body(data, limits)
        && let Ok(content) = render_propfind_response(&[item], "/", &request, limits)
    {
        assert!(
            content.len() + DAV_MULTISTATUS_PREFIX.len() + DAV_MULTISTATUS_SUFFIX.len()
                <= limits.max_response_size
        );
        assert_rendered_dav_xml_is_well_formed(&content);
    }
    if let Ok(updates) = parse_proppatch_body(data, limits)
        && let Ok(content) = render_proppatch_response("/fuzz-item", &updates, limits)
    {
        assert!(
            content.len() + DAV_MULTISTATUS_PREFIX.len() + DAV_MULTISTATUS_SUFFIX.len()
                <= limits.max_response_size
        );
        assert_rendered_dav_xml_is_well_formed(&content);
    }
}

#[cfg(feature = "fuzzing")]
fn assert_rendered_dav_xml_is_well_formed(content: &str) {
    let document = format!("{DAV_MULTISTATUS_PREFIX}{content}{DAV_MULTISTATUS_SUFFIX}");
    assert!(
        parse_xml(document.as_bytes()).is_ok(),
        "renderer produced malformed DAV XML"
    );
}

#[cfg(test)]
mod tests;
