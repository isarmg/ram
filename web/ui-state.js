/**
 * 服务端渲染数据与 DOM 的信任边界。模板中的 JSON 先经 Base64 解码和
 * 结构校验，再组成 `AppContext`；所有元素查找都校验具体 DOM 类型，
 * 使模板/脚本版本不匹配能立即失败，而不是在后续操作中静默放宽权限。
 *
 * Trust boundary between server-rendered state and the DOM. Base64 JSON is
 * structurally validated before becoming `AppContext`, and every required
 * element is checked against its concrete DOM class so template/script skew
 * fails immediately instead of silently relaxing behavior.
 */

import { decodeBase64 } from "./app-utils.js";

const U64_MAXIMUM = (2n ** 64n) - 1n;
const U64_MAXIMUM_AS_NUMBER = Number(U64_MAXIMUM);
const MUTATION_VERSION_PATTERN = /^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.(0|[1-9][0-9]{0,19})$/;

/** @typedef {"Dir"|"SymlinkDir"|"File"|"SymlinkFile"} PathType */

/**
 * @typedef {object} PathItem
 * @property {PathType} path_type
 * @property {string} name
 * @property {number} mtime
 * @property {number} size
 * @property {boolean} size_known
 */

/**
 * 服务端渲染的页面状态。此定义必须与 `src/server/model.rs` 对齐；解析器拒绝畸形载荷，
 * 不能让缺失权限字段变成宽松的 truthy 值。
 *
 * Server-rendered page state. Keep this definition aligned with
 * `src/server/model.rs`; parsing rejects malformed payloads instead of letting
 * missing permission fields become permissive truthy values.
 *
 * @typedef {object} IndexData
 * @property {string} href
 * @property {string} uri_prefix
 * @property {"Index"|"Edit"|"View"} kind
 * @property {PathItem[]} paths
 * @property {boolean} allow_upload
 * @property {boolean} allow_delete
 * @property {boolean} allow_search
 * @property {boolean} allow_archive
 * @property {boolean} can_save
 * @property {boolean} can_delete
 * @property {boolean} can_move
 * @property {string} user
 * @property {boolean} dir_exists
 * @property {boolean} editable
 * @property {boolean} truncated
 * @property {boolean} omitted_non_utf8
 * @property {string | null} mutation_version
 */

/**
 * @typedef {object} DomRefs
 * @property {HTMLDivElement} indexPage
 * @property {HTMLDivElement} editorPage
 * @property {HTMLTableElement} pathsTable
 * @property {HTMLTableSectionElement} pathsTableHead
 * @property {HTMLTableSectionElement} pathsTableBody
 * @property {HTMLTableElement} uploadersTable
 * @property {HTMLTableSectionElement} uploadersTableBody
 * @property {HTMLDivElement} emptyFolder
 * @property {HTMLDivElement} listingNotice
 * @property {HTMLTextAreaElement} editor
 * @property {HTMLDivElement} notEditable
 * @property {HTMLButtonElement} logoutButton
 * @property {HTMLSpanElement} userName
 */

/**
 * @typedef {object} AppContext
 * @property {IndexData} data
 * @property {Readonly<Record<string, string>>} params
 * @property {DomRefs} dom
 * @property {string} emptyNote
 */

/**
 * @param {unknown} value
 * @returns {value is Record<string, unknown>}
 */
function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * @param {Record<string, unknown>} value
 * @param {string} field
 */
function requireString(value, field) {
  const result = value[field];
  if (typeof result !== "string") throw new TypeError(`Invalid page data field: ${field}`);
  return result;
}

/**
 * @param {Record<string, unknown>} value
 * @param {string} field
 */
function requireBoolean(value, field) {
  const result = value[field];
  if (typeof result !== "boolean") throw new TypeError(`Invalid page data field: ${field}`);
  return result;
}

/**
 * 目录变更版本来自安全关键的响应边界，不能把任意 truthy 字符串转发成请求头。
 * UUID 必须是规范小写连字符形式，revision 必须是规范且不超过 u64 的十进制。
 *
 * Directory mutation versions cross a security-sensitive response boundary;
 * never forward an arbitrary truthy string as a request header. The UUID is
 * canonical lowercase hyphenated text and the revision is canonical u64 decimal.
 *
 * @param {unknown} value
 */
function requireOptionalMutationVersion(value) {
  // `null` 是有意义的失败关闭状态：扫描与某个活跃/新启动变更重叠时服务端不会签名，
  // UI 仍可展示读取结果，但必须隐藏 DELETE/MOVE 并提示刷新。
  // `null` is a meaningful fail-closed state: when a scan overlaps an active/new mutation the
  // server does not sign it. The UI may still show read results, but hides DELETE/MOVE and asks
  // for a refresh.
  if (value === null) return null;
  if (typeof value !== "string") throw new TypeError("Invalid page data field: mutation_version");
  const match = MUTATION_VERSION_PATTERN.exec(value);
  if (!match || BigInt(match[2]) > U64_MAXIMUM) {
    throw new TypeError("Invalid page data field: mutation_version");
  }
  return value;
}

/**
 * JSON 只有一种 number 类型，而 Rust 模型使用 `u64`。时间值会驱动 Date
 * 计算，因此必须是安全整数；大于 2^53 的文件大小则可以作为近似显示，
 * 但不得参与启用 JavaScript 缓冲下载等安全决策。
 *
 * JSON has one number type while the Rust model uses `u64`. Timestamps drive
 * Date calculations and must be safe integers. File sizes above 2^53 may be
 * displayed approximately, but must never enable security-sensitive choices
 * such as JavaScript-buffered downloads.
 *
 * @param {unknown} value
 * @param {string} field
 * @param {number} [maximum]
 */
function requireUnsignedSafeInteger(value, field, maximum = Number.MAX_SAFE_INTEGER) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > maximum) {
    throw new TypeError(`Invalid path ${field}`);
  }
  return value;
}

/** @param {unknown} value @param {string} field */
function requireUnsignedU64Number(value, field) {
  // 中文：稀疏文件可合法超过 2^53，不能因前端精度限制使整个目录失效。
  // u64::MAX 和相邻域外值可舍入为同一 double，因此这不是精确 u64 证明；
  // 它只排除明显畸形的 JSON 数字，且返回值只能作近似显示。
  // English: sparse files can legitimately exceed 2^53, so frontend precision
  // must not make the whole directory unusable. u64::MAX and a neighboring
  // out-of-domain integer can round to the same double; this is not an exact
  // u64 proof. It rejects clearly malformed JSON numbers, and callers may use
  // the result only as an approximate display value.
  if (typeof value !== "number" || !Number.isFinite(value) || !Number.isInteger(value)
    || value < 0 || value > U64_MAXIMUM_AS_NUMBER) {
    throw new TypeError(`Invalid path ${field}`);
  }
  return value;
}

/**
 * 校验服务端规范化的绝对应用路径。`href` 中的文件名稍后会逐段编码；
 * `uri_prefix` 会直接赋给根面包屑，因此还必须排除查询、片段和反斜杠。
 *
 * Validate a server-normalized absolute application path. Filename segments
 * in `href` are encoded later, while `uri_prefix` is assigned directly to the
 * root breadcrumb and must additionally exclude query, fragment, and backslash syntax.
 *
 * @param {string} value
 * @param {string} field
 * @param {boolean} directUrl
 */
function requireNormalizedAppPath(value, field, directUrl) {
  if (!value.startsWith("/") || value.includes("\0")) {
    throw new TypeError(`Invalid page data field: ${field}`);
  }
  if (directUrl && (value.includes("?") || value.includes("#") || value.includes("\\"))) {
    throw new TypeError(`Invalid page data field: ${field}`);
  }
  const parts = value.split("/");
  const last = parts.length - 1;
  if (parts.some((part, index) => index > 0 && index < last && (!part || part === "." || part === ".."))) {
    throw new TypeError(`Invalid page data field: ${field}`);
  }
  const finalPart = parts[last] ?? "";
  if (value !== "/" && finalPart && [".", ".."].includes(finalPart)) {
    throw new TypeError(`Invalid page data field: ${field}`);
  }
  if (directUrl) {
    // 中文：URL parser 也会规范化百分号编码的点段（例如 `%2e%2e`）。
    // 字符串分段检查看不到这个变换，所以直接赋给 href 的前缀还必须
    // 与浏览器规范化结果逐字节一致。
    // English: URL parsers also normalize percent-encoded dot segments such
    // as `%2e%2e`, which string component checks cannot see. A prefix assigned
    // directly to href must therefore equal the browser-normalized pathname.
    const parsed = new URL(value, "https://ram.invalid/");
    if (parsed.origin !== "https://ram.invalid" || parsed.pathname !== value) {
      throw new TypeError(`Invalid page data field: ${field}`);
    }
  }
  return value;
}

/** @param {unknown} value */
function parsePathItem(value) {
  if (!isRecord(value)) throw new TypeError("Invalid path item");
  const pathType = requireString(value, "path_type");
  if (!["Dir", "SymlinkDir", "File", "SymlinkFile"].includes(pathType)) {
    throw new TypeError("Invalid path type");
  }
  // ECMAScript Date 的有效域是 Unix epoch 前后 8.64e15 毫秒；服务端模型
  // 已把 epoch 之前的时间压到 0，所以这里只接受无符号有效日期。
  // ECMAScript Date is defined only within 8.64e15 milliseconds of the Unix
  // epoch. The server already clamps pre-epoch values to zero, so accept only
  // unsigned timestamps that the browser can represent as a valid Date.
  const mtime = requireUnsignedSafeInteger(value.mtime, "mtime", 8_640_000_000_000_000);
  const size = requireUnsignedU64Number(value.size, "size");
  const name = requireString(value, "name");
  // 中文：搜索结果可包含多段相对路径，但空段、点段、绝对路径和 NUL 都不是
  // 服务端模型可能产生的值。必须在创建 href 前拒绝，否则浏览器会规范化 `..`
  // 并把一个损坏的嵌入状态变成指向父级资源的可点击操作。
  // English: Search results may contain multiple relative segments, but empty
  // segments, dot segments, absolute paths, and NUL are impossible server
  // values. Reject them before creating hrefs, or browser `..` normalization
  // could turn damaged embedded state into a clickable parent-resource action.
  const nameParts = name.split("/");
  if (nameParts.some(part => !part || part === "." || part === ".." || part.includes("\0"))) {
    throw new TypeError("Invalid path item name");
  }
  return /** @type {PathItem} */ ({
    path_type: pathType,
    name,
    mtime,
    size,
    size_known: requireBoolean(value, "size_known"),
  });
}

/** @param {unknown} value */
export function parseIndexData(value) {
  if (!isRecord(value)) throw new TypeError("Invalid page data");
  const kind = requireString(value, "kind");
  if (!["Index", "Edit", "View"].includes(kind)) throw new TypeError("Invalid page kind");
  const userValue = value.user;
  if (typeof userValue !== "string" && userValue !== null) throw new TypeError("Invalid page user");
  const href = requireNormalizedAppPath(requireString(value, "href"), "href", false);
  const uriPrefix = requireNormalizedAppPath(requireString(value, "uri_prefix"), "uri_prefix", true);
  if (!uriPrefix.endsWith("/")) throw new TypeError("Invalid page data field: uri_prefix");
  const common = {
    href,
    uri_prefix: uriPrefix,
    kind,
    user: userValue ?? "",
  };
  if (kind === "Index") {
    if (!Array.isArray(value.paths)) throw new TypeError("Invalid page paths");
    return /** @type {IndexData} */ ({
      ...common,
      paths: value.paths.map(parsePathItem),
      allow_upload: requireBoolean(value, "allow_upload"),
      allow_delete: requireBoolean(value, "allow_delete"),
      allow_search: requireBoolean(value, "allow_search"),
      allow_archive: requireBoolean(value, "allow_archive"),
      dir_exists: requireBoolean(value, "dir_exists"),
      truncated: requireBoolean(value, "truncated"),
      omitted_non_utf8: requireBoolean(value, "omitted_non_utf8"),
      mutation_version: requireOptionalMutationVersion(value.mutation_version),
      can_save: false,
      can_delete: false,
      can_move: false,
      editable: false,
    });
  }
  return /** @type {IndexData} */ ({
    ...common,
    paths: [],
    allow_upload: requireBoolean(value, "allow_upload"),
    allow_delete: requireBoolean(value, "allow_delete"),
    allow_search: false,
    allow_archive: false,
    can_save: requireBoolean(value, "can_save"),
    can_delete: requireBoolean(value, "can_delete"),
    can_move: requireBoolean(value, "can_move"),
    dir_exists: false,
    editable: requireBoolean(value, "editable"),
    truncated: false,
    omitted_non_utf8: false,
    mutation_version: null,
  });
}

/**
 * @template {Element} T
 * @param {string} selector
 * @param {{new(...args: never[]): T}} constructor
 */
export function requireElement(selector, constructor) {
  const element = document.querySelector(selector);
  if (!(element instanceof constructor)) throw new Error(`Required UI element is missing: ${selector}`);
  return element;
}

/** @returns {DomRefs} */
function collectDom() {
  return {
    indexPage: requireElement(".index-page", HTMLDivElement),
    editorPage: requireElement(".editor-page", HTMLDivElement),
    pathsTable: requireElement(".paths-table", HTMLTableElement),
    pathsTableHead: requireElement(".paths-table thead", HTMLTableSectionElement),
    pathsTableBody: requireElement(".paths-table tbody", HTMLTableSectionElement),
    uploadersTable: requireElement(".uploaders-table", HTMLTableElement),
    uploadersTableBody: requireElement(".uploaders-table tbody", HTMLTableSectionElement),
    emptyFolder: requireElement(".empty-folder", HTMLDivElement),
    listingNotice: requireElement(".listing-notice", HTMLDivElement),
    editor: requireElement(".editor", HTMLTextAreaElement),
    notEditable: requireElement(".not-editable", HTMLDivElement),
    logoutButton: requireElement(".logout-btn", HTMLButtonElement),
    userName: requireElement(".user-name", HTMLSpanElement),
  };
}

/** @returns {AppContext} */
export function loadAppContext() {
  const template = document.getElementById("index-data");
  if (!(template instanceof HTMLTemplateElement)) throw new Error("Embedded page data is missing");
  const encoded = template.content.textContent?.trim() ?? "";
  if (!encoded) throw new Error("Embedded page data is empty");
  let raw;
  try {
    raw = JSON.parse(decodeBase64(encoded));
  } catch (error) {
    throw new Error("Embedded page data is invalid", { cause: error });
  }
  const data = parseIndexData(raw);
  const params = Object.freeze(Object.fromEntries(new URLSearchParams(window.location.search)));
  return {
    data,
    params,
    dom: collectDom(),
    emptyNote: params.q ? "No results" : data.dir_exists
      ? "Empty folder"
      : "Folder will be created when a file is uploaded",
  };
}

/** @param {string} [name] */
export function resourceUrl(name) {
  let url = window.location.href.split(/[?#]/, 1)[0];
  if (name === undefined) return url;
  if (!url.endsWith("/")) url += "/";
  return url + name.split("/").map(encodeURIComponent).join("/");
}

/** @param {string} url */
export function baseName(url) {
  const part = url.split("/").filter(Boolean).at(-1);
  return part === undefined ? "" : decodeURIComponent(part);
}

/** @param {string} filename */
export function extensionName(filename) {
  const dot = filename.lastIndexOf(".");
  return dot <= 0 || dot === filename.length - 1 ? "" : filename.slice(dot).toLowerCase();
}

/** @param {unknown} error */
export function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

/** @param {unknown} error */
export function showFatalError(error) {
  document.title = "Ram UI error";
  // 中文：启动可能在某些头部控件已绑定/显示后失败。只替换 main
  // 会留下“看似可用、实际处于半初始化状态”的写操作。致命页必须
  // 同时隐藏整个头部，使警报成为唯一可聚焦表面。
  // English: initialization can fail after header controls were bound or
  // revealed. Replacing only main would leave write actions that look usable
  // but belong to a partially initialized app. Hide the entire header so the
  // alert is the only focusable surface on a fatal page.
  document.querySelector(".head")?.classList.add("hidden");
  const main = document.querySelector(".main") ?? document.body;
  const alert = document.createElement("div");
  alert.className = "listing-notice fatal-error";
  alert.setAttribute("role", "alert");
  alert.tabIndex = -1;
  alert.textContent = `Unable to initialize the file manager: ${errorMessage(error)}`;
  main.replaceChildren(alert);
  alert.focus();
}

export const types = {};
