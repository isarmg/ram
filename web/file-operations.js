/**
 * 目录页操作与浏览器上传编排。模块把认证合并、小文件 token 下载、
 * 目录遍历预算和上传状态机收敛在一处。服务端仍是授权与路径安全的权威；
 * 这里的检查用于在发起昂贵请求前给用户快速、确定的反馈。
 *
 * Directory-page operations and browser upload orchestration. Authentication
 * coalescing, bounded token downloads, traversal budgets, and upload state are
 * centralized here. The server remains authoritative for authorization and
 * path safety; client checks provide early deterministic feedback.
 */

import {
  ApiError,
  assertResponseOk,
  checkAuthentication,
  createDirectory,
  createEmptyFile,
  deleteResource,
  downloadWithToken,
  logOut,
  MAX_API_ERROR_BODY_BYTES,
  moveResource,
  REQUEST_TOTAL_TIMEOUT_MS,
  resourceExists,
} from "./api.js";
import { formatDirSize, formatDuration, formatFileSize, formatMtime, formatPercent } from "./app-utils.js";
import { createIcon, pathIconName } from "./icons.js";
import { UploadScheduler } from "./upload-scheduler.js";
import { errorMessage, requireElement, resourceUrl } from "./ui-state.js";

const MAX_CONCURRENT_UPLOADS = 2;
const MAX_SUBPATHS_COUNT = 1000;
export const MAX_BROWSER_TOKEN_DOWNLOAD_BYTES = 16 * 1024 * 1024;
export const MAX_UPLOAD_ROWS = 1000;
export const MAX_UPLOAD_TREE_DEPTH = 32;
export const MAX_UPLOAD_TREE_ENTRIES = 1000;
/** 同一页面最多运行一个浏览器目录枚举器。 / At most one browser directory enumerator may run per page. */
export const MAX_CONCURRENT_UPLOAD_TRAVERSALS = 1;
/** 单次 FileSystemEntry 回调最长等待时间。 / Maximum wait for one FileSystemEntry callback. */
export const UPLOAD_TRAVERSAL_CALLBACK_TIMEOUT_MS = 30_000;
/** 一次拖放目录遍历的绝对总期限。 / Absolute deadline for one dropped-directory traversal. */
export const UPLOAD_TRAVERSAL_TOTAL_TIMEOUT_MS = 2 * 60 * 1000;

/** @typedef {"new"|"queued"|"running"|"complete"|"failed"|"cancelled"} UploadState */

/** @type {Promise<string> | null} */
let authenticationPromise = null;
let tokenDownloadActive = false;
let activeUploadTraversals = 0;
// 中文：FileSystemEntry 没有取消原语。Promise 超时后 UI 不再视为 pending，
// 但在浏览器真正回调前仍须阻止下一次枚举，避免逐次超时积累不可释放闭包。
// English: FileSystemEntry has no cancellation primitive. A timed-out promise
// no longer counts as pending UI work, but a new traversal remains blocked until
// the browser actually calls back so repeated timeouts cannot retain closures.
let unresolvedUploadTraversalCallbacks = 0;

/**
 * 只有安全整数且已知不超过上限的大小才可启用 JS 内存下载。
 * XFS 等文件系统允许大于 2^53 的稀疏文件；这些值可以近似显示，
 * 但精度不足以支撑“小文件”的缓冲决策，必须交给浏览器原生流式下载。
 *
 * Enable an in-memory JavaScript download only for a safe-integer size known
 * to be within the budget. Filesystems such as XFS permit sparse files above
 * 2^53; those values may be displayed approximately, but lack the precision
 * needed for a "small file" buffering decision and must stream natively.
 *
 * @param {number} size
 */
export function browserTokenDownloadLimit(size) {
  return Number.isSafeInteger(size) && size >= 0 && size <= MAX_BROWSER_TOKEN_DOWNLOAD_BYTES
    ? MAX_BROWSER_TOKEN_DOWNLOAD_BYTES
    : undefined;
}

/** @param {string} value */
export function isSafePathSegment(value) {
  // 只以 `/` 分段：Ram 运行在 Linux，反斜杠是合法文件名字节，不是路径分隔符。
  // Split only on `/`: Ram is Linux-only, where backslash is a valid filename byte rather than a path separator.
  return value.length > 0 && value !== "." && value !== ".."
    && !value.includes("/") && !value.includes("\0");
}

/**
 * @param {File & {webkitRelativePath?: string}} file
 * @param {boolean} requireRelativePath
 */
export function uploadDirectoryParts(file, requireRelativePath = false) {
  const relative = file.webkitRelativePath ?? "";
  if (!relative) {
    if (requireRelativePath) throw new Error("The browser did not preserve the selected folder path");
    if (!isSafePathSegment(file.name)) throw new Error("The selected file has an unsafe name");
    return [];
  }
  const parts = relative.split("/");
  if (parts.at(-1) !== file.name || parts.some(part => !isSafePathSegment(part))) {
    throw new Error("The selected folder contains an unsafe relative path");
  }
  const directories = parts.slice(0, -1);
  if (directories.length > MAX_UPLOAD_TREE_DEPTH) {
    throw new Error(`The selected folder exceeds the ${MAX_UPLOAD_TREE_DEPTH}-directory depth limit`);
  }
  return directories;
}

/** @param {string} value */
export function validateMovePath(value) {
  let path = value.startsWith("/") ? value : `/${value}`;
  const trailingSlash = path.length > 1 && path.endsWith("/");
  const parts = path.slice(1).split("/");
  if (trailingSlash) parts.pop();
  if (parts.length === 0 || parts.some(part => !isSafePathSegment(part))) {
    throw new Error("The destination must use non-empty path segments and cannot contain . or ..");
  }
  path = `/${parts.join("/")}${trailingSlash ? "/" : ""}`;
  return path;
}

/**
 * 列表操作必须基于服务端签发的稳定扫描版本；令牌缺失说明扫描与变更重叠，安全做法是
 * 要求刷新。本函数只为 Index 返回 mutation token；Edit 的调用方必须独立传入其已获取的
 * 强源 ETag，API 层会确保两类条件头互斥，View 则没有危险操作。
 *
 * Listing actions must use the server-signed stable-scan version. A missing
 * token means the scan overlapped a mutation, so refresh rather than silently
 * degrading to an unconditional destructive request. This function returns a
 * mutation token only for Index. An Edit caller separately supplies its strong
 * source ETag, the API layer keeps both condition types mutually exclusive,
 * and View exposes no destructive action.
 *
 * @param {import("./ui-state.js").AppContext} context
 */
export function mutationVersionForListAction(context) {
  if (context.data.kind !== "Index") return undefined;
  if (!context.data.mutation_version) {
    throw new Error("The directory changed while this listing was generated. Refresh and try again.");
  }
  return context.data.mutation_version;
}

/**
 * 成功变更会在服务端推进 revision，因此当前页面的令牌此刻已确定过期。把它立即清空，
 * 防止页面重复发送一个已知会得到 412 的条件，并让重新渲染隐藏危险操作。
 *
 * A successful mutation advances the server revision, so this page's token is
 * now known stale. Clear it immediately to avoid sending a guaranteed 412 and
 * let a rerender hide destructive actions until the page refreshes.
 *
 * @param {import("./ui-state.js").AppContext} context
 */
export function invalidateListingMutationVersion(context) {
  if (context.data.kind === "Index") context.data.mutation_version = null;
}

/** @param {import("./ui-state.js").AppContext} context */
async function authenticate(context) {
  authenticationPromise ??= checkAuthentication(resourceUrl()).finally(() => {
    authenticationPromise = null;
  });
  const user = await authenticationPromise;
  // CHECKAUTH 可能是页面加载后的第一次认证。同步可变页面状态，使后续
  // LOGOUT 使用真实用户名，而不是服务端渲染时可能为空的快照。
  // CHECKAUTH may be the page's first completed authentication. Synchronize
  // mutable page state so a later LOGOUT uses the real user, not a stale empty
  // server-rendered snapshot.
  context.data.user = user;
  context.dom.logoutButton.classList.remove("hidden");
  context.dom.userName.textContent = user;
  return user;
}

/** @extends {UploadScheduler<Uploader>} */
class TypedUploadScheduler extends UploadScheduler {}

/**
 * 一个浏览器上传任务。状态由 `uploadScheduler` 统一拥有，XHR 终止事件委托给调度器，
 * 因此可重复触发而不会重复释放并发槽。
 *
 * One browser upload job. Its state is owned by `uploadScheduler`; XHR terminal
 * events delegate back to the scheduler and are therefore idempotent.
 */
class Uploader {
  static nextId = 0;

  /**
   * @param {import("./ui-state.js").AppContext} context
   * @param {File} file
   * @param {string[]} pathParts
   */
  constructor(context, file, pathParts) {
    this.context = context;
    /** @type {File | null} */
    this.file = file;
    this.name = [...pathParts, file.name].join("/");
    this.url = resourceUrl(this.name);
    this.id = Uploader.nextId++;
    /** @type {UploadState} */
    this.state = "new";
    /** @type {HTMLTableCellElement | null} */
    this.statusCell = null;
    /** @type {XMLHttpRequest | null} */
    this.request = null;
    this.uploaded = 0;
    this.lastUpdate = 0;
  }

  upload() {
    const row = document.createElement("tr");
    row.id = `upload${this.id}`;
    row.className = "uploader";
    const iconCell = document.createElement("td");
    iconCell.className = "path cell-icon";
    iconCell.append(createIcon("file"));
    const nameCell = document.createElement("td");
    nameCell.className = "path cell-name";
    const link = document.createElement("a");
    link.href = this.url;
    link.textContent = this.name;
    nameCell.append(link);
    const statusCell = document.createElement("td");
    statusCell.className = "cell-status upload-status";
    statusCell.id = `uploadStatus${this.id}`;
    statusCell.setAttribute("aria-live", "polite");
    row.append(iconCell, nameCell, statusCell);
    // 中文：动态行必须位于显式 tbody 内。把 tr 直接挂到 table 上虽然
    // 某些浏览器会视觉容错，但会破坏 DOM 表格模型和辅助技术的行归属。
    // English: dynamic rows belong in an explicit tbody. Appending tr directly
    // to table may look acceptable through browser recovery, but violates the
    // DOM table model and can detach rows from their table for assistive tech.
    this.context.dom.uploadersTableBody.append(row);
    this.context.dom.uploadersTable.classList.remove("hidden");
    this.context.dom.emptyFolder.classList.add("hidden");
    this.statusCell = statusCell;
    this.enqueue();
  }

  enqueue() {
    if (!uploadScheduler.enqueue(this)) return;
    this.renderQueued();
  }

  renderQueued() {
    if (!this.statusCell) return;
    this.statusCell.closest("tr")?.setAttribute("data-upload-state", "queued");
    const label = document.createElement("span");
    label.textContent = "Queued ";
    const cancel = document.createElement("button");
    cancel.type = "button";
    cancel.className = "cancel-upload-btn";
    cancel.textContent = "Cancel";
    cancel.setAttribute("aria-label", `Cancel upload of ${this.name}`);
    cancel.addEventListener("click", () => this.cancel());
    this.statusCell.replaceChildren(label, cancel);
  }

  async start() {
    if (this.state !== "running") return;
    await authenticate(this.context);
    if (this.state !== "running") return;
    this.startRequest();
  }

  startRequest() {
    const file = this.file;
    if (!file) {
      this.fail("The browser released the selected file");
      return;
    }
    this.uploaded = 0;
    this.lastUpdate = performance.now();
    const xhr = new XMLHttpRequest();
    this.request = xhr;
    let responseRejected = false;
    /** @param {string} reason */
    const rejectResponse = reason => {
      if (responseRejected) return;
      responseRejected = true;
      this.fail(reason);
      xhr.abort();
    };
    xhr.upload.addEventListener("progress", event => this.progress(event));
    // XHR 会自动缓冲响应；即使 PUT 请求体受服务端限制，恶意代理仍可以
    // 返回巨大错误页。声明长度用于提前终止，download progress 限制实际字节，
    // load 边界最后复核 ArrayBuffer 大小。
    // XHR buffers responses automatically. A malicious proxy could return a
    // huge error page even though the PUT body is server-bounded, so declared
    // length, download progress, and the final ArrayBuffer are all checked.
    xhr.addEventListener("readystatechange", () => {
      if (xhr.readyState !== XMLHttpRequest.HEADERS_RECEIVED) return;
      const declared = xhr.getResponseHeader("content-length");
      if (declared === null) return;
      if (!/^\d+$/.test(declared) || !Number.isSafeInteger(Number(declared))) {
        rejectResponse("Upload response had an invalid Content-Length");
      } else if (Number(declared) > MAX_API_ERROR_BODY_BYTES) {
        rejectResponse(`Upload response exceeded ${MAX_API_ERROR_BODY_BYTES} bytes`);
      }
    });
    xhr.addEventListener("progress", event => {
      if (event.loaded > MAX_API_ERROR_BODY_BYTES) {
        rejectResponse(`Upload response exceeded ${MAX_API_ERROR_BODY_BYTES} bytes`);
      }
    });
    xhr.addEventListener("load", () => {
      if (responseRejected) return;
      const responseBytes = xhr.response instanceof ArrayBuffer ? xhr.response.byteLength : 0;
      if (responseBytes > MAX_API_ERROR_BODY_BYTES) {
        rejectResponse(`Upload response exceeded ${MAX_API_ERROR_BODY_BYTES} bytes`);
        return;
      }
      if (xhr.status >= 200 && xhr.status < 300) this.complete();
      else this.fail(`${xhr.status} ${xhr.statusText}`.trim());
    });
    xhr.addEventListener("error", () => this.fail("Network error"));
    xhr.addEventListener("abort", () => {
      if (this.state !== "cancelled") this.fail("Upload aborted");
    });
    xhr.addEventListener("timeout", () => this.fail("Upload request timed out"));
    xhr.open("PUT", this.url);
    xhr.responseType = "arraybuffer";
    xhr.timeout = REQUEST_TOTAL_TIMEOUT_MS;
    // 目录上传没有显式的“覆盖”决策点，因此默认只创建。同名文件在服务端
    // 最终变更锁内返回 412，不会因两个页面并发上传而静默丢失数据。
    // Directory upload has no explicit overwrite decision, so it is create-only.
    // The server evaluates this condition under the final mutation lock and
    // returns 412 instead of silently losing data from concurrent pages.
    xhr.setRequestHeader("If-None-Match", "*");
    xhr.send(file);
    this.renderRunning();
  }

  renderRunning() {
    if (!this.statusCell) return;
    this.statusCell.closest("tr")?.setAttribute("data-upload-state", "running");
    const label = document.createElement("span");
    label.textContent = "Uploading ";
    const cancel = document.createElement("button");
    cancel.type = "button";
    cancel.className = "cancel-upload-btn";
    cancel.textContent = "Cancel";
    cancel.setAttribute("aria-label", `Cancel upload of ${this.name}`);
    cancel.addEventListener("click", () => this.cancel());
    this.statusCell.replaceChildren(label, cancel);
  }

  /** @param {ProgressEvent<XMLHttpRequestEventTarget>} event */
  progress(event) {
    if (this.state !== "running" || !this.statusCell || !this.file) return;
    // 中文：速度采样使用单调时钟，系统校时不会产生负速度或假的剩余时间。
    // English: sample transfer speed with a monotonic clock so a wall-clock
    // adjustment cannot produce negative speed or a fabricated ETA.
    const now = performance.now();
    const elapsed = now - this.lastUpdate;
    if (elapsed < 300) return;
    const speed = (event.loaded - this.uploaded) / elapsed * 1000;
    const [speedValue, speedUnit] = formatFileSize(speed);
    const percent = this.file.size === 0 ? 100 : event.loaded / this.file.size * 100;
    const duration = formatDuration((event.total - event.loaded) / speed);
    const progress = document.createElement("span");
    progress.textContent = `${formatPercent(percent)} ${duration} · ${speedValue} ${speedUnit}/s `;
    const cancel = document.createElement("button");
    cancel.type = "button";
    cancel.className = "cancel-upload-btn";
    cancel.textContent = "Cancel";
    cancel.setAttribute("aria-label", `Cancel upload of ${this.name}`);
    cancel.addEventListener("click", () => this.cancel());
    this.statusCell.replaceChildren(progress, cancel);
    this.uploaded = event.loaded;
    this.lastUpdate = now;
  }

  complete() {
    if (!uploadScheduler.settle(this, "complete")) return;
    this.request = null;
    this.file = null;
    if (this.statusCell) {
      this.statusCell.closest("tr")?.setAttribute("data-upload-state", "complete");
      this.statusCell.textContent = "✓ Complete";
    }
    const listingVersionWasAvailable = this.context.data.kind === "Index"
      && this.context.data.mutation_version !== null;
    invalidateListingMutationVersion(this.context);
    if (listingVersionWasAvailable && this.context.data.allow_delete) {
      // 中文：成功 PUT 已推进服务端 mutation revision。多个并发上传可能近乎同时
      // 完成，但只有第一个完成者需要重绘；令牌置空是幂等的，重绘会立即移除所有
      // 仍携带旧列表版本的 DELETE/MOVE 控件并展示刷新提示。
      // English: a successful PUT advances the server mutation revision.
      // Concurrent uploads may finish together, but only the first completion
      // needs to rerender: nulling the token is idempotent, removes every
      // DELETE/MOVE control carrying the stale listing version, and exposes the
      // refresh notice immediately.
      renderPathsTable(this.context);
      renderListingNotice(this.context);
    }
  }

  /** @param {string} [reason] */
  fail(reason = "") {
    if (!uploadScheduler.settle(this, "failed")) return;
    this.request = null;
    if (!this.statusCell) return;
    this.statusCell.closest("tr")?.setAttribute("data-upload-state", "failed");
    const failure = document.createElement("span");
    // 中文：错误原因需要是可见文本，不能只放在 title；触屏和屏幕阅读器
    // 用户通常无法发现 hover tooltip。服务端诊断仍受网络层的字节上限。
    // English: make the reason visible rather than title-only; touch and screen
    // reader users generally cannot discover hover tooltips. Server diagnostics
    // remain bounded by the network-layer byte budget.
    failure.textContent = reason ? `✗ Failed: ${reason} ` : "✗ Failed ";
    failure.title = reason;
    const retry = document.createElement("button");
    retry.type = "button";
    retry.className = "retry-btn";
    retry.textContent = "↻ Retry";
    retry.setAttribute("aria-label", `Retry upload of ${this.name}`);
    retry.addEventListener("click", () => this.retry());
    this.statusCell.replaceChildren(failure, retry);
  }

  retry() {
    if (this.state !== "failed") return;
    this.enqueue();
  }

  cancel() {
    if (!uploadScheduler.cancel(this)) return;
    const request = this.request;
    this.request = null;
    request?.abort();
    if (!this.statusCell) return;
    this.statusCell.closest("tr")?.setAttribute("data-upload-state", "cancelled");
    const cancelled = document.createElement("span");
    cancelled.textContent = "Cancelled ";
    const retry = document.createElement("button");
    retry.type = "button";
    retry.className = "retry-btn";
    retry.textContent = "↻ Retry";
    retry.setAttribute("aria-label", `Retry cancelled upload of ${this.name}`);
    retry.addEventListener("click", () => this.retryCancelled());
    this.statusCell.replaceChildren(cancelled, retry);
  }

  retryCancelled() {
    if (this.state !== "cancelled") return;
    this.state = "new";
    this.enqueue();
  }
}

const uploadScheduler = new TypedUploadScheduler(MAX_CONCURRENT_UPLOADS, uploader => uploader.start());

/** @param {import("./ui-state.js").AppContext} context */
export async function setupIndexPage(context) {
  const { data, dom } = context;
  if (data.allow_archive) {
    const download = requireElement(".download", HTMLAnchorElement);
    download.href = `${resourceUrl()}?zip`;
    download.title = "Download folder as a .zip file";
    download.classList.add("dlwt");
    // 中文：目录 ZIP 的长度直到流结束才知道，服务端已经用 Content-Disposition: attachment
    // 指定下载。WebKit 会挂起同时带空 download 属性的未知长度响应，因此目录归档移除该
    // 冗余属性；普通文件页仍保留 HTML 原生 download 提示。
    // English: A directory ZIP has no length until its stream finishes, and the server already
    // marks it as Content-Disposition: attachment. WebKit can stall an unknown-length response when
    // the link also has an empty download attribute, so archives remove that redundant attribute;
    // ordinary file pages retain the native HTML download hint.
    download.removeAttribute("download");
    download.classList.remove("hidden");
  }
  if (data.allow_upload) {
    setupDropzone(context);
    setupUploadInput(context);
    setupCreateControls(context);
  }
  if (data.allow_search) setupSearch(context);
  renderPathsTableHead(context);
  renderPathsTable(context);
  renderListingNotice(context);
}

/** @param {import("./ui-state.js").AppContext} context */
function renderListingNotice(context) {
  const { data, dom, params } = context;
  const mutationSnapshotUnavailable = data.allow_delete && data.mutation_version === null;
  if (!data.truncated && !data.omitted_non_utf8 && !mutationSnapshotUnavailable) return;
  const messages = [];
  if (data.truncated) {
    messages.push(params.q
      ? "Search results were truncated at the server limit. Refine the search to see a narrower result set."
      : "This directory contains more entries than the server returns in one response. The list below is incomplete.");
  }
  if (data.omitted_non_utf8) {
    messages.push(data.allow_archive
      ? "Some Linux entries have non-UTF-8 names and are omitted from this view. Download the folder as ZIP for a lossless representation."
      : "Some Linux entries have non-UTF-8 names and are omitted from this view.");
  }
  if (mutationSnapshotUnavailable) {
    messages.push("Delete and move actions are disabled because no stable directory snapshot is available. Refresh to try again.");
  }
  dom.listingNotice.textContent = messages.join(" ");
  dom.listingNotice.classList.remove("hidden");
}

/** @param {import("./ui-state.js").AppContext} context */
function renderPathsTableHead(context) {
  const items = [
    { name: "name", colSpan: 2, text: "Name" },
    { name: "mtime", colSpan: 1, text: "Last Modified" },
    { name: "size", colSpan: 1, text: "Size" },
  ];
  const row = document.createElement("tr");
  // 中文：服务端在没有 sort 参数时依然按名称升序，该默认也是
  // 真实排序状态，不能把列头画成“未排序”。显式的未知 sort 值仍保持
  // 未选中，与服务端对该异常查询的行为一致。
  // English: the server sorts by name ascending when `sort` is absent, so the
  // default is a real sort state rather than "unsorted". An explicit unknown
  // value remains unselected, matching the server's anomalous-query behavior.
  const currentSort = Object.hasOwn(context.params, "sort") ? context.params.sort : "name";
  for (const item of items) {
    let iconName = /** @type {"sortBoth"|"sortDown"|"sortUp"} */ ("sortBoth");
    let order = "desc";
    if (currentSort === item.name) {
      if (context.params.order === "desc") {
        order = "asc";
        iconName = "sortDown";
      } else {
        iconName = "sortUp";
      }
    }
    const query = new URLSearchParams({ ...context.params, order, sort: item.name });
    const header = document.createElement("th");
    header.scope = "col";
    header.className = `cell-${item.name}`;
    header.colSpan = item.colSpan;
    if (currentSort === item.name) {
      // 中文：图标只是视觉提示；`aria-sort` 把当前（而非点击后）排序方向
      // 附着在真正的列头上，让辅助技术获得与视觉用户相同的状态。
      // English: the icon is only a visual hint. `aria-sort` exposes the current
      // (not next-click) direction on the actual column header to assistive tech.
      header.setAttribute("aria-sort", context.params.order === "desc" ? "descending" : "ascending");
    }
    const link = document.createElement("a");
    link.href = `?${query}`;
    link.append(document.createTextNode(item.text));
    const icon = document.createElement("span");
    icon.append(createIcon(iconName));
    link.append(icon);
    header.append(link);
    row.append(header);
  }
  const actions = document.createElement("th");
  actions.scope = "col";
  actions.className = "cell-actions";
  actions.textContent = "Actions";
  row.append(actions);
  context.dom.pathsTableHead.replaceChildren(row);
}

/**
 * @param {import("./ui-state.js").AppContext} context
 * @param {number} [focusIndex]
 */
function renderPathsTable(context, focusIndex) {
  const { data, dom } = context;
  dom.pathsTableBody.replaceChildren();
  if (data.paths.length === 0) {
    dom.pathsTable.classList.add("hidden");
    dom.emptyFolder.textContent = context.emptyNote;
    dom.emptyFolder.classList.remove("hidden");
    if (focusIndex !== undefined) {
      dom.emptyFolder.tabIndex = -1;
      dom.emptyFolder.focus();
    }
    return;
  }
  dom.emptyFolder.classList.add("hidden");
  dom.pathsTable.classList.remove("hidden");
  data.paths.forEach((item, index) => dom.pathsTableBody.append(createPathRow(context, item, index)));
  if (focusIndex !== undefined) {
    const targetIndex = Math.min(focusIndex, data.paths.length - 1);
    const target = dom.pathsTableBody.querySelector(`#addPath${targetIndex} .action-btn, #addPath${targetIndex} a`);
    if (target instanceof HTMLElement) target.focus();
  }
}

/**
 * @param {import("./ui-state.js").AppContext} context
 * @param {import("./ui-state.js").PathItem} item
 * @param {number} index
 */
function createPathRow(context, item, index) {
  let url = resourceUrl(item.name);
  const isDirectory = item.path_type.endsWith("Dir");
  if (isDirectory) url += "/";
  const row = document.createElement("tr");
  row.id = `addPath${index}`;
  const iconCell = document.createElement("td");
  iconCell.className = "path cell-icon";
  iconCell.append(createIcon(pathIconName(item.path_type)));
  const nameCell = document.createElement("td");
  nameCell.className = "path cell-name";
  const nameLink = document.createElement("a");
  nameLink.href = url;
  nameLink.textContent = item.name;
  if (!isDirectory) {
    nameLink.target = "_blank";
    nameLink.rel = "noopener";
  }
  nameCell.append(nameLink);
  const modified = document.createElement("td");
  modified.className = "cell-mtime";
  modified.textContent = formatMtime(item.mtime);
  const size = document.createElement("td");
  size.className = "cell-size";
  size.textContent = isDirectory
    ? formatDirSize(item.size, item.size_known, MAX_SUBPATHS_COUNT)
    : formatFileSize(item.size).join(" ");
  const actions = document.createElement("td");
  actions.className = "cell-actions";
  if ((isDirectory && context.data.allow_archive) || !isDirectory) {
    const tokenDownloadLimit = isDirectory ? undefined : browserTokenDownloadLimit(item.size);
    actions.append(createActionLink("download", isDirectory ? `${url}?zip` : url,
      isDirectory ? "Download folder as a .zip file" : "Download file",
      isDirectory ? `Download ${item.name} as a zip file` : `Download ${item.name}`, true,
      tokenDownloadLimit, !isDirectory));
  }
  let hasEdit = false;
  if (context.data.allow_delete) {
    if (context.data.allow_upload) {
      if (context.data.mutation_version !== null) {
        const move = createActionButton("move", "Move and rename", `Move or rename ${item.name}`);
        move.addEventListener("click", async () => {
          const destination = await movePathInteractive(context, url);
          if (destination) window.location.assign(new URL(".", destination).href);
        });
        actions.append(move);
      }
      if (!isDirectory) {
        actions.append(createActionLink("edit", `${url}?edit`, "Edit file", `Edit ${item.name}`));
        hasEdit = true;
      }
    }
    if (context.data.mutation_version !== null) {
      const remove = createActionButton("delete", "Delete", `Delete ${item.name}`);
      remove.addEventListener("click", async () => {
        if (remove.disabled) return;
        remove.disabled = true;
        if (await deletePathInteractive(context, item.name, url)) {
          const currentIndex = removePathItem(context.data.paths, item);
          if (currentIndex !== undefined) renderPathsTable(context, currentIndex);
          renderListingNotice(context);
        } else {
          remove.disabled = false;
        }
      });
      actions.append(remove);
    }
  }
  if (!hasEdit && !isDirectory) actions.append(createActionLink("view", `${url}?view`, "View file", `View ${item.name}`));
  row.append(iconCell, nameCell, modified, size, actions);
  return row;
}

/**
 * 按稳定对象身份删除已渲染项，而不使用创建闭包时的索引。当两个 DELETE
 * 逆序完成时，前一次 splice 会改变后续索引；对象身份仍然不变。
 *
 * Remove a rendered item by stable object identity, never by the index captured
 * when its closure was created. An earlier concurrent DELETE may shift every
 * later index, while the item identity remains stable.
 *
 * @param {import("./ui-state.js").PathItem[]} paths
 * @param {import("./ui-state.js").PathItem} item
 * @returns {number | undefined}
 */
export function removePathItem(paths, item) {
  const index = paths.indexOf(item);
  if (index < 0) return undefined;
  paths.splice(index, 1);
  return index;
}

/**
 * @param {import("./icons.js").IconName} iconName
 * @param {string} href
 * @param {string} title
 * @param {string} label
 * @param {boolean} [download]
 * @param {number} [tokenDownloadLimit]
 * @param {boolean} [downloadAttribute]
 */
function createActionLink(iconName, href, title, label, download = false, tokenDownloadLimit,
  downloadAttribute = download) {
  const link = document.createElement("a");
  link.className = download ? "action-btn dlwt" : "action-btn";
  link.href = href;
  link.title = title;
  link.setAttribute("aria-label", label);
  if (download) {
    if (downloadAttribute) link.download = "";
    if (tokenDownloadLimit !== undefined) {
      link.dataset.tokenDownloadLimit = String(tokenDownloadLimit);
    }
  }
  else {
    link.target = "_blank";
    link.rel = "noopener";
  }
  link.append(createIcon(iconName));
  return link;
}

/**
 * @param {import("./icons.js").IconName} iconName
 * @param {string} title
 * @param {string} label
 */
function createActionButton(iconName, title, label) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "action-btn";
  button.title = title;
  button.setAttribute("aria-label", label);
  button.append(createIcon(iconName));
  return button;
}

/** @param {import("./ui-state.js").AppContext} context */
export function setupAuthentication(context) {
  const { data, dom } = context;
  dom.userName.textContent = data.user;
  if (data.user) {
    dom.logoutButton.classList.remove("hidden");
    setupTokenDownloads();
  }
  dom.logoutButton.addEventListener("click", async () => {
    dom.logoutButton.disabled = true;
    try {
      await logOut(resourceUrl(), data.user);
      window.location.assign(resourceUrl());
    } catch (error) {
      window.alert(`Logout failed: ${errorMessage(error)}`);
      dom.logoutButton.disabled = false;
    }
  });
}

function setupTokenDownloads() {
  document.addEventListener("click", async event => {
    if (!(event instanceof MouseEvent) || event.button !== 0 || event.defaultPrevented) return;
    if (event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
    const target = event.target instanceof Element ? event.target.closest("a.dlwt") : null;
    if (!(target instanceof HTMLAnchorElement)) return;
    const rawLimit = target.dataset.tokenDownloadLimit;
    // 中文：未知大小的归档和已知大文件保留浏览器原生流式下载路径。
    // English: Unknown-size archives and known-large files stay on the browser's native streaming path.
    if (rawLimit === undefined) return;
    const limit = Number(rawLimit);
    if (!Number.isSafeInteger(limit) || limit < 0) return;
    // 中文：第二个并发点击也走浏览器流式路径，使 JavaScript 同时只缓冲一个小文件。
    // English: A simultaneous second click also streams natively, bounding JavaScript buffering to one small file.
    if (tokenDownloadActive) return;
    event.preventDefault();
    tokenDownloadActive = true;
    try {
      const blob = await downloadWithToken(target.href, limit);
      const objectUrl = URL.createObjectURL(blob);
      const download = document.createElement("a");
      download.href = objectUrl;
      const pathname = new URL(target.href).pathname;
      const rawName = pathname.split("/").filter(Boolean).at(-1);
      const name = rawName ? decodeURIComponent(rawName) : "download";
      download.download = new URL(target.href).searchParams.has("zip") ? `${name}.zip` : name;
      document.body.append(download);
      download.click();
      download.remove();
      setTimeout(() => URL.revokeObjectURL(objectUrl), 0);
    } catch {
      // 中文：token 支持是可选的；未配置密钥时保留普通认证下载。
      // English: Token support is optional; preserve ordinary authenticated downloads when no key is configured.
      const fallback = document.createElement("a");
      fallback.href = target.href;
      fallback.download = target.download;
      document.body.append(fallback);
      fallback.click();
      fallback.remove();
    } finally {
      tokenDownloadActive = false;
    }
  });
}

/** @param {import("./ui-state.js").AppContext} context */
function setupSearch(context) {
  const form = requireElement(".searchbar", HTMLFormElement);
  form.classList.remove("hidden");
  form.addEventListener("submit", event => {
    event.preventDefault();
    const query = new FormData(form).get("q");
    window.location.assign(typeof query === "string" && query
      ? `${resourceUrl()}?q=${encodeURIComponent(query)}`
      : resourceUrl());
  });
  if (context.params.q) requireElement("#search", HTMLInputElement).value = context.params.q;
}

/** @param {import("./ui-state.js").AppContext} context */
function setupUploadInput(context) {
  const button = requireElement(".upload-file", HTMLButtonElement);
  const input = requireElement("#file", HTMLInputElement);
  const folderButton = requireElement(".upload-folder", HTMLButtonElement);
  const folderInput = requireElement("#folder", HTMLInputElement);
  button.classList.remove("hidden");
  folderButton.classList.remove("hidden");
  button.addEventListener("click", () => input.click());
  input.addEventListener("change", () => {
    enqueueSelectedFiles(context, input.files ?? [], false);
    input.value = "";
  });
  folderButton.addEventListener("click", () => folderInput.click());
  folderInput.addEventListener("change", () => {
    enqueueSelectedFiles(context, folderInput.files ?? [], true);
    folderInput.value = "";
  });
}

/**
 * @param {import("./ui-state.js").AppContext} context
 * @param {File} file
 * @param {string[]} directories
 */
function enqueueUpload(context, file, directories) {
  while (context.dom.uploadersTable.querySelectorAll("tr.uploader").length >= MAX_UPLOAD_ROWS) {
    const completed = context.dom.uploadersTable.querySelector("tr.uploader[data-upload-state='complete']");
    if (!completed) return false;
    completed.remove();
  }
  new Uploader(context, file, directories).upload();
  return true;
}

/**
 * @param {import("./ui-state.js").AppContext} context
 * @param {Iterable<File>} files
 * @param {boolean} requireRelativePath
 */
function enqueueSelectedFiles(context, files, requireRelativePath) {
  let rejected = 0;
  for (const file of files) {
    try {
      const directories = uploadDirectoryParts(file, requireRelativePath);
      if (!enqueueUpload(context, file, directories)) {
        rejected += 1;
        break;
      }
    } catch {
      rejected += 1;
    }
  }
  if (rejected > 0) {
    window.alert(
      `Some files were not queued. A selection may contain at most ${MAX_UPLOAD_ROWS} retained uploads, `
      + `use at most ${MAX_UPLOAD_TREE_DEPTH} directory levels, and cannot contain . or .. path segments.`,
    );
  }
}

/** @param {import("./ui-state.js").AppContext} context */
function setupCreateControls(context) {
  const folder = requireElement(".new-folder", HTMLButtonElement);
  folder.classList.remove("hidden");
  folder.addEventListener("click", async () => {
    const name = window.prompt("Enter folder name");
    if (!name) return;
    if (!isSafePathSegment(name)) {
      window.alert("A folder name must be one path segment and cannot be . or ..");
      return;
    }
    try {
      await authenticate(context);
      const url = resourceUrl(name);
      await createDirectory(url);
      window.location.assign(`${url}/`);
    } catch (error) {
      window.alert(`Cannot create folder \`${name}\`: ${errorMessage(error)}`);
    }
  });
  const file = requireElement(".new-file", HTMLButtonElement);
  file.classList.remove("hidden");
  file.addEventListener("click", async () => {
    const name = window.prompt("Enter file name");
    if (!name) return;
    if (!isSafePathSegment(name)) {
      window.alert("A file name must be one path segment and cannot be . or ..");
      return;
    }
    try {
      await authenticate(context);
      const url = resourceUrl(name);
      await createEmptyFile(url);
      window.location.assign(`${url}?edit`);
    } catch (error) {
      window.alert(`Cannot create file \`${name}\`: ${errorMessage(error)}`);
    }
  });
}

/**
 * @typedef {object} DroppedItemSelection
 * @property {FileSystemEntry[]} entries
 * @property {File[]} files
 * @property {number} unreadableFileItems
 */

/**
 * 把 DataTransfer 的标准 FileList 与非标准 FileSystemEntry 视图解析成无重复的上传计划。
 * 文本 item 不参与文件计数；没有 Entry API，或没有目录且任一 file item 返回 null 时，
 * 整体回退到 FileList。只要存在目录 Entry，就不能整体回退（FileList 可能重复或展平目录
 * 内容）；此时仅用对应 item.getAsFile() 恢复 null 的顶层文件，仍无法读取的 item 必须
 * 计数并由调用方明确提示。
 *
 * Resolve the standard FileList and non-standard FileSystemEntry views into a
 * duplicate-free upload plan. Text items do not count as files. If the Entry
 * API is absent—or any file item returns null and no directory entry exists—
 * fall back to the complete FileList. Once a directory entry exists, never use
 * that whole list because it may duplicate or flatten directory contents;
 * recover only a null top-level item through its own getAsFile(), and count any
 * item still unreadable so the caller can report it explicitly.
 *
 * @param {ArrayLike<DataTransferItem>} items
 * @param {ArrayLike<File>} files
 * @returns {DroppedItemSelection}
 */
export function resolveDroppedItems(items, files) {
  const fallbackFiles = Array.from(files);
  /** @type {DataTransferItem[]} */
  const fileItems = [];
  for (let index = 0; index < items.length; index += 1) {
    const item = items[index];
    if (item?.kind === "file") fileItems.push(item);
  }
  if (fileItems.length === 0) {
    return { entries: [], files: fallbackFiles, unreadableFileItems: 0 };
  }

  /** @type {FileSystemEntry[]} */
  const entries = [];
  /** @type {DataTransferItem[]} */
  const unresolvedItems = [];
  let hasDirectoryEntry = false;
  for (const item of fileItems) {
    const getEntry = /** @type {DataTransferItem & {webkitGetAsEntry?: () => FileSystemEntry | null}} */ (item)
      .webkitGetAsEntry;
    /** @type {FileSystemEntry | null} */
    let entry = null;
    if (typeof getEntry === "function") {
      try {
        entry = getEntry.call(item);
      } catch {
        entry = null;
      }
    }
    if (entry) {
      entries.push(entry);
      if (entry.isDirectory) hasDirectoryEntry = true;
    } else {
      unresolvedItems.push(item);
    }
  }

  if (!hasDirectoryEntry && unresolvedItems.length > 0) {
    return {
      entries: [],
      files: fallbackFiles,
      unreadableFileItems: Math.max(0, fileItems.length - fallbackFiles.length),
    };
  }

  /** @type {File[]} */
  const directFiles = [];
  let unreadableFileItems = 0;
  for (const item of unresolvedItems) {
    let file = null;
    try {
      file = item.getAsFile();
    } catch {
      file = null;
    }
    if (file) directFiles.push(file);
    else unreadableFileItems += 1;
  }
  return { entries, files: directFiles, unreadableFileItems };
}

/** @param {import("./ui-state.js").AppContext} context */
function setupDropzone(context) {
  for (const name of ["drag", "dragstart", "dragend", "dragover", "dragenter", "dragleave", "drop"]) {
    document.addEventListener(name, event => {
      event.preventDefault();
      event.stopPropagation();
    });
  }
  document.addEventListener("drop", event => {
    if (!(event instanceof DragEvent) || !event.dataTransfer) return;
    const { items, files } = event.dataTransfer;
    const selection = resolveDroppedItems(items, files);
    if (selection.files.length > 0) {
      enqueueSelectedFiles(context, selection.files, false);
    }
    if (selection.unreadableFileItems > 0) {
      window.alert(
        `${selection.unreadableFileItems} dropped file or folder item(s) were not exposed by the browser and were not queued. `
        + "Retry them with the file or folder picker.",
      );
    }
    if (selection.entries.length === 0) return;
    void runDroppedEntryTraversal(
      selection.entries,
      (file, directories) => enqueueUpload(context, file, directories),
    ).catch(error => {
      window.alert(errorMessage(error));
    });
  });
}

/**
 * @typedef {object} UploadTraversal
 * @property {number} entries
 * @property {number} startedAt
 * @property {number} callbackTimeoutMs
 * @property {number} totalTimeoutMs
 */

/**
 * @typedef {object} UploadTraversalOptions
 * @property {number} [callbackTimeoutMs]
 * @property {number} [totalTimeoutMs]
 */

/** @param {number | undefined} value @param {number} fallback @param {string} name */
function traversalTimeout(value, fallback, name) {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < 1) {
    throw new TypeError(`${name} must be a positive safe integer`);
  }
  return result;
}

/**
 * 每个非标准 FileSystemEntry API 调用同时受单回调 idle 上限和整个遍历的
 * 绝对期限约束。浏览器扩展 API 若漏掉 success/error 回调，不能让页面永久保持
 * 半完成状态或无限压住 beforeunload 守卫。
 *
 * Bound every non-standard FileSystemEntry call by both a per-callback wait and
 * the traversal's absolute deadline. If a browser extension API omits both its
 * success and error callbacks, it must not leave the page half-finished or hold
 * the beforeunload guard forever.
 *
 * @param {UploadTraversal} traversal
 */
function nextTraversalCallbackTimeout(traversal) {
  const totalRemaining = traversal.totalTimeoutMs - (performance.now() - traversal.startedAt);
  if (totalRemaining <= 0) {
    throw new Error(`Folder traversal exceeded ${traversal.totalTimeoutMs} milliseconds`);
  }
  return Math.min(traversal.callbackTimeoutMs, totalRemaining);
}

/**
 * 记录一个浏览器拥有的不可取消回调，并返回幂等释放函数。超时刻意不释放该计数；
 * 只有 success/error（包括迟到回调）才能证明浏览器不再需要这组闭包。
 *
 * Track one uncancellable callback owned by the browser and return an idempotent
 * release function. A timeout deliberately retains the count: only a success or
 * error callback, including a late one, proves the browser no longer needs it.
 */
function retainUploadTraversalCallback() {
  unresolvedUploadTraversalCallbacks += 1;
  let retained = true;
  return () => {
    if (!retained) return;
    retained = false;
    unresolvedUploadTraversalCallbacks = Math.max(0, unresolvedUploadTraversalCallbacks - 1);
  };
}

/** @param {FileSystemFileEntry} entry @param {UploadTraversal} traversal @returns {Promise<File>} */
function readFileEntry(entry, traversal) {
  const timeoutMs = nextTraversalCallbackTimeout(traversal);
  return new Promise((resolve, reject) => {
    let settled = false;
    const timeout = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new Error(`Folder traversal timed out while reading ${entry.name}`));
    }, timeoutMs);
    const releaseCallback = retainUploadTraversalCallback();
    /** @param {File} file */
    const succeed = file => {
      releaseCallback();
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      resolve(file);
    };
    const fail = () => {
      releaseCallback();
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      reject(new Error(`The browser could not read dropped file ${entry.name}`));
    };
    try {
      entry.file(succeed, fail);
    } catch {
      fail();
    }
  });
}

/** @param {FileSystemDirectoryReader} reader @param {string} name @param {UploadTraversal} traversal @returns {Promise<FileSystemEntry[]>} */
function readDirectoryEntries(reader, name, traversal) {
  const timeoutMs = nextTraversalCallbackTimeout(traversal);
  return new Promise((resolve, reject) => {
    let settled = false;
    const timeout = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new Error(`Folder traversal timed out while enumerating ${name}`));
    }, timeoutMs);
    const releaseCallback = retainUploadTraversalCallback();
    /** @param {FileSystemEntry[]} entries */
    const succeed = entries => {
      releaseCallback();
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (!Array.isArray(entries)) {
        reject(new Error(`The browser returned an invalid directory batch for ${name}`));
      } else {
        resolve(entries);
      }
    };
    const fail = () => {
      releaseCallback();
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      reject(new Error(`The browser could not enumerate dropped folder ${name}`));
    };
    try {
      reader.readEntries(succeed, fail);
    } catch {
      fail();
    }
  });
}

/**
 * 以顺序深度优先方式处理浏览器返回的所有分批目录项。全局 entry 计数在
 * 类型分支前递增，因而文件、目录、模糊项和之后的 `readEntries()` 批次共用同一预算。
 * 每次递归都复制路径数组，避免迟到回调看到兄弟分支的可变路径。
 *
 * Process every browser-supplied directory batch with sequential depth-first
 * traversal. The global entry count advances before type dispatch, so files,
 * directories, ambiguous entries, and later `readEntries()` batches share one
 * budget. Each recursive call copies its path array so a late callback cannot
 * observe a mutable path from a sibling branch.
 *
 * @param {FileSystemEntry[]} entries
 * @param {string[]} directories
 * @param {UploadTraversal} traversal
 * @param {(file: File, directories: string[]) => boolean} onFile
 */
async function addFileEntries(entries, directories, traversal, onFile) {
  for (const entry of entries) {
    traversal.entries += 1;
    if (traversal.entries > MAX_UPLOAD_TREE_ENTRIES) {
      throw new Error(
        `Folder traversal stopped after ${MAX_UPLOAD_TREE_ENTRIES} entries. Select a smaller folder.`,
      );
    }
    if (!isSafePathSegment(entry.name)) {
      throw new Error("Folder traversal stopped at an unsafe . or .. path segment.");
    }
    if (entry.isFile === entry.isDirectory) {
      throw new Error(`Folder traversal returned an ambiguous entry type for ${entry.name}`);
    }
    if (entry.isFile) {
      const file = await readFileEntry(/** @type {FileSystemFileEntry} */ (entry), traversal);
      if (!isSafePathSegment(file.name) || file.name !== entry.name) {
        throw new Error(`The browser returned an inconsistent dropped-file name for ${entry.name}`);
      }
      if (!onFile(file, directories)) {
        throw new Error(`Folder upload stopped at the ${MAX_UPLOAD_ROWS}-file browser queue limit.`);
      }
    } else if (entry.isDirectory) {
      if (directories.length >= MAX_UPLOAD_TREE_DEPTH) {
        throw new Error(
          `Folder traversal stopped at the ${MAX_UPLOAD_TREE_DEPTH}-directory depth limit.`,
        );
      }
      /** @type {FileSystemDirectoryReader} */
      let reader;
      try {
        reader = /** @type {FileSystemDirectoryEntry} */ (entry).createReader();
      } catch {
        throw new Error(`The browser could not enumerate dropped folder ${entry.name}`);
      }
      while (true) {
        const batch = await readDirectoryEntries(reader, entry.name, traversal);
        if (batch.length === 0) break;
        await addFileEntries(batch, [...directories, entry.name], traversal, onFile);
      }
    } else {
      throw new Error("Folder traversal returned an unsupported entry type.");
    }
  }
}

/**
 * 运行一次有界拖放遍历，并把整个异步枚举期计入 `uploadState.pending`。
 * 这样 FileSystemEntry 尚未回调、还没有 Uploader 入队时，离页守卫也不会误判为空闲。
 * 顺序枚举还把单次遍历的活跃浏览器回调数限制为 1；全局准入限制则拒绝重叠遍历，
 * 避免连续拖放绕过单次预算并同时保留多组闭包和 FileSystemEntry 对象。
 *
 * Run one bounded drop traversal and include its full asynchronous lifetime in
 * `uploadState.pending`. The unload guard therefore remains accurate before a
 * FileSystemEntry callback has produced an Uploader. Sequential enumeration
 * also caps callbacks within one traversal at one. A global admission limit
 * rejects overlapping traversals so repeated drops cannot bypass the per-run
 * budget and retain multiple sets of closures and FileSystemEntry objects.
 *
 * @param {FileSystemEntry[]} entries
 * @param {(file: File, directories: string[]) => boolean} onFile
 * @param {UploadTraversalOptions} [options]
 */
export async function runDroppedEntryTraversal(entries, onFile, options = {}) {
  if (!Array.isArray(entries)) throw new TypeError("dropped entries must be an array");
  if (typeof onFile !== "function") throw new TypeError("dropped-file callback must be a function");
  const traversal = {
    entries: 0,
    startedAt: performance.now(),
    callbackTimeoutMs: traversalTimeout(
      options.callbackTimeoutMs,
      UPLOAD_TRAVERSAL_CALLBACK_TIMEOUT_MS,
      "callbackTimeoutMs",
    ),
    totalTimeoutMs: traversalTimeout(
      options.totalTimeoutMs,
      UPLOAD_TRAVERSAL_TOTAL_TIMEOUT_MS,
      "totalTimeoutMs",
    ),
  };
  if (activeUploadTraversals >= MAX_CONCURRENT_UPLOAD_TRAVERSALS
    || unresolvedUploadTraversalCallbacks > 0) {
    throw new Error(
      "Another dropped-folder traversal is already in progress, or its browser callback is still unresolved. Wait for it to finish and try again.",
    );
  }
  activeUploadTraversals += 1;
  try {
    await addFileEntries(entries, [], traversal, onFile);
  } finally {
    activeUploadTraversals = Math.max(0, activeUploadTraversals - 1);
  }
}

/**
 * @param {import("./ui-state.js").AppContext} context
 * @param {string} name
 * @param {string} url
 * @param {string} [sourceEtag]
 */
export async function deletePathInteractive(context, name, url, sourceEtag) {
  if (!window.confirm(`Delete \`${name}\`?`)) return false;
  try {
    await authenticate(context);
    await deleteResource(url, mutationVersionForListAction(context), sourceEtag);
    invalidateListingMutationVersion(context);
    return true;
  } catch (error) {
    if (error instanceof ApiError && error.status === 412) {
      const changed = sourceEtag === undefined
        ? "The directory changed since this listing was loaded. Refresh before trying again."
        : "The file changed on the server since this page was loaded. Reload before trying again.";
      window.alert(`Cannot delete \`${name}\`: ${changed}`);
    } else {
      window.alert(`Cannot delete \`${name}\`: ${errorMessage(error)}`);
    }
    return false;
  }
}

/**
 * @param {import("./ui-state.js").AppContext} context
 * @param {string} sourceUrl
 * @param {string} [sourceEtag]
 */
export async function movePathInteractive(context, sourceUrl, sourceEtag) {
  const source = new URL(sourceUrl);
  const prefix = context.data.uri_prefix.replace(/\/$/, "");
  const oldPath = decodeURIComponent(source.pathname.slice(prefix.length));
  let newPath = window.prompt("Enter new path", oldPath);
  if (!newPath) return undefined;
  try {
    newPath = validateMovePath(newPath);
  } catch (error) {
    window.alert(`Cannot use destination \`${newPath}\`: ${errorMessage(error)}`);
    return undefined;
  }
  if (newPath === oldPath) return undefined;
  const destination = source.origin + prefix + newPath.split("/").map(encodeURIComponent).join("/");
  try {
    await authenticate(context);
    const probe = await resourceExists(destination);
    if (probe.status === 200) {
      // HEAD 与 MOVE Overwrite:T 之间无法用 Ram 当前的 DAV 子集对目标 ETag 做
      // tagged `If` 原子约束。浏览器 UI 因此拒绝覆盖，避免“确认之后、MOVE 之前”
      // 被其他客户端更新的文件静默丢失。
      // Ram's current DAV subset cannot bind the destination ETag atomically
      // across HEAD and MOVE Overwrite:T with a tagged `If` condition. The web
      // UI therefore refuses overwrite rather than losing a version created
      // after the user's probe.
      window.alert("The destination already exists. Delete it explicitly before moving this item.");
      return undefined;
    } else if (probe.status !== 404) {
      await assertResponseOk(probe);
    }
    await moveResource(
      sourceUrl,
      destination,
      false,
      mutationVersionForListAction(context),
      sourceEtag,
    );
    invalidateListingMutationVersion(context);
    return destination;
  } catch (error) {
    if (error instanceof ApiError && error.status === 412) {
      const changed = sourceEtag === undefined
        ? "The directory changed since this listing was loaded. Refresh before trying again."
        : "The source file changed on the server since this page was loaded. Reload before trying again.";
      window.alert(`Cannot move \`${oldPath}\` to \`${newPath}\`: ${changed}`);
    } else {
      window.alert(`Cannot move \`${oldPath}\` to \`${newPath}\`: ${errorMessage(error)}`);
    }
    return undefined;
  }
}

export const uploadState = {
  get active() { return uploadScheduler.active; },
  // 中文：pending 包含尚在枚举且还未生成上传作业的拖放目录。
  // English: Pending work includes dropped directories still being enumerated before jobs exist.
  get pending() { return uploadScheduler.pending + activeUploadTraversals; },
};
