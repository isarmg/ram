/**
 * 前端 HTTP 边界层。本模块只负责把用户操作翻译为有类型的网络请求，并在数据
 * 进入 DOM、Authorization 头或浏览器 Blob 前执行字节级上限。`Content-Length`
 * 只是提前拒绝的优化，流中实际收到的字节数才是最终依据。
 *
 * Frontend HTTP boundary. This module translates UI operations into typed
 * requests and applies byte budgets before data reaches the DOM, an
 * Authorization header, or a browser Blob. `Content-Length` is only an
 * early-rejection optimization; received stream bytes remain authoritative.
 */

/** 文件服务器返回的有类型非成功响应。 / A typed non-success HTTP response returned by the file server. */
export class ApiError extends Error {
  /**
   * @param {number} status
   * @param {string} statusText
   * @param {string} body
   */
  constructor(status, statusText, body) {
    super(body || `${status} ${statusText || "request failed"}`);
    this.name = "ApiError";
    this.status = status;
    this.statusText = statusText;
    this.body = body;
  }
}

export const MAX_API_ERROR_BODY_BYTES = 64 * 1024;
export const MAX_AUTHENTICATED_USERNAME_BYTES = 256;
export const MAX_BEARER_TOKEN_BYTES = 8192;
/** 前端交互等待服务端响应头的最长时间。 / Maximum wait for response headers from an interactive request. */
export const REQUEST_TOTAL_TIMEOUT_MS = 15 * 60 * 1000;
/** 有界响应流两个连续 chunk 之间的最长停滞。 / Maximum stall between chunks of a bounded response stream. */
export const RESPONSE_IDLE_TIMEOUT_MS = 30 * 1000;
/** 便捷下载、编辑和预览响应的总读取期限。 / Total read deadline for convenience downloads, edits, and previews. */
export const RESPONSE_TOTAL_TIMEOUT_MS = 15 * 60 * 1000;
/** 有界响应允许的最大流分块数。 / Maximum stream chunks accepted by one bounded response. */
export const MAX_BUFFERED_RESPONSE_CHUNKS = 65_536;

/**
 * 严格识别单个 RFC 强 entity-tag。引号内的逗号合法，但多个标签、弱前缀、
 * 空白、控制字符和超出 HTTP header byte 范围的 Unicode 都必须拒绝。
 *
 * Strictly recognize one RFC strong entity-tag. A comma inside the quoted
 * opaque value is legal; lists, weak prefixes, whitespace, controls, and
 * Unicode outside the HTTP header-byte range are rejected.
 *
 * @param {string | null} value
 */
export function isStrongEntityTag(value) {
  if (value === null || value.length < 2 || value[0] !== '"' || value.at(-1) !== '"') return false;
  for (let index = 1; index < value.length - 1; index += 1) {
    const code = value.charCodeAt(index);
    if (code === 0x21 || (code >= 0x23 && code <= 0x7e) || (code >= 0x80 && code <= 0xff)) continue;
    return false;
  }
  return true;
}

/**
 * 将短控制面响应限制在服务器协议允许的字节数内。正文按 UTF-8 解码；大小按原始字节
 * 计算，不能被多字节字符或虚假的 Content-Length 绕过。
 *
 * Bound a short control-plane response to the protocol's byte budget. The
 * body is decoded as UTF-8, while enforcement uses raw bytes so multibyte text
 * and a dishonest Content-Length cannot bypass the limit.
 *
 * @param {Response} response
 * @param {number} maxBytes
 * @param {boolean} [fatalUtf8]
 */
async function readBoundedText(response, maxBytes, fatalUtf8 = true) {
  // 复用同一个流式字节边界，避免 `text()` 先为伪造/缺失长度的响应分配
  // 无界字符串。这些控制面限额很小，后续 Blob 到 ArrayBuffer 的一次有界拷贝可接受。
  // Reuse the streaming byte boundary instead of `text()`, which could allocate
  // an unbounded string for a missing/dishonest length. Control-plane budgets
  // are small, so the subsequent bounded Blob-to-ArrayBuffer copy is acceptable.
  const blob = await readBoundedDownloadBlob(response, maxBytes);
  return new TextDecoder("utf-8", { fatal: fatalUtf8 }).decode(await blob.arrayBuffer());
}

/** @param {Response} response */
async function readBoundedErrorText(response) {
  // HEAD 和一些中间件错误合法地没有响应体。HTTP 状态是权威结果，
  // 不能因为可选诊断文本缺失而被“no readable body”覆盖。
  // HEAD and middleware errors may legitimately have no body. Preserve the
  // authoritative HTTP status instead of replacing it with a body-read error.
  if (response.body === null) return "";
  try {
    return await readBoundedText(response, MAX_API_ERROR_BODY_BYTES, false);
  } catch (error) {
    if (error instanceof DownloadTooLargeError) {
      return `[response body exceeded ${MAX_API_ERROR_BODY_BYTES} bytes]`;
    }
    // 正文是诊断附件；输送错误或非法长度不得丢掉已收到的状态码。
    // The body is diagnostic only; transport/protocol failures must not erase
    // the status code already received from the server.
    return "[response body unavailable]";
  }
}

/** @param {Response} response */
export async function assertResponseOk(response) {
  if (!response.ok) {
    throw new ApiError(response.status, response.statusText, await readBoundedErrorText(response));
  }
  return response;
}

/**
 * @param {string} url
 * @param {RequestInit} [init]
 */
export async function request(url, init) {
  return assertResponseOk(await fetchWithTimeout(url, init));
}

/**
 * 执行正文无语义的控制面请求。状态码已足以确定结果，成功后立即取消任何
 * 意外响应体，避免错误配置的代理用“成功 + 无限正文”长期占用浏览器内存、
 * 连接和服务端响应许可。
 *
 * Perform a control-plane request whose success body has no protocol meaning.
 * Once the status is accepted, cancel any unexpected body so a misconfigured
 * proxy cannot attach an endless success payload and retain browser memory,
 * the connection, or a server response permit.
 *
 * @param {string} url
 * @param {RequestInit} init
 */
async function requestWithoutResponseBody(url, init) {
  const response = await request(url, init);
  cancelResponseBody(response, "successful control response body is unused");
  return response;
}

/**
 * 为“等待响应头”阶段施加总期限。fetch 在响应头可用时就完成，因此流式
 * 响应体仍由下方独立的 idle/total deadline 管理。调用方传入 signal 时，
 * 将其取消原因与必选总期限合并，任一条件先到都会终止请求。
 *
 * Bound the wait for response headers. Fetch resolves once headers arrive, so
 * body streaming has separate idle/total deadlines below. A caller-supplied
 * signal is composed with the mandatory total deadline; whichever aborts
 * first terminates the request without hiding the caller's reason.
 *
 * @param {string} url
 * @param {RequestInit} [init]
 */
async function fetchWithTimeout(url, init) {
  // 中文：调用方取消和安全总期限是两个独立条件，不能因为传入 `signal`
  // 就关闭总期限。手动转发取消原因，并在请求结束后移除监听器，避免长寿命
  // caller signal 持有已完成请求的 controller。
  // English: caller cancellation and the safety deadline are independent
  // conditions; supplying a `signal` must not disable the deadline. Forward
  // its reason and remove the listener after completion so a long-lived caller
  // signal cannot retain controllers for requests that already finished.
  const controller = new AbortController();
  const callerSignal = init?.signal;
  const forwardCallerAbort = () => {
    if (!controller.signal.aborted) controller.abort(callerSignal?.reason);
  };
  if (callerSignal?.aborted) forwardCallerAbort();
  else callerSignal?.addEventListener("abort", forwardCallerAbort, { once: true });
  const timeout = setTimeout(
    () => controller.abort(new Error(`Request exceeded ${REQUEST_TOTAL_TIMEOUT_MS} milliseconds`)),
    REQUEST_TOTAL_TIMEOUT_MS,
  );
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
    callerSignal?.removeEventListener("abort", forwardCallerAbort);
  }
}

/** @param {string} url */
export async function checkAuthentication(url) {
  const response = await request(url, { method: "CHECKAUTH" });
  const user = await readBoundedText(response, MAX_AUTHENTICATED_USERNAME_BYTES);
  if (!user) throw new Error("The server returned an empty authenticated username");
  return user;
}

/**
 * LOGOUT 需要重置浏览器凭据缓存，而 fetch 无法表达该操作。Ram 按协议返回
 * 401 challenge 触发重置，所以这个特定状态是成功终态，不是普通 API 错误；
 * 网络、超时或其它状态仍保留当前页面并报告。
 *
 * LOGOUT requires a browser credential-cache reset, which fetch cannot express.
 * Ram deliberately returns a 401 challenge to trigger that reset, so this one
 * status is a successful terminal state rather than an ordinary API error.
 * Network, timeout, and all other status failures remain visible on the page.
 *
 * @param {string} url
 * @param {string} user
 */
export function logOut(url, user) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    let settled = false;
    /** @param {unknown} [value] */
    const rejectOnce = value => {
      if (settled) return;
      settled = true;
      reject(value);
    };
    const resolveOnce = () => {
      if (settled) return;
      settled = true;
      resolve(undefined);
    };
    /** @param {string} message */
    const rejectOversized = message => {
      rejectOnce(new Error(message));
      xhr.abort();
    };
    xhr.open("LOGOUT", url, true, user);
    // 中文：使用 ArrayBuffer 后可在 load 阶段按解压后的实际字节复核。
    // `responseText` 会在检查前构造 UTF-16 字符串，无法对压缩比异常的
    // 诊断正文提供同等的最终内存边界。
    // English: ArrayBuffer permits a final check against actual decoded bytes.
    // `responseText` would allocate a UTF-16 string before that check and gives
    // weaker protection against a diagnostic body with an extreme compression ratio.
    xhr.responseType = "arraybuffer";
    xhr.timeout = 10_000;
    xhr.addEventListener("readystatechange", () => {
      if (xhr.readyState !== XMLHttpRequest.HEADERS_RECEIVED) return;
      const declared = xhr.getResponseHeader("content-length");
      if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > MAX_API_ERROR_BODY_BYTES)) {
        rejectOversized(`Logout response exceeded ${MAX_API_ERROR_BODY_BYTES} bytes`);
      }
    });
    xhr.addEventListener("progress", event => {
      if (event.loaded <= MAX_API_ERROR_BODY_BYTES) return;
      rejectOversized(`Logout response exceeded ${MAX_API_ERROR_BODY_BYTES} bytes`);
    });
    xhr.addEventListener("load", () => {
      const bytes = xhr.response instanceof ArrayBuffer ? new Uint8Array(xhr.response) : new Uint8Array();
      if (bytes.byteLength > MAX_API_ERROR_BODY_BYTES) {
        rejectOversized(`Logout response exceeded ${MAX_API_ERROR_BODY_BYTES} bytes`);
        return;
      }
      // 401 是服务端 LOGOUT 处理器的显式协议结果；也接受 2xx，以兼容已在
      // 上游代理完成凭据清理的部署。
      // 401 is the server LOGOUT handler's explicit contract. Also accept 2xx
      // for deployments whose upstream proxy has already completed the reset.
      if (xhr.status === 401 || (xhr.status >= 200 && xhr.status < 300)) resolveOnce();
      else rejectOnce(new ApiError(
        xhr.status,
        xhr.statusText,
        new TextDecoder("utf-8").decode(bytes),
      ));
    });
    xhr.addEventListener("error", () => rejectOnce(new Error("Logout request failed")));
    xhr.addEventListener("abort", () => rejectOnce(new Error("Logout request was aborted")));
    xhr.addEventListener("timeout", () => rejectOnce(new Error("Logout request timed out")));
    xhr.send();
  });
}

/**
 * @param {string} url
 * @param {RequestInit} [init]
 */
export function loadFile(url, init) {
  return request(url, init);
}

/**
 * 浏览器编辑始终是条件写入。缺少 ETag 不代表允许覆盖；服务器不能提供强校验器时，
 * 调用方必须禁用保存。
 *
 * A browser edit is always conditional. Absence of an ETag is not permission
 * to overwrite: callers must disable saving when the server cannot provide a
 * strong validator.
 *
 * @param {string} url
 * @param {string} etag
 * @param {BodyInit} body
 */
export function saveFile(url, etag, body) {
  return requestWithoutResponseBody(url, {
    method: "PUT",
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "If-Match": etag,
    },
    body,
  });
}

/**
 * 为源资源变更构造且只构造一种并发前置条件。目录列表使用服务端签发的扫描版本，
 * 编辑页使用用户实际读取到的强 ETag；同时发送二者会混淆两种不同快照的含义，
 * 因而在发出请求前失败关闭。
 *
 * Build exactly one concurrency precondition for a source-resource mutation.
 * Directory listings use the server-signed scan version, while editor pages
 * use the strong ETag of the representation the user actually read. Sending
 * both would mix two distinct snapshot models, so fail closed before fetch.
 *
 * @param {string | undefined} mutationVersion
 * @param {string | undefined} sourceEtag
 * @returns {Record<string, string> | undefined}
 */
function sourceMutationHeaders(mutationVersion, sourceEtag) {
  if (mutationVersion !== undefined && (typeof mutationVersion !== "string" || !mutationVersion)) {
    throw new TypeError("mutationVersion must be a non-empty string when supplied");
  }
  if (sourceEtag !== undefined && !isStrongEntityTag(sourceEtag)) {
    throw new TypeError("sourceEtag must be a single strong entity-tag when supplied");
  }
  if (mutationVersion !== undefined && sourceEtag !== undefined) {
    throw new TypeError("mutationVersion and sourceEtag are mutually exclusive");
  }
  if (mutationVersion !== undefined) return { "X-Ram-If-Mutation-Version": mutationVersion };
  if (sourceEtag !== undefined) return { "If-Match": sourceEtag };
  return undefined;
}

/**
 * @param {string} url
 * @param {string} [mutationVersion]
 * @param {string} [sourceEtag]
 */
export function deleteResource(url, mutationVersion, sourceEtag) {
  return requestWithoutResponseBody(url, {
    method: "DELETE",
    headers: sourceMutationHeaders(mutationVersion, sourceEtag),
  });
}

/** @param {string} url */
export function createDirectory(url) {
  return requestWithoutResponseBody(url, { method: "MKCOL" });
}

/** @param {string} url */
export function createEmptyFile(url) {
  return requestWithoutResponseBody(url, { method: "PUT", headers: { "If-None-Match": "*" }, body: "" });
}

/** @param {string} url */
export function resourceExists(url) {
  return fetchWithTimeout(url, { method: "HEAD" });
}

/**
 * @param {string} sourceUrl
 * @param {string} destinationUrl
 * @param {boolean} overwrite
 * @param {string} [mutationVersion]
 * @param {string} [sourceEtag]
 */
export function moveResource(sourceUrl, destinationUrl, overwrite, mutationVersion, sourceEtag) {
  const preconditionHeaders = sourceMutationHeaders(mutationVersion, sourceEtag);
  return requestWithoutResponseBody(sourceUrl, {
    method: "MOVE",
    headers: {
      Destination: destinationUrl,
      Overwrite: overwrite ? "T" : "F",
      ...preconditionHeaders,
    },
  });
}

export class DownloadTooLargeError extends Error {
  /**
   * @param {number} limit
   * @param {number} observed
   */
  constructor(limit, observed) {
    super(`Buffered response exceeded the ${limit} byte browser limit (observed ${observed})`);
    this.name = "DownloadTooLargeError";
    this.limit = limit;
    this.observed = observed;
  }
}

export class ResponseTimeoutError extends Error {
  /** @param {"idle" | "total"} kind @param {number} milliseconds */
  constructor(kind, milliseconds) {
    super(`Response stream exceeded its ${milliseconds} millisecond ${kind} timeout`);
    this.name = "ResponseTimeoutError";
    this.kind = kind;
    this.milliseconds = milliseconds;
  }
}

export class ResponseChunkLimitError extends Error {
  /** @param {number} limit */
  constructor(limit) {
    super(`Response stream exceeded the ${limit} chunk browser limit`);
    this.name = "ResponseChunkLimitError";
    this.limit = limit;
  }
}

/**
 * @typedef {object} ResponseDeadlines
 * @property {number} [idleMs]
 * @property {number} [totalMs]
 */

/**
 * 在一次 `reader.read()` 上同时应用“距离最后非空进展”的 idle 期限和整体
 * 截止时间。必须每次重新计算两者；空 chunk 不是进展，而持续的单字节
 * 进展也只能续 idle，不能续绝对 total deadline。
 *
 * Apply both a since-last-nonempty-progress idle limit and an absolute deadline
 * to one read. Empty chunks are not progress, while one-byte trickle traffic
 * may renew only the idle limit and never the absolute deadline.
 *
 * @param {ReadableStreamDefaultReader<Uint8Array>} reader
 * @param {number} startedAt
 * @param {number} progressedAt
 * @param {number} idleMs
 * @param {number} totalMs
 */
async function readWithDeadlines(reader, startedAt, progressedAt, idleMs, totalMs) {
  // 中文：`performance.now()` 单调递增，不受用户校时、NTP 或时区变化影响；
  // 安全期限不能因为系统时钟回拨而被意外延长。
  // English: `performance.now()` is monotonic across wall-clock, NTP, and
  // timezone changes, so a clock rollback cannot silently extend a safety deadline.
  const now = performance.now();
  const totalRemaining = totalMs - (now - startedAt);
  if (totalRemaining <= 0) throw new ResponseTimeoutError("total", totalMs);
  const idleRemaining = idleMs - (now - progressedAt);
  if (idleRemaining <= 0) throw new ResponseTimeoutError("idle", idleMs);
  const wait = Math.min(idleRemaining, totalRemaining);
  const kind = totalRemaining <= idleRemaining ? "total" : "idle";
  /** @type {ReturnType<typeof setTimeout> | undefined} */
  let timeout;
  try {
    return await Promise.race([
      reader.read(),
      new Promise((_, reject) => {
        timeout = setTimeout(() => reject(new ResponseTimeoutError(kind, kind === "idle" ? idleMs : totalMs)), wait);
      }),
    ]);
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
}

/**
 * 按实际流字节、分块数与时间预算读取响应。返回连续副本，使上游
 * chunk 视图的生命周期和后备缓冲区复用不会影响调用方。字节上限本身不能
 * 限制数百万个空/1-byte chunk 的对象与调度开销，因此必须另算 chunk 预算。
 *
 * Read a response under actual-byte, chunk-count, and time budgets. The
 * returned contiguous copy is independent of upstream chunk views and backing
 * buffer reuse. A byte limit alone does not bound the allocation/scheduling
 * overhead of millions of empty or one-byte chunks, hence the separate budget.
 *
 * @param {Response} response
 * @param {number} maxBytes
 * @param {ResponseDeadlines} [deadlines]
 */
export async function readBoundedResponseBytes(response, maxBytes, deadlines = {}) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
    throw new TypeError("maxBytes must be a non-negative safe integer");
  }
  const idleMs = deadlines.idleMs ?? RESPONSE_IDLE_TIMEOUT_MS;
  const totalMs = deadlines.totalMs ?? RESPONSE_TOTAL_TIMEOUT_MS;
  if (!Number.isSafeInteger(idleMs) || idleMs < 1 || !Number.isSafeInteger(totalMs) || totalMs < 1) {
    throw new TypeError("response deadlines must be positive safe integers");
  }
  const declaredValue = response.headers.get("content-length");
  if (declaredValue !== null) {
    if (!/^\d+$/.test(declaredValue)) {
      cancelResponseBody(response, "invalid Content-Length");
      throw new Error("Response Content-Length is invalid");
    }
    const declared = Number(declaredValue);
    if (!Number.isSafeInteger(declared)) {
      cancelResponseBody(response, "unsafe Content-Length");
      throw new Error("Response Content-Length is too large");
    }
    if (declared > maxBytes) {
      cancelResponseBody(response, "declared response exceeds byte budget");
      throw new DownloadTooLargeError(maxBytes, declared);
    }
  }
  if (!response.body) throw new Error("Response has no readable body");

  const reader = /** @type {ReadableStreamDefaultReader<Uint8Array>} */ (response.body.getReader());
  // 中文：指数扩容把存活分配数限制为 O(log n)，不为每个网络 chunk
  // 保留一个 JS 对象。初始 64 KiB 在小响应内存和大响应拷贝次数之间取平衡。
  // English: exponential growth bounds live allocations to O(log n) and never
  // retains one JavaScript object per network chunk. The initial 64 KiB balances
  // small-response memory against copy count for larger responses.
  let output = new Uint8Array(Math.min(maxBytes, 64 * 1024));
  let received = 0;
  let chunkCount = 0;
  const startedAt = performance.now();
  let progressedAt = startedAt;
  let preserveBoundaryError = false;
  try {
    while (true) {
      const result = await readWithDeadlines(reader, startedAt, progressedAt, idleMs, totalMs);
      if (result.done) break;
      chunkCount += 1;
      if (chunkCount > MAX_BUFFERED_RESPONSE_CHUNKS) {
        throw new ResponseChunkLimitError(MAX_BUFFERED_RESPONSE_CHUNKS);
      }
      const { value } = result;
      if (!(value instanceof Uint8Array)) throw new TypeError("Response stream returned invalid bytes");
      const nextReceived = received + value.byteLength;
      if (nextReceived > maxBytes) throw new DownloadTooLargeError(maxBytes, nextReceived);
      if (nextReceived > output.byteLength) {
        const capacity = Math.min(maxBytes, Math.max(nextReceived, Math.max(1, output.byteLength * 2)));
        const grown = new Uint8Array(capacity);
        grown.set(output.subarray(0, received));
        output = grown;
      }
      output.set(value, received);
      received = nextReceived;
      if (value.byteLength > 0) progressedAt = performance.now();
    }
  } catch (error) {
    preserveBoundaryError = true;
    // 取消只是最佳努力，不等待它：自定义/buggy 流的 cancel promise 也可能永不完成，
    // 不得让它把已经确定的大小或超时错误变成新的永久挂起。
    // Cancellation is best-effort and deliberately not awaited: a buggy custom
    // stream may never resolve cancel, which must not hide an authoritative
    // size/timeout failure behind another permanent wait.
    try {
      void reader.cancel("bounded response rejected").catch(() => {});
    } catch {
      // 保留原始边界错误。 / Preserve the original boundary error.
    }
    throw error;
  } finally {
    try {
      reader.releaseLock();
    } catch (error) {
      // 中文：异常/被篡改的 stream 可能在 cancel 后仍报告 pending read。
      // 只有已确定的大小、chunk 或超时错误可以压过 releaseLock 清理错误；
      // 正常路径上的 release 失败仍要向上暴露。
      // English: an anomalous/tampered stream may still report a pending read
      // after cancellation. An established size/chunk/timeout error remains
      // authoritative over cleanup failure; on success, release errors surface.
      if (!preserveBoundaryError) throw error;
    }
  }
  return output.byteLength === received ? output : output.slice(0, received);
}

/**
 * 有界读取响应，避免缺失、过期或虚假的 Content-Length 把便捷下载变成无界浏览器分配。
 * 调用方可回退到普通导航，由浏览器下载管理器直接流式接收。
 *
 * Read a response without allowing a missing, stale, or dishonest
 * Content-Length header to turn a convenience download into an unbounded
 * browser allocation. The caller may fall back to an ordinary navigation,
 * which lets the browser stream the response to its download manager.
 *
 * @param {Response} response
 * @param {number} maxBytes
 * @param {ResponseDeadlines} [deadlines]
 */
export async function readBoundedDownloadBlob(response, maxBytes, deadlines = {}) {
  const bytes = await readBoundedResponseBytes(response, maxBytes, deadlines);
  return new Blob([bytes], { type: response.headers.get("content-type") ?? "" });
}

/**
 * 丢弃无需消费的响应体，但不等待取消完成。自定义或异常流的
 * `cancel()` 也可能抛错或永不结束；清理失败不得覆盖调用方已经确定的结果。
 *
 * Discard an unused response body without waiting for cancellation to finish.
 * A custom or anomalous stream's `cancel()` may throw or never settle; cleanup
 * failure must not replace the result the caller has already established.
 *
 * @param {Response} response
 * @param {string} reason
 */
function cancelResponseBody(response, reason) {
  try {
    void response.body?.cancel(reason).catch(() => {});
  } catch {
    // 中文：协议或大小错误保持权威；取消失败不能把拒绝结果改成成功。
    // English: The protocol/size error remains authoritative when cancelling
    // an already failed transport also rejects.
  }
}

/**
 * 生成不会出现在 URL 中的 Bearer 令牌，并通过 Authorization 头下载。该路径只用于显式
 * 有界的小文件；大文件或大小未知的文件使用浏览器普通导航。
 *
 * Generate a bearer token without putting it in a URL and download through an
 * Authorization header. This path is reserved for small, explicitly bounded
 * files; large or unknown-size downloads use ordinary browser navigation.
 *
 * @param {string} url
 * @param {number} maxBytes
 */
export async function downloadWithToken(url, maxBytes) {
  const tokenResponse = await request(`${url}${url.includes("?") ? "&" : "?"}tokengen`, {
    method: "POST",
    cache: "no-store",
  });
  const token = await readBoundedText(tokenResponse, MAX_BEARER_TOKEN_BYTES);
  if (!token) throw new Error("The server returned an empty download token");
  if (!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) {
    throw new Error("The server returned an invalid download token");
  }
  const download = await request(url, {
    headers: { Authorization: `Bearer ${token}` },
    cache: "no-store",
  });
  return readBoundedDownloadBlob(download, maxBytes);
}
