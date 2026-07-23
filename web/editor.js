/**
 * 文件编辑/预览页控制器。读取路径先限制原始字节，再解码或构造受限
 * sandbox iframe；保存路径只接受 UTF-8 与强 ETag，并用 `If-Match`
 * 把“用户看到的版本”与“服务器要替换的版本”绑定。
 *
 * File editor/preview controller. Reads are byte-bounded before decoding or
 * entering a constrained sandbox iframe. Saves require UTF-8 and a strong
 * ETag, then bind the viewed and replaced versions through `If-Match`.
 */

import {
  ApiError,
  DownloadTooLargeError,
  checkAuthentication,
  isStrongEntityTag,
  loadFile,
  readBoundedResponseBytes as readBoundedNetworkBytes,
  saveFile,
} from "./api.js";
import { getEncoding, hasUtf8Bom, isUtf8Encoding } from "./app-utils.js";
import { deletePathInteractive, movePathInteractive } from "./file-operations.js";
import { baseName, errorMessage, extensionName, requireElement, resourceUrl } from "./ui-state.js";

const PREVIEW_FORMATS = new Set([
  ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".avif", ".webp", ".svg",
  ".mp4", ".webm", ".mp3", ".ogg", ".wav", ".m4a", ".opus",
]);

/**
 * 防止恶意或意外超大的响应让管理页面成为无界内存查看器。响应在到达时流式计数，
 * 因此即使代理省略或伪造 Content-Length，上限仍然有效。
 *
 * Keep a malicious or unexpectedly large response from turning the management
 * page into an unbounded in-memory file viewer. The response is streamed and
 * checked as it arrives, so this limit remains effective even when a proxy
 * omits or lies about Content-Length.
 */
export const MAX_INLINE_PREVIEW_BYTES = 16 * 1024 * 1024;
/** 与 `src/server/content.rs` 中的 `EDITABLE_TEXT_MAX_SIZE` 保持一致。 / Keep this aligned with `EDITABLE_TEXT_MAX_SIZE` in `src/server/content.rs`. */
export const MAX_EDITABLE_TEXT_BYTES = 4 * 1024 * 1024;

let editorDirty = false;

/**
 * 只读暴露页面级未保存状态，供统一 `beforeunload` 守卫使用。状态转移仍
 * 封装在本模块，其它代码不能假造“已保存”。
 *
 * Read-only page-level dirty state for the shared `beforeunload` guard. State
 * transitions remain encapsulated here so another module cannot claim edits
 * were saved.
 */
export const editorState = {
  get dirty() { return editorDirty; },
};

/**
 * 在分配编码缓冲区前计算 TextEncoder 将产生的 UTF-8 字节数。孤立代理项按 U+FFFD
 * 计算，与 TextEncoder 的替换行为一致；超过上限立即停止扫描。
 *
 * Count the UTF-8 bytes TextEncoder will produce before allocating its output
 * buffer. Lone surrogates count as U+FFFD, matching TextEncoder replacement,
 * and scanning stops as soon as the limit is exceeded.
 *
 * @param {string} value
 * @param {number} maximumBytes
 * @returns {number | undefined}
 */
export function boundedUtf8Length(value, maximumBytes) {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 0) {
    throw new RangeError("The UTF-8 byte limit must be a non-negative safe integer");
  }
  let bytes = 0;
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit <= 0x7f) bytes += 1;
    else if (codeUnit <= 0x7ff) bytes += 2;
    else if (codeUnit >= 0xd800 && codeUnit <= 0xdbff
      && index + 1 < value.length
      && value.charCodeAt(index + 1) >= 0xdc00
      && value.charCodeAt(index + 1) <= 0xdfff) {
      bytes += 4;
      index += 1;
    } else bytes += 3;
    if (bytes > maximumBytes) return undefined;
  }
  return bytes;
}

/**
 * 把响应流读取为有界字节数组。Content-Length 仅用于提前拒绝；文件在页面渲染后变化或
 * 代理虚报长度时，以实际接收字节数为准。
 *
 * Stream one response into a bounded byte array. Content-Length is only an
 * early-rejection hint: the received byte count remains authoritative when a
 * file changes after the management page was rendered or a proxy lies.
 *
 * @param {Response} response
 * @param {number} maximumBytes
 * @param {string} limitMessage
 */
export async function readBoundedResponseBytes(response, maximumBytes, limitMessage, deadlines = {}) {
  try {
    return await readBoundedNetworkBytes(response, maximumBytes, deadlines);
  } catch (error) {
    // 编辑器的公开错误文案描述具体功能限额，底层读取器仍保留通用、
    // 可结构化的实际字节证据。
    // Translate only the structured byte-limit error into the editor-specific
    // user message; protocol and timeout errors retain their original detail.
    if (error instanceof DownloadTooLargeError) throw new RangeError(limitMessage, { cause: error });
    throw error;
  }
}

/** @param {Response} response @param {number} [maximumBytes] */
export function readBoundedEditorBytes(response, maximumBytes = MAX_EDITABLE_TEXT_BYTES) {
  return readBoundedResponseBytes(
    response,
    maximumBytes,
    `Web editing is limited to ${maximumBytes} bytes.`,
  );
}

/**
 * 把已认证文件响应读取为有界 Blob。Content-Length 仅用于提前拒绝，实际接收字节数才是
 * 最终依据。
 *
 * Read an authenticated file response into a bounded blob. Content-Length is
 * only an early-rejection hint; the received byte count is authoritative.
 *
 * @param {Response} response
 * @param {number} [maximumBytes]
 */
export async function readBoundedPreviewBlob(response, maximumBytes = MAX_INLINE_PREVIEW_BYTES) {
  const limitMessage = `Inline previews are limited to ${maximumBytes} bytes.`;
  const bytes = await readBoundedResponseBytes(response, maximumBytes, limitMessage);
  return new Blob([bytes.buffer], {
    type: response.headers.get("content-type") ?? "application/octet-stream",
  });
}

/**
 * Blob 导航避免 opaque-origin iframe 再发一次认证请求。空 sandbox 属性有意不授予
 * 脚本、同源、表单、弹窗或导航能力。
 *
 * Blob navigation avoids a second authenticated request from an opaque-origin
 * frame. An empty sandbox attribute deliberately grants no script, origin,
 * form, popup or navigation capabilities to uploaded content.
 *
 * @param {Document} ownerDocument
 * @param {string} previewUrl
 * @param {number} viewportHeight
 */
export function createSandboxedPreview(ownerDocument, previewUrl, viewportHeight) {
  const preview = ownerDocument.createElement("iframe");
  preview.src = previewUrl;
  preview.title = "File preview";
  preview.setAttribute("sandbox", "");
  preview.width = "100%";
  preview.height = `${Math.max(200, viewportHeight - 100)}`;
  return preview;
}

/** @param {string | null} etag */
export function isStrongEtag(etag) {
  return isStrongEntityTag(etag);
}

/**
 * @param {import("./ui-state.js").AppContext} context
 * @param {string} message
 */
function disableEditor(context, message) {
  context.dom.editor.classList.add("hidden");
  document.querySelector(".save-btn")?.classList.add("hidden");
  context.dom.notEditable.textContent = message;
  context.dom.notEditable.classList.remove("hidden");
}

/** @param {import("./ui-state.js").AppContext} context */
export async function setupEditorPage(context) {
  const { data, dom } = context;
  const url = resourceUrl();
  const canEdit = data.kind === "Edit" && data.can_save;
  let editorEtag = "";
  let preserveBom = false;
  let saveEnabled = false;
  let cleanText = "";
  let editorMutationActive = false;
  const hasSourceMutationControls = data.kind === "Edit" && (data.can_move || data.can_delete);
  editorDirty = false;

  /** @param {boolean} disabled */
  const setMutationControlsDisabled = disabled => {
    const saveControl = document.querySelector(".save-btn");
    if (saveControl instanceof HTMLButtonElement) saveControl.disabled = disabled;
    // 中文：源操作除了服从页面互斥锁，还必须等待强校验器。任何 finally
    // 路径都不能通过简单的 `disabled = false` 意外恢复无条件 DELETE/MOVE。
    // English: source mutations obey both the page exclusion lock and strong
    // validator readiness. No finally path may accidentally re-enable an
    // unconditional DELETE/MOVE through a plain `disabled = false`.
    const sourceDisabled = disabled || (data.kind === "Edit" && !isStrongEtag(editorEtag));
    for (const selector of [".move-file", ".delete-file"]) {
      const control = document.querySelector(selector);
      if (control instanceof HTMLButtonElement) control.disabled = sourceDisabled;
    }
  };

  /**
   * 所有 Edit 页的 DELETE/MOVE 都必须绑定到页面获取的强校验器。按钮在异步
   * GET/HEAD 完成前已经存在于 DOM，因而点击处理器本身也必须失败关闭，不能只依赖
   * disabled 状态。返回 `null` 表示已向用户解释拒绝原因。
   *
   * DELETE/MOVE on every Edit page must bind to a strong validator obtained by
   * that page. The buttons already exist while asynchronous GET/HEAD is in
   * flight, so handlers fail closed independently of the disabled state.
   * `null` means the rejection was explained to the user.
   *
   * @param {"move" | "delete"} action
   * @returns {string | undefined | null}
   */
  const sourceEtagForAction = action => {
    if (data.kind !== "Edit") return undefined;
    if (isStrongEtag(editorEtag)) return editorEtag;
    window.alert(
      `Cannot safely ${action} this file because its current strong ETag has not been loaded. `
      + "Return to the parent directory and refresh its listing. Its mutation-version guard assumes this Ram process "
      + "is the sole writer; shell tools, sync jobs, or another server require external write coordination.",
    );
    return null;
  };

  /**
   * 发布一个仅在强比较中有效的源校验器。弱/缺失 ETag 永远不会解锁危险操作。
   * Publish a source validator only when it supports strong comparison. A weak
   * or missing ETag never unlocks destructive controls.
   *
   * @param {string | null} etag
   */
  const adoptSourceEtag = etag => {
    if (etag === null || !isStrongEtag(etag)) return false;
    editorEtag = etag;
    if (!editorMutationActive) setMutationControlsDisabled(false);
    return true;
  };

  /**
   * disabled 按钮无法触发 alert，所以校验器获取失败必须同时写入持久可见状态。
   * 父目录页可重新获取 mutation-version 列表；该保护仅在 Ram 唯一写入者模型内成立。
   *
   * A disabled button cannot raise an alert, so validator acquisition failures
   * also need persistent visible status. The parent directory can obtain a
   * fresh mutation-version listing, whose guard applies only under Ram's
   * sole-writer model.
   *
   * @param {string} reason
  */
  const explainSourceEtagUnavailable = reason => {
    if (!hasSourceMutationControls) return;
    const guidance = `Move and delete remain disabled because ${reason}. Return to the parent directory and refresh its listing. `
      + "Its mutation-version guard assumes this Ram process is the sole writer; shell tools, sync jobs, or another "
      + "server require external write coordination.";
    const existing = dom.notEditable.textContent.trim();
    if (!existing.includes(guidance)) {
      dom.notEditable.textContent = existing ? `${existing} ${guidance}` : guidance;
    }
    dom.notEditable.classList.remove("hidden");
  };

  /**
   * 对没有内联 GET 的二进制/超大文件先确认认证，再用 no-store HEAD 获取源快照 ETag。
   * Authenticate first, then obtain a no-store HEAD source validator for a
   * binary or oversized file that has no inline GET.
   */
  const loadSourceEtagFromHead = async () => {
    if (!hasSourceMutationControls) return;
    try {
      const user = await checkAuthentication(url);
      context.data.user = user;
      context.dom.logoutButton.classList.remove("hidden");
      context.dom.userName.textContent = user;
      const response = await loadFile(url, { method: "HEAD", cache: "no-store" });
      if (!adoptSourceEtag(response.headers.get("etag"))) {
        explainSourceEtagUnavailable("the authenticated HEAD response did not provide a strong ETag");
      }
    } catch (error) {
      explainSourceEtagUnavailable(`the authenticated HEAD snapshot failed: ${errorMessage(error)}`);
    }
  };

  // 初始空 ETag 必须立即反映为禁用状态，覆盖 DOM 中按钮默认的 enabled 属性。
  // Reflect the initially empty ETag immediately instead of inheriting the
  // buttons' enabled-by-default DOM state.
  setMutationControlsDisabled(false);

  const download = requireElement(".download", HTMLAnchorElement);
  download.classList.remove("hidden");
  download.href = url;

  if (data.kind === "Edit") {
    if (data.can_move) {
      const moveButton = requireElement(".move-file", HTMLButtonElement);
      moveButton.classList.remove("hidden");
      moveButton.addEventListener("click", async () => {
        if (editorMutationActive) return;
        const sourceEtag = sourceEtagForAction("move");
        if (sourceEtag === null) return;
        if (editorDirty && !window.confirm("Discard unsaved edits and move this file?")) return;
        editorMutationActive = true;
        setMutationControlsDisabled(true);
        const previousReadOnly = dom.editor.readOnly;
        dom.editor.readOnly = true;
        let navigationStarted = false;
        try {
          const query = window.location.href.slice(url.length);
          const destination = await movePathInteractive(context, url, sourceEtag);
          if (destination) {
            editorDirty = false;
            window.location.assign(destination + query);
            navigationStarted = true;
          }
        } finally {
          editorMutationActive = false;
          if (!navigationStarted) {
            dom.editor.readOnly = previousReadOnly;
            setMutationControlsDisabled(false);
          }
        }
      });
    }
    if (data.can_delete) {
      const deleteButton = requireElement(".delete-file", HTMLButtonElement);
      deleteButton.classList.remove("hidden");
      deleteButton.addEventListener("click", async () => {
        if (editorMutationActive) return;
        const sourceEtag = sourceEtagForAction("delete");
        if (sourceEtag === null) return;
        editorMutationActive = true;
        setMutationControlsDisabled(true);
        const previousReadOnly = dom.editor.readOnly;
        dom.editor.readOnly = true;
        let navigationStarted = false;
        try {
          const deleted = await deletePathInteractive(context, baseName(url), url, sourceEtag);
          if (deleted) {
            editorDirty = false;
            window.location.assign(new URL(".", url).href);
            navigationStarted = true;
          }
        } finally {
          editorMutationActive = false;
          if (!navigationStarted) {
            dom.editor.readOnly = previousReadOnly;
            setMutationControlsDisabled(false);
          }
        }
      });
    }
  }

  if (!canEdit) dom.editor.readOnly = true;
  if (!data.editable) {
    const extension = extensionName(baseName(url));
    if (PREVIEW_FORMATS.has(extension)) {
      try {
        const response = await loadFile(url);
        const etag = response.headers.get("etag");
        const blob = await readBoundedPreviewBlob(response);
        const previewUrl = URL.createObjectURL(blob);
        const preview = createSandboxedPreview(document, previewUrl, window.innerHeight);
        let revoked = false;
        const revokePreviewUrl = () => {
          if (revoked) return;
          revoked = true;
          URL.revokeObjectURL(previewUrl);
        };
        preview.addEventListener("error", revokePreviewUrl, { once: true });
        window.addEventListener("pagehide", revokePreviewUrl, { once: true });
        dom.notEditable.after(preview);
        if (!adoptSourceEtag(etag)) {
          explainSourceEtagUnavailable("the completed preview GET did not provide a strong ETag");
        }
      } catch (error) {
        disableEditor(context, `The file could not be previewed: ${errorMessage(error)} Use Download instead.`);
        explainSourceEtagUnavailable("the preview snapshot could not be loaded and verified");
      }
    } else {
      disableEditor(context, "Cannot edit because the file is too large or binary.");
      await loadSourceEtagFromHead();
    }
    return;
  }

  try {
    const response = await loadFile(url);
    const etag = response.headers.get("etag");
    const encoding = getEncoding(response.headers.get("content-type"));
    const bytes = await readBoundedEditorBytes(response);
    const sourceEtagReady = adoptSourceEtag(etag);
    if (canEdit && !isUtf8Encoding(encoding)) {
      disableEditor(context, `Web editing is limited to UTF-8 files. This file declares ${encoding || "an unknown encoding"}; download it and use an encoding-aware editor.`);
      if (!sourceEtagReady) {
        explainSourceEtagUnavailable("the completed file GET did not provide a strong ETag");
      }
      return;
    }
    if (canEdit && !sourceEtagReady) {
      disableEditor(context, "Safe web editing requires a strong ETag, but this response did not provide one.");
      explainSourceEtagUnavailable("the completed file GET did not provide a strong ETag");
      return;
    }
    const decoder = new TextDecoder(encoding, { fatal: canEdit });
    preserveBom = isUtf8Encoding(encoding) && hasUtf8Bom(bytes);
    dom.editor.value = decoder.decode(bytes);
    // 中文：clean 基线必须可推进。保存请求在途时用户仍可继续输入；若请求只保存了
    // 较早快照，成功后会把基线推进到那个已确认的服务端表示，而不是把较新的输入
    // 错标为“已保存”。
    // English: the clean baseline must be movable. Users may continue typing
    // while a save is in flight; if it commits an earlier snapshot, advance
    // the baseline only to that confirmed server representation and never mark
    // newer input as saved.
    cleanText = dom.editor.value;
    if (canEdit) {
      // 与初始文本比较而非单向置位，因此用户完全撤销修改后会自动回到
      // clean，不会在没有实际数据损失风险时弹出离页提示。
      // Compare with the loaded text rather than latching once: a complete undo
      // returns to clean state and avoids a false navigation warning.
      dom.editor.addEventListener("input", () => {
        editorDirty = dom.editor.value !== cleanText;
      });
    }
    dom.editor.classList.remove("hidden");
    if (!sourceEtagReady) {
      explainSourceEtagUnavailable("the completed file GET did not provide a strong ETag");
    }
    saveEnabled = canEdit && isUtf8Encoding(encoding) && sourceEtagReady;
  } catch (error) {
    disableEditor(context, canEdit
      ? `This file could not be loaded as valid UTF-8: ${errorMessage(error)}`
      : `The file could not be loaded: ${errorMessage(error)}`);
    explainSourceEtagUnavailable("the file snapshot could not be loaded and verified");
    return;
  }

  if (!saveEnabled) return;
  const saveButton = requireElement(".save-btn", HTMLButtonElement);
  saveButton.classList.remove("hidden");
  saveButton.addEventListener("click", async () => {
    if (editorMutationActive) return;
    // 中文：保存、移动和删除共享一个页面级互斥状态。保存期间文本框仍可输入，
    // 由下方快照逻辑保留新内容；其它命名空间变更必须禁用，否则 MOVE/DELETE
    // 可能与旧 URL 上的 PUT 交错，产生 404/412 或错误导航。
    // English: save, move, and delete share one page-level exclusion state.
    // The textarea remains editable during save and the snapshot logic below
    // retains newer input, while namespace mutations are disabled so MOVE or
    // DELETE cannot interleave with a PUT against the old URL.
    editorMutationActive = true;
    setMutationControlsDisabled(true);
    let navigationStarted = false;
    try {
      const user = await checkAuthentication(url);
      context.data.user = user;
      context.dom.logoutButton.classList.remove("hidden");
      context.dom.userName.textContent = user;
      const bomBytes = preserveBom ? 3 : 0;
      const encodedLength = boundedUtf8Length(
        dom.editor.value,
        MAX_EDITABLE_TEXT_BYTES - bomBytes,
      );
      if (encodedLength === undefined) {
        window.alert(`Web editing is limited to ${MAX_EDITABLE_TEXT_BYTES} UTF-8 bytes.`);
        return;
      }
      const encoded = new TextEncoder().encode(dom.editor.value);
      if (encoded.byteLength !== encodedLength) {
        throw new Error("The browser returned an inconsistent UTF-8 encoding length");
      }
      // TextEncoder 会把孤立 UTF-16 代理项替换为 U+FFFD。这里同时保留文本框
      // 快照和字节实际表示的规范文本，确保保存后复核比较的是同一种表示。
      // English: TextEncoder replaces lone UTF-16 surrogates with U+FFFD.
      // Retain both the textarea snapshot and the exact canonical text
      // represented by the bytes so post-save verification compares like with like.
      const submittedText = dom.editor.value;
      const submittedCanonicalText = new TextDecoder("utf-8", { fatal: true }).decode(encoded);
      const submittedWithBom = preserveBom;
      const body = preserveBom
        ? new Blob([new Uint8Array([0xef, 0xbb, 0xbf]), encoded], { type: "text/plain;charset=utf-8" })
        : encoded;
      await saveFile(url, editorEtag, body);
      if (dom.editor.value === submittedText) {
        editorDirty = false;
        window.location.reload();
        navigationStarted = true;
        return;
      }

      // 中文：PUT 成功只能证明 `submittedText` 已提交，不能证明请求期间产生的
      // 新输入也已提交。重新无缓存读取正文与强 ETag，并同时核对规范文本和 BOM；
      // 只有二者仍等于刚提交的字节时才采用新 ETag。若外部写入者抢在复核前改写，
      // 保留旧 ETag 会让下一次保存以 412 安全失败，绝不把未知版本当作新基线。
      // English: PUT success proves only that `submittedText` was committed,
      // not that edits made while it was in flight were saved. Re-read the
      // body and strong ETag without cache, checking both canonical text and
      // BOM before adopting the validator. If an external writer wins before
      // verification, retain the old ETag so the next save fails safely with
      // 412 instead of treating an unseen representation as the new baseline.
      try {
        const refreshed = await loadFile(url, { cache: "no-store" });
        const refreshedEtag = refreshed.headers.get("etag");
        const refreshedBytes = await readBoundedEditorBytes(refreshed);
        const refreshedHasBom = hasUtf8Bom(refreshedBytes);
        const refreshedText = new TextDecoder("utf-8", { fatal: true }).decode(refreshedBytes);
        if (!isStrongEtag(refreshedEtag)
          || refreshedText !== submittedCanonicalText
          || refreshedHasBom !== submittedWithBom) {
          throw new Error("the saved representation changed before its validator could be refreshed");
        }
        editorEtag = refreshedEtag ?? "";
        preserveBom = refreshedHasBom;
        cleanText = submittedCanonicalText;
        editorDirty = dom.editor.value !== cleanText;
        if (!editorDirty) {
          window.location.reload();
          navigationStarted = true;
          return;
        }
        window.alert("An earlier snapshot was saved. Your newer edits remain unsaved and can be saved again.");
      } catch (refreshError) {
        editorDirty = true;
        window.alert(
          `An earlier snapshot was saved, but its new validator could not be verified: ${errorMessage(refreshError)} `
          + "Your newer edits remain in the editor; copy them before reloading.",
        );
      }
    } catch (error) {
      if (error instanceof ApiError && error.status === 412) {
        window.alert("This file was modified on the server since you opened it. Reload to get the latest version before saving.");
      } else {
        window.alert(`Failed to save file: ${errorMessage(error)}`);
      }
    } finally {
      editorMutationActive = false;
      if (!navigationStarted) setMutationControlsDisabled(false);
    }
  });
}
