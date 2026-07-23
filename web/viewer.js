/**
 * 有界只读文件查看器。文本和媒体预览在实际接收字节上执行硬上限；
 * 上传内容进入无权限 sandbox iframe，页面不提供任何写入能力。
 *
 * Bounded read-only file viewer. Text and media previews enforce hard limits
 * on bytes actually received. Uploaded media enters a capability-free sandbox,
 * and this page exposes no mutation controls.
 */

import {
  DownloadTooLargeError,
  loadFile,
  readBoundedResponseBytes as readBoundedNetworkBytes,
} from "./api.js";
import { getEncoding } from "./app-utils.js";
import { baseName, errorMessage, extensionName, requireElement, resourceUrl } from "./ui-state.js";

const PREVIEW_FORMATS = new Set([
  ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".avif", ".webp", ".svg",
  ".mp4", ".webm", ".mp3", ".ogg", ".wav", ".m4a", ".opus",
]);

export const MAX_INLINE_PREVIEW_BYTES = 16 * 1024 * 1024;
export const MAX_TEXT_VIEW_BYTES = 4 * 1024 * 1024;

/**
 * @param {Response} response
 * @param {number} maximumBytes
 * @param {string} limitMessage
 * @param {{idleMs?: number, totalMs?: number}} [deadlines]
 */
export async function readBoundedResponseBytes(
  response,
  maximumBytes,
  limitMessage,
  deadlines = {},
) {
  try {
    return await readBoundedNetworkBytes(response, maximumBytes, deadlines);
  } catch (error) {
    if (error instanceof DownloadTooLargeError) {
      throw new RangeError(limitMessage, { cause: error });
    }
    throw error;
  }
}

/** @param {Response} response @param {number} [maximumBytes] */
export function readBoundedTextBytes(response, maximumBytes = MAX_TEXT_VIEW_BYTES) {
  return readBoundedResponseBytes(
    response,
    maximumBytes,
    `Text previews are limited to ${maximumBytes} bytes.`,
  );
}

/** @param {Response} response @param {number} [maximumBytes] */
export async function readBoundedPreviewBlob(
  response,
  maximumBytes = MAX_INLINE_PREVIEW_BYTES,
) {
  const bytes = await readBoundedResponseBytes(
    response,
    maximumBytes,
    `Inline previews are limited to ${maximumBytes} bytes.`,
  );
  return new Blob([bytes.buffer], {
    type: response.headers.get("content-type") ?? "application/octet-stream",
  });
}

/**
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

/**
 * @param {import("./ui-state.js").AppContext} context
 * @param {string} message
 */
function showStatus(context, message) {
  context.dom.viewerStatus.textContent = message;
  context.dom.viewerStatus.classList.remove("hidden");
}

/** @param {import("./ui-state.js").AppContext} context */
export async function setupViewerPage(context) {
  const { data, dom } = context;
  const url = resourceUrl();
  const download = requireElement(".download", HTMLAnchorElement);
  download.href = `${url}?download`;
  download.download = baseName(url);
  download.classList.remove("hidden");

  if (data.text_viewable) {
    try {
      const response = await loadFile(url);
      const bytes = await readBoundedTextBytes(response);
      const encoding = getEncoding(response.headers.get("content-type"));
      dom.textViewer.textContent = new TextDecoder(encoding, { fatal: true }).decode(bytes);
      dom.textViewer.classList.remove("hidden");
    } catch (error) {
      showStatus(context, `The text preview could not be loaded: ${errorMessage(error)} Use Download instead.`);
    }
    return;
  }

  const extension = extensionName(baseName(url));
  if (!PREVIEW_FORMATS.has(extension)) {
    showStatus(context, "This file type is not available for inline preview. Use Download instead.");
    return;
  }

  try {
    const response = await loadFile(url);
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
    dom.viewerStatus.after(preview);
  } catch (error) {
    showStatus(context, `The file could not be previewed: ${errorMessage(error)} Use Download instead.`);
  }
}
