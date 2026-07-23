/** 浏览器端共享的无副作用帮助函数。 / Shared, side-effect-free browser helpers. */

/** @param {string|number} value @param {number} size */
export function padZero(value, size) {
  return String(value).padStart(size, "0").slice(-size);
}

/** @param {number} mtime */
export function formatMtime(mtime) {
  // 中文：0 是服务端表示“时间不可用”的显式值。其它值仍在这里
  // 做最后一次 Date 域检查，使该独立工具函数不会渲染 `NaN-NaN`。
  // English: zero is the server's explicit "timestamp unavailable" value.
  // Recheck every other value against the Date domain so this standalone
  // formatter never renders a misleading `NaN-NaN` date.
  if (mtime === 0 || !Number.isSafeInteger(mtime) || mtime < 0 || mtime > 8_640_000_000_000_000) return "";
  const date = new Date(mtime);
  const year = String(date.getFullYear()).padStart(4, "0");
  return `${year}-${padZero(date.getMonth() + 1, 2)}-${padZero(date.getDate(), 2)} ${padZero(date.getHours(), 2)}:${padZero(date.getMinutes(), 2)}`;
}

/** @param {number} size @param {boolean} sizeKnown @param {number} [maximum] */
export function formatDirSize(size, sizeKnown, maximum = 1000) {
  if (!sizeKnown) return "—";
  const unit = size === 1 ? "item" : "items";
  const number = size >= maximum ? `>${maximum - 1}` : `${size}`;
  return `${number} ${unit}`;
}

/** @param {number|null|undefined} size @returns {[number, string]} */
export function formatFileSize(size) {
  if (size === null || size === undefined || !Number.isFinite(size) || size <= 0) return [0, "B"];
  const sizes = ["B", "KB", "MB", "GB", "TB", "PB", "EB"];
  // 中文：文件大小是整字节，但上传速度会以小于 1 B/s 的小数调用此函数。
  // 对数在 (0, 1) 内产生负索引，必须夹到 B，否则 UI 会显示 `undefined/s`。
  // English: file sizes are integral bytes, but upload speeds can call this
  // formatter with a fraction below 1 B/s. Its logarithm yields a negative
  // index, which must clamp to B or the UI renders `undefined/s`.
  const index = Math.max(0, Math.min(Math.floor(Math.log(size) / Math.log(1024)), sizes.length - 1));
  const raw = size / 1024 ** index;
  const value = index > 0 && raw < 999.95 ? Math.round(raw * 10) / 10 : Math.round(raw);
  return [value, sizes[index]];
}

/** @param {number} seconds */
export function formatDuration(seconds) {
  if (!Number.isFinite(seconds) || seconds < 0) return "--:--:--";
  const rounded = Math.ceil(seconds);
  const hours = Math.floor(rounded / 3600);
  const minutes = Math.floor((rounded - hours * 3600) / 60);
  const remainder = rounded - hours * 3600 - minutes * 60;
  // 中文：小时是可增长的计数而非两位时钟字段；大文件在慢链路上
  // 可能超过 99 小时，不能被 `padZero(...).slice(-2)` 静默截断。
  // English: hours are an unbounded count, not a two-digit clock field. A
  // large transfer on a slow link can exceed 99 hours and must not silently
  // wrap through `padZero(...).slice(-2)`.
  return `${String(hours).padStart(2, "0")}:${padZero(minutes, 2)}:${padZero(remainder, 2)}`;
}

/** @param {number} percent */
export function formatPercent(percent) {
  if (!Number.isFinite(percent)) return "0%";
  const bounded = Math.min(Math.max(percent, 0), 100);
  return bounded > 10 ? `${bounded.toFixed(1)}%` : `${bounded.toFixed(2)}%`;
}

/** @param {string|null} contentType */
export function getEncoding(contentType) {
  if (!contentType) return "utf-8";
  for (const parameter of contentType.split(";").slice(1)) {
    const [name, rawValue] = parameter.split("=", 2);
    if (name?.trim().toLowerCase() === "charset" && rawValue) {
      return rawValue.trim().replace(/^["']|["']$/g, "").toLowerCase();
    }
  }
  return "utf-8";
}

/** @param {string} encoding */
export function isUtf8Encoding(encoding) {
  return encoding === "utf-8" || encoding === "utf8" || encoding === "unicode-1-1-utf-8";
}

/** @param {Uint8Array} bytes */
export function hasUtf8Bom(bytes) {
  return bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf;
}

/** @param {string} base64String */
export function decodeBase64(base64String) {
  // 当前 evergreen 浏览器可直接构造字节数组，但开发期使用的 Node 24 尚未实现该 API。
  // 回退路径只把 atob 的 Latin-1 代码单元映射回原始字节；它不会把二进制字符串当作
  // Unicode 文本，也不会使用已弃用且有损的 escape/decodeURIComponent 技巧。
  // Evergreen browsers can construct the byte array directly, while the development-time Node 24
  // runtime does not yet expose this API. The fallback maps atob's Latin-1 code units back to their
  // exact bytes; it neither treats the binary string as Unicode nor uses the deprecated, lossy
  // escape/decodeURIComponent workaround.
  let bytes;
  if (typeof Uint8Array.fromBase64 === "function") {
    bytes = Uint8Array.fromBase64(base64String);
  } else {
    const binary = globalThis.atob(base64String);
    bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
  }
  // 页面状态是服务端与脚本之间的协议，不是面向用户的容错文本。默认
  // TextDecoder 会把非法字节替换为 U+FFFD，可能让被破坏的 JSON 悄然变成另一个
  // 有效值；fatal 解码确保任何非规范 UTF-8 都进入统一启动错误页。
  // Embedded state is a server/script protocol, not forgiving user text.
  // Default replacement with U+FFFD could turn damaged JSON into a different
  // valid value; fatal decoding sends every malformed UTF-8 payload to the
  // single initialization-error path.
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}
