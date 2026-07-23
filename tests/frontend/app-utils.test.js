import { describe, expect, test } from "vitest";
import {
  decodeBase64,
  formatDirSize,
  formatDuration,
  formatFileSize,
  formatMtime,
  formatPercent,
  getEncoding,
} from "../../web/app-utils.js";

describe("browser utility boundaries", () => {
  test("decodes UTF-8 page data without lossy string tricks", () => {
    const nativeFromBase64 = Uint8Array.fromBase64;
    Uint8Array.fromBase64 = undefined;
    try {
      expect(decodeBase64(Buffer.from('{"name":"世界😀"}').toString("base64")))
        .toBe('{"name":"世界😀"}');
      expect(() => decodeBase64(Buffer.from([0xc3, 0x28]).toString("base64")))
        .toThrow(/encoded data|valid|encoding/i);
    } finally {
      Uint8Array.fromBase64 = nativeFromBase64;
    }
  });

  test("formats bounded sizes and progress edge cases", () => {
    expect(formatDirSize(0, false)).toBe("—");
    expect(formatDirSize(1, true)).toBe("1 item");
    expect(formatDirSize(1000, true)).toBe(">999 items");
    expect(formatFileSize(0)).toEqual([0, "B"]);
    expect(formatFileSize(0.5)).toEqual([1, "B"]);
    expect(formatPercent(Number.NaN)).toBe("0%");
    expect(formatDuration(Number.POSITIVE_INFINITY)).toBe("--:--:--");
    expect(formatDuration(100 * 60 * 60)).toBe("100:00:00");
    expect(formatMtime(0)).toBe("");
    expect(formatMtime(8_640_000_000_000_001)).toBe("");
  });

  test("parses charset parameters in any position", () => {
    expect(getEncoding("text/plain; boundary=x; charset=\"UTF-8\"")).toBe("utf-8");
  });
});
