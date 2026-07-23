import { JSDOM } from "jsdom";
import { describe, expect, test } from "vitest";
import {
  boundedUtf8Length,
  createSandboxedPreview,
  isStrongEtag,
  MAX_EDITABLE_TEXT_BYTES,
  readBoundedEditorBytes,
  readBoundedPreviewBlob,
  readBoundedResponseBytes,
} from "../../web/editor.js";

test("browser editing requires a strong ETag", () => {
  expect(isStrongEtag(null)).toBe(false);
  expect(isStrongEtag("")).toBe(false);
  expect(isStrongEtag('W/"weak"')).toBe(false);
  expect(isStrongEtag('"strong"')).toBe(true);
  expect(isStrongEtag('"comma,inside"')).toBe(true);
  for (const malformed of ['"old", "new"', ' "tag"', '"tag" ', '"bad quote"here"', '"line\nfeed"', '"Ā"']) {
    expect(isStrongEtag(malformed)).toBe(false);
  }
});

describe("bounded editor loading", () => {
  test("accepts N bytes and rejects a streamed N+1 body despite a smaller advertised length", async () => {
    const accepted = await readBoundedEditorBytes(new Response(
      new Uint8Array(MAX_EDITABLE_TEXT_BYTES),
      { headers: { "content-length": String(MAX_EDITABLE_TEXT_BYTES) } },
    ));
    expect(accepted.byteLength).toBe(MAX_EDITABLE_TEXT_BYTES);

    await expect(readBoundedEditorBytes(new Response(
      new Uint8Array(MAX_EDITABLE_TEXT_BYTES + 1),
      { headers: { "content-length": String(MAX_EDITABLE_TEXT_BYTES) } },
    ))).rejects.toThrow(`limited to ${MAX_EDITABLE_TEXT_BYTES} bytes`);
  });

  test("uses Content-Length only to reject an obvious oversized response early", async () => {
    await expect(readBoundedEditorBytes(new Response(new Uint8Array([1]), {
      headers: { "content-length": String(MAX_EDITABLE_TEXT_BYTES + 1) },
    }))).rejects.toThrow(`limited to ${MAX_EDITABLE_TEXT_BYTES} bytes`);
  });

  test("fails closed when a successful-looking response has no readable body", async () => {
    await expect(readBoundedEditorBytes(new Response(null))).rejects.toThrow(/readable body/i);
  });

  test("cancels a response that stalls below the byte limit", async () => {
    let cancelled = false;
    const response = new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(new Uint8Array([1]));
      },
      cancel() {
        cancelled = true;
      },
    }));
    await expect(readBoundedResponseBytes(response, 4, "limited", { idleMs: 10, totalMs: 100 }))
      .rejects.toThrow(/idle timeout/i);
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(cancelled).toBe(true);
  });
});

describe("bounded editor saving", () => {
  test.each(["", "ASCII", "世界", "A😀B", "\ud800x", "x\udfff"])(
    "counts TextEncoder bytes exactly for %j",
    value => {
      const actual = new TextEncoder().encode(value).byteLength;
      expect(boundedUtf8Length(value, actual)).toBe(actual);
      if (actual > 0) expect(boundedUtf8Length(value, actual - 1)).toBeUndefined();
    },
  );

  test("rejects invalid byte budgets", () => {
    expect(() => boundedUtf8Length("text", -1)).toThrow(/non-negative safe integer/);
    expect(() => boundedUtf8Length("text", 1.5)).toThrow(/non-negative safe integer/);
  });
});

describe("sandboxed file previews", () => {
  test("preserve the response type and enforce the actual streamed byte limit", async () => {
    const accepted = await readBoundedPreviewBlob(new Response(new Uint8Array([1, 2, 3]), {
      headers: { "content-type": "image/png", "content-length": "3" },
    }), 3);
    expect(accepted.size).toBe(3);
    expect(accepted.type).toBe("image/png");
    expect([...new Uint8Array(await accepted.arrayBuffer())]).toEqual([1, 2, 3]);

    await expect(readBoundedPreviewBlob(new Response(new Uint8Array([1, 2, 3]), {
      headers: { "content-length": "1" },
    }), 2)).rejects.toThrow("limited to 2 bytes");
  });

  test("rejects an oversized Content-Length before buffering its body", async () => {
    await expect(readBoundedPreviewBlob(new Response(new Uint8Array([1]), {
      headers: { "content-length": "100" },
    }), 10)).rejects.toThrow("limited to 10 bytes");
  });

  test("grants uploaded content no iframe sandbox capabilities", () => {
    const dom = new JSDOM();
    const frame = createSandboxedPreview(dom.window.document, "blob:https://files.example/id", 500);
    expect(frame.getAttribute("sandbox")).toBe("");
    expect(frame.getAttribute("sandbox")).not.toContain("allow-scripts");
    expect(frame.getAttribute("sandbox")).not.toContain("allow-same-origin");
    expect(frame.src).toBe("blob:https://files.example/id");
    expect(frame.height).toBe("400");
  });
});
