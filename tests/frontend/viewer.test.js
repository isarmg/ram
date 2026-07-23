import { JSDOM } from "jsdom";
import { describe, expect, test } from "vitest";
import {
  createSandboxedPreview,
  readBoundedPreviewBlob,
  readBoundedResponseBytes,
  readBoundedTextBytes,
} from "../../web/viewer.js";

describe("bounded read-only text viewing", () => {
  test("accepts the exact byte limit and rejects a streamed extra byte", async () => {
    const accepted = await readBoundedTextBytes(new Response(
      new Uint8Array([1, 2, 3]),
      { headers: { "content-length": "3" } },
    ), 3);
    expect([...accepted]).toEqual([1, 2, 3]);

    await expect(readBoundedTextBytes(new Response(
      new Uint8Array([1, 2, 3, 4]),
      { headers: { "content-length": "3" } },
    ), 3)).rejects.toThrow("limited to 3 bytes");
  });

  test("uses Content-Length only for an early oversized rejection", async () => {
    await expect(readBoundedTextBytes(new Response(new Uint8Array([1]), {
      headers: { "content-length": "100" },
    }), 10)).rejects.toThrow("limited to 10 bytes");
  });

  test("fails closed when a response has no readable body", async () => {
    await expect(readBoundedTextBytes(new Response(null), 10)).rejects.toThrow(/readable body/i);
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
