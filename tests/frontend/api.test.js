import { afterEach, describe, expect, test, vi } from "vitest";
import {
  ApiError,
  DownloadTooLargeError,
  MAX_API_ERROR_BODY_BYTES,
  MAX_AUTHENTICATED_USERNAME_BYTES,
  MAX_BUFFERED_RESPONSE_CHUNKS,
  REQUEST_TOTAL_TIMEOUT_MS,
  ResponseChunkLimitError,
  assertResponseOk,
  checkAuthentication,
  createDirectory,
  deleteResource,
  logOut,
  moveResource,
  readBoundedDownloadBlob,
  request,
} from "../../web/api.js";

function streamedResponse(chunks, headers = {}, status = 200) {
  return new Response(new ReadableStream({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(new Uint8Array(chunk));
      controller.close();
    },
  }), { headers, status });
}

/** @param {number} count @param {Uint8Array} chunk */
function repeatedChunkResponse(count, chunk) {
  let emitted = 0;
  return new Response(new ReadableStream({
    pull(controller) {
      if (emitted >= count) {
        controller.close();
        return;
      }
      emitted += 1;
      controller.enqueue(chunk);
    },
  }));
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  FakeLogoutXhr.body = undefined;
});

class FakeLogoutXhr {
  static status = 401;
  static lastOpen = undefined;
  static body = undefined;

  constructor() {
    this.status = 0;
    this.statusText = "";
    this.responseText = "";
    this.response = new ArrayBuffer(0);
    this.responseType = "";
    this.readyState = 0;
    this.listeners = new Map();
  }

  open(...args) {
    FakeLogoutXhr.lastOpen = args;
  }

  addEventListener(name, listener) {
    this.listeners.set(name, listener);
  }

  getResponseHeader() {
    return null;
  }

  abort() {
    this.listeners.get("abort")?.();
  }

  send() {
    this.status = FakeLogoutXhr.status;
    this.statusText = this.status === 401 ? "Unauthorized" : "Service Unavailable";
    this.responseText = FakeLogoutXhr.body
      ?? (this.status === 401 ? "Authentication required" : "injected");
    this.response = new TextEncoder().encode(this.responseText).buffer;
    queueMicrotask(() => this.listeners.get("load")?.());
  }
}

/**
 * 返回一个只会在传入 signal 取消时失败的 fetch stub。
 * Return a fetch stub that rejects only when its supplied signal aborts.
 */
function abortOnlyFetch() {
  return vi.fn((_url, init) => new Promise((_, reject) => {
    if (!init?.signal) throw new Error("request did not provide an AbortSignal");
    const rejectAbort = () => reject(init.signal.reason);
    if (init.signal.aborted) rejectAbort();
    else init.signal.addEventListener("abort", rejectAbort, { once: true });
  }));
}

test("DELETE and MOVE forward only validated listing mutation versions", async () => {
  const fetchMock = vi.fn(async () => new Response(null, { status: 204 }));
  vi.stubGlobal("fetch", fetchMock);
  const version = "00000000-0000-0000-0000-000000000001.42";

  await deleteResource("/from-listing", version);
  let [, init] = fetchMock.mock.calls.at(-1);
  expect(init.method).toBe("DELETE");
  expect(new Headers(init.headers).get("x-ram-if-mutation-version")).toBe(version);

  await moveResource("/source", "/destination", false, version);
  [, init] = fetchMock.mock.calls.at(-1);
  const moveHeaders = new Headers(init.headers);
  expect(init.method).toBe("MOVE");
  expect(moveHeaders.get("destination")).toBe("/destination");
  expect(moveHeaders.get("overwrite")).toBe("F");
  expect(moveHeaders.get("x-ram-if-mutation-version")).toBe(version);

  await deleteResource("/headerless-delete");
  [, init] = fetchMock.mock.calls.at(-1);
  expect(new Headers(init.headers).has("x-ram-if-mutation-version")).toBe(false);
  await moveResource("/headerless-source", "/headerless-destination", false);
  [, init] = fetchMock.mock.calls.at(-1);
  expect(new Headers(init.headers).has("x-ram-if-mutation-version")).toBe(false);

  expect(() => deleteResource("/invalid", "")).toThrow(/mutationVersion/);
  expect(() => moveResource("/invalid", "/destination", false, "")).toThrow(/mutationVersion/);
});

describe("bounded browser downloads", () => {
  test("combines caller cancellation with the mandatory response-header deadline", async () => {
    const caller = new AbortController();
    vi.stubGlobal("fetch", abortOnlyFetch());
    const callerAbort = expect(request("/caller-abort", { signal: caller.signal }))
      .rejects.toThrow("caller stopped");
    caller.abort(new Error("caller stopped"));
    await callerAbort;

    vi.useFakeTimers();
    const dormantCaller = new AbortController();
    vi.stubGlobal("fetch", abortOnlyFetch());
    const timedOut = expect(request("/deadline", { signal: dormantCaller.signal }))
      .rejects.toThrow(`Request exceeded ${REQUEST_TOTAL_TIMEOUT_MS} milliseconds`);
    await vi.advanceTimersByTimeAsync(REQUEST_TOTAL_TIMEOUT_MS);
    await timedOut;
  });

  test("accepts the exact received-byte limit", async () => {
    const blob = await readBoundedDownloadBlob(
      streamedResponse([[1, 2], [3, 4]], { "content-type": "application/octet-stream" }),
      4,
    );
    expect(blob.size).toBe(4);
    expect([...new Uint8Array(await blob.arrayBuffer())]).toEqual([1, 2, 3, 4]);
  });

  test("grows one contiguous buffer without changing bytes across capacity boundaries", async () => {
    const first = new Uint8Array(60 * 1024).fill(0x11);
    const second = new Uint8Array(10 * 1024).fill(0x22);
    const bytes = new Uint8Array(await (await readBoundedDownloadBlob(
      streamedResponse([first, second]),
      first.byteLength + second.byteLength,
    )).arrayBuffer());
    expect(bytes).toHaveLength(70 * 1024);
    expect(bytes[0]).toBe(0x11);
    expect(bytes[first.byteLength - 1]).toBe(0x11);
    expect(bytes[first.byteLength]).toBe(0x22);
    expect(bytes.at(-1)).toBe(0x22);
  });

  test("accepts the exact chunk budget and rejects one additional nonempty or empty chunk", async () => {
    const accepted = await readBoundedDownloadBlob(
      repeatedChunkResponse(MAX_BUFFERED_RESPONSE_CHUNKS, new Uint8Array([7])),
      MAX_BUFFERED_RESPONSE_CHUNKS,
      { idleMs: 30_000, totalMs: 30_000 },
    );
    expect(accepted.size).toBe(MAX_BUFFERED_RESPONSE_CHUNKS);

    await expect(readBoundedDownloadBlob(
      repeatedChunkResponse(MAX_BUFFERED_RESPONSE_CHUNKS + 1, new Uint8Array([7])),
      MAX_BUFFERED_RESPONSE_CHUNKS + 1,
      { idleMs: 30_000, totalMs: 30_000 },
    )).rejects.toEqual(expect.objectContaining({
      name: "ResponseChunkLimitError",
      limit: MAX_BUFFERED_RESPONSE_CHUNKS,
    }));

    const acceptedEmpty = await readBoundedDownloadBlob(
      repeatedChunkResponse(MAX_BUFFERED_RESPONSE_CHUNKS, new Uint8Array()),
      0,
      { idleMs: 30_000, totalMs: 30_000 },
    );
    expect(acceptedEmpty.size).toBe(0);

    await expect(readBoundedDownloadBlob(
      repeatedChunkResponse(MAX_BUFFERED_RESPONSE_CHUNKS + 1, new Uint8Array()),
      0,
      { idleMs: 30_000, totalMs: 30_000 },
    )).rejects.toBeInstanceOf(ResponseChunkLimitError);
  }, 30_000);

  test("empty chunks do not renew the useful-progress idle deadline", async () => {
    let cancelled = false;
    const response = new Response(new ReadableStream({
      async pull(controller) {
        await new Promise(resolve => setTimeout(resolve, 1));
        if (!cancelled) controller.enqueue(new Uint8Array());
      },
      cancel() {
        cancelled = true;
      },
    }));
    await expect(readBoundedDownloadBlob(response, 0, { idleMs: 10, totalMs: 100 }))
      .rejects.toThrow(/idle timeout/i);
    expect(cancelled).toBe(true);
  });

  test("rejects one byte beyond the limit even when Content-Length is absent", async () => {
    await expect(readBoundedDownloadBlob(streamedResponse([[1, 2], [3, 4, 5]]), 4))
      .rejects.toEqual(expect.objectContaining({ name: "DownloadTooLargeError", limit: 4, observed: 5 }));
  });

  test("uses Content-Length only for an early fail-closed rejection", async () => {
    await expect(readBoundedDownloadBlob(
      streamedResponse([[1]], { "content-length": "5" }),
      4,
    )).rejects.toBeInstanceOf(DownloadTooLargeError);

    const blob = await readBoundedDownloadBlob(
      streamedResponse([[1, 2, 3, 4]], { "content-length": "1" }),
      4,
    );
    expect(blob.size).toBe(4);
  });

  test("cancels an unread oversized declared response", async () => {
    let cancelled = false;
    const response = new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(new Uint8Array([1]));
      },
      cancel() {
        cancelled = true;
      },
    }), { headers: { "content-length": "5" } });
    await expect(readBoundedDownloadBlob(response, 4)).rejects.toBeInstanceOf(DownloadTooLargeError);
    expect(cancelled).toBe(true);
  });

  test("preserves the HTTP status while bounding an oversized error body", async () => {
    const response = streamedResponse(
      [new Uint8Array(MAX_API_ERROR_BODY_BYTES + 1).fill(120)],
      {},
      500,
    );
    await expect(assertResponseOk(response)).rejects.toEqual(expect.objectContaining({
      name: "ApiError",
      status: 500,
      body: `[response body exceeded ${MAX_API_ERROR_BODY_BYTES} bytes]`,
    }));
    await expect(assertResponseOk(streamedResponse([[111, 111, 112, 115]], {}, 400)))
      .rejects.toBeInstanceOf(ApiError);
  });

  test("preserves status for bodyless HEAD-style and unreadable error bodies", async () => {
    await expect(assertResponseOk(new Response(null, { status: 503, statusText: "Unavailable" })))
      .rejects.toEqual(expect.objectContaining({
        name: "ApiError",
        status: 503,
        body: "",
      }));

    const invalidLength = streamedResponse([[1]], { "content-length": "not-a-number" }, 502);
    await expect(assertResponseOk(invalidLength)).rejects.toEqual(expect.objectContaining({
      name: "ApiError",
      status: 502,
      body: "[response body unavailable]",
    }));
  });

  test("cancels a trickle response that stalls below its byte limit", async () => {
    let cancelled = false;
    const response = new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(new Uint8Array([1]));
      },
      cancel() {
        cancelled = true;
      },
    }));
    await expect(readBoundedDownloadBlob(response, 4, { idleMs: 10, totalMs: 100 }))
      .rejects.toThrow(/idle timeout/i);
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(cancelled).toBe(true);
  });

  test("cancels an unexpected success body for bodyless mutation APIs", async () => {
    let cancelled = false;
    vi.stubGlobal("fetch", vi.fn(async () => new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(new Uint8Array([1]));
      },
      cancel() {
        cancelled = true;
      },
    }), { status: 201 })));

    await expect(createDirectory("/new-directory")).resolves.toBeInstanceOf(Response);
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(cancelled).toBe(true);
  });

  test("bounds authenticated names before use", async () => {
    const usernameFetch = vi.fn(async () => streamedResponse([
      new Uint8Array(MAX_AUTHENTICATED_USERNAME_BYTES + 1).fill(97),
    ]));
    vi.stubGlobal("fetch", usernameFetch);
    await expect(checkAuthentication("/private"))
      .rejects.toBeInstanceOf(DownloadTooLargeError);
  });
});

describe("logout protocol", () => {
  test("treats the deliberate 401 challenge as successful credential reset", async () => {
    FakeLogoutXhr.status = 401;
    FakeLogoutXhr.body = undefined;
    vi.stubGlobal("XMLHttpRequest", FakeLogoutXhr);
    await expect(logOut("/private", "alice")).resolves.toBeUndefined();
    expect(FakeLogoutXhr.lastOpen).toEqual(["LOGOUT", "/private", true, "alice"]);
  });

  test("keeps unrelated server failures visible", async () => {
    FakeLogoutXhr.status = 503;
    FakeLogoutXhr.body = undefined;
    vi.stubGlobal("XMLHttpRequest", FakeLogoutXhr);
    await expect(logOut("/private", "alice")).rejects.toEqual(expect.objectContaining({
      name: "ApiError",
      status: 503,
      body: "injected",
    }));
  });

  test("rejects a decompressed logout response beyond the final byte budget", async () => {
    FakeLogoutXhr.status = 503;
    FakeLogoutXhr.body = "x".repeat(MAX_API_ERROR_BODY_BYTES + 1);
    vi.stubGlobal("XMLHttpRequest", FakeLogoutXhr);
    await expect(logOut("/private", "alice"))
      .rejects.toThrow(`Logout response exceeded ${MAX_API_ERROR_BODY_BYTES} bytes`);
  });
});
