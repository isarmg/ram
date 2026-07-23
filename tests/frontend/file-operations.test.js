import { describe, expect, test } from "vitest";
import {
  MAX_UPLOAD_TREE_DEPTH,
  isSafePathSegment,
  invalidateListingMutationVersion,
  mutationVersionForListAction,
  removePathItem,
  resolveDroppedItems,
  runDroppedEntryTraversal,
  uploadState,
  uploadDirectoryParts,
  validateMovePath,
} from "../../web/file-operations.js";

/**
 * @param {Partial<DataTransferItem & {webkitGetAsEntry?: () => FileSystemEntry | null}>} overrides
 */
function droppedItem(overrides) {
  return /** @type {DataTransferItem & {webkitGetAsEntry?: () => FileSystemEntry | null}} */ ({
    kind: "file",
    type: "application/octet-stream",
    getAsFile: () => null,
    getAsString: () => {},
    ...overrides,
  });
}

describe("browser path admission", () => {
  test("returns mutation snapshots only for directory listings", () => {
    const version = "00000000-0000-0000-0000-000000000001.7";
    expect(mutationVersionForListAction({ data: { kind: "Index", mutation_version: version } }))
      .toBe(version);
    expect(() => mutationVersionForListAction({ data: { kind: "Index", mutation_version: null } }))
      .toThrow(/refresh/i);
    expect(mutationVersionForListAction({ data: { kind: "View", mutation_version: null } }))
      .toBeUndefined();

    const listing = { data: { kind: "Index", mutation_version: version } };
    invalidateListingMutationVersion(listing);
    expect(listing.data.mutation_version).toBeNull();
    expect(() => mutationVersionForListAction(listing)).toThrow(/refresh/i);
    const viewer = { data: { kind: "View", mutation_version: null } };
    invalidateListingMutationVersion(viewer);
    expect(viewer.data.mutation_version).toBeNull();
  });

  test("rejects dot segments and separators used by create controls", () => {
    expect(isSafePathSegment("report.txt")).toBe(true);
    for (const value of ["", ".", "..", "nested/name", "nul\0name"]) {
      expect(isSafePathSegment(value)).toBe(false);
    }
  });

  test("removes reverse-completing concurrent rows by stable identity", () => {
    const first = { name: "first" };
    const second = { name: "second" };
    const third = { name: "third" };
    const paths = [first, second, third];

    expect(removePathItem(paths, first)).toBe(0);
    // 中文：`second` 原本位于索引 1；首次 DELETE 后前移到索引 0。
    // `second` was originally index 1 but shifted to 0 after the first DELETE.
    expect(removePathItem(paths, second)).toBe(0);
    expect(paths).toEqual([third]);
    expect(removePathItem(paths, second)).toBeUndefined();
  });

  test("validates move destinations without browser dot-segment normalization", () => {
    expect(validateMovePath("folder/new.txt")).toBe("/folder/new.txt");
    expect(validateMovePath("/folder/subdir/")).toBe("/folder/subdir/");
    for (const value of ["/", "/folder/../escape", "/folder/./file", "/folder//file"]) {
      expect(() => validateMovePath(value)).toThrow(/destination/i);
    }
  });

  test("requires preserved, bounded directory-picker paths", () => {
    expect(uploadDirectoryParts({
      name: "file.txt",
      webkitRelativePath: "root/nested/file.txt",
    }, true)).toEqual(["root", "nested"]);
    expect(() => uploadDirectoryParts({ name: "file.txt", webkitRelativePath: "" }, true))
      .toThrow(/preserve/i);
    expect(() => uploadDirectoryParts({
      name: "file.txt",
      webkitRelativePath: `${Array(MAX_UPLOAD_TREE_DEPTH + 1).fill("d").join("/")}/file.txt`,
    }, true)).toThrow(/depth/i);
    expect(() => uploadDirectoryParts({
      name: "file.txt",
      webkitRelativePath: "root/../file.txt",
    }, true)).toThrow(/unsafe/i);
  });
});

describe("dropped-directory asynchronous boundaries", () => {
  test("counts enumeration as pending before a File callback produces an upload", async () => {
    const file = /** @type {File} */ ({ name: "delayed.txt" });
    const entry = /** @type {FileSystemFileEntry} */ ({
      name: "delayed.txt",
      isFile: true,
      isDirectory: false,
      file(success) {
        setTimeout(() => success(file), 5);
      },
    });
    const accepted = [];
    const traversal = runDroppedEntryTraversal(
      [entry],
      (selected, directories) => {
        accepted.push([selected.name, directories]);
        return true;
      },
      { callbackTimeoutMs: 100, totalTimeoutMs: 100 },
    );
    expect(uploadState.pending).toBe(1);
    await traversal;
    expect(uploadState.pending).toBe(0);
    expect(accepted).toEqual([["delayed.txt", []]]);
  });

  test("times out an unresolved callback and blocks reuse until a late browser reply", async () => {
    let releaseLateCallback = () => {};
    const entry = /** @type {FileSystemFileEntry} */ ({
      name: "stalled.txt",
      isFile: true,
      isDirectory: false,
      file(_success, failure) { releaseLateCallback = failure; },
    });
    await expect(runDroppedEntryTraversal(
      [entry],
      () => true,
      { callbackTimeoutMs: 5, totalTimeoutMs: 50 },
    )).rejects.toThrow(/timed out while reading stalled\.txt/);
    expect(uploadState.pending).toBe(0);

    const recoveredFile = /** @type {File} */ ({ name: "recovered.txt" });
    const recoveredEntry = /** @type {FileSystemFileEntry} */ ({
      name: "recovered.txt",
      isFile: true,
      isDirectory: false,
      file(success) { success(recoveredFile); },
    });
    await expect(runDroppedEntryTraversal(
      [recoveredEntry],
      () => true,
      { callbackTimeoutMs: 50, totalTimeoutMs: 50 },
    )).rejects.toThrow(/callback is still unresolved/i);
    // 中文：迟到 error 不会改写已经报告的超时，但会证明浏览器释放了回调。
    // English: A late error cannot rewrite the reported timeout, but proves the browser released its callback.
    releaseLateCallback();
    await expect(runDroppedEntryTraversal(
      [recoveredEntry],
      () => true,
      { callbackTimeoutMs: 50, totalTimeoutMs: 50 },
    )).resolves.toBeUndefined();
    expect(uploadState.pending).toBe(0);
  });

  test("rejects an overlapping traversal instead of accumulating browser callbacks", async () => {
    const firstFile = /** @type {File} */ ({ name: "first.txt" });
    let releaseFirst = () => {};
    const firstEntry = /** @type {FileSystemFileEntry} */ ({
      name: "first.txt",
      isFile: true,
      isDirectory: false,
      file(success) {
        releaseFirst = () => success(firstFile);
      },
    });
    const secondEntry = /** @type {FileSystemFileEntry} */ ({
      name: "second.txt",
      isFile: true,
      isDirectory: false,
      file(success) { success(/** @type {File} */ ({ name: "second.txt" })); },
    });

    const firstTraversal = runDroppedEntryTraversal(
      [firstEntry],
      () => true,
      { callbackTimeoutMs: 100, totalTimeoutMs: 100 },
    );
    try {
      expect(uploadState.pending).toBe(1);
      await expect(runDroppedEntryTraversal(
        [secondEntry],
        () => true,
        { callbackTimeoutMs: 100, totalTimeoutMs: 100 },
      )).rejects.toThrow(/already in progress/i);
      expect(uploadState.pending).toBe(1);
    } finally {
      releaseFirst();
      await firstTraversal;
    }
    expect(uploadState.pending).toBe(0);
  });

  test("enumerates repeated directory batches sequentially with stable relative paths", async () => {
    const file = /** @type {File} */ ({ name: "nested.txt" });
    const fileEntry = /** @type {FileSystemFileEntry} */ ({
      name: "nested.txt",
      isFile: true,
      isDirectory: false,
      file(success) { success(file); },
    });
    const batches = [[fileEntry], []];
    const directory = /** @type {FileSystemDirectoryEntry} */ ({
      name: "folder",
      isFile: false,
      isDirectory: true,
      createReader() {
        return /** @type {FileSystemDirectoryReader} */ ({
          readEntries(success) { success(batches.shift() ?? []); },
        });
      },
    });
    const accepted = [];
    await runDroppedEntryTraversal([directory], (selected, directories) => {
      accepted.push([selected.name, directories]);
      return true;
    });
    expect(accepted).toEqual([["nested.txt", ["folder"]]]);
  });
});

describe("drop item compatibility resolution", () => {
  test("falls back to DataTransfer.files when the Entry API is absent", () => {
    const file = /** @type {File} */ ({ name: "fallback.txt" });
    const item = droppedItem({ getAsFile: () => file });
    expect(resolveDroppedItems([item], [file])).toEqual({
      entries: [],
      files: [file],
      unreadableFileItems: 0,
    });
  });

  test("falls back once for all-null file entries instead of silently dropping them", () => {
    const first = /** @type {File} */ ({ name: "first.txt" });
    const second = /** @type {File} */ ({ name: "second.txt" });
    const items = [
      droppedItem({ webkitGetAsEntry: () => null, getAsFile: () => first }),
      droppedItem({ webkitGetAsEntry: () => null, getAsFile: () => second }),
    ];
    expect(resolveDroppedItems(items, [first, second])).toEqual({
      entries: [],
      files: [first, second],
      unreadableFileItems: 0,
    });
  });

  test("ignores mixed text items while preserving a valid file entry", () => {
    const file = /** @type {File} */ ({ name: "entry.txt" });
    const entry = /** @type {FileSystemFileEntry} */ ({
      name: "entry.txt",
      isFile: true,
      isDirectory: false,
      file() {},
    });
    const text = droppedItem({ kind: "string", type: "text/plain" });
    const selected = resolveDroppedItems(
      [text, droppedItem({ webkitGetAsEntry: () => entry, getAsFile: () => file })],
      [file],
    );
    expect(selected).toEqual({ entries: [entry], files: [], unreadableFileItems: 0 });
  });

  test("keeps directory traversal duplicate-free and reports null items it cannot recover", () => {
    const entryFile = /** @type {File} */ ({ name: "entry.txt" });
    const recoveredFile = /** @type {File} */ ({ name: "recovered.txt" });
    const fileEntry = /** @type {FileSystemFileEntry} */ ({
      name: "entry.txt",
      isFile: true,
      isDirectory: false,
      file() {},
    });
    const directoryEntry = /** @type {FileSystemDirectoryEntry} */ ({
      name: "folder",
      isFile: false,
      isDirectory: true,
      createReader() {},
    });
    const selected = resolveDroppedItems([
      droppedItem({ webkitGetAsEntry: () => fileEntry, getAsFile: () => entryFile }),
      droppedItem({ webkitGetAsEntry: () => directoryEntry }),
      droppedItem({ webkitGetAsEntry: () => null, getAsFile: () => recoveredFile }),
      droppedItem({ webkitGetAsEntry: () => null, getAsFile: () => null }),
    ], [entryFile, recoveredFile]);

    expect(selected.entries).toEqual([fileEntry, directoryEntry]);
    // 中文：完整 FileList 没有被加入，因此 entry.txt 不会同时按 Entry 和 File 上传。
    // English: the complete FileList is not added, so entry.txt cannot upload
    // once as an Entry and again as a File.
    expect(selected.files).toEqual([recoveredFile]);
    expect(selected.unreadableFileItems).toBe(1);
  });
});
