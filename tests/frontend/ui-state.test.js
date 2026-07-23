import { expect, test } from "vitest";
import { directoryQueryParams, parseIndexData } from "../../web/ui-state.js";

test("generated directory links retain only browsing query state", () => {
  expect(directoryQueryParams("?q=report&sort=size&order=desc&token=secret&edit=true"))
    .toEqual({ q: "report", sort: "size", order: "desc" });
});

test("index data is normalized independently from the read-only viewer", () => {
  const data = parseIndexData({
    href: "/",
    kind: "Index",
    uri_prefix: "/",
    allow_upload: true,
    allow_delete: true,
    allow_search: true,
    allow_archive: true,
    dir_exists: true,
    user: "admin",
    truncated: false,
    omitted_non_utf8: false,
    mutation_version: "00000000-0000-0000-0000-000000000001.9",
    paths: [{ path_type: "File", name: "a", mtime: 1, size: 2, size_known: true }],
  });
  expect(data.kind).toBe("Index");
  expect(data.paths).toHaveLength(1);
  expect(data.text_viewable).toBe(false);
  expect(data.mutation_version).toBe("00000000-0000-0000-0000-000000000001.9");
});

test("viewer data is normalized without inventing directory permissions", () => {
  const data = parseIndexData({
    href: "/a",
    kind: "View",
    uri_prefix: "/",
    user: null,
    text_viewable: true,
  });
  expect(data.user).toBe("");
  expect(data.allow_search).toBe(false);
  expect(data.paths).toEqual([]);
  expect(data.text_viewable).toBe(true);
  expect(data.mutation_version).toBeNull();
});

test("malformed capability fields fail closed", () => {
  expect(() => parseIndexData({ href: "/", kind: "Index", uri_prefix: "/", user: null, paths: [] }))
    .toThrow(/allow_upload/);
});

test("malformed embedded path names cannot become browser-normalized parent links", () => {
  const base = {
    href: "/",
    kind: "Index",
    uri_prefix: "/",
    allow_upload: true,
    allow_delete: true,
    allow_search: true,
    allow_archive: true,
    dir_exists: true,
    user: "admin",
    truncated: false,
    omitted_non_utf8: false,
    mutation_version: null,
  };
  for (const name of ["", "/absolute", "parent/../escape", "double//segment", "nul\0name"]) {
    expect(() => parseIndexData({
      ...base,
      paths: [{ path_type: "File", name, mtime: 1, size: 2, size_known: true }],
    })).toThrow(/path item name/i);
  }
  expect(parseIndexData({
    ...base,
    paths: [{ path_type: "File", name: "search/nested.txt", mtime: 1, size: 2, size_known: true }],
  }).paths[0].name).toBe("search/nested.txt");
});

test("path metadata enforces Date bounds without rejecting huge sparse-file sizes", () => {
  const base = {
    href: "/",
    kind: "Index",
    uri_prefix: "/",
    allow_upload: true,
    allow_delete: true,
    allow_search: true,
    allow_archive: true,
    dir_exists: true,
    user: "admin",
    truncated: false,
    omitted_non_utf8: false,
    mutation_version: null,
  };
  const huge = parseIndexData({
    ...base,
    paths: [{ path_type: "File", name: "sparse.img", mtime: 1, size: 2 ** 63, size_known: true }],
  });
  expect(huge.paths[0].size).toBe(2 ** 63);

  for (const mtime of [-1, 1.5, Number.MAX_SAFE_INTEGER, Number.POSITIVE_INFINITY]) {
    expect(() => parseIndexData({
      ...base,
      paths: [{ path_type: "File", name: "bad-time", mtime, size: 1, size_known: true }],
    })).toThrow(/mtime/);
  }
  for (const size of [-1, 1.5, Number.POSITIVE_INFINITY, 2 ** 65]) {
    expect(() => parseIndexData({
      ...base,
      paths: [{ path_type: "File", name: "bad-size", mtime: 1, size, size_known: true }],
    })).toThrow(/size/);
  }
});

test("index mutation versions are required, canonical, and bounded to u64", () => {
  const base = {
    href: "/",
    kind: "Index",
    uri_prefix: "/",
    allow_upload: true,
    allow_delete: true,
    allow_search: true,
    allow_archive: true,
    dir_exists: true,
    user: "admin",
    truncated: false,
    omitted_non_utf8: false,
    paths: [],
  };
  const maximum = "00000000-0000-0000-0000-000000000001.18446744073709551615";
  expect(parseIndexData({ ...base, mutation_version: null }).mutation_version).toBeNull();
  expect(parseIndexData({ ...base, mutation_version: maximum }).mutation_version).toBe(maximum);
  for (const mutation_version of [
    undefined,
    "00000000-0000-0000-0000-000000000001.00",
    "00000000-0000-0000-0000-000000000001.18446744073709551616",
    "00000000-0000-0000-0000-00000000000A.1",
  ]) {
    expect(() => parseIndexData({ ...base, mutation_version })).toThrow(/mutation_version/);
  }
});

test("embedded navigation roots are normalized path-only URLs", () => {
  const base = {
    href: "/file.txt",
    kind: "View",
    uri_prefix: "/ram/",
    user: "admin",
    text_viewable: true,
  };
  expect(parseIndexData(base).uri_prefix).toBe("/ram/");
  const scriptScheme = ["java", "script:alert(1)"].join("");
  for (const uri_prefix of [
    scriptScheme,
    "//attacker/",
    "/ram/../",
    "/ram/%2e%2e/",
    "/ram?next=/",
  ]) {
    expect(() => parseIndexData({ ...base, uri_prefix })).toThrow(/uri_prefix/);
  }
  for (const href of ["relative", "/parent/../file", "/double//file"] ) {
    expect(() => parseIndexData({ ...base, href })).toThrow(/href/);
  }
});
