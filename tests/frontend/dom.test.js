import { readFile } from "node:fs/promises";
import { JSDOM } from "jsdom";
import { describe, expect, test } from "vitest";

describe("embedded UI shell", () => {
  test("uses semantic controls and contains no inline event handlers", async () => {
    const source = await readFile("web/index.html", "utf8");
    const dom = new JSDOM(source);
    const document = dom.window.document;

    expect(document.querySelectorAll("button.control").length).toBe(3);
    expect(document.querySelector("header.head")).not.toBeNull();
    expect(document.querySelector('nav.breadcrumb[aria-label="Breadcrumb"]')).not.toBeNull();
    expect(document.querySelector("main.main")).not.toBeNull();
    expect(document.querySelector('form.searchbar[role="search"]')).not.toBeNull();
    expect(document.querySelector(".empty-folder")?.getAttribute("role")).toBe("status");
    const viewerStatus = document.querySelector(".viewer-status");
    expect(viewerStatus?.getAttribute("role")).toBe("status");
    expect(viewerStatus?.getAttribute("aria-live")).toBe("polite");
    expect(viewerStatus?.getAttribute("aria-atomic")).toBe("true");
    expect(document.querySelector(".upload-file")?.getAttribute("aria-label")).toBe("Upload files");
    expect(document.querySelector(".upload-folder")?.getAttribute("aria-label")).toBe("Upload folder");
    expect(document.querySelector("#folder")?.hasAttribute("webkitdirectory")).toBe(true);
    expect(document.querySelector(".uploaders-table > tbody.uploaders-table-body")).not.toBeNull();
    expect(document.querySelector(".text-viewer")?.getAttribute("aria-label")).toBe("File contents");
    expect(document.querySelector("#editor")).toBeNull();
    expect(document.querySelector(".save-btn")).toBeNull();
    expect(document.querySelector("script")?.getAttribute("type")).toBe("module");
    expect(document.querySelectorAll("[onclick],[onchange],[onsubmit]")).toHaveLength(0);
  });
});
