import { readFile } from "node:fs/promises";
import { JSDOM } from "jsdom";
import { describe, expect, test } from "vitest";

describe("embedded UI shell", () => {
  test("uses semantic controls and contains no inline event handlers", async () => {
    const source = await readFile("web/index.html", "utf8");
    const dom = new JSDOM(source);
    const document = dom.window.document;

    expect(document.querySelectorAll("button.control").length).toBeGreaterThan(3);
    expect(document.querySelector("header.head")).not.toBeNull();
    expect(document.querySelector('nav.breadcrumb[aria-label="Breadcrumb"]')).not.toBeNull();
    expect(document.querySelector("main.main")).not.toBeNull();
    expect(document.querySelector('form.searchbar[role="search"]')).not.toBeNull();
    expect(document.querySelector(".empty-folder")?.getAttribute("role")).toBe("status");
    const editorStatus = document.querySelector(".not-editable");
    expect(editorStatus?.getAttribute("role")).toBe("status");
    expect(editorStatus?.getAttribute("aria-live")).toBe("polite");
    expect(editorStatus?.getAttribute("aria-atomic")).toBe("true");
    expect(document.querySelector(".upload-file")?.getAttribute("aria-label")).toBe("Upload files");
    expect(document.querySelector(".upload-folder")?.getAttribute("aria-label")).toBe("Upload folder");
    expect(document.querySelector("#folder")?.hasAttribute("webkitdirectory")).toBe(true);
    expect(document.querySelector(".uploaders-table > tbody.uploaders-table-body")).not.toBeNull();
    expect(document.querySelector("#editor")?.getAttribute("spellcheck")).toBe("false");
    expect(document.querySelector("script")?.getAttribute("type")).toBe("module");
    expect(document.querySelectorAll("[onclick],[onchange],[onsubmit]")).toHaveLength(0);
  });
});
