import { JSDOM } from "jsdom";
import { afterEach, expect, test, vi } from "vitest";
import { createIcon } from "../../web/icons.js";

afterEach(() => vi.unstubAllGlobals());

test("ascending sort icon contains both arrow arms and stays decorative", () => {
  const dom = new JSDOM();
  vi.stubGlobal("DOMParser", dom.window.DOMParser);
  vi.stubGlobal("document", dom.window.document);

  const icon = createIcon("sortUp");
  const path = icon.querySelector("path")?.getAttribute("d") ?? "";
  // 中文：左右斜边分别以 4.354/11.646 为端点，避免再退化成半个箭头。
  // English: the 4.354 and 11.646 endpoints prove both diagonal arms remain present.
  expect(path).toContain("L4.354 5.854");
  expect(path).toContain("l4 4");
  expect(path).toContain("L8.5 2.707");
  expect(icon.getAttribute("aria-hidden")).toBe("true");
  expect(icon.getAttribute("focusable")).toBe("false");
});
