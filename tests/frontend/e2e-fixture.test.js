import { afterEach, expect, test } from "vitest";
import { readFile } from "node:fs/promises";
import { prepareE2eData } from "../../tests/e2e/fixtures.js";

const previous = process.env.RAM_E2E_DATA_DIR;

afterEach(() => {
  if (previous === undefined) delete process.env.RAM_E2E_DATA_DIR;
  else process.env.RAM_E2E_DATA_DIR = previous;
});

test("an inherited E2E data directory outside target is rejected", async () => {
  process.env.RAM_E2E_DATA_DIR = "/tmp/ram-e2e-must-not-write-here";
  await expect(prepareE2eData()).rejects.toThrow(/outside target/);
});

test("worker config reload accepts only the isolated target prefix", async () => {
  process.env.RAM_E2E_DATA_DIR = "target/playwright-data-worker-123";
  await expect(prepareE2eData()).resolves.toMatch(/\/target\/playwright-data-worker-123$/);
});

test("Playwright passes adversarial data paths only through quoted environment expansion", async () => {
  process.env.RAM_E2E_DATA_DIR = "target/playwright-data-$(touch should-never-run)";
  await expect(prepareE2eData()).resolves.toContain("$(touch should-never-run)");

  const source = await readFile("playwright.config.js", "utf8");
  // 中文：回归锁定安全结构：固定命令只展开双引号环境变量，
  // 不得再把 dataDirectory/tokenRevocationFile 插值到 shell 源文本。
  // English: lock in the safe structure: a fixed command expands only quoted
  // environment variables and never interpolates dataDirectory/tokenRevocationFile into shell source.
  expect(source).toContain('"$RAM_E2E_DATA_DIR"');
  expect(source).toContain('"$RAM_E2E_TOKEN_REVOCATION_FILE"');
  const command = source.match(/command:\s*([^\n]+)/)?.[1] ?? "";
  expect(command).not.toMatch(/dataDirectory|tokenRevocationFile|JSON\.stringify/);
});
