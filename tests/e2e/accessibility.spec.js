import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

// 中文：上传的原子发布包含文件与父目录 fsync；冷缓存或繁忙文件系统可能超过
// Playwright 默认 5 秒断言期限，但仍应受明确的 30 秒交互预算约束。
// English: atomic upload publication includes file and parent-directory fsync.
// Cold or busy storage may exceed Playwright's five-second assertion default,
// while remaining bounded by an explicit 30-second interaction budget.
const MUTATION_UI_TIMEOUT_MS = 30_000;

test("directory UI records moderate issues and blocks serious violations", async ({ page }, testInfo) => {
  const response = await page.goto("/");
  expect(response).not.toBeNull();
  const policy = response.headers()["content-security-policy"];
  expect(response.headers()["permissions-policy"])
    .toBe("camera=(), geolocation=(), microphone=(), payment=(), usb=()");
  for (const directive of [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "connect-src 'self'",
    "frame-src blob:",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ]) {
    expect(policy).toContain(directive);
  }
  await expect(page).toHaveTitle(/Index of/);
  // The desktop toolbar deliberately retains dufs 0.46's compact geometry.
  // Touch target sizing is verified in the coarse-pointer test below.
  const results = await new AxeBuilder({ page }).analyze();
  const moderate = results.violations.filter(item => item.impact === "moderate");
  await testInfo.attach("axe-moderate.json", {
    body: Buffer.from(JSON.stringify(moderate, null, 2)),
    contentType: "application/json",
  });
  const serious = results.violations.filter(item => ["serious", "critical"].includes(item.impact));
  expect(serious).toEqual([]);
});

test("viewer stays read-only for both read-only and read-write paths", async ({ baseURL, browser }) => {
  const context = await browser.newContext({
    baseURL,
    httpCredentials: { username: "reader", password: "reader", send: "always" },
  });
  const page = await context.newPage();
  try {
    await page.goto("/hello.txt?view");
    await expect(page.locator(".text-viewer"))
      .toContainText("Hello from the browser integration fixture.");
    await expect(page.locator("#editor")).toHaveCount(0);
    await expect(page.getByRole("button", { name: /Save|Move|Delete/ })).toHaveCount(0);
    expect((await context.request.put("/hello.txt", { data: "forbidden" })).status()).toBe(403);

    await page.goto("/dir1/hello.txt?view");
    await expect(page.locator(".text-viewer")).toBeVisible();
    await expect(page.locator("#editor")).toHaveCount(0);
    await expect(page.getByRole("button", { name: /Save|Move|Delete/ })).toHaveCount(0);
  } finally {
    await context.close();
  }
});

test("keyboard focus and coarse-pointer controls remain visible and usable", async ({
  baseURL,
  browser,
}) => {
  const context = await browser.newContext({
    baseURL,
    hasTouch: true,
    viewport: { width: 390, height: 844 },
    httpCredentials: { username: "admin", password: "admin", send: "always" },
  });
  const page = await context.newPage();
  try {
    await page.goto("/");
    const upload = page.locator(".upload-file");
    await expect(upload).toBeVisible();
    const box = await upload.boundingBox();
    expect(box.width).toBeGreaterThanOrEqual(44);
    expect(box.height).toBeGreaterThanOrEqual(44);

    await upload.focus();
    expect(await upload.evaluate(element =>
      element.ownerDocument.defaultView.getComputedStyle(element).outlineWidth,
    )).toBe("2px");
  } finally {
    await context.close();
  }
});

test("management CSP permits bounded sandboxed blob previews", async ({ page }) => {
  const previewPath = "/csp-preview.png";
  const onePixelPng = Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
    "base64",
  );
  try {
    const upload = await page.request.put(previewPath, { data: onePixelPng });
    expect(upload.status()).toBe(201);

    const previewResponse = page.waitForResponse(response =>
      new URL(response.url()).pathname === previewPath
      && response.request().resourceType() === "fetch",
    );
    await page.goto(`${previewPath}?view`);
    const frame = page.locator('iframe[title="File preview"]');
    await expect(frame).toBeVisible();
    expect((await previewResponse).status()).toBe(200);
    await expect(frame).toHaveAttribute("src", /^blob:/);
    await expect(frame).toHaveAttribute("sandbox", "");
    await expect.poll(() => page.frames().some(candidate => candidate.url().startsWith("blob:")))
      .toBe(true);
  } finally {
    await page.request.delete(previewPath);
  }
});

test("a zero-byte file is uploaded and announced", async ({ page }) => {
  const uploadedPath = "/empty-browser-upload.txt";
  try {
    await page.goto("/");
    await expect(page.getByRole("button", { name: "Delete hello.txt" })).toBeVisible();
    await page.locator("#file").setInputFiles({
      name: uploadedPath.slice(1),
      mimeType: "text/plain",
      buffer: Buffer.alloc(0),
    });
    await expect(page.getByText("✓ Complete")).toBeVisible({ timeout: MUTATION_UI_TIMEOUT_MS });
    // 中文：动态上传行必须位于 tbody，不依赖浏览器对非法 table>tr 的容错。
    // English: dynamic upload rows belong in tbody and must not rely on browser recovery for invalid table>tr markup.
    await expect(page.locator(".uploaders-table > tbody > tr.uploader")).toHaveCount(1);
    // 中文：PUT 成功已使页面加载时的目录版本过期；危险操作必须在当前页面立即
    // 消失，而不是让用户点击后才从服务端收到可预见的 412。
    // English: successful PUT makes the page-load directory version stale.
    // Dangerous controls must disappear immediately rather than waiting for a
    // predictable server-side 412 after the user clicks one.
    await expect(page.getByRole("button", { name: "Delete hello.txt" })).toHaveCount(0);
    await expect(page.getByRole("alert")).toContainText("no stable directory snapshot");
    const response = await page.request.get(uploadedPath);
    expect(response.status()).toBe(200);
    expect((await response.body()).length).toBe(0);
  } finally {
    await page.request.delete(uploadedPath);
  }
});
