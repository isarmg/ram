import { expect, test } from "@playwright/test";

const MUTATION_UI_TIMEOUT_MS = 30_000;

/** @param {string} value */
const pathFor = value => `/${value.replace(/[^a-zA-Z0-9._-]/g, "-")}`;

/**
 * @param {import("@playwright/test").Page} page
 * @param {string[]} paths
 */
async function cleanup(page, paths) {
  for (const path of paths.reverse()) {
    const response = await page.request.delete(path);
    expect([200, 204, 404]).toContain(response.status());
  }
}

/** @param {import("@playwright/test").Download} download */
async function readDownload(download) {
  const stream = await download.createReadStream();
  const chunks = [];
  for await (const chunk of stream) chunks.push(chunk);
  return Buffer.concat(chunks);
}

test("malformed embedded state renders an accessible initialization error", async ({ page }) => {
  await page.route("**/", async route => {
    const response = await route.fetch();
    const body = (await response.text()).replace(
      /(<template id="index-data">)[^<]*(<\/template>)/,
      "$1not-valid-base64$2",
    );
    await route.fulfill({ response, body });
  });
  await page.goto("/");
  await expect(page).toHaveTitle("Ram UI error");
  await expect(page.getByRole("alert")).toContainText("Unable to initialize the file manager");
  await expect(page.locator(".head")).toBeHidden();
});

test("search, sorting, folder creation, move and delete remain available", async ({ page }, testInfo) => {
  const prefix = `${testInfo.project.name}-${Date.now()}`;
  const folder = pathFor(`${prefix}-folder`);
  const original = pathFor(`${prefix}-file.txt`);
  const moved = pathFor(`${prefix}-moved.txt`);
  const neighbour = pathFor(`${prefix}-neighbour.txt`);
  try {
    await page.goto("/");
    await page.getByLabel("Search folders or files").fill("hello");
    await page.getByLabel("Search folders or files").press("Enter");
    await expect(page).toHaveURL(/\?q=hello$/);
    await expect(page.getByRole("link", { name: "hello.txt", exact: true })).toBeVisible();

    await page.goto("/");
    await expect(page.locator(".paths-table th.cell-name")).toHaveAttribute("aria-sort", "ascending");
    await page.getByRole("link", { name: /Last Modified/ }).click();
    await expect(page).toHaveURL(/sort=mtime/);
    await expect(page.locator("th.cell-mtime")).toHaveAttribute("aria-sort", "descending");

    page.once("dialog", dialog => dialog.accept(folder.slice(1)));
    await page.getByRole("button", { name: "Create a new folder" }).click();
    await expect(page).toHaveURL(new RegExp(`${folder}/?$`), { timeout: MUTATION_UI_TIMEOUT_MS });

    expect((await page.request.put(original, { data: "read only in the browser" })).status()).toBe(201);
    expect((await page.request.put(neighbour, { data: "neighbour" })).status()).toBe(201);
    await page.goto("/");
    page.once("dialog", dialog => dialog.accept(moved));
    await page.getByRole("button", { name: `Move or rename ${original.slice(1)}` }).click();
    await expect(page).toHaveURL(/\/$/, { timeout: MUTATION_UI_TIMEOUT_MS });
    await expect(page.getByRole("link", { name: moved.slice(1), exact: true })).toBeVisible();

    const remove = page.getByRole("button", { name: `Delete ${moved.slice(1)}` });
    await remove.focus();
    page.once("dialog", dialog => dialog.accept());
    await remove.click();
    await expect(page.getByRole("link", { name: moved.slice(1), exact: true })).toHaveCount(0);
    await expect.poll(() => page.evaluate(() =>
      // eslint-disable-next-line no-undef -- evaluated in the browser realm / 在浏览器作用域求值
      document.activeElement?.tagName,
    )).not.toBe("BODY");
  } finally {
    await cleanup(page, [neighbour, moved, original, folder]);
  }
});

test("text viewing is read-only and the old edit query exposes no editor", async ({ page }, testInfo) => {
  const path = pathFor(`${testInfo.project.name}-${Date.now()}-view.txt`);
  try {
    expect((await page.request.put(path, { data: "只读内容\nsecond line" })).status()).toBe(201);

    await page.goto(`${path}?view`);
    await expect(page.locator(".text-viewer")).toHaveText("只读内容\nsecond line");
    const downloadHref = await page.getByRole("link", { name: "Download file" }).getAttribute("href");
    const downloadUrl = new URL(downloadHref, page.url());
    expect(downloadUrl.pathname).toBe(path);
    expect(downloadUrl.search).toBe("?download");
    await expect(page.locator("#editor")).toHaveCount(0);
    await expect(page.getByRole("button", { name: /Save|Move|Delete/ })).toHaveCount(0);

    const response = await page.goto(`${path}?edit`);
    expect(response?.status()).toBe(200);
    expect(await response?.text()).toBe("只读内容\nsecond line");
    await expect(page.locator("#editor")).toHaveCount(0);
  } finally {
    await cleanup(page, [path]);
  }
});

test("text viewer rejects invalid UTF-8 and rechecks the streamed byte limit", async ({ page }, testInfo) => {
  const prefix = `${testInfo.project.name}-${Date.now()}`;
  const binary = pathFor(`${prefix}-binary.txt`);
  const oversized = pathFor(`${prefix}-oversized.txt`);
  const maximum = 4 * 1024 * 1024;
  try {
    // Keep the server-side text classification deterministic, then make the
    // viewer receive bytes that are invalid for the response's declared UTF-8
    // encoding. The server legitimately detects and serves non-UTF-8 text, so
    // arbitrary on-disk bytes are not by themselves a malformed text response.
    expect((await page.request.put(binary, { data: "initially valid text" })).status()).toBe(201);
    await page.route(`**${binary}`, async route => {
      const request = route.request();
      if (request.method() === "GET" && request.resourceType() === "fetch") {
        await route.fulfill({
          status: 200,
          headers: { "content-type": "text/plain; charset=utf-8" },
          body: Buffer.from([0xc3, 0x28]),
        });
      } else {
        await route.continue();
      }
    });
    await page.goto(`${binary}?view`);
    await expect(page.locator(".viewer-status")).toContainText(/could not be loaded/i);
    await expect(page.locator(".text-viewer")).toBeHidden();
    await expect(page.getByRole("link", { name: "Download file" })).toBeVisible();
    await page.unroute(`**${binary}`);

    expect((await page.request.put(oversized, { data: "initially small" })).status()).toBe(201);
    await page.route(`**${oversized}`, async route => {
      const request = route.request();
      if (request.method() === "GET" && request.resourceType() === "fetch") {
        await route.fulfill({
          status: 200,
          headers: { "content-type": "text/plain; charset=utf-8" },
          body: Buffer.alloc(maximum + 1, 0x61),
        });
      } else {
        await route.continue();
      }
    });
    await page.goto(`${oversized}?view`);
    const status = page.locator(".viewer-status");
    await expect(status).toHaveAttribute("role", "status");
    await expect(status).toHaveAttribute("aria-live", "polite");
    await expect(status).toHaveAttribute("aria-atomic", "true");
    await expect(status).toContainText(`limited to ${maximum} bytes`);
    await expect(page.locator(".text-viewer")).toBeHidden();
  } finally {
    await page.unroute(`**${binary}`);
    await page.unroute(`**${oversized}`);
    await cleanup(page, [oversized, binary]);
  }
});

test("media viewing buffers within a capability-free sandbox", async ({ page }, testInfo) => {
  const path = pathFor(`${testInfo.project.name}-${Date.now()}-preview.png`);
  const onePixelPng = Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
    "base64",
  );
  try {
    expect((await page.request.put(path, { data: onePixelPng })).status()).toBe(201);
    const previewResponse = page.waitForResponse(response =>
      new URL(response.url()).pathname === path
      && response.request().resourceType() === "fetch",
    );
    await page.goto(`${path}?view`);
    const frame = page.locator('iframe[title="File preview"]');
    await expect(frame).toBeVisible();
    expect((await previewResponse).status()).toBe(200);
    await expect(frame).toHaveAttribute("src", /^blob:/);
    await expect(frame).toHaveAttribute("sandbox", "");
    await expect.poll(() => page.frames().some(candidate => candidate.url().startsWith("blob:")))
      .toBe(true);
  } finally {
    await cleanup(page, [path]);
  }
});

test("upload failures can be retried and uploads remain create-only", async ({ page }, testInfo) => {
  const prefix = `${testInfo.project.name}-${Date.now()}`;
  const failed = pathFor(`${prefix}-failed.txt`);
  const existing = pathFor(`${prefix}-existing.txt`);
  let failOnce = true;
  let createCondition = "";
  await page.route("**/*", async route => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    if (request.method() !== "PUT" || ![failed, existing].includes(pathname)) {
      await route.continue();
      return;
    }
    createCondition = request.headers()["if-none-match"] ?? createCondition;
    if (pathname === failed && failOnce) {
      failOnce = false;
      await route.fulfill({ status: 503, body: "injected upload failure" });
    } else {
      await route.continue();
    }
  });
  try {
    expect((await page.request.put(existing, { data: "original server value" })).status()).toBe(201);
    await page.goto("/");
    await page.locator("#file").setInputFiles([
      { name: failed.slice(1), mimeType: "text/plain", buffer: Buffer.from("retry me") },
      { name: existing.slice(1), mimeType: "text/plain", buffer: Buffer.from("must not overwrite") },
    ]);
    await expect(page.getByRole("button", { name: `Retry upload of ${failed.slice(1)}` })).toBeVisible();
    await page.getByRole("button", { name: `Retry upload of ${failed.slice(1)}` }).click();
    await expect(page.getByText("✓ Complete", { exact: true })).toHaveCount(1);
    expect(await (await page.request.get(failed)).text()).toBe("retry me");
    await expect(page.getByRole("button", { name: `Retry upload of ${existing.slice(1)}` })).toBeVisible();
    expect(createCondition).toBe("*");
    expect(await (await page.request.get(existing)).text()).toBe("original server value");
  } finally {
    await page.unroute("**/*");
    await cleanup(page, [existing, failed]);
  }
});

test("file and directory downloads use browser-native streaming", async ({
  browserName,
  page,
}, testInfo) => {
  const prefix = `${testInfo.project.name}-${Date.now()}`;
  const file = pathFor(`${prefix}-download.txt`);
  const largeFile = pathFor(`${prefix}-large.bin`);
  const folder = pathFor(`${prefix}-archive`);
  const largeSize = (5 * 1024 * 1024) + 17;
  try {
    expect((await page.request.put(file, { data: "file body" })).status()).toBe(201);
    expect((await page.request.put(largeFile, {
      data: Buffer.alloc(largeSize, 0x5a),
    })).status()).toBe(201);
    expect((await page.request.fetch(folder, { method: "MKCOL" })).status()).toBe(201);
    expect((await page.request.put(`${folder}/inside.txt`, { data: "archive body" })).status()).toBe(201);
    await page.goto("/");

    const fileLink = page.getByRole("link", { name: `Download ${file.slice(1)}` });
    const fileUrl = new URL(await fileLink.getAttribute("href"), page.url());
    expect(fileUrl.pathname).toBe(file);
    expect(fileUrl.search).toBe("?download");
    expect(await fileLink.getAttribute("download")).toBe(file.slice(1));

    const largeLink = page.getByRole("link", { name: `Download ${largeFile.slice(1)}` });
    const largeUrl = new URL(await largeLink.getAttribute("href"), page.url());
    expect(largeUrl.pathname).toBe(largeFile);
    expect(largeUrl.search).toBe("?download");
    expect(await largeLink.getAttribute("download")).toBe(largeFile.slice(1));

    const archiveLink = page.getByRole("link", { name: `Download ${folder.slice(1)} as a zip file` });
    const archiveUrl = new URL(await archiveLink.getAttribute("href"), page.url());
    expect(archiveUrl.pathname).toBe(`${folder}/`);
    expect(archiveUrl.search).toBe("?zip");
    expect(await archiveLink.getAttribute("download")).toBeNull();

    if (browserName === "webkit") {
      // Playwright's Linux WebKit port does not surface downloads as Download
      // objects. Verify the same native-link contract at both boundaries:
      // JavaScript exposes only links, and the server forces attachment
      // responses that real Safari/WebKit hands to its download manager.
      const fileResponse = await page.request.get(fileUrl.toString());
      expect(fileResponse.headers()["content-disposition"]).toMatch(/^attachment;/);
      expect(await fileResponse.text()).toBe("file body");
      const largeResponse = await page.request.get(largeUrl.toString());
      expect(largeResponse.headers()["content-disposition"]).toMatch(/^attachment;/);
      expect((await largeResponse.body()).length).toBe(largeSize);
      const archiveResponse = await page.request.get(archiveUrl.toString());
      expect(archiveResponse.headers()["content-disposition"]).toMatch(/^attachment;/);
      expect((await archiveResponse.body()).subarray(0, 2).toString()).toBe("PK");
      return;
    }

    const [fileDownload] = await Promise.all([page.waitForEvent("download"), fileLink.click()]);
    expect((await readDownload(fileDownload)).toString()).toBe("file body");

    const [largeDownload] = await Promise.all([
      page.waitForEvent("download"),
      largeLink.click(),
    ]);
    const largeStream = await largeDownload.createReadStream();
    let downloadedBytes = 0;
    for await (const chunk of largeStream) downloadedBytes += chunk.length;
    expect(downloadedBytes).toBe(largeSize);

    const [archiveDownload] = await Promise.all([
      page.waitForEvent("download"),
      archiveLink.click(),
    ]);
    expect(archiveDownload.suggestedFilename()).toBe(`${folder.slice(1)}.zip`);
    expect((await readDownload(archiveDownload)).subarray(0, 2).toString()).toBe("PK");
  } finally {
    await cleanup(page, [folder, largeFile, file]);
  }
});

test("logout failures remain visible without leaving the directory", async ({ page }) => {
  await page.goto("/");
  await page.route("**/*", async route => {
    if (route.request().method() === "LOGOUT") {
      await route.fulfill({ status: 503, body: "injected" });
    } else {
      await route.continue();
    }
  });
  const message = new Promise(resolve => page.once("dialog", dialog => {
    resolve(dialog.message());
    void dialog.accept();
  }));
  await page.getByRole("button", { name: /Log out/ }).click();
  expect(await message).toContain("Logout failed");
  await expect(page).toHaveURL(/\/$/);
  await page.unroute("**/*");
});

test("desktop toolbar retains its compact layout", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 720 });
  await page.goto("/");
  const breadcrumb = page.getByRole("navigation", { name: "Breadcrumb" });
  const toolbox = page.locator(".toolbox");
  const upload = page.getByRole("button", { name: "Upload files" });
  const search = page.getByRole("searchbox", { name: "Search folders or files" });
  const searchbar = page.getByRole("search", { name: "Search files and folders" });
  const [breadcrumbBox, toolboxBox, uploadBox, searchBox, searchbarBox] = await Promise.all([
    breadcrumb.boundingBox(),
    toolbox.boundingBox(),
    upload.boundingBox(),
    search.boundingBox(),
    searchbar.boundingBox(),
  ]);
  expect(breadcrumbBox).not.toBeNull();
  expect(toolboxBox).not.toBeNull();
  expect(uploadBox).not.toBeNull();
  expect(searchBox).not.toBeNull();
  expect(searchbarBox).not.toBeNull();
  expect(Math.abs(toolboxBox.x - (breadcrumbBox.x + breadcrumbBox.width))).toBeLessThanOrEqual(1);
  expect(searchbarBox.x - (toolboxBox.x + toolboxBox.width)).toBeCloseTo(10, 0);
  expect(searchbarBox.height).toBeCloseTo(24, 0);
  expect(searchBox.height).toBeCloseTo(22, 0);
});

test("mobile viewport and keyboard navigation keep controls usable", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  const upload = page.getByRole("button", { name: "Upload files" });
  const uploadFolder = page.getByRole("button", { name: "Upload folder" });
  const search = page.getByRole("searchbox", { name: "Search folders or files" });
  for (const control of [upload, uploadFolder, search]) {
    await expect(control).toBeVisible();
    const box = await control.boundingBox();
    expect(box?.width).toBeGreaterThanOrEqual(44);
    expect(box?.height).toBeGreaterThanOrEqual(44);
  }
  await page.keyboard.press("Tab");
  await expect.poll(() => page.evaluate(() =>
    // eslint-disable-next-line no-undef -- evaluated in the browser realm / 在浏览器作用域求值
    document.activeElement !== document.body,
  )).toBe(true);
  await upload.focus();
  await expect(upload).toBeFocused();
});
