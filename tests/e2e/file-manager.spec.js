import { expect, test } from "@playwright/test";

// 中文：原子发布包含目录 fsync；慢磁盘或冷 CI 上可能超过 Playwright 默认 5 秒断言期限。
// English: Atomic publication includes directory fsync and may exceed Playwright's
// default five-second assertion timeout on slow storage or a cold CI worker.
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

/**
 * 接受一次危险操作的确认/路径提示，并在最终错误 alert 后返回全部文案。
 * Accept a destructive-action confirmation/path prompt and return every
 * message once the terminal error alert has been dismissed.
 *
 * @param {import("@playwright/test").Page} page
 * @param {string} [promptValue]
 * @returns {Promise<string[]>}
 */
function acceptMutationDialogsUntilAlert(page, promptValue) {
  return new Promise((resolve, reject) => {
    const messages = [];
    /** @param {import("@playwright/test").Dialog} dialog */
    const handleDialog = async dialog => {
      const type = dialog.type();
      messages.push(dialog.message());
      try {
        if (type === "prompt") await dialog.accept(promptValue);
        else await dialog.accept();
        if (type === "alert") {
          page.off("dialog", handleDialog);
          resolve(messages);
        }
      } catch (error) {
        page.off("dialog", handleDialog);
        reject(error);
      }
    };
    page.on("dialog", handleDialog);
  });
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

test("search, sorting, create, move and delete work with keyboard focus restoration", async ({ page }, testInfo) => {
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

    await page.goto("/");
    page.once("dialog", dialog => dialog.accept(original.slice(1)));
    await page.getByRole("button", { name: "Create a new file" }).click();
    await expect(page).toHaveURL(new RegExp(`${original.replace(".", "\\.")}\\?edit$`), {
      timeout: MUTATION_UI_TIMEOUT_MS,
    });

    page.once("dialog", dialog => dialog.accept(moved));
    await page.getByRole("button", { name: "Move and rename" }).click();
    await expect(page).toHaveURL(new RegExp(`${moved.replace(".", "\\.")}\\?edit$`), {
      timeout: MUTATION_UI_TIMEOUT_MS,
    });

    expect((await page.request.put(neighbour, { data: "neighbour" })).status()).toBe(201);
    await page.goto("/");
    const remove = page.getByRole("button", { name: `Delete ${moved.slice(1)}` });
    await remove.focus();
    page.once("dialog", dialog => dialog.accept());
    await remove.click();
    await expect(page.getByRole("link", { name: moved.slice(1), exact: true })).toHaveCount(0);
    await expect.poll(() => page.evaluate(() => {
      // eslint-disable-next-line no-undef -- evaluated in the browser realm / 在浏览器作用域求值
      return document.activeElement?.tagName;
    })).not.toBe("BODY");
  } finally {
    await cleanup(page, [neighbour, moved, original, folder]);
  }
});

test("editor rejects stale ETags and preserves a UTF-8 BOM", async ({ page }, testInfo) => {
  const prefix = `${testInfo.project.name}-${Date.now()}`;
  const conflict = pathFor(`${prefix}-conflict.txt`);
  const bom = pathFor(`${prefix}-bom.txt`);
  try {
    expect((await page.request.put(conflict, { data: "initial" })).status()).toBe(201);
    await page.goto(`${conflict}?edit`);
    await expect(page.locator("#editor")).toHaveValue("initial");
    await page.locator("#editor").fill("browser edit");
    expect((await page.request.put(conflict, { data: "server edit" })).status()).toBe(204);
    const conflictMessage = new Promise(resolve => page.once("dialog", dialog => {
      resolve(dialog.message());
      void dialog.accept();
    }));
    await page.getByRole("button", { name: "Save file" }).click();
    expect(await conflictMessage).toContain("modified on the server");
    expect(await (await page.request.get(conflict)).text()).toBe("server edit");

    const bomBytes = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from("with bom")]);
    expect((await page.request.put(bom, { data: bomBytes })).status()).toBe(201);
    await page.goto(`${bom}?edit`);
    await expect(page.locator("#editor")).toHaveValue("with bom");
    await page.locator("#editor").fill("changed");
    const savedResponse = page.waitForResponse(response => {
      const request = response.request();
      return request.method() === "PUT" && new URL(response.url()).pathname === bom;
    });
    await page.getByRole("button", { name: "Save file" }).click();
    expect((await savedResponse).status()).toBe(204);
    const saved = await (await page.request.get(bom)).body();
    expect([...saved.subarray(0, 3)]).toEqual([0xef, 0xbb, 0xbf]);
    expect(saved.subarray(3).toString()).toBe("changed");
  } finally {
    await cleanup(page, [bom, conflict]);
  }
});

test("editor DELETE and MOVE reject stale source ETags without changing either path", async ({ page }, testInfo) => {
  const prefix = `${testInfo.project.name}-${Date.now()}`;
  const deleted = pathFor(`${prefix}-stale-delete.txt`);
  const moved = pathFor(`${prefix}-stale-move.txt`);
  const destination = pathFor(`${prefix}-must-not-exist.txt`);
  let releaseInitialGet;
  try {
    expect((await page.request.put(deleted, { data: "delete initial" })).status()).toBe(201);
    expect((await page.request.put(moved, { data: "move initial" })).status()).toBe(201);

    let resolveInitialGetStarted;
    const initialGetStarted = new Promise(resolve => { resolveInitialGetStarted = resolve; });
    await page.route(`**${deleted}`, async route => {
      const request = route.request();
      if (request.method() !== "GET" || request.resourceType() !== "fetch") {
        await route.continue();
        return;
      }
      resolveInitialGetStarted?.();
      await new Promise(resolve => { releaseInitialGet = resolve; });
      await route.continue();
    });
    await page.goto(`${deleted}?edit`);
    await initialGetStarted;

    // 中文：初始 GET 尚未返回时控件必须禁用；即使脚本绕过原生 disabled 人工
    // 派发事件，处理器的第二层检查也必须拒绝，绝不能发出无条件 DELETE。
    // English: controls stay disabled until the initial GET returns. Even if
    // script bypasses native disabled handling and dispatches an event, the
    // handler's second guard must reject rather than issue unconditional DELETE.
    const deleteButton = page.getByRole("button", { name: "Delete file" });
    await expect(deleteButton).toBeDisabled();
    const earlyWarning = new Promise(resolve => page.once("dialog", async dialog => {
      resolve(dialog.message());
      await dialog.accept();
    }));
    await deleteButton.evaluate(button => {
      // eslint-disable-next-line no-undef -- evaluated in the browser realm / 在浏览器作用域求值
      button.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });
    expect(await earlyWarning).toContain("strong ETag has not been loaded");
    releaseInitialGet?.();
    await expect(page.getByRole("textbox", { name: "Editor" })).toHaveValue("delete initial");
    await page.unroute(`**${deleted}`);
    await expect(deleteButton).toBeEnabled();

    expect((await page.request.put(deleted, { data: "delete external replacement" })).status()).toBe(204);
    const deleteResponse = page.waitForResponse(response =>
      response.request().method() === "DELETE" && new URL(response.url()).pathname === deleted,
    );
    const deleteDialogs = acceptMutationDialogsUntilAlert(page);
    await page.getByRole("button", { name: "Delete file" }).click();
    expect((await deleteResponse).status()).toBe(412);
    expect((await deleteDialogs).join(" ")).toContain("file changed on the server");
    const deleteSurvivor = await page.request.get(deleted);
    expect(deleteSurvivor.status()).toBe(200);
    expect(await deleteSurvivor.text()).toBe("delete external replacement");

    await page.goto(`${moved}?edit`);
    await expect(page.getByRole("textbox", { name: "Editor" })).toHaveValue("move initial");
    expect((await page.request.put(moved, { data: "move external replacement" })).status()).toBe(204);
    const moveResponse = page.waitForResponse(response =>
      response.request().method() === "MOVE" && new URL(response.url()).pathname === moved,
    );
    const moveDialogs = acceptMutationDialogsUntilAlert(page, destination);
    await page.getByRole("button", { name: "Move and rename" }).click();
    expect((await moveResponse).status()).toBe(412);
    expect((await moveDialogs).join(" ")).toContain("source file changed on the server");
    const moveSurvivor = await page.request.get(moved);
    expect(moveSurvivor.status()).toBe(200);
    expect(await moveSurvivor.text()).toBe("move external replacement");
    expect((await page.request.get(destination)).status()).toBe(404);
  } finally {
    releaseInitialGet?.();
    await page.unrouteAll({ behavior: "wait" });
    await cleanup(page, [destination, moved, deleted]);
  }
});

test("editor preserves input typed while an earlier save snapshot is in flight", async ({ page }, testInfo) => {
  const path = pathFor(`${testInfo.project.name}-${Date.now()}-save-race.txt`);
  const rejectedMoveDestination = pathFor(`${testInfo.project.name}-${Date.now()}-save-race-move.txt`);
  let releaseFirstPut;
  let firstPut = true;
  try {
    expect((await page.request.put(path, { data: "initial" })).status()).toBe(201);
    await page.goto(`${path}?edit`);
    let resolveFirstPutStarted;
    const firstPutStarted = new Promise(resolve => { resolveFirstPutStarted = resolve; });
    // 中文：fixture 的初始化 PUT 必须在注册 route 之前完成；不同 Playwright
    // 版本对 page.request 与页面路由的组合边界可能不同，不能让测试自己的拦截器
    // 把种子请求无限挂起。
    // English: finish the fixture PUT before installing the route. Playwright
    // versions need not share identical page.request routing boundaries, and
    // the test must never deadlock its own seed request.
    await page.route(`**${path}`, async route => {
      if (route.request().method() !== "PUT" || !firstPut) {
        await route.continue();
        return;
      }
      firstPut = false;
      resolveFirstPutStarted?.();
      await new Promise(resolve => { releaseFirstPut = resolve; });
      await route.continue();
    });
    const editor = page.getByRole("textbox", { name: "Editor" });
    await editor.fill("submitted snapshot");
    await page.getByRole("button", { name: "Save file" }).click();
    await firstPutStarted;

    await expect(page.getByRole("button", { name: "Move and rename" })).toBeDisabled();
    await expect(page.getByRole("button", { name: "Delete file" })).toBeDisabled();
    await expect(editor).not.toHaveAttribute("readonly", "");

    // 中文：保存事件已经捕获请求体，但响应尚未返回；这正是旧实现会把后续
    // 输入错误清零并 reload 的竞态窗口。
    // English: the save handler has captured its request body but the response
    // is still pending—the exact window in which the old implementation would
    // clear and reload away newer input.
    await editor.fill("newer unsaved input");
    const snapshotNotice = new Promise(resolve => page.once("dialog", dialog => {
      resolve(dialog.message());
      void dialog.accept();
    }));
    releaseFirstPut?.();
    expect(await snapshotNotice).toContain("earlier snapshot was saved");
    await expect(editor).toHaveValue("newer unsaved input");
    const committedSnapshot = await page.request.get(path);
    expect(await committedSnapshot.text()).toBe("submitted snapshot");
    const committedEtag = committedSnapshot.headers().etag;
    expect(committedEtag).toMatch(/^".*"$/);

    // 中文：保存后的无缓存复核必须更新所有后续源操作共享的 ETag，而不只是下一次
    // PUT。这里让 MOVE 固定返回 412，仅检查它携带的校验器且保留编辑缓冲区。
    // English: post-save verification must update the ETag shared by every
    // later source mutation, not only the next PUT. Reject MOVE deliberately
    // after observing its validator so the editor buffer remains available.
    let observedMoveEtag;
    /** @param {import("@playwright/test").Route} route */
    const rejectObservedMove = async route => {
      if (route.request().method() === "MOVE") {
        observedMoveEtag = route.request().headers()["if-match"];
        await route.fulfill({ status: 412, body: "" });
      } else {
        await route.continue();
      }
    };
    await page.route(`**${path}`, rejectObservedMove);
    const rejectedMove = page.waitForResponse(response =>
      response.request().method() === "MOVE" && new URL(response.url()).pathname === path,
    );
    const moveDialogs = acceptMutationDialogsUntilAlert(page, rejectedMoveDestination);
    await page.getByRole("button", { name: "Move and rename" }).click();
    expect((await rejectedMove).status()).toBe(412);
    await moveDialogs;
    await page.unroute(`**${path}`, rejectObservedMove);
    expect(observedMoveEtag).toBe(committedEtag);
    await expect(editor).toHaveValue("newer unsaved input");

    const secondSave = page.waitForResponse(response =>
      response.request().method() === "PUT" && new URL(response.url()).pathname === path,
    );
    await page.getByRole("button", { name: "Save file" }).click();
    expect((await secondSave).status()).toBe(204);
    await expect.poll(async () => (await (await page.request.get(path)).text()))
      .toBe("newer unsaved input");
  } finally {
    releaseFirstPut?.();
    await page.unroute(`**${path}`);
    await cleanup(page, [rejectedMoveDestination, path]);
  }
});

test("editor warns before navigation would discard unsaved text", async ({ page }, testInfo) => {
  const path = pathFor(`${testInfo.project.name}-${Date.now()}-dirty-editor.txt`);
  try {
    expect((await page.request.put(path, { data: "saved text" })).status()).toBe(201);
    await page.goto(`${path}?edit`);
    const editor = page.getByRole("textbox", { name: "Editor" });
    await expect(editor).toHaveValue("saved text");
    await editor.fill("unsaved browser text");

    // 中文：离页对话框由浏览器而不是应用渲染；拒绝导航后必须保留 URL 与编辑缓冲区。
    // English: The browser owns the beforeunload dialog. Dismissing navigation
    // must preserve both the URL and the in-memory edit buffer.
    const warningType = new Promise(resolve => page.once("dialog", dialog => {
      resolve(dialog.type());
      void dialog.dismiss();
    }));
    await page.getByRole("link", { name: "Root" }).click();
    expect(await warningType).toBe("beforeunload");
    await expect(page).toHaveURL(new RegExp(`${path.replace(".", "\\.")}\\?edit$`));
    await expect(editor).toHaveValue("unsaved browser text");

    // 中文：完全撤销修改会回到 clean 状态，此时面包屑导航不应再产生误报警告。
    // English: Restoring the exact loaded value returns to clean state, so
    // breadcrumb navigation must proceed without another false warning.
    await editor.fill("saved text");
    await page.getByRole("link", { name: "Root" }).click();
    await expect(page).toHaveURL(/\/$/);
  } finally {
    await cleanup(page, [path]);
  }
});

test("non-UTF-8 and oversized files are shown fail-closed", async ({ page }, testInfo) => {
  const prefix = `${testInfo.project.name}-${Date.now()}`;
  const binary = pathFor(`${prefix}-binary.txt`);
  const large = pathFor(`${prefix}-large.txt`);
  const unavailableHead = pathFor(`${prefix}-head-failure.bin`);
  try {
    expect((await page.request.put(binary, { data: Buffer.from([0xff, 0xfe, 0xfd, 0x00]) })).status()).toBe(201);
    await page.goto(`${binary}?edit`);
    await expect(page.locator(".not-editable")).toContainText(/UTF-8|valid|binary/i);
    await expect(page.getByRole("button", { name: "Save file" })).toBeHidden();
    await expect(page.getByRole("button", { name: "Move and rename" })).toBeEnabled();
    await expect(page.getByRole("button", { name: "Delete file" })).toBeEnabled();

    expect((await page.request.put(large, { data: Buffer.alloc(4 * 1024 * 1024 + 1, 0x61) })).status()).toBe(201);
    await page.goto(`${large}?edit`);
    await expect(page.locator(".not-editable")).toContainText(/too large|binary/i);
    await expect(page.locator("#editor")).toBeHidden();
    // 中文：非预览文件没有正文 GET，控件只能在认证 HEAD 返回强 ETag 后解锁；
    // 超过服务端强 ETag 预算的文件只有弱校验器，必须持续失败关闭。
    // English: a non-preview file has no body GET, so controls unlock only
    // after an authenticated HEAD supplies a strong ETag. Files beyond the
    // server's strong-ETag budget expose only a weak validator and stay closed.
    await expect(page.getByRole("button", { name: "Move and rename" })).toBeDisabled();
    await expect(page.getByRole("button", { name: "Delete file" })).toBeDisabled();
    await expect(page.locator(".not-editable")).toContainText(/did not provide a strong ETag/i);
    await expect(page.locator(".not-editable")).toContainText(/parent directory/i);

    expect((await page.request.put(unavailableHead, { data: Buffer.from([0x00, 0xff, 0x00]) })).status()).toBe(201);
    await page.route(`**${unavailableHead}`, async route => {
      if (route.request().method() === "HEAD") await route.fulfill({ status: 503, body: "" });
      else await route.continue();
    });
    await page.goto(`${unavailableHead}?edit`);
    await expect(page.getByRole("button", { name: "Move and rename" })).toBeDisabled();
    await expect(page.getByRole("button", { name: "Delete file" })).toBeDisabled();
    await expect(page.locator(".not-editable")).toContainText(/HEAD snapshot failed/i);
    await expect(page.locator(".not-editable")).toContainText(/parent directory/i);
  } finally {
    await page.unroute(`**${unavailableHead}`);
    await cleanup(page, [unavailableHead, large, binary]);
  }
});

test("preview Edit pages reuse strong GET ETags and reject weak validators", async ({ page }, testInfo) => {
  const prefix = `${testInfo.project.name}-${Date.now()}`;
  const strongPreview = pathFor(`${prefix}-strong-preview.png`);
  const weakPreview = pathFor(`${prefix}-weak-preview.png`);
  const pngBytes = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00]);
  try {
    expect((await page.request.put(strongPreview, { data: pngBytes })).status()).toBe(201);
    expect((await page.request.put(weakPreview, { data: pngBytes })).status()).toBe(201);

    await page.goto(`${strongPreview}?edit`);
    await expect(page.locator("iframe[title='File preview']")).toBeAttached();
    await expect(page.getByRole("button", { name: "Delete file" })).toBeEnabled();
    expect((await page.request.put(strongPreview, { data: Buffer.concat([pngBytes, Buffer.from([1])]) })).status()).toBe(204);
    const staleDelete = page.waitForResponse(response =>
      response.request().method() === "DELETE" && new URL(response.url()).pathname === strongPreview,
    );
    const staleDialogs = acceptMutationDialogsUntilAlert(page);
    await page.getByRole("button", { name: "Delete file" }).click();
    expect((await staleDelete).status()).toBe(412);
    expect((await staleDialogs).join(" ")).toContain("file changed on the server");
    expect((await page.request.get(strongPreview)).status()).toBe(200);

    await page.route(`**${weakPreview}`, async route => {
      const request = route.request();
      if (request.method() === "GET" && request.resourceType() === "fetch") {
        await route.fulfill({
          status: 200,
          headers: { "content-type": "image/png", etag: 'W/"weak-preview"' },
          body: pngBytes,
        });
      } else {
        await route.continue();
      }
    });
    await page.goto(`${weakPreview}?edit`);
    await expect(page.locator("iframe[title='File preview']")).toBeAttached();
    await expect(page.getByRole("button", { name: "Move and rename" })).toBeDisabled();
    await expect(page.getByRole("button", { name: "Delete file" })).toBeDisabled();
    await expect(page.locator(".not-editable")).toContainText(/did not provide a strong ETag/i);
    await expect(page.locator(".not-editable")).toContainText(/parent directory/i);
  } finally {
    await page.unroute(`**${weakPreview}`);
    await cleanup(page, [weakPreview, strongPreview]);
  }
});

test("editor rechecks the streamed 4 MiB boundary after page metadata becomes stale", async ({ page }, testInfo) => {
  const path = pathFor(`${testInfo.project.name}-${Date.now()}-editor-race.txt`);
  const maximum = 4 * 1024 * 1024;
  try {
    expect((await page.request.put(path, { data: "initially small" })).status()).toBe(201);
    await page.route(`**${path}`, async route => {
      const request = route.request();
      if (request.method() === "GET" && request.resourceType() === "fetch") {
        await route.fulfill({
          status: 200,
          headers: {
            "content-type": "text/plain; charset=utf-8",
            etag: '"replacement"',
          },
          body: Buffer.alloc(maximum + 1, 0x61),
        });
      } else {
        await route.continue();
      }
    });

    await page.goto(`${path}?edit`);
    const status = page.locator(".not-editable");
    await expect(status).toHaveAttribute("role", "status");
    await expect(status).toHaveAttribute("aria-live", "polite");
    await expect(status).toHaveAttribute("aria-atomic", "true");
    await expect(status).toContainText(`limited to ${maximum} bytes`);
    expect(await status.evaluate(element => element.ownerDocument.activeElement === element)).toBe(false);
    await expect(page.locator("#editor")).toBeHidden();
    await expect(page.getByRole("button", { name: "Save file" })).toBeHidden();
  } finally {
    await page.unroute(`**${path}`);
    await cleanup(page, [path]);
  }
});

test("upload failure, retry, cancellation and bounded concurrency are visible", async ({ page }, testInfo) => {
  const prefix = `${testInfo.project.name}-${Date.now()}`;
  const failed = pathFor(`${prefix}-failed.txt`);
  const first = pathFor(`${prefix}-one.txt`);
  const second = pathFor(`${prefix}-two.txt`);
  const third = pathFor(`${prefix}-three.txt`);
  let active = 0;
  let maximum = 0;
  let failOnce = true;
  await page.route("**/*", async route => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    if (request.method() !== "PUT" || ![failed, first, second, third].includes(pathname)) {
      await route.continue();
      return;
    }
    active += 1;
    maximum = Math.max(maximum, active);
    await new Promise(resolve => setTimeout(resolve, 150));
    active -= 1;
    if (pathname === failed && failOnce) {
      failOnce = false;
      await route.fulfill({ status: 503, body: "injected upload failure" });
    } else {
      await route.continue();
    }
  });
  try {
    await page.goto("/");
    await page.locator("#file").setInputFiles([
      { name: failed.slice(1), mimeType: "text/plain", buffer: Buffer.from("retry me") },
      { name: first.slice(1), mimeType: "text/plain", buffer: Buffer.alloc(128 * 1024, 1) },
      { name: second.slice(1), mimeType: "text/plain", buffer: Buffer.alloc(128 * 1024, 2) },
      { name: third.slice(1), mimeType: "text/plain", buffer: Buffer.alloc(128 * 1024, 3) },
    ]);
    const cancel = page.getByRole("button", { name: new RegExp(`Cancel upload of ${third.slice(1)}`) });
    await expect(cancel).toBeVisible();
    await page.setViewportSize({ width: 390, height: 844 });
    const cancelBox = await cancel.boundingBox();
    expect(cancelBox?.width).toBeGreaterThanOrEqual(44);
    expect(cancelBox?.height).toBeGreaterThanOrEqual(44);
    await cancel.click();
    await expect(page.getByText("Cancelled", { exact: false })).toBeVisible();
    await expect(page.getByRole("button", { name: `Retry upload of ${failed.slice(1)}` })).toBeVisible();
    await page.getByRole("button", { name: `Retry upload of ${failed.slice(1)}` }).click();
    await expect(page.getByText("✓ Complete", { exact: true })).toHaveCount(3);
    expect(maximum).toBeLessThanOrEqual(2);
  } finally {
    await page.unroute("**/*");
    await cleanup(page, [third, second, first, failed]);
  }
});

test("browser uploads are create-only and reject oversized response bodies", async ({ page }, testInfo) => {
  const prefix = `${testInfo.project.name}-${Date.now()}`;
  const existing = pathFor(`${prefix}-existing.txt`);
  const oversized = pathFor(`${prefix}-oversized-response.txt`);
  let createCondition = "";
  await page.route("**/*", async route => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    if (request.method() !== "PUT" || ![existing, oversized].includes(pathname)) {
      await route.continue();
      return;
    }
    createCondition = request.headers()["if-none-match"] ?? createCondition;
    if (pathname === oversized) {
      // 中文：模拟不可信反向代理返回超过前端 64 KiB 预算的错误页。
      // English: Simulate an untrusted reverse proxy returning an error page
      // beyond the frontend's 64 KiB response budget.
      await route.fulfill({ status: 503, body: "x".repeat(64 * 1024 + 1) });
    } else {
      await route.continue();
    }
  });
  try {
    expect((await page.request.put(existing, { data: "original server value" })).status()).toBe(201);
    await page.goto("/");
    await page.locator("#file").setInputFiles([
      { name: existing.slice(1), mimeType: "text/plain", buffer: Buffer.from("must not overwrite") },
      { name: oversized.slice(1), mimeType: "text/plain", buffer: Buffer.from("request body") },
    ]);

    await expect(page.getByRole("button", { name: `Retry upload of ${existing.slice(1)}` })).toBeVisible();
    await expect(page.getByRole("button", { name: `Retry upload of ${oversized.slice(1)}` })).toBeVisible();
    expect(createCondition).toBe("*");
    expect(await (await page.request.get(existing)).text()).toBe("original server value");
    expect((await page.request.get(oversized)).status()).toBe(404);
  } finally {
    await page.unroute("**/*");
    await cleanup(page, [oversized, existing]);
  }
});

test("token download keeps credentials out of URLs and logout failures stay visible", async ({ page }, testInfo) => {
  const file = pathFor(`${testInfo.project.name}-${Date.now()}-token.txt`);
  try {
    expect((await page.request.put(file, { data: "token body" })).status()).toBe(201);
    await page.goto("/");
    let bearerHeader = "";
    const requestedUrls = [];
    page.on("request", request => {
      requestedUrls.push(request.url());
      if (new URL(request.url()).pathname === file) bearerHeader = request.headers().authorization ?? bearerHeader;
    });
    const issued = page.waitForRequest(request =>
      request.method() === "POST"
      && new URL(request.url()).pathname === file
      && new URL(request.url()).searchParams.has("tokengen"),
    );
    const browserDownload = page.waitForEvent("download");
    await page.getByRole("link", { name: `Download ${file.slice(1)}` }).click();
    const tokenRequest = await issued;
    const tokenResponse = await tokenRequest.response();
    if (!tokenResponse) throw new Error("token request completed without a response");
    expect(tokenResponse.status()).toBe(200);
    const download = await browserDownload;
    expect(download.suggestedFilename()).toBe(file.slice(1));
    expect((await readDownload(download)).toString()).toBe("token body");
    expect(bearerHeader).toMatch(/^Bearer /);
    // 前端已经消费签发响应；Chromium 不保证 DevTools 之后仍缓存其 body。实际下载请求头是
    // 更权威的端到端观测点，也能直接证明 token 没有进入 URL。
    // The frontend has already consumed the issuance response, and Chromium need not retain its
    // body in the DevTools cache. The real download request header is the authoritative end-to-end
    // observation and directly proves the token never entered a URL.
    const token = bearerHeader.slice("Bearer ".length);
    expect(token.length).toBeGreaterThan(20);
    expect(requestedUrls.every(url => !url.includes(token))).toBe(true);

    await page.route("**/*", async route => {
      if (route.request().method() === "LOGOUT") await route.fulfill({ status: 503, body: "injected" });
      else await route.continue();
    });
    const message = new Promise(resolve => page.once("dialog", dialog => {
      resolve(dialog.message());
      void dialog.accept();
    }));
    await page.getByRole("button", { name: /Log out/ }).click();
    expect(await message).toContain("Logout failed");
    await expect(page).toHaveURL(/\/$/);
  } finally {
    if (!page.isClosed()) await page.unroute("**/*");
    await cleanup(page, [file]);
  }
});

test("directory download uses the browser-native streaming path", async ({ page }, testInfo) => {
  const folder = pathFor(`${testInfo.project.name}-${Date.now()}-native-archive`);
  try {
    expect((await page.request.fetch(folder, { method: "MKCOL" })).status()).toBe(201);
    expect((await page.request.put(`${folder}/inside.txt`, { data: "archive body" })).status()).toBe(201);
    await page.goto("/");

    // 中文：归档大小事先未知，所以必须由浏览器下载管理器流式接收，不能走 JS 内存缓冲。
    // 将它与 token blob 下载分成独立测试，避免 Safari/WebKit 的单页多次自动下载权限把两种路径相互污染。
    // English: archive size is unknown, so the browser download manager must stream it instead of
    // JavaScript buffering it. Keep this separate from the token/blob test because Safari/WebKit's
    // per-page multiple-download permission can otherwise couple two independent code paths.
    const archiveLink = page.getByRole("link", { name: `Download ${folder.slice(1)} as a zip file` });
    // 服务端 attachment 已决定下载；未知长度 ZIP 不得再携带会让 WebKit 挂起的空 download 属性。
    // The server attachment already selects downloading; an unknown-size ZIP must not retain the
    // empty download attribute that stalls WebKit.
    expect(await archiveLink.getAttribute("download")).toBeNull();
    const [archiveDownload] = await Promise.all([
      page.waitForEvent("download"),
      archiveLink.click(),
    ]);
    expect(archiveDownload.suggestedFilename()).toBe(`${folder.slice(1)}.zip`);
    expect((await readDownload(archiveDownload)).subarray(0, 2).toString()).toBe("PK");
  } finally {
    await cleanup(page, [folder]);
  }
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
  await expect.poll(() => page.evaluate(() => {
    // eslint-disable-next-line no-undef -- evaluated in the browser realm / 在浏览器作用域求值
    return document.activeElement !== document.body;
  })).toBe(true);
  await upload.focus();
  await expect(upload).toBeFocused();
});
