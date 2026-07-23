import { defineConfig, devices } from "@playwright/test";
import { allocateLoopbackPort, LOOPBACK_HOST, prepareE2eData } from "./tests/e2e/fixtures.js";

const PORT_ENV = "RAM_E2E_PORT";
const inheritedPort = process.env[PORT_ENV];
const port = inheritedPort === undefined
  ? await allocateLoopbackPort()
  : Number(inheritedPort);
if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
  throw new Error(`${PORT_ENV} must be an integer TCP port between 1 and 65535`);
}
// 中文：Playwright 会在 worker 中重新求值配置；在启动 worker 和服务器前发布父进程
// 分配的端口，使所有进程共用一个 origin 而不各自分配。
// English: Playwright reevaluates config in workers. Publish the parent port
// before spawning workers/server so every process uses one origin.
process.env[PORT_ENV] = String(port);
const baseURL = `http://${LOOPBACK_HOST}:${port}`;
const dataDirectory = await prepareE2eData();
// 中文：安全状态位于服务根之外但共享隔离 target 前缀，清理时不会触碰仓库/运行态数据。
// English: Security state stays outside the served root but under the isolated target prefix for safe teardown.
const tokenRevocationFile = `${dataDirectory}.token-revocations.json`;
// 中文：不把环境提供的路径插值到 Playwright 的 shell command。即使是
// JSON 双引号也不会阻止 shell 在 `$()`/反引号上执行命令替换。路径仅作为
// 环境值传递，固定命令再用双引号展开；shell 不会对展开结果二次求值。
// English: never interpolate an environment-provided path into Playwright's
// shell command. JSON double quotes do not stop `$()`/backtick substitution.
// Pass paths only as environment values and expand them inside double quotes
// in a fixed command; shells do not evaluate expansion results a second time.
const webServerEnvironment = {
  ...process.env,
  RAM_E2E_DATA_DIR: dataDirectory,
  RAM_E2E_PORT: String(port),
  RAM_E2E_TOKEN_REVOCATION_FILE: tokenRevocationFile,
};
// 不允许调用 Playwright 的宿主通过显式配置路径改变 E2E 服务器。
// Do not let the Playwright caller alter the E2E server through an explicit config path.
delete webServerEnvironment.RAM_CONFIG;
if (process.env.RAM_E2E_CARGO_TARGET_DIR) {
  webServerEnvironment.CARGO_TARGET_DIR = process.env.RAM_E2E_CARGO_TARGET_DIR;
}

export default defineConfig({
  testDir: "tests/e2e",
  outputDir: "target/playwright-results",
  globalTeardown: "./tests/e2e/global-teardown.js",
  fullyParallel: false,
  // 中文：所有项目共用一个有状态文件服务 fixture；串行 worker 防止跨浏览器清理与写入竞态。
  // English: Every project shares one stateful server fixture; serial workers prevent cross-browser cleanup races.
  workers: 1,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL,
    // 中文：APIRequestContext 不共享 Chromium 认证缓存，API 检查需预先发送本地 Basic 凭据。
    // English: APIRequestContext does not share Chromium's auth cache, so API checks send local Basic credentials preemptively.
    httpCredentials: { username: "admin", password: "admin", send: "always" },
    trace: "retain-on-failure",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
  ],
  webServer: {
    command: 'cargo run --locked -- "$RAM_E2E_DATA_DIR" --port "$RAM_E2E_PORT" --auth admin:admin@/:rw --auth reader:reader@/:ro,/dir1:rw --allow-all --token-secret 0123456789abcdef0123456789abcdef --token-audience ram-e2e --token-revocation-file "$RAM_E2E_TOKEN_REVOCATION_FILE"',
    env: webServerEnvironment,
    reuseExistingServer: false,
    timeout: 300_000,
    url: `${baseURL}/__ram__/health`,
  },
});
