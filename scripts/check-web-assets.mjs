import { access, readFile } from "node:fs/promises";

const repositoryRoot = new URL("../", import.meta.url);
const readSource = (path) => readFile(new URL(path, repositoryRoot), "utf8");

const modulePaths = [
  "web/index.js",
  "web/api.js",
  "web/app-utils.js",
  "web/file-operations.js",
  "web/icons.js",
  "web/page-init.js",
  "web/ui-state.js",
  "web/upload-scheduler.js",
  "web/viewer.js",
];
const [html, css, content, ...modules] = await Promise.all([
  readSource("web/index.html"),
  readSource("web/index.css"),
  readSource("src/server/content.rs"),
  ...modulePaths.map(readSource),
]);
const moduleSource = Object.fromEntries(modulePaths.map((path, index) => [path, modules[index]]));
const js = moduleSource["web/index.js"];
const utils = moduleSource["web/app-utils.js"];
const scheduler = moduleSource["web/upload-scheduler.js"];
const operations = moduleSource["web/file-operations.js"];
const viewer = moduleSource["web/viewer.js"];
const allJavaScript = modules.join("\n");

try {
  await access(new URL("web/editor.js", repositoryRoot));
  throw new Error("web/editor.js must be removed with the online editor");
} catch (error) {
  if (error?.code !== "ENOENT") throw error;
}

function requirePattern(value, pattern, message) {
  if (!pattern.test(value)) throw new Error(message);
}

function rejectPattern(value, pattern, message) {
  if (pattern.test(value)) throw new Error(message);
}

requirePattern(html, /__INDEX_DATA__/, "index.html must preserve __INDEX_DATA__");
requirePattern(html, /__ASSETS_PREFIX__/, "index.html must preserve __ASSETS_PREFIX__");
requirePattern(html, /<script\s+type="module"/, "the application entrypoint must be an ES module");
requirePattern(html, /<button[^>]+class="logout-btn/, "logout must be a native button");
requirePattern(html, /aria-live="polite"|class="empty-folder hidden" role="status"/, "dynamic status needs an accessible announcement");
rejectPattern(html, /<div[^>]+(?:move-file|delete-file|new-folder|new-file|save-btn|logout-btn)/, "primary actions must not be clickable divs");
rejectPattern(html, /id="editor"|class="[^"]*\b(?:edit-file|new-file|save-btn)\b/, "the read-only UI must not expose editor controls");
rejectPattern(html, /\son[a-z]+\s*=/i, "inline event handlers are forbidden");

const bodyRule = css.match(/body\s*\{[^}]*\}/s)?.[0] ?? "";
rejectPattern(bodyRule, /min-width\s*:/, "body must not force a desktop minimum width");
requirePattern(css, /:focus-visible/, "keyboard focus styles are required");

rejectPattern(allJavaScript, /filter\s*\([^)]*\.size\s*>\s*0/, "zero-byte files must not be dropped");
rejectPattern(allJavaScript, /\b(?:innerHTML|outerHTML|insertAdjacentHTML|eval|Function)\b/, "dynamic HTML/code construction is forbidden");
requirePattern(js, /from "\.\/page-init\.js"/, "index.js must remain a minimal page entrypoint");
requirePattern(operations, /from "\.\/upload-scheduler\.js"/, "upload scheduling must remain a separate state machine");
requirePattern(operations, /createActionButton\("move"/, "move must use the native-button action factory");
requirePattern(operations, /createActionButton\("delete"/, "delete must use the native-button action factory");
requirePattern(operations, /document\.createElement\("button"\)/, "mutation actions must be native buttons");
requirePattern(operations, /retry\(\)[\s\S]*this\.enqueue\(\)/, "upload retries must re-enter the queue");
rejectPattern(operations, /findUploadOffset|resumeBeforeUpload/, "atomic PUT retries must not infer an offset from the live file");
requirePattern(operations, /this\.state !== "running"/, "upload terminal events must be idempotent");
requirePattern(viewer, /readBoundedNetworkBytes/, "the viewer must recheck bytes actually received");
requirePattern(viewer, /TextDecoder\([^)]*\{\s*fatal:\s*true\s*\}/, "text previews must reject invalid encodings");
requirePattern(viewer, /setAttribute\(["']sandbox["'],\s*["']["']\)/, "active previews must use a capability-free sandbox");
requirePattern(viewer, /URL\.revokeObjectURL/, "preview object URLs must be revoked");
rejectPattern(allJavaScript, /from ["']\.\/editor\.js["']|searchParams\.(?:get|has)\(["']edit["']\)/, "editor code and ?edit routing are forbidden");
rejectPattern(allJavaScript, /\bPATCH\b|X-Update-Range/i, "resumable PATCH upload code is forbidden");
requirePattern(moduleSource["web/ui-state.js"], /\["q",\s*"sort",\s*"order"\]/, "generated links must use an explicit query-parameter allowlist");
requirePattern(allJavaScript, /Overwrite: overwrite/, "MOVE must close the destination probe race with an explicit Overwrite header");
requirePattern(allJavaScript, /setRequestHeader\(["']If-None-Match["'],\s*["']\*["']\)/, "new uploads must be create-only");
requirePattern(operations, /data\.truncated/, "truncated listings must be disclosed in the UI");
requirePattern(utils, /if \(!sizeKnown\) return "—"/, "unknown directory sizes must not be shown as zero");
rejectPattern(
  allJavaScript,
  /\bBearer\b|downloadWithToken|searchParams\.(?:get|has|set)\(["']token["']\)|[?&]token=/i,
  "the browser UI must not retain bearer-token behavior",
);
for (const path of modulePaths) {
  requirePattern(content, new RegExp(`"${path.slice("web/".length).replace(".", "\\.")}"`), `the backend must serve ${path}`);
}

console.log("Web source policy checks passed");
