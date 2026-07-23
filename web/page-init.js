/**
 * 浏览器启动编排层。它先校验嵌入状态与 DOM，再渲染面包屑和通用认证
 * 控件，最后根据 `Index/View` 类型进入目录页或只读查看页。任一阶段异常都
 * 进入唯一的致命错误界面，避免留下部分初始化、可误操作的页面。
 *
 * Browser bootstrap orchestrator. It validates embedded state and DOM,
 * renders navigation/authentication, then dispatches Index versus View
 * setup. Any stage failure reaches one fatal-error surface, avoiding a
 * partially initialized page that still appears actionable.
 */

import { setupAuthentication, setupIndexPage, uploadState } from "./file-operations.js";
import { createIcon } from "./icons.js";
import { loadAppContext, requireElement, showFatalError } from "./ui-state.js";
import { setupViewerPage } from "./viewer.js";

/**
 * 仅使用 DOM 文本节点渲染面包屑；URL 段只编码一次，绝不解释为标记。
 *
 * Render a breadcrumb using only DOM text nodes. URL segments are encoded once
 * and never interpreted as markup.
 *
 * @param {string} href
 * @param {string} uriPrefix
 */
function addBreadcrumb(href, uriPrefix) {
  // 中文：模板使用 nav landmark 表达导航语义，此处只依赖通用
  // HTMLElement 能力，避免把正确的语义升级误报为模板/脚本版本不匹配。
  // English: the template now uses a nav landmark. This renderer needs only
  // HTMLElement behavior, so it must not mistake that semantic upgrade for
  // template/script skew by requiring the old div class.
  const breadcrumb = requireElement(".breadcrumb", HTMLElement);
  const parts = href === "/" ? [""] : href.split("/");
  let path = uriPrefix;
  parts.forEach((name, index) => {
    if (index > 0) {
      if (!path.endsWith("/")) path += "/";
      path += encodeURIComponent(name);
    }
    if (index === 0) {
      const root = document.createElement("a");
      root.href = path;
      root.title = "Root";
      root.setAttribute("aria-label", "Root");
      root.append(createIcon("home"));
      breadcrumb.append(root);
    } else if (index === parts.length - 1) {
      const current = document.createElement("b");
      current.textContent = name;
      current.setAttribute("aria-current", "page");
      breadcrumb.append(current);
    } else {
      const ancestor = document.createElement("a");
      ancestor.href = path;
      ancestor.textContent = name;
      breadcrumb.append(ancestor);
    }
    if (index !== parts.length - 1) {
      const separator = document.createElement("span");
      separator.className = "separator";
      separator.textContent = "/";
      separator.setAttribute("aria-hidden", "true");
      breadcrumb.append(separator);
    }
  });
}

/** 初始化浏览器 UI，并把失败渲染为无障碍警报。 / Initialize the UI and render failures as an accessible alert. */
export async function startApplication() {
  try {
    const context = loadAppContext();
    window.addEventListener("beforeunload", event => {
      if (uploadState.pending > 0 || uploadState.active > 0) {
        event.preventDefault();
        // 现代浏览器只显示自有文案，但仍要设置 returnValue 才能兼容旧的
        // beforeunload 触发契约。
        // Modern browsers show their own text, but assigning returnValue keeps
        // compatibility with the older beforeunload triggering contract.
        event.returnValue = "";
      }
    });
    addBreadcrumb(context.data.href, context.data.uri_prefix);
    setupAuthentication(context);
    if (context.data.kind === "Index") {
      document.title = `Index of ${context.data.href} - Ram`;
      context.dom.indexPage.classList.remove("hidden");
      await setupIndexPage(context);
    } else {
      document.title = `View ${context.data.href} - Ram`;
      context.dom.viewerPage.classList.remove("hidden");
      await setupViewerPage(context);
    }
  } catch (error) {
    showFatalError(error);
  }
}
