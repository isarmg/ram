// 保持入口极小：等待模板 DOM 完成后，把所有可观测的启动与错误处理交给 `page-init.js`。
// Keep the entry point tiny: after the template DOM is complete, delegate all observable startup and error handling to `page-init.js`.
import { startApplication } from "./page-init.js";

window.addEventListener("DOMContentLoaded", () => {
  void startApplication();
});
