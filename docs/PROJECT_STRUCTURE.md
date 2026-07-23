# 项目结构

```text
.
├── .github/
│   ├── workflows/
│   │   ├── ci.yaml
│   │   ├── fuzz.yaml
│   │   └── release.yaml
│   └── CODEOWNERS
├── docs/                 用户、安全、贡献和代码说明
├── fuzz/                 独立 cargo-fuzz workspace 与语料
├── scripts/              小型静态、许可证和依赖检查
├── src/
│   ├── auth/             认证、ACL、认证失败限流
│   ├── config/           CLI/YAML/环境合并和安全校验
│   ├── http/             HTTP 方法、body 和 I/O 看门狗
│   ├── identity/         路径与直接 TCP 来源身份
│   ├── logging/          有界 stdout/stderr 访问日志
│   ├── runtime/          HTTP/1.1、准入和优雅关闭
│   └── server/           路由、文件系统、读写、搜索、ZIP
├── tests/
│   ├── e2e/              Chromium 行为与可访问性
│   ├── frontend/         浏览器模块单元测试
│   └── *.rs              Rust 黑盒集成测试
├── web/                  内嵌浏览器页面、样式和 ES modules
├── Cargo.toml
├── config.example.yaml
├── package.json
├── README.md
└── LICENSE
```

## 边界

- `src/main.rs` 只负责调用库入口。
- 配置来源和默认值只在 `src/config/` 定义，避免 CLI、环境变量和 YAML 各自漂移。
- 所有服务路径操作都经 `src/server/filesystem/`，不得从路由重新拼接绝对路径。
- 浏览器源文件直接内嵌到二进制；修改 `web/` 后必须同步前端测试和 Rust 资源测试。
- `fuzz/` 有独立 lockfile，不进入生产依赖图。
- `.github/workflows/release.yaml` 只打包 Linux x86_64 二进制、README、LICENSE 和示例配置。

生成目录 `target/`、`coverage/`、Playwright 输出和 fuzz 临时语料都不得提交。
