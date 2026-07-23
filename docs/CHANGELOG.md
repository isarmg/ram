# 变更记录

本文件记录影响使用、配置和升级的变化。版本遵循 Semantic Versioning。

## [Unreleased]

### 变更

- 产品范围收缩为个人内网中的浏览器文件管理器。
- 删除临时下载 Token、在线编辑、PATCH 和完整 WebDAV。
- 保留只读预览、普通下载、Range、条件请求、搜索和 ZIP。
- 浏览器写操作只保留 PUT、DELETE、MKCOL 和 MOVE。
- 删除应用内 TLS、H2C、Unix socket、可信代理来源头和 CORS。
- 删除 quota hook、SPA/render、外部 assets、文件 hash 和应用内日志轮转。
- 默认资源预算调整为少量个人设备并发使用，同时保持所有关键上限。
- 日志改由 stdout/stderr 输出，交给 journald 或容器运行时轮转。
- CI 收缩为 Linux x86_64、Rust、前端模块、Chromium、依赖审计和许可证检查。
- Release 收缩为单个 Linux x86_64 GitHub Release 及 SHA-256。

### 升级注意

- 删除配置文件中已移除的字段，再执行 `ram --check-config --config ...`。
- TLS 必须由网关或反向代理终止。
- 不再支持 WebDAV 挂载、第三方 DAV 客户端、编辑入口或旧 Token 链接。
- 同一可写目录仍只能由一个 Ram 实例管理。

## [0.1.0]

- 项目命令名为 `ram`，Cargo 包名为 `ram-fileserver`。
- 基于 dufs 0.46.0 建立 Linux 浏览器文件管理器。
- 引入 Linux `openat2`/dirfd 根目录隔离、原子写入和有界资源控制。
- 项目采用 MIT 许可证。

[Unreleased]: https://github.com/isarmg/ram/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/isarmg/ram/releases/tag/v0.1.0
