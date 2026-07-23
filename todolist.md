# Ram 浏览器文件管理器精简 TODO

状态：第二至第十一阶段已于 2026-07-23 完成；清单保留为实现与验收记录。

## 目标

将当前项目精简为个人多设备使用的浏览器文件管理器：

- 支持目录浏览、上传、下载、断点下载、搜索、压缩下载、新建目录、移动、重命名和删除。
- 支持手机、电脑和平板同时访问。
- 只支持浏览器，不支持系统挂载、Rclone、Finder、Cyberduck 或其他 WebDAV 客户端。
- 不支持在线编辑文件。
- 不提供临时分享或 Bearer 下载令牌。
- 保留限流、路径隔离、可靠写入和日志安全。

## 实施原则

- [x] 每完成一个阶段后再进入下一阶段，避免一次删除过多能力而难以定位回归。
- [x] 删除功能时同步删除配置项、CLI 参数、环境变量、文档、测试和不再使用的依赖。
- [x] 保持默认拒绝危险配置，不通过降低安全默认值换取简化。

## 第一阶段：删除临时下载 Token

- [x] 删除 `src/auth/token.rs`。
- [x] 删除 `?tokengen` 路由和 `handle_tokengen`。
- [x] 删除 Bearer Authorization 认证分支。
- [x] 删除 Token HMAC 签名、验证、claims、audience、JTI 和 TTL。
- [x] 删除 Token 撤销接口、撤销内存状态、持久状态文件和锁文件。
- [x] 删除以下配置项及对应 CLI/环境变量：
  - [x] `token-secret`
  - [x] `token-secret-file`
  - [x] `token-audience`
  - [x] `token-ttl`
  - [x] `token-revocation-file`
- [x] 删除 Token 专用认证限流和错误响应。
- [x] 删除前端 `downloadWithToken`。
- [x] 删除 `file-operations.js` 中小文件 Token 下载拦截逻辑。
- [x] 所有文件下载按钮改用普通同源认证链接。
- [x] 保持大文件由浏览器原生流式下载，禁止在 JavaScript 中缓存整个文件。
- [x] 保持目录 ZIP 使用浏览器原生流式下载。
- [x] 删除 Token 前端测试、E2E 测试、认证测试和持久化状态测试。
- [x] 删除文档中的 Token 签发、吊销、密钥备份和恢复说明。

## 第二阶段：删除在线编辑能力

- [x] 删除 `web/editor.js`。
- [x] 删除 `index.html` 中的 editor 页面、textarea 和编辑状态区域。
- [x] 删除 CSS 中仅供 editor 使用的样式。
- [x] 删除编辑图标、编辑按钮和 `?edit` 链接。
- [x] 删除“新建空文件后进入编辑器”的前端流程。
- [x] 删除服务端 `?edit` 处理分支。
- [x] 删除编辑器页面数据模型、`can_save` 和编辑器专用状态。
- [x] 删除编辑器专用强 ETag 保存和脏缓冲逻辑。
- [x] 删除编辑器单元测试、浏览器测试和可访问性测试。
- [x] 保留安全的只读 `?view`，但将其改成不依赖编辑器保存逻辑的独立查看器。
- [x] 只读查看器继续限制文件大小、字符编码和主动内容，不允许保存、移动或删除。
- [x] 保留普通下载、ETag、条件请求和 Range；它们不是编辑器专属能力。

## 第三阶段：删除 PATCH

- [x] 确认网页上传始终使用完整文件 PUT。
- [x] 确认没有第三方客户端依赖 `PATCH` 和 `X-Update-Range`。
- [x] 从方法注册表、`Allow`、CORS 方法集合和路由中删除 PATCH。
- [x] 删除 `X-Update-Range` 解析和校验。
- [x] 删除 PATCH 偏移、append 和局部覆盖逻辑。
- [x] 删除 PATCH 为旧文件创建完整副本的发布流程。
- [x] 删除 PATCH 专用 ACL、前置条件、错误映射和测试。
- [x] 保留 PUT 私有候选文件、大小检查、原子 rename、fsync 和失败清理。

## 第四阶段：删除完整 WebDAV

- [x] 删除 PROPFIND。
- [x] 删除 PROPPATCH。
- [x] 删除 WebDAV XML 请求解析和属性渲染。
- [x] 删除 DAV property、XML body、元素数量和响应大小配置。
- [x] 删除 DAV capability 声明和相关测试。
- [x] 删除 `quick-xml`（确认没有其他调用后）。
- [x] 删除未被前端使用的 COPY 方法。
- [x] 保留网页文件管理器需要的方法：
  - [x] PUT：上传。
  - [x] DELETE：删除。
  - [x] MKCOL：新建目录。
  - [x] MOVE：移动和重命名。
- [x] 将保留的 MKCOL/MOVE 从“WebDAV 支持”文档改写成内部文件管理 API。
- [x] 删除系统挂载、第三方 DAV 客户端和协议兼容性文档。

## 第五阶段：删除不用的网络和部署能力

- [x] 删除 H2C 配置和 prior-knowledge HTTP/2 分支。
- [x] 删除 Linux abstract Unix socket 支持。
- [x] 删除 pathname Unix socket 支持。
- [x] 删除 unix socket mode、uid、gid 配置和检查。
- [x] 删除 trusted proxy、CIDR allowlist 和转发来源头解析。
- [x] Ram 只保留 HTTP/1.x 服务能力（浏览器通常使用 HTTP/1.1），不实现 HTTP/2 或 TLS 终止。
- [x] 删除应用内直连 TLS、证书、私钥和 HSTS 配置。
- [x] 删除 rustls 相关生产依赖和 TLS 专用测试。
- [x] 在删除 TLS feature 前，先以 `--no-default-features` 验证主要部署构建。
- [x] 保持 HTTP/1.1 请求头、连接、空闲和写入超时。
- [x] 保持优雅关闭。
- [x] 保持来源和认证限流。

## 第六阶段：删除不用的存储和页面能力

- [x] 删除 `storage-quota-hook` 及其超时、进程组、身份固定和测试。
- [x] 保留 `storage-space-check`。
- [x] 配置合理的 `storage-reserve`。
- [x] 删除 CORS 配置和实现，前端与 API 固定同源。
- [x] 删除 SPA、render-index、render-try-index。
- [x] 删除外部 assets 覆盖能力。
- [x] 删除文件 hash 功能。
- [x] 保留搜索。
- [x] 保留 ZIP 压缩下载。
- [x] 保留文件和目录上传。
- [x] 保留新建目录、移动、重命名和删除。

## 第七阶段：简化资源配置

- [x] 保留所有资源限制机制，不改成无限制。
- [x] 新增固定的 `personal-intranet` 或类似资源配置档。
- [x] 将很少需要修改的细粒度参数改为内部常量或高级配置。
- [x] 推荐初始限制：

```yaml
max-connections: 64
max-concurrent-requests: 32
max-concurrent-requests-per-source: 32
max-concurrent-requests-per-user: 32
max-request-queue: 32

max-blocking-threads: 12
max-expensive-tasks: 2

max-concurrent-uploads: 4
max-concurrent-uploads-per-user: 2
max-concurrent-uploads-per-source: 3

max-search-results: 5000
max-directory-entries: 10000

storage-space-check: true
storage-reserve: 5G
```

- [x] 同机网关会聚合来源、共享账号会聚合用户，因此每来源和每用户请求上限与
  全局请求上限同为 32；上传仍使用更低的独立上限。
- [x] 根据实际最大文件调整 upload 和 archive 大小上限，不能设为无限。
- [x] 根据现有认证方式和实际并发调整每用户限制；如果不适用则只保留全局和来源限制。

## 第八阶段：简化日志

- [x] 日志默认写 stdout/stderr，由 journald 收集和轮转。
- [x] 删除应用内日志文件轮转和备份管理。
- [x] 删除不再使用的日志文件路径槽位和权限检查。
- [x] 保留请求 ID、认证用户、来源、状态码、耗时和响应结果。
- [x] 保留 Authorization、Cookie、Token、密码和查询参数脱敏。
- [x] 保留日志队列容量和丢弃计数，避免慢日志输出阻塞请求。

## 第九阶段：简化 CI

- [x] 保留 `cargo fmt --check`。
- [x] 保留 `cargo clippy --all-targets --all-features -- -D warnings`。
- [x] 保留 `cargo test --all-features --locked`。
- [x] 在 TLS 代码删除前，将无 TLS feature 构建和测试作为主要检查。
- [x] TLS 代码完全删除后，去掉重复的 all-features/no-default-features 组合。
- [x] 保留 `npm ci`、lint、typecheck 和前端单元测试。
- [x] 保留 Chromium E2E。
- [x] 保留 cargo audit、cargo deny 和许可证检查。
- [x] 删除已经移除功能对应的 Token、编辑器、PATCH 和 DAV 测试。
- [x] Firefox/WebKit 改成发布前或定期运行，不在每次提交运行。
- [x] 删除 ARM64 CI。
- [x] 根据实际文件系统保留 ext4 集成测试。
- [x] fuzz 保留手动或每月运行，不在每次提交执行。
- [x] performance workflow 改为手动，或者在没有稳定基线前删除。

## 第十阶段：简化 GitHub Release

- [x] 只保留实际服务器架构的 Linux GNU release。
- [x] tag 格式固定为 `vMAJOR.MINOR.PATCH`。
- [x] 检查 tag 与 Cargo 包版本一致。
- [x] TLS feature 删除前构建 `cargo build --release --locked --no-default-features`。
- [x] TLS feature 删除后恢复普通的 `cargo build --release --locked`。
- [x] 打包二进制、README、LICENSE 和示例配置。
- [x] 生成 SHA-256 校验和。
- [x] 自动创建 GitHub Release。
- [x] 不发布 crates.io。
- [x] 不发布 Docker Hub。
- [x] 删除不需要的双 SBOM、复杂证明、双人 finalizer 和企业级签名标签要求。
- [x] 如果仍需要 GitHub artifact attestation，只保留一种证明流程。
- [x] 保留 GitHub Actions 依赖的固定 commit SHA。

## 第十一阶段：精简文档和仓库治理

- [x] README 以中文为主，删除重复英文全文。
- [x] 保留快速安装、应用配置、备份、恢复和升级。
- [x] 删除 Token、编辑器、PATCH、已删除 WebDAV 能力的文档。
- [x] 删除应用直连 TLS、trusted proxy、Unix socket 和 H2C 文档。
- [x] 保留“不支持同一可写目录多实例”的说明。
- [x] 保留上游 dufs 归属和 MIT 许可证声明。
- [x] CODEOWNERS 只列出实际管理员，或删除 CODEOWNERS。
- [x] 删除不适用于个人仓库的双人审批和复杂治理要求。
- [x] 保持 CONTRIBUTING 与仓库治理检查一致，避免文档检查再次阻塞 CI。

## 不得删除的安全与可靠性能力

- [x] 保留 Linux `openat2`/dirfd 根目录隔离。
- [x] 保留 `RESOLVE_BENEATH`、magic-link 防护和默认符号链接限制。
- [x] 保留特殊文件、FIFO 和设备文件检查。
- [x] 保留服务目录与配置、认证、日志等敏感路径的隔离检查。
- [x] 保留 PUT 私有候选文件和原子发布。
- [x] 保留失败、取消和崩溃后的候选文件清理。
- [x] 保留 fsync 和父目录同步。
- [x] 保留 ETag、条件请求和并发覆盖防护。
- [x] 保留 Range 和流式大文件下载。
- [x] 保留请求头、请求体、目录、搜索、ZIP 和响应大小限制。
- [x] 保留连接、请求、用户、来源、上传和昂贵任务并发限制。
- [x] 保留认证失败退避和限流。
- [x] 保留安全响应头、CSP、no-store 和 nosniff。
- [x] 保留日志凭据脱敏。
- [x] 保留优雅关闭和超时。

## 最终验收清单

- [x] 未认证请求无法浏览、下载、上传或修改文件。
- [x] 多台设备同时浏览、上传和下载时不出现非预期 429/503。
- [x] 普通下载、大文件下载和 ZIP 均不会被 JavaScript 整体缓存；只读预览仅允许在
  4 MiB 文本或 16 MiB 媒体硬上限内有界缓冲。
- [x] 在线编辑入口、`?edit` 和 PATCH 不再存在。
- [x] `?tokengen`、Bearer Token 和撤销状态文件不再存在。
- [x] PROPFIND、PROPPATCH、WebDAV XML 和第三方挂载支持不再存在。
- [x] 浏览器使用的 PUT、DELETE、MKCOL 和 MOVE 仍正常工作。
- [x] 路径穿越、根外符号链接和特殊文件读取仍被拒绝。
- [x] 中断上传不会产生可见半文件。
- [x] 服务重启后残留候选文件能够安全清理。
- [x] 日志中不出现密码、Authorization、Cookie 或其他凭据。
- [x] CI 和 Release 只包含当前实际保留的功能与目标平台。
- [x] `cargo test`、Clippy、前端测试以及 Chromium、Firefox、WebKit E2E 全部通过。
