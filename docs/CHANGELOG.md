# 变更记录

本文件记录面向用户和运维者的显著变化。格式参考 Keep a Changelog，版本遵循 Semantic
Versioning；合并请求应在 `Unreleased` 下描述行为和迁移影响，发布时再归入具体版本。

## [Unreleased]

### Added

- 增加只读 `ram --check-config` 启动前检查，复用真实配置合并与安全校验但不绑定端口或创建
  运行时状态。
- 增加默认 TLS 生产配置的 Rust 覆盖率趋势报告、Vitest V8 覆盖率和安全模块分组摘要；
  `--no-default-features` 由普通 x86_64/ARM64 测试矩阵完整验证。
- 增加对最终 LTO/strip tar 解压产物的原生架构协议烟测、诊断日志和制品哈希保留。
- 增加安全报告、贡献、部署威胁模型和仓库保护操作文档。
- 增加专用 Runner 性能基线、严格环境指纹、人工审批基线与回归阈值比较器。
- 增加目录稳定扫描的进程内 `mutation_version`；内置管理 UI 的列表来源 DELETE/MOVE 会在
  全部路径锁取得后原子校验该版本，过期时以无副作用的 412 要求刷新。

### Changed

- 项目自本版本起统一以 MIT 许可证发布；既有版本按其发布时的 `MIT OR Apache-2.0` 条款
  继续可用，已经授予的权利不受影响。MIT 不包含 Apache-2.0 的显式贡献者专利许可与终止
  条款，使用方应据此评估。
- 重组仓库物理边界：身份代码进入 `src/identity/`，大型服务器模块采用目录模块并分离测试，
  fixture 与覆盖率策略归入 `tests/`，供应链清单改为发布时生成；新增双语结构契约和路径漂移门禁。
- Rust 安全工具链升级到 1.97.1，直接 ZIP 实现升级到 8.6，并刷新 Rust/npm/CI 依赖到审计时
  最新的稳定或安全修订版本。
- 移除可执行文件相邻 `config.yaml` 的自动发现及专用于禁用该行为的 `RAM_NO_CONFIG`；YAML
  现在只能通过 `--config` 或 `RAM_CONFIG` 显式选择。
- Linux 非 UTF-8 名称在 HTML/JSON/search/DAV 中显式省略并发出不完整信号；ZIP 使用无损、
  无歧义的原始字节导出表示。
- 搜索和 ZIP 对 traversal root 与每个已打开真实对象重新执行 ACL，防止 IndexOnly symlink
  别名扩大权限。
- Release 记录 profile、ELF Build ID、动态链接信息与独立 debug-symbol 状态。
- Release 仅接受可从默认分支到达、版本文档一致、受规则保护、GitHub 验证签名有效且直接
  指向构建 commit 的 annotated tag；最终附件先完整上传到草稿，再发布且拒绝替换。
- 发布二进制显式固定 x86-64 v1/generic ARM64 CPU 基线，并对最终 tar、ELF 加固、动态库和
  glibc 2.39 符号上限执行 fail-closed 验证。
- CycloneDX/SPDX 清单从 JSON 语法检查升级为根包、版本、生产依赖覆盖和开发依赖隔离的
  语义检查。
- GitHub Release 在独立 finalizer 重新验证草稿身份与精确附件清单前始终保持私有；失败草稿
  恢复会扫描完整有界分页并校验唯一 tag/commit/marker。发布流程不上传外部软件包注册表。

### Fixed

- `ram --version` 现在报告公开命令名 `ram`，不再泄露内部库 crate 名
  `ram_fileserver`。
- systemd 部署示例使用托管的 runtime/state/logs 目录，避免首次部署因可写目录尚未创建而
  在执行服务前失败。
- 统一 Range `416` 的 `Content-Range`/`Accept-Ranges` 响应头。
- 修复空测试 fixture 造成的假通过，并增强测试 server 的启动失败诊断。
- 浏览器编辑器在二次读取时重新执行 4 MiB 实收字节上限；小文件 token 下载限制为
  16 MiB 单任务，较大文件与 ZIP 使用原生流式下载。
- 目录 ZIP 链接依赖服务端 `Content-Disposition: attachment`，不再附加冗余的空
  `download` 属性，避免 WebKit 挂起未知长度的原生流式下载。
- 上传 UI 分离键盘可达的文件/文件夹选择，限制队列、目录条目和深度，并拒绝会被浏览器
  URL 解析器归一化的空段、`.` 与 `..` 创建/移动目标。
- 流式 ZIP 根据每个条目的“剩余预算 + 增长哨兵”输入上界及 Deflate 保守膨胀上界预声明
  ZIP64，避免默认或自定义近 4 GiB 预算在响应已开始后才因 local header 容量不足而中止。
- ZIP 条目名编码后超过 65,535 字节时在响应前以类型化 `422` 拒绝，避免写 local header 时
  把长度转换为 `u16` 触发 panic。
- 日志关停 flush 改用 2 秒总 deadline；日志目的端卡死时允许丢失队尾记录，不再无限阻塞退出。
- 日志 flush 会报告关停前最后一批 dropped 计数；并发 barrier 按 FIFO 顺序完成，不能越过
  更早的记录或 barrier。
- 静态配置已禁用的 PUT/PATCH/DELETE/MKCOL/COPY/MOVE 会在正文、Destination 和变更锁之前
  返回 403，不再让无副作用拒绝推进目录 `mutation_version` 或使管理 UI 快照失效。

### Security

- 文件系统短阻塞操作现在在 `spawn_blocking` 前经过服务根/资源根共享准入，真实闭包持有许可到
  syscall 返回；取消请求不再产生未计数的排队或在途工作。完整、单 Range 与 multipart 下载
  改为每次 metadata/read/seek 独立准入，网络背压期间不持有许可。
- 非文本管理页预览改为已认证、实际流量上限 16 MiB 的本地 blob，并在不授予任何能力的
  iframe sandbox 中打开，避免 opaque-origin frame 重复认证和无界浏览器内存占用。
- 配置、认证/token 状态、quota hook、TLS、日志和自定义资源的启动前检查采用固定对象身份
  与 fail-closed 校验。
- 无效 UTF-8 URL 在进入读写路由前统一拒绝，避免有损路径归一化造成别名或错误对象访问。
- HTTP/1 请求头缓冲、字段数量和解析后总量采用显式预算，避免继承依赖库可变的隐式默认值。
- Unix socket 日志保留内核 `SO_PEERCRED` 的完整 `uid/gid/pid`；认证、请求和上传的安全来源
  分桶只按 UID 聚合，防止 fork、PID 或获准主组变化拆分预算。
- 启动隔离同时按 inode 与 namespace slot 拒绝碰撞：敏感输入、撤销状态/锁、日志及
  `.1`–`.5` 轮转槽和 pathname listener 输出槽之间的任何别名均关闭失败。
- Bearer token 先完成 MAC 验证才允许真实 `sub` 选择退避状态；畸形/无效 token 按已验证来源
  共用固定桶，认证状态满容量时关闭失败且不驱逐仍有效的失败/退避记录。
- 持久 token 撤销查询/写入在提交 blocking worker 前经过原子失败预留以及全局/来源/协议主体
  准入；取消请求不能提前释放真实 worker 租约。重复撤销同一有效 JTI 不再推进 generation 或
  重写文件。Bearer-invalid、Bearer-subject、撤销写与 Basic/Digest 失败桶均使用不可碰撞域。
- Basic/Digest 改用“来源跨用户名预算 + 来源/声明用户名桶”的原子双层限流：成功只清本用户名，
  不清来源历史失败，低权账号不能清洗管理员猜测，轮换假用户名也不能绕过；退避到期允许一个
  recovery proof，避免永久锁死。unknown 明文 Basic 无条件执行不可预测 dummy 比较；含哈希
  部署的 known hash、known plaintext、unknown Basic 统一为一次 HMAC 比较加一次同 profile
  哈希。SHA-512-crypt rounds 要求实例内统一，避免存在性通过限流、准入或 timing 泄露。
- 持久 token secret 自动派生的默认撤销后端现在会在资源校验前进入 effective 拓扑，并在安全
  配置后再次复核；启动与 `--check-config` 都拒绝小于 5 的 blocking pool，检查模式不创建文件。

## [0.1.0]

### Changed

- 项目包名为 `ram-fileserver`，命令名为 `ram`；支持 Linux GNU x86_64 与 ARM64。
- 采用 Rust 2024、Linux `openat2` 根目录能力边界、Basic/Digest/Bearer 认证、细粒度路径 ACL、
  有界 WebDAV/ZIP/search/hash、原子写和直接 TLS。

该版本以前的历史可从 Git tag 和 GitHub Release notes 查询。后续发布不得只依赖自动生成的
commit 标题；涉及配置、安全边界或升级步骤的变化必须保留人工编写说明。

[Unreleased]: https://github.com/isarmg/ram/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/isarmg/ram/releases/tag/v0.1.0

---

# Changelog (English)

This file records user- and operator-visible changes. It follows Keep a Changelog and Semantic
Versioning. Pull requests describe behavior and migration under `Unreleased`; release preparation
moves entries into a concrete version.

## [Unreleased]

### Added

- Read-only `ram --check-config`, reusing real merge/security validation without binding listeners or
  creating runtime state.
- Rust coverage trends for the default TLS production configuration, Vitest V8 coverage, and
  security-module summaries; the regular x86_64/ARM64 matrix fully tests the no-default build.
- Native-architecture protocol smoke tests over extracted final LTO/stripped archives, with diagnostic
  logs and retained artifact hashes.
- Security reporting, contribution, deployment threat-model, and repository-protection documentation.
- Dedicated-runner performance baselines with strict environment fingerprints, reviewed baselines,
  and threshold comparisons.
- A process-local `mutation_version` for stable directory scans. Listing-originated DELETE/MOVE in
  the built-in manager atomically validates it after all path locks and returns side-effect-free 412
  when the listing is stale.

### Changed

- License new releases under MIT only. Previously published versions remain available under their
  published `MIT OR Apache-2.0` terms, and existing grants are unaffected. MIT does not include
  Apache-2.0's explicit contributor patent grant and termination terms; users should evaluate that
  tradeoff.
- Reorganize repository boundaries: identity code now lives under `src/identity/`, large server
  modules use directory modules with extracted tests, fixtures and coverage policy live under
  `tests/`, and supply-chain inventories are generated at release time. A bilingual structure
  contract and path-drift gates now protect the layout.
- Upgrade the security toolchain to Rust 1.97.1, the direct ZIP implementation to 8.6, and refresh
  Rust/npm/CI dependencies to the latest stable or security-patched versions available at audit time.
- Remove executable-adjacent `config.yaml` auto-discovery and its dedicated `RAM_NO_CONFIG` opt-out;
  YAML is now selected only through explicit `--config` or `RAM_CONFIG`.
- Linux non-UTF-8 names are omitted with an incompleteness signal from HTML/JSON/search/DAV; ZIP uses
  an unambiguous lossless raw-byte export notation.
- Search and ZIP reauthorize every traversal root and opened object, preventing an IndexOnly symlink
  alias from expanding access.
- Releases record profile, ELF Build ID, dynamic-link information, and independent debug-symbol state.
- Releases accept only annotated tags reachable from the default branch, version-consistent across
  docs, ruleset-protected, marked validly signed by GitHub, and directly targeting the build commit.
  Attachments are completed in a draft before publication and cannot be replaced.
- Binaries explicitly target x86-64 v1/generic ARM64 and fail closed on final tar, ELF hardening,
  dynamic-library, and glibc 2.39 symbol-ceiling checks.
- CycloneDX/SPDX checking now validates root package/version, production dependency coverage, and
  development-dependency isolation rather than JSON syntax alone.
- GitHub Releases remain private drafts until an independent finalizer revalidates draft identity and
  the exact asset inventory. Failed-draft recovery scans the complete bounded pagination and requires
  one exact tag/commit/marker identity. The release workflow does not upload to an external package
  registry.

### Fixed

- `ram --version` reports the public command name rather than the internal `ram_fileserver` crate.
- The systemd example uses managed runtime/state/log directories so first deployment does not fail
  before service execution.
- Range 416 responses consistently include `Content-Range`/`Accept-Ranges`.
- Empty test fixtures can no longer produce false passes; test-server startup diagnostics are richer.
- The browser editor reapplies a 4 MiB received-byte bound on its second read. Token downloads buffer
  at most one 16 MiB small file; larger files and ZIP use native streaming.
- Directory ZIP links rely on the server's `Content-Disposition: attachment` and omit the redundant
  empty `download` attribute, preventing WebKit from stalling unknown-length native streams.
- Upload UI separates keyboard-reachable file/folder selection, bounds queues/entries/depth, and
  rejects empty, `.`, and `..` target segments normalized by browser URL parsing.
- Streaming ZIP predeclares ZIP64 from each entry's remaining-budget-plus-growth-sentinel input ceiling
  and a conservative Deflate expansion ceiling, avoiding near-4-GiB local-header failures after the
  response has started, including custom budgets.
- ZIP entry names longer than 65,535 encoded bytes are rejected before the response with a typed
  `422`, preventing a panic when converting the local-header name length to `u16`.
- Shutdown log flush now has one two-second total deadline; a stuck destination may lose tail records
  but can no longer block process exit indefinitely.
- Log flush reports the final batch of dropped records before shutdown; concurrent barriers complete
  in FIFO order and cannot overtake earlier records or barriers.
- PUT/PATCH/DELETE/MKCOL/COPY/MOVE disabled by static configuration now return 403 before bodies,
  Destination parsing, or mutation locks, so a side-effect-free denial cannot advance the directory
  `mutation_version` or invalidate manager snapshots.

### Security

- Filesystem jobs now pass shared served/assets admission before `spawn_blocking`, with the real
  closure retaining its permit until syscall return. Cancellation cannot create uncounted queued or
  in-flight work. Full, single-range, and multipart downloads acquire per metadata/read/seek
  operation and hold no permit during network backpressure.
- Non-text preview uses an authenticated, actually received 16 MiB-bounded local blob in an empty
  iframe sandbox, avoiding repeat authentication from an opaque origin and unbounded browser memory.
- Startup checks for configuration, auth/token state, quota hook, TLS, logs, and custom assets retain
  object identity and fail closed.
- Invalid UTF-8 URLs are rejected before read/write routing, avoiding lossy path aliases.
- HTTP/1 request-head buffering, field count, and post-parse total have explicit budgets rather than
  depending on mutable library defaults.
- Unix-socket logs retain the complete kernel `SO_PEERCRED` `uid/gid/pid`; security source buckets for
  authentication, requests, and uploads group only by UID so fork, PID, or permitted-primary-group
  changes cannot split a budget.
- Startup isolation rejects collisions by both inode and namespace slot: any alias among sensitive
  inputs, revocation state/locks, logs and their `.1`–`.5` rotation slots, and pathname-listener
  output slots fails closed.
- Bearer tokens must pass MAC verification before their real `sub` selects backoff state. Malformed or
  invalid tokens share one fixed bucket per verified source, and full authentication state fails
  closed without evicting live failure/backoff records.
- Persistent revocation reads/writes now use atomic provisional failure state plus bounded global,
  source, and protocol-subject admission before spawning; cancellation cannot release a real worker's
  lease early. Duplicate active-JTI revocation no longer advances generation or rewrites the file.
  Bearer-invalid, bearer-subject, mutation, and Basic/Digest rate domains cannot collide.
- Basic/Digest now use an atomic two-layer throttle: a cross-name source budget plus a
  source/claimed-name bucket. Success clears only that name and never source history, so a
  low-privilege login cannot launder administrator guesses and fake-name rotation cannot bypass
  backoff; one recovery proof is admitted after expiry to avoid permanent lockout. Unknown plaintext
  Basic always performs an unpredictable dummy comparison. In a hashed deployment, known hash, known
  plaintext, and unknown Basic each perform one HMAC comparison plus one same-profile hash.
  SHA-512-crypt rounds must be uniform within the instance, closing rate/admission/timing enumeration.
- A default revocation backend derived from a persistent token secret now enters the effective
  topology before resource validation and is checked again after security configuration. Startup and
  `--check-config` both reject a blocking pool smaller than five; check mode creates no state file.

## [0.1.0]

### Changed

- Package name is `ram-fileserver`, command name is `ram`, with Linux GNU x86_64 and ARM64 support.
- Uses Rust 2024, Linux `openat2` root capabilities, Basic/Digest/Bearer authentication, fine-grained
  path ACLs, bounded WebDAV/ZIP/search/hash, atomic writes, and direct TLS.

Earlier history is available through Git tags and GitHub Release notes. Future releases must retain
human-written notes for configuration, security-boundary, and upgrade changes rather than relying only
on generated commit titles.
