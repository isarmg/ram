# 贡献指南

感谢改进 Ram。这个项目把认证、Linux 文件系统能力边界、原子写和资源上限视为产品契约；
行为改动应同时说明兼容性、部署影响和负向安全情况，而不仅证明正常请求可用。

安全漏洞请按 [SECURITY.md](SECURITY.md) 私密报告，不要提交公开 issue 或 PR。

## 开始之前

- 服务端开发和集成测试必须在 Linux 5.6+、可读 `/proc/self/fd` 且允许 `openat2` 的环境运行。
- 使用 `rust-toolchain.toml` 固定的 Rust 版本以及仓库 lockfile。
- 前端源码直接嵌入二进制，没有转译步骤；开发检查使用 `package-lock.json` 固定依赖。
- 改动保持聚焦，不要顺便重排无关代码或更新无关依赖。
- 不要提交生产凭据、私钥、token、日志、真实目录内容、`target/`、`node_modules/` 或覆盖率产物。

建议先运行：

```sh
cargo check --locked
npm ci --ignore-scripts
```

## 设计不变量

所有请求路径必须维持以下顺序：

1. 严格 percent decode 和路径规范化；无效 UTF-8、NUL、`.`/`..` 等非法表示必须失败。
2. 验证 Basic/Digest/Bearer 身份，并得到具体请求方法的 ACL capability。
3. 通过根目录 descriptor 和 `openat2` 打开对象；对 descriptor 解析出的真实相对路径再次授权。
4. 写方法同时检查全局 capability、目标/父目录 ACL、HTTP precondition 和资源预算。
5. 仅在全部检查完成后产生可见副作用；失败、取消、超时和关停不得遗留可发布临时文件。

不要用字符串前缀、预先 `canonicalize` 的路径或客户端提供的 symlink 名替代 descriptor 派生
身份。不要在 `openat2` 不可用时退回不安全实现。不能表达为 URL/JSON/XML 的 Linux 名称应
遵守 README 中的非 UTF-8 策略，不能有损替换后继续授权。

新增 HTTP/WebDAV 方法或 capability 时，更新 `src/server/capabilities.rs` 的单一方法注册表
及其不变量测试；不要在配置、认证、路由、precondition 和 CORS 中各自新增漂移的字符串列表。
前端按钮只能反映服务端能力，不能成为权限边界。

所有远程输入解析必须有长度/数量上限且不能 panic。目录、ZIP、哈希和大正文必须流式或有界；
blocking worker 的 permit 必须由真正的 worker 生命周期持有，不能在 timeout future 返回时提前
释放。错误和访问日志不得记录 Authorization、Bearer token、明文密码或文件内容。

## 必须运行的检查

提交 Rust 改动前运行双生产特性组合：

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- --deny warnings
cargo clippy --all-targets --no-default-features --locked -- --deny warnings
cargo test --all-targets --all-features --locked
cargo test --all-targets --no-default-features --locked
RUSTDOCFLAGS='--deny warnings' cargo doc --no-deps --all-features --locked
```

`--all-features` 会包含仅供 harness 使用的 `fuzzing` feature；覆盖率 job 只插桩默认 TLS
生产配置，`--no-default-features` 仍由普通 x86_64/ARM64 矩阵完整测试。新增 fuzz target 时按
`fuzz/README.md` 加入最小 corpus，本地至少执行有界 smoke。

前端改动运行：

```sh
npm ci --ignore-scripts
npm audit --audit-level=high
npm run check
npx playwright install chromium firefox webkit
npm run test:e2e
```

发布、依赖或许可证改动还应运行：

```sh
cargo audit --deny warnings
cargo deny --locked check
cargo package --locked
```

若机器资源有限，可以先运行相关测试文件，但 PR 交付前仍需完整矩阵。集成测试会启动真实
loopback server；高并发环境建议设置 `RUST_TEST_THREADS=4`，不要靠扩大不变量超时掩盖竞态。

## 测试要求

- 修 bug：先写能在旧实现失败的最小回归测试，并验证修复后的状态码、响应头和副作用。
- 预算：覆盖 `N-1`、`N`、`N+1`，以及取消、超时、关停、permit/worker 释放和残留清理。
- 协议：适用时同时覆盖 HTTP/1.1 与 HTTP/2，不以客户端默认协商结果代替显式断言。
- 文件系统：覆盖 symlink、rename/replace、非 UTF-8、目录与普通文件根、IndexOnly ACL。
- 写入：覆盖 precondition 竞态、磁盘/flush/sync/rename/parent-fsync 失败和原目标保留。
- 前端：模块测试之外，为用户可见流程增加 Chromium、Firefox、WebKit E2E；可访问性问题至少
  记录 moderate，serious/critical 必须阻断。

测试 fixture 只能写临时目录。E2E 不得修改仓库跟踪的 `tests/e2e/data`；每个测试应获得独立
拷贝并在结束时清理。

## 提交与变更说明

- 使用清楚的提交信息，正文说明“为什么”以及安全/兼容性取舍。
- 公共行为、配置、CLI、响应格式或升级步骤变化需更新 README、`config.example.yaml` 和
  [CHANGELOG.md](CHANGELOG.md) 的 `Unreleased`。
- 新依赖必须说明用途、维护状态、生产/开发图位置、许可证和为什么现有依赖不能完成任务。
- 不兼容改动必须有弃用窗口或明确迁移说明；不能静默放宽安全默认值。
- 贡献默认按仓库的 MIT 许可证提供。

## 安全审阅与所有权

认证、路径、文件系统、写操作、WebDAV、TLS、资源预算、前端主动内容、依赖和发布 workflow
属于安全敏感区域。此类 PR 必须由至少一名未编写该改动的合格维护者独立审阅；高风险修复
应由两名维护者参与（作者加独立 reviewer），并附完整测试证据。

CODEOWNERS 只负责自动请求审阅，不能单独保证批准规则。仓库管理员还必须按
[仓库治理检查表](REPOSITORY_GOVERNANCE.md) 配置 branch/tag/release 保护，并定期审计；
fork 或镜像不能假定上游设置自动继承。

发布版本必须从受 tag ruleset 保护、GitHub 标记为有效签名的 annotated tag 触发；轻量 tag
或无法验证的 GPG/SSH/S/MIME 签名不会进入构建发布阶段。

---

# Contributing Guide

Thank you for improving Ram. Authentication, Linux filesystem capabilities, atomic writes, and
resource limits are product contracts here. A behavioral change should explain compatibility,
deployment impact, and negative security cases—not only demonstrate a successful request.

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md); do not open a public
issue or pull request first.

## Before you begin

- Server development and integration tests require Linux 5.6+, readable `/proc/self/fd`, and
  permitted `openat2`.
- Use the Rust version pinned by `rust-toolchain.toml` and the checked-in lockfile.
- Frontend source is embedded directly without transpilation; development dependencies are pinned by
  `package-lock.json`.
- Keep changes focused; do not reorder unrelated code or update unrelated dependencies.
- Never commit production credentials, keys, tokens, logs, real served data, `target/`,
  `node_modules/`, or coverage output.

Start with:

```sh
cargo check --locked
npm ci --ignore-scripts
```

## Design invariants

Every request path must preserve this order:

1. Strictly percent-decode and normalize the path; invalid UTF-8, NUL, `.`, `..`, and other invalid
   representations fail.
2. Verify Basic/Digest/Bearer identity and derive the method-specific ACL capability.
3. Open through the root descriptor and `openat2`, then re-authorize the descriptor-derived real
   relative path.
4. For mutations, check global capability, target/parent ACL, HTTP preconditions, and resource budgets.
5. Publish visible side effects only after every check; failure, cancellation, timeout, and shutdown
   must not leave a publishable temporary file.

Do not replace descriptor identity with string prefixes, precomputed `canonicalize`, or a client
symlink spelling. There is no insecure fallback when `openat2` is unavailable. Linux names that
cannot be represented in URL/JSON/XML must follow README's non-UTF-8 policy and must never be
lossily replaced before authorization.

When adding an HTTP/WebDAV method or capability, update the single registry in
`src/server/capabilities.rs` and its invariant tests. Do not create separate drifting string lists in
configuration, authentication, routing, preconditions, and CORS. Frontend controls reflect server
capabilities; they are not an authorization boundary.

Every remote-input parser needs length/count limits and must not panic. Directories, ZIP, hashes, and
large bodies must stream or remain bounded. A blocking-worker permit belongs to the real worker
lifetime, not the timeout future. Errors and access logs must never contain Authorization values,
Bearer tokens, plaintext passwords, or file contents.

## Required checks

Run both production feature combinations for Rust changes:

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- --deny warnings
cargo clippy --all-targets --no-default-features --locked -- --deny warnings
cargo test --all-targets --all-features --locked
cargo test --all-targets --no-default-features --locked
RUSTDOCFLAGS='--deny warnings' cargo doc --no-deps --all-features --locked
```

`--all-features` includes the harness-only `fuzzing` feature. Coverage instruments only the default
TLS production configuration; the regular x86_64/ARM64 matrix still fully tests
`--no-default-features`. New fuzz targets need a minimal corpus documented in `fuzz/README.md` and at
least a bounded local smoke run.

For frontend changes:

```sh
npm ci --ignore-scripts
npm audit --audit-level=high
npm run check
npx playwright install chromium firefox webkit
npm run test:e2e
```

For release, dependency, or license changes also run:

```sh
cargo audit --deny warnings
cargo deny --locked check
cargo package --locked
```

Targeted tests are useful on a small machine, but the full matrix is required before delivery.
Integration tests launch real loopback servers. On a contended host, prefer `RUST_TEST_THREADS=4`;
do not hide races by increasing invariant timeouts.

## Test requirements

- A bug fix starts with a minimal regression that fails on the old implementation and checks status,
  headers, and side effects after the fix.
- Budgets cover `N-1`, `N`, `N+1`, cancellation, timeout, shutdown, worker/permit release, and residue cleanup.
- Protocol changes cover HTTP/1.1 and HTTP/2 where applicable, with explicit assertions rather than
  relying on client negotiation defaults.
- Filesystem cases cover symlinks, rename/replace, non-UTF-8 names, directory/file roots, and IndexOnly ACL.
- Mutation cases cover precondition races, disk/flush/sync/rename/parent-fsync failures, and preservation
  of the original target.
- User-visible frontend flows add Chromium, Firefox, and WebKit E2E coverage. Accessibility findings
  at least record moderate issues; serious/critical findings block delivery.

Fixtures write only to temporary directories. E2E must never mutate tracked `tests/e2e/data`; each run
uses an isolated copy and removes it afterward.

## Commits and change notes

- Use clear commit messages and explain why, including security/compatibility tradeoffs.
- Public behavior, configuration, CLI, response format, or upgrade changes update README,
  `config.example.yaml`, and the `Unreleased` section of [CHANGELOG.md](CHANGELOG.md).
- A new dependency documents its purpose, maintenance status, graph location, license, and why an
  existing dependency is insufficient.
- Breaking changes need a deprecation window or explicit migration; never silently relax secure defaults.
- Contributions are provided under the repository's MIT License.

## Security review and ownership

Authentication, paths, filesystem operations, writes, WebDAV, TLS, resource budgets, frontend active
content, dependencies, and release workflows are security-sensitive. Such a PR needs independent
review by at least one qualified maintainer who did not author it. A high-risk fix involves two
maintainers (author plus independent reviewer) and includes complete test evidence.

CODEOWNERS requests review but does not enforce approval rules. Administrators must configure and
periodically audit branch/tag/release protection using the
[repository governance checklist](REPOSITORY_GOVERNANCE.md); forks and mirrors do not inherit it.

A release must originate from an annotated tag protected by a tag ruleset and marked as validly signed
by GitHub. Lightweight tags or unverifiable GPG/SSH/S/MIME signatures do not enter the build stage.
