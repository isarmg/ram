# 项目文件结构

本文说明 Ram 仓库的物理目录、Rust 模块边界、测试资料和生成制品应放在哪里。运行时调用顺序
和安全边界图见 [代码工作流程与模块作用](CODE_FLOW.md)，部署假设见
[部署威胁模型](THREAT_MODEL.md)。

## 1. 顶层布局

```text
.
├── src/                  Rust 库、二进制入口与单元测试
├── web/                  直接嵌入二进制的原生浏览器模块
├── tests/                黑盒、前端、E2E、fixture 与覆盖率策略
├── fuzz/                 独立锁定的 cargo-fuzz workspace 和 corpus
├── benchmarks/           可复现性能基线、schema 与比较工具
├── scripts/              CI、供应链、发布与覆盖率检查器
├── docs/                 变更、安全、贡献、架构、流程、威胁模型和治理文档
├── release-metadata/     发布时生成的供应链清单边界
└── .github/              GitHub 所有权、依赖更新与工作流配置
```

根目录只保留生态工具必须发现的清单、项目入口 `README.md` 和唯一的 `LICENSE`；
`CHANGELOG.md`、`SECURITY.md`、`CONTRIBUTING.md` 与其它长期文档统一放在 `docs/`。
构建输出、下载后的发布制品和带机器路径的供应链清单不得提交。

## 2. Rust 模块

```text
src/
├── main.rs               最小二进制入口
├── lib.rs                crate 边界；正常构建只公开 run，fuzzing 提供隐藏测试钩子
├── auth/                 ACL、Basic/Digest、token、限速和认证测试
├── config/               CLI、schema、来源合并、路径解析和校验
├── http/                 HTTP 方法模型、body 与 I/O watchdog
├── identity/             路径对象身份与网络来源身份
├── logging/              访问日志、脱敏、队列与轮转
├── runtime/              listener、协议接入、连接生命周期和关停
├── server/               请求状态、路由、读取、写入、DAV 与响应
└── utils/                无领域状态的共享解析/编码辅助
```

结构规则：

1. `main.rs` 不承载业务逻辑；可测试实现进入库模块。
2. 身份固定属于 `identity/`，路径身份和来源身份不能散落到 crate 根。
3. 超大安全模块采用目录模块，并把同模块单元测试放在目录内；测试模块名保持稳定，避免
   `--exact` 门禁静默失效。
4. `server/capabilities.rs` 是方法、OPTIONS、Allow 和 CORS 能力的唯一策略源；路由模块不得
   建立第二份字符串清单。
5. 生产模块之间通过最窄的 `pub(crate)`/`pub(super)` 接口协作；不得为了测试扩大公开 API。
6. 移动被覆盖率分组跟踪的源码时，必须同步 `scripts/report-coverage.mjs` 及其前端测试。

## 3. 测试与 fixture

```text
tests/
├── *.rs                  每个文件一个独立黑盒集成测试 crate
├── common/               黑盒测试复用的进程、请求和 Digest 工具
├── fixtures/
│   ├── config.yaml       检入的配置 fixture
│   └── tls/              测试证书、私钥和自定位生成脚本
├── frontend/             Vitest 模块/DOM/策略测试
├── e2e/                  Playwright 三浏览器测试与隔离服务树
└── coverage/policy.json  覆盖率趋势、目标和未来强制下限
```

测试只能修改临时目录或忽略的 `target/`。TLS 生成脚本必须相对自身路径写入，不能依赖调用者
当前目录。`fixtures/` 中的私钥仅供测试，不能进入 crates.io 包；发布归档检查器使用精确成员
白名单阻止它们进入二进制制品。

## 4. Fuzz、基准与脚本

- `fuzz/Cargo.toml` 的 `[[bin]]` 是 fuzz target 的结构事实源。
  `scripts/check-fuzz-layout.py` 强制 harness、非空 corpus、两套 CI matrix 和双语文档清单一致。
- `benchmarks/` 同时保存 runner、比较器、阈值与已审查基线；环境契约记录在其 README。
- `scripts/` 只放可独立执行的仓库工具。仓库感知脚本必须从自身位置解析仓库根，或提供显式
  项目根参数；CI 固定从仓库根调用。安全/发布检查器需要 CODEOWNERS 双人所有权。

## 5. 生成物与发布元数据

`target/`、`dist/`、`verified-source/`、`smoke-diagnostics/`、覆盖率输出和本地依赖目录都属于
可删除生成物。`release-metadata/` 只保留目录说明；CycloneDX、SPDX 和第三方许可证报告在
发布任务中从锁文件重新生成、校验并作为短期 artifact 传递。这样避免提交时间戳、随机 UUID
和构建机绝对路径，同时让发布证据绑定到实际构建。

## 6. 移动文件检查表

移动或拆分文件时至少检查：

- Rust `mod`/`use`、`include_str!`/`include_bytes!` 的源文件相对路径；
- Cargo `package.include` 与发布归档精确成员；
- CODEOWNERS、覆盖率分组、workflow 和治理检查器中的路径；
- README、流程图、fuzz 文档与测试中的示例路径；
- 全仓旧路径搜索结果必须为零，再运行完整双特性和三浏览器门禁。

---

# Project Structure (English)

This document defines where Ram's physical files, Rust module boundaries, test material, and generated
artifacts belong. See [Code Flow and Module Responsibilities](CODE_FLOW.md) for runtime call graphs and
security boundaries, and [Deployment Threat Model](THREAT_MODEL.md) for deployment assumptions.

## 1. Top-level layout

```text
.
├── src/                  Rust library, binary entry point, and unit tests
├── web/                  Native browser modules embedded directly in the binary
├── tests/                Black-box, frontend, E2E, fixture, and coverage policy files
├── fuzz/                 Separately locked cargo-fuzz workspace and corpora
├── benchmarks/           Reproducible baselines, schemas, and comparison tools
├── scripts/              CI, supply-chain, release, and coverage checkers
├── docs/                 Change, security, contribution, architecture, flow, threat-model, and governance documents
├── release-metadata/     Release-time supply-chain inventory boundary
└── .github/              Ownership, dependency-update, and workflow configuration
```

The repository root retains only ecosystem-discovered manifests, the project-entry `README.md`, and
the single `LICENSE`. `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`, and other long-lived
documentation live under `docs/`. Build output, downloaded release artifacts, and inventories
containing machine paths are never committed.

## 2. Rust modules

```text
src/
├── main.rs               Minimal binary entry point
├── lib.rs                Crate boundary; normal builds export run, fuzzing adds hidden hooks
├── auth/                 ACL, Basic/Digest, tokens, rate limits, and auth tests
├── config/               CLI, schema, source merge, path resolution, and validation
├── http/                 HTTP method model, bodies, and I/O watchdog
├── identity/             Filesystem-object and network-source identity
├── logging/              Access logging, redaction, queues, and rotation
├── runtime/              Listeners, protocol admission, connection lifetime, and shutdown
├── server/               Request state, routing, reads, writes, DAV, and responses
└── utils/                Shared parsing/encoding helpers without domain state
```

Structural rules:

1. `main.rs` contains no business logic; testable implementation belongs in library modules.
2. Identity pinning belongs in `identity/`; path and source identity do not live at the crate root.
3. Large security modules use directory modules and colocate their unit-test modules. Test module names
   stay stable so `--exact` gates cannot silently stop matching.
4. `server/capabilities.rs` is the only policy source for methods, OPTIONS, Allow, and CORS; routers do
   not create a second string registry.
5. Production modules collaborate through the narrowest `pub(crate)`/`pub(super)` interfaces; tests do
   not justify widening the public API.
6. Moving a source tracked by coverage groups also updates `scripts/report-coverage.mjs` and its
   frontend tests.

## 3. Tests and fixtures

```text
tests/
├── *.rs                  One independent black-box integration-test crate per file
├── common/               Shared process, request, and Digest helpers
├── fixtures/
│   ├── config.yaml       Checked-in configuration fixture
│   └── tls/              Test certificates, private keys, and self-locating generator
├── frontend/             Vitest module, DOM, and policy tests
├── e2e/                  Three-browser Playwright tests and isolated served tree
└── coverage/policy.json  Coverage trends, targets, and future enforced floors
```

Tests write only to temporary directories or ignored `target/` paths. The TLS generator writes relative
to its own location, never the caller's current directory. Private keys under `fixtures/` are test-only
and excluded from the crates.io package; the release archive checker uses an exact member allowlist to
keep them out of binary artifacts.

## 4. Fuzzing, benchmarks, and scripts

- `[[bin]]` entries in `fuzz/Cargo.toml` are the structural source of truth for fuzz targets.
  `scripts/check-fuzz-layout.py` keeps harnesses, non-empty corpora, both CI matrices, and bilingual
  documentation lists synchronized.
- `benchmarks/` owns its runner, comparator, thresholds, and reviewed baselines; its README defines the
  environment contract.
- `scripts/` contains independently executable repository tools. Repository-aware scripts either resolve
  the root from their own location or accept an explicit project-root argument; CI invokes them from the
  repository root. Security and release checkers have two-owner CODEOWNERS rules.

## 5. Generated files and release metadata

`target/`, `dist/`, `verified-source/`, `smoke-diagnostics/`, coverage output, and local dependency trees
are disposable. `release-metadata/` retains only its directory contract. CycloneDX, SPDX, and
third-party-license reports are regenerated from lock files during release, validated, and transferred
as short-lived artifacts. This avoids committing timestamps, random UUIDs, and build-machine absolute
paths while binding release evidence to the actual build.

## 6. File-move checklist

When moving or splitting a file, check at least:

- Rust `mod`/`use` declarations and source-relative `include_str!`/`include_bytes!` paths;
- Cargo `package.include` and the release archive's exact members;
- paths in CODEOWNERS, coverage groups, workflows, and governance checkers;
- example paths in README, flow diagrams, fuzz documentation, and tests; and
- a repository-wide old-path search returning zero before the complete dual-feature and three-browser
  gates run.
