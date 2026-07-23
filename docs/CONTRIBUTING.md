# 贡献说明

Ram 是面向个人内网浏览器使用的小型文件管理器。变更应保持这个范围，不重新引入在线
编辑、临时分享、WebDAV 挂载、应用内 TLS 或多实例共享写目录。

## 提交前

Rust：

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
```

前端：

```sh
npm ci --ignore-scripts
npm run check
npx playwright install --with-deps chromium
npm run test:e2e -- --project=chromium
```

依赖策略：

```sh
cargo audit --deny warnings
cargo deny --locked check
python3 scripts/check-license-policy.py
./scripts/check-production-deps.sh
```

只运行与改动相关的测试可以用于开发迭代，但合并前应完成全部检查。

## 变更要求

- 删除能力时，同步删除配置、CLI、环境变量、实现、测试、文档和依赖。
- 文件系统改动不得绕过根 dirfd、`openat2` 约束、特殊文件检查或 ACL。
- PUT 必须继续使用私有候选、原子发布、失败清理和目录同步。
- 新的循环、队列、请求体或响应体必须有明确上限。
- 前端下载和 ZIP 必须保持浏览器原生流式行为。
- 日志不得记录密码、Authorization、Cookie 或敏感查询参数。
- 修改用户可见行为时更新 `docs/CHANGELOG.md`。

## 提交和审查

提交应聚焦一个可解释的变化，并在说明中写明行为影响和验证结果。个人仓库不要求双人
审批；仓库管理员可以直接合并自己已完整验证的改动。涉及认证、路径隔离、原子写入和
Release 权限的变更仍应单独仔细复核。

## 发布

只有仓库管理员可以创建版本标签。标签必须是 `vMAJOR.MINOR.PATCH`，且与 Cargo 包版本
完全一致。推送标签后，GitHub Actions 自动创建 Linux x86_64 Release。

仓库治理约定见 [docs/REPOSITORY_GOVERNANCE.md](REPOSITORY_GOVERNANCE.md)。
