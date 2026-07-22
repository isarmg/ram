# Ram 项目整改与优化 To-Do List

> 适用版本：0.47.0  
> 最后更新：2026-07-22

> 维护规则：已完成的具体任务立即从本文删除；发布候选门禁属于重复性工作，始终保留。

# 每个发布候选都要重复的门禁

开发分支上的一次通过不能永久关闭以下清单。

## 构建与依赖

- [ ] `cargo fmt --all --check`。
- [ ] `cargo clippy --all-targets --all-features --locked -- --deny warnings`。
- [ ] `cargo clippy --all-targets --no-default-features --locked -- --deny warnings`。
- [ ] `cargo test --all-targets --all-features --locked`。
- [ ] `cargo test --all-targets --no-default-features --locked`。
- [ ] `RUSTDOCFLAGS='--deny warnings' cargo doc --no-deps --all-features --locked`。
- [ ] `cargo audit` 与 `cargo deny check`。
- [ ] `npm run check` 与三浏览器 `npm run test:e2e`。

## 安全与制品

- [ ] 路径穿越、符号链接越界、真实对象 ACL、Digest、token、条件写、WebDAV 预算、H2/全局并发、慢速上传、写锁、公平性和日志脱敏回归。
- [ ] `cargo package` 不含测试私钥、`node_modules`、构建输出或秘密。
- [ ] x86_64/aarch64 制品机器类型、解压后健康/认证/TLS/Range/写入/关停 smoke 正确。
- [ ] SBOM、第三方许可证、SHA-256、签名和 provenance attestation 完整且彼此绑定。

---

# Ram Remediation and Optimization To-Do List

> Applies to: 0.47.0  
> Last updated: 2026-07-22

> Maintenance rule: remove each concrete task immediately after completion; recurring release-candidate gates always remain.

# Gates repeated for every release candidate

A development-branch pass never closes these recurring checks permanently.

## Build and dependencies

- [ ] `cargo fmt --all --check`.
- [ ] `cargo clippy --all-targets --all-features --locked -- --deny warnings`.
- [ ] `cargo clippy --all-targets --no-default-features --locked -- --deny warnings`.
- [ ] `cargo test --all-targets --all-features --locked`.
- [ ] `cargo test --all-targets --no-default-features --locked`.
- [ ] `RUSTDOCFLAGS='--deny warnings' cargo doc --no-deps --all-features --locked`.
- [ ] `cargo audit` and `cargo deny check`.
- [ ] `npm run check` and three-browser `npm run test:e2e`.

## Security and artifacts

- [ ] Regress path traversal, symlink escape, real-object ACL, Digest, tokens, conditional writes, DAV budgets, H2/global admission, trickle uploads, write-lock fairness, and log redaction.
- [ ] Ensure `cargo package` excludes test private keys, `node_modules`, build outputs, and secrets.
- [ ] Verify x86_64/aarch64 machine types and extracted-artifact health/auth/TLS/Range/write/shutdown smoke tests.
- [ ] Verify SBOM, third-party licenses, SHA-256, signatures, and provenance attestations are complete and mutually bound.
