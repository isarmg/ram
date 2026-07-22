# 仓库治理与发布保护检查表

CODEOWNERS 和 workflow 文件只能表达仓库内意图；GitHub branch rules、tag rules、私密漏洞
报告、immutable releases、环境保护和人员权限属于仓库外状态，不会随 clone/fork 自动复制。
仓库管理员应在 GitHub UI/API 中逐项启用，并至少每季度以及维护者变更后审计。

## `main` 分支

- 禁止直接 push、force push 和删除；所有改动通过 pull request。
- 至少 1 个独立批准；认证、filesystem/server、发布 workflow 和依赖策略要求 CODEOWNER 批准。
- 新 commit 推送后取消旧批准；要求所有 review conversation resolved。
- 要求 CI 的 Rust 双特性、前端、供应链和发布静态检查成功。
- 管理员和自动化账号同样受规则约束；仅给最小权限的 break-glass 角色例外并审计使用。
- 若使用 merge queue，要求它重新运行相同必需检查；禁止只验证 PR head 而未验证 merge commit。

## tag 与 Release

- 建立匹配 `v*` 的 tag ruleset，仅允许受信维护者/发布环境创建，禁止更新或删除；GitHub
  ruleset 使用 glob 而不是正则表达式，因此严格的 SemVer 形状由发布 workflow 再次校验。
  发布前还要验证 Cargo/npm/README/CHANGELOG 版本一致、tag 可从默认分支到达且直接指向
  当前构建 commit。
- 首选 GitHub immutable releases；若该仓库/套餐尚不可用，Release 发布后禁止替换附件或重新
  指向 tag，修复必须增加新 patch 版本。
- Release workflow 使用 environment protection、最小 `contents: write` 和短期 OIDC；crates.io
  使用 trusted publishing，不保存长期 token。
- 保持 build provenance、语义验证后的 SBOM attestation、archive/binary checksum、源码包
  跨 job 哈希连续性和最终 tar 原生架构烟测；所有附件先进入草稿，完整后才公开 Release。
- 稳定版 GitHub Release 必须在 crates.io trusted publishing 成功后才由独立 finalizer 公开；
  新发布还必须在 `cargo publish` 返回后有界轮询 crates.io，直到远端版本 SHA-256 与本次已
  验证 `.crate` 完全相同；只有短暂 404 可重试。若版本已存在，也只允许相同的 SHA-256
  比对成功后走完全相同的恢复路径。
  失败重跑只可删除带有同 repository、tag、commit 隐藏标记的 draft；已公开或身份不符的
  Release 一律关闭失败并要求人工审计。草稿恢复必须扫描完整的有界分页，确认同 tag 只有
  一个候选，并同时校验 `target_commitish`；不得依赖发布 action 的近期页启发式查找。
- x86-64 与 ARM64 分别生成目标特定 CycloneDX。每个归档的外层 manifest 必须直接绑定
  `ram` 二进制、目标 CycloneDX 与 SPDX 的 SHA-256，并作为自定义 attestation predicate；
  这补足 cargo-sbom 不能按目标架构生成 SPDX 的工具限制。
- 发布 tag 必须是签名的 annotated tag；Release workflow 通过 GitHub Git Data API 要求
  `verification.verified=true`、`reason=valid`，并验证 tag 直接指向当前构建 commit。轻量 tag、
  未验证签名和 tag 链都会 fail closed；tag 保护和签名是互补控制。

## 安全与维护者

- 启用 Private vulnerability reporting 和 Security Advisories；按 `SECURITY.md` 测试通知渠道。
- 安全敏感 CODEOWNERS 至少包含两名实际拥有仓库 read/review 权限且同意值守的人，不能用不
  存在的 team、bot 或无权限账号凑数。
- 每季度核对 organization/repository owner、outside collaborator、Actions secret、environment
  reviewer、deploy key、GitHub App 和 crates.io owner；立即移除离任或闲置访问。
- Dependabot/RustSec 警报必须有负责人和处理时限；临时 ignore 必须写明到期日期和上游链接。

## 审计证据

审计记录至少保存日期、执行人、ruleset 导出或截图、必需检查名称、两名 CODEOWNER、发布
environment reviewer、immutable-release 状态、私密报告入口测试和最近一次发布制品验证。
不得把 UI 设置“计划启用”写成“已启用”。

以下项目只有仓库管理员完成并记录证据后才能勾选：

- [ ] `main` branch ruleset 已启用且包含独立/CODEOWNER 审阅。
- [ ] tag ruleset 禁止 `v*` tag 更新和删除。
- [ ] immutable releases 已启用，或有经过记录的不可变附件替代流程。
- [ ] 发布 environment、OIDC/trusted publishing 和最小权限已复核。
- [ ] 两名真实安全 CODEOWNER 均可收到并完成 review request。
- [ ] Private vulnerability reporting 入口已通过无敏感数据的测试。

---

# Repository Governance and Release Protection Checklist

CODEOWNERS and workflows express only repository intent. GitHub branch/tag rules, private reporting,
immutable releases, environment protection, and personnel permissions are external state and are not
copied by clone/fork. Administrators must configure them in GitHub and audit at least quarterly and
after maintainer changes.

## `main` branch

- Prohibit direct push, force push, and deletion; require pull requests.
- Require at least one independent approval. Authentication, filesystem/server, release workflow, and
  dependency-policy changes require CODEOWNER approval.
- Dismiss approval after new commits and require every review conversation resolved.
- Require CI's two Rust feature configurations, frontend, supply-chain, and release static checks.
- Apply rules to administrators/automation; audit any least-privilege break-glass exception.
- A merge queue reruns the same checks against the merge commit, not only the PR head.

## Tags and Releases

- Create a `v*` tag ruleset allowing only trusted maintainers/release environments and prohibiting
  update/delete. GitHub uses globs, so the release workflow separately validates strict SemVer,
  Cargo/npm/README/CHANGELOG consistency, default-branch reachability, and direct commit targeting.
- Prefer immutable releases. If unavailable, never replace published attachments or retarget tags;
  issue a new patch release.
- Protect the release environment, grant only `contents: write`, use short-lived OIDC, and use
  crates.io trusted publishing rather than stored long-lived tokens.
- Preserve build provenance, semantically checked SBOM attestations, archive/binary checksums,
  source-package hash continuity between jobs, and native-architecture smoke tests. Upload everything
  to a draft before publication.
- A stable GitHub Release is finalized only after crates.io trusted publishing succeeds. A new
  publication must also poll crates.io within a fixed bound after `cargo publish` returns, until the
  remote SHA-256 exactly matches the newly verified `.crate`; only a transient 404 is retryable. An
  existing version is likewise a recovery path only after the same checksum comparison succeeds. A
  retry may delete only a draft carrying the exact repository/tag/commit marker; published
  or mismatched releases fail closed for manual audit. Draft recovery scans the complete bounded
  pagination, requires exactly one candidate for the tag, and also verifies `target_commitish`; it does
  not rely on a release action's recent-page lookup heuristic.
- Generate target-specific CycloneDX documents for x86-64 and ARM64. A per-target outer manifest binds
  the SHA-256 of the `ram` binary, CycloneDX, and SPDX and is used as a custom attestation predicate,
  explicitly compensating for cargo-sbom's lack of target-specific SPDX generation.
- Require a signed annotated tag whose GitHub Git Data response has `verification.verified=true` and
  `reason=valid`, directly targeting the built commit. Lightweight tags, unverifiable signatures, and
  tag chains fail closed. Tag protection and signature verification are complementary.

## Security and maintainers

- Enable Private vulnerability reporting and Security Advisories; test notification per `SECURITY.md`.
- Security CODEOWNERS include at least two real people with repository read/review permission and an
  agreed duty rota—not nonexistent teams, bots, or inaccessible accounts.
- Quarterly audit organization/repository owners, outside collaborators, Actions secrets, environment
  reviewers, deploy keys, GitHub Apps, and crates.io owners; remove stale access immediately.
- Assign RustSec/Dependabot alerts with deadlines; temporary ignores need an expiry and upstream link.

## Audit evidence

Keep date, operator, ruleset export/screenshot, required-check names, two CODEOWNERS, release environment
reviewer, immutable-release status, a private-reporting test, and the latest artifact validation. Never
record a merely planned UI setting as enabled.

Only an administrator with recorded evidence may check these boxes:

- [ ] `main` ruleset includes independent/CODEOWNER review.
- [ ] `v*` tag ruleset prohibits update and deletion.
- [ ] Immutable releases are enabled or a documented immutable-attachment substitute exists.
- [ ] Release environment, OIDC/trusted publishing, and least privilege are reviewed.
- [ ] Two real security CODEOWNERS receive and complete review requests.
- [ ] Private vulnerability reporting was tested without sensitive data.
