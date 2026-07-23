# 仓库治理

本仓库由单个实际管理员维护，不采用企业级双人审批、签名标签、发布 finalizer 或不可变
制品证明流程。

## 分支

- `main` 是唯一长期分支。
- 建议启用禁止 force-push 和删除的基础分支保护。
- CI 通过后，管理员可以直接合并自己的变更，不要求第二位审批者。
- 自动依赖更新仍须通过同一 CI。

## Actions 权限

- 默认工作流只有只读 `contents` 权限。
- 只有 `release.yaml` 在版本标签触发时拥有 `contents: write`。
- 第三方 Actions 固定到完整 commit SHA。
- 不向 pull request 暴露发布凭据。

## 发布

- 标签必须为 `vMAJOR.MINOR.PATCH` 并与 Cargo 版本一致。
- Release 只包含 Linux x86_64 压缩包和 SHA-256 文件。
- Release 直接公开，不创建草稿，不发布到外部注册表。
- 若标签或附件错误，由管理员修正版本后创建新版本；不要静默替换已公开附件。

## 管理员检查

仓库管理员应定期确认：

- CODEOWNERS 仍只列出实际管理员；
- 默认分支和 Actions 权限没有被意外扩大；
- GitHub secrets 中没有已废弃凭据；
- CI、fuzz 和 Release 仍与当前产品范围一致；
- 安全问题有可用的私密报告入口。

这些 GitHub 侧设置无法由仓库文件完全证明，管理员在修改设置后自行复核即可。
