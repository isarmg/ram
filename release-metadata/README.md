# 发布供应链元数据

本目录是发布工作流的临时输出边界，不保存生成快照。发布任务会从锁定的依赖图重新生成：

- 每个发布目标一份 CycloneDX JSON；
- 一份 SPDX 2.3 JSON；
- 一份包含生产与构建依赖的第三方许可证 HTML。

这些文件包含生成时间、随机文档标识和构建机路径，提交它们既不能证明可复现性，也会泄露
本地目录。CI 会在上传前依据 `Cargo.lock` 验证语义，并将精确文件作为短期 artifact 传给构建
和发布任务。本地生成物由 `.gitignore` 排除。

---

# Release supply-chain metadata

This directory is the release workflow's temporary output boundary; generated snapshots are not
committed. Each release regenerates, from the locked dependency graph:

- one CycloneDX JSON document per release target;
- one SPDX 2.3 JSON document; and
- one third-party-license HTML report for normal and build dependencies.

These files contain generation times, random document identifiers, and build-machine paths. Committing
them neither proves reproducibility nor protects local path privacy. CI validates their semantics against
`Cargo.lock` before uploading the exact files as a short-lived artifact for build and release jobs. Local
outputs are excluded by `.gitignore`.
