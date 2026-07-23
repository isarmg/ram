# 安全策略

Ram 直接处理认证凭据、不可信 HTTP/WebDAV 请求和本地文件系统对象。请把可能导致
越权读取/写入、路径逃逸、认证绕过、凭据泄漏、拒绝服务或发布制品被替换的问题按安全
漏洞私密报告，不要先创建公开 issue、讨论或拉取请求。

## 支持版本

安全支持以仓库 `Cargo.toml` 中的稳定版本为准：

| 版本线 | 支持级别 |
| --- | --- |
| 最新稳定 minor | 接收全部安全修复 |
| 前一个稳定 minor | 仅接收 critical/high 且可安全回移的修复 |
| 更早版本、预发布版本和非官方构建 | 不支持；请先升级或在最新提交上复现 |

维护者发布新的稳定 minor 后，应同步更新 Release notes 和本表的解释。无法升级的部署方
仍可提交报告，但维护者不承诺为已停止支持的分支制作补丁。

## 私密报告渠道

首选 GitHub 的
[私密漏洞报告](https://github.com/isarmg/ram/security/advisories/new)。该渠道允许维护者与
报告者在 Security Advisory 草稿中协调、准备私有修复和申请 CVE。

如果 GitHub 私密报告入口不可用，请只在普通 issue 中说明“无法访问私密报告渠道”，
不要附带漏洞细节。维护者会提供一次性私密协调方式。项目当前没有公布其它受监控的安全
邮箱，任何未经本文列出的邮箱、聊天账号或上游项目 issue 都不应被当作已送达 Ram 维护者。

若问题也影响上游 dufs，请分别使用其安全渠道协调；未经双方同意，不要把一方的私密材料
转发到另一方。

## 报告内容

尽量提供：

- 受影响的 Ram 版本、commit、架构、内核与文件系统类型；
- 去除秘密后的配置、认证/ACL 规则和部署拓扑；
- 最小请求序列、预期行为、实际行为与稳定复现概率；
- 攻击者需要的网络、本地账户、写目录或代理控制能力；
- 对机密性、完整性、可用性以及跨租户边界的影响；
- 已知临时缓解措施和建议披露日期；
- 如有补丁，附带能在修复前失败、修复后通过的回归测试。

不要发送真实密码、私钥、Bearer token、生产文件、完整访问日志或未经授权取得的数据。
使用最小化 fixture；日志中的 Authorization、Cookie、查询 token 和文件内容必须脱敏。

## 响应目标

以下是正常维护能力下的目标，不是法律或服务等级保证：

| 阶段 | 目标时间 |
| --- | --- |
| 确认收到 | 3 个工作日内 |
| 初步严重度与复现结论 | 7 个自然日内 |
| 调查期间状态更新 | 至少每 7 个自然日一次 |
| critical 修复目标 | 确认后 14 个自然日内 |
| high 修复目标 | 确认后 30 个自然日内 |
| moderate/low | 纳入下一个合理的稳定版本 |

复杂的内核/文件系统竞态、上游依赖漏洞或需要跨项目协调的问题可能延长时间。维护者会说明
原因、当前缓解措施和下次更新时间。报告者若在上述确认期限后仍未收到回复，可在不披露细节
的前提下公开提醒维护者检查私密报告。

## 严重度与处理原则

维护者综合可利用性、所需权限、默认配置、影响范围和可恢复性判断严重度。以下通常按高优先
级处理：

- 绕过认证、路径 ACL、真实对象复核或 Linux 根目录能力边界；
- 不可信写用户覆盖/删除其权限外对象，或通过 symlink/rename 竞态越权；
- Basic、Digest、Bearer、token secret、撤销状态或 TLS 私钥泄漏；
- 可远程触发的无限内存、线程、fd、blocking worker 或磁盘消耗；
- Release、checksum、attestation 或发布凭据被替换/绕过；
- 默认或文档推荐部署中可远程利用的进程崩溃。

修复必须优先保持 fail closed，不得以降低 ACL、路径隔离、原子写或资源预算换取兼容性。
安全修复需增加负向回归测试，并同时验证默认 TLS 与 `--no-default-features`。

## 协调披露流程

1. 维护者在私密 Advisory 中确认范围、严重度、受影响版本和临时缓解措施。
2. 修复在私有分支中由至少一名未编写该修复的维护者进行安全审阅。
3. 在受支持架构/特性组合完成测试，准备版本、变更说明、校验和、SBOM 和 provenance。
4. 发布修复版本与 Advisory；必要时申请 CVE，并清楚列出升级/缓解步骤。
5. 公开修复后再开放完整技术讨论。除非报告者拒绝，公告会按其希望的名称致谢。

默认协调窗口为确认漏洞后的 90 天；critical/high 且已有活跃利用证据时可以缩短。若报告者
计划提前披露，请尽早协商具体日期。维护者不会要求无限期保密，也不会因善意、在授权范围内
且遵守本策略的研究威胁采取法律行动。

## 部署假设

Ram 的安全边界会随部署类型改变。提交漏洞前请阅读
[部署威胁模型](docs/THREAT_MODEL.md)，尤其说明服务树是否可被其它本地进程修改、是否存在
不可信写用户、反向代理是否重写 Host/路径、是否多实例共享写目录，以及底层是否为
NFS/FUSE。超出支持假设的问题仍可报告，但可能被归类为加固建议而非漏洞。

---

# Security Policy

Ram directly handles credentials, untrusted HTTP/WebDAV requests, and local filesystem objects.
Privately report issues that could cause unauthorized reads/writes, path escape, authentication
bypass, credential disclosure, denial of service, or release replacement. Do not first create a
public issue, discussion, or pull request.

## Supported versions

Security support follows the stable version in `Cargo.toml`:

| Release line | Support |
| --- | --- |
| Latest stable minor | All security fixes |
| Previous stable minor | Only critical/high fixes that can be safely backported |
| Older, prerelease, and unofficial builds | Unsupported; upgrade or reproduce on the latest commit |

After a stable minor release, maintainers update release notes and this interpretation. Reports from
deployments that cannot upgrade are welcome, but unsupported branches are not guaranteed a patch.

## Private reporting channel

Prefer GitHub [private vulnerability reporting](https://github.com/isarmg/ram/security/advisories/new),
which supports coordination, private fixes, and CVE requests in a Security Advisory draft.

If that entry point is unavailable, open an ordinary issue saying only that private reporting is
unavailable—include no vulnerability detail. Maintainers will provide a one-time private channel. The
project publishes no other monitored security mailbox; unlisted mail, chat, or an upstream issue does
not count as delivery to Ram maintainers.

If upstream dufs is also affected, coordinate separately through its channel and do not forward one
project's private material to the other without both parties' agreement.

## What to include

Where possible provide:

- affected Ram version/commit, architecture, kernel, and filesystem;
- redacted configuration, authentication/ACL rules, and deployment topology;
- minimal request sequence, expected and actual behavior, and reproduction rate;
- network, local-account, writable-directory, or proxy control required by the attacker;
- confidentiality, integrity, availability, and cross-tenant impact;
- known mitigations and a proposed disclosure date;
- a regression test that fails before and passes after a proposed patch.

Do not send real passwords, private keys, Bearer tokens, production files, full access logs, or data
obtained without authorization. Minimize fixtures and redact Authorization, Cookie, query tokens, and
file contents.

## Response targets

These are goals under normal maintainer capacity, not a legal or service-level guarantee:

| Stage | Target |
| --- | --- |
| Receipt acknowledgment | Within 3 business days |
| Initial severity/reproduction assessment | Within 7 calendar days |
| Investigation updates | At least every 7 calendar days |
| Critical fix target | Within 14 calendar days after confirmation |
| High fix target | Within 30 calendar days after confirmation |
| Moderate/low | Next reasonable stable release |

Kernel/filesystem races, upstream dependency bugs, or cross-project coordination may take longer.
Maintainers state the reason, current mitigation, and next update. If acknowledgment is overdue, a
reporter may publicly remind maintainers to check private reports without disclosing details.

## Severity and handling

Severity combines exploitability, required privilege, default configuration, scope, and recovery.
High-priority examples include:

- bypassing authentication, path ACL, real-object revalidation, or the Linux root capability;
- an untrusted writer changing objects outside its rights through symlink/rename races;
- disclosure of Basic/Digest/Bearer material, token secrets/revocations, or TLS keys;
- remotely unbounded memory, threads, file descriptors, blocking workers, or disk consumption;
- replacement/bypass of releases, checksums, attestations, or publishing credentials;
- a remotely triggered process crash in default or recommended deployment.

Fixes preserve fail-closed behavior and never trade away ACLs, path isolation, atomic writes, or
resource budgets for compatibility. Security fixes add negative regression coverage under default TLS
and `--no-default-features`.

## Coordinated disclosure

1. Maintainers confirm scope, severity, affected versions, and temporary mitigation in a private Advisory.
2. A private fix receives security review from a maintainer who did not author it.
3. Supported architectures/features are tested; version, notes, checksums, SBOM, and provenance are prepared.
4. The fixed release and Advisory are published, with a CVE and upgrade/mitigation steps where appropriate.
5. Full technical discussion opens after publication; reporters are credited under their preferred name unless declined.

The default coordination window is 90 days after confirmation and may be shortened for critical/high
issues with active exploitation. Maintainers do not demand indefinite secrecy and will not threaten
good-faith research performed within authorization and this policy.

## Deployment assumptions

Read the [deployment threat model](docs/THREAT_MODEL.md) and state whether another local process can
modify the served tree, whether writers are untrusted, whether a reverse proxy rewrites Host/path,
whether multiple instances share a writable directory, and whether storage is NFS/FUSE. Reports
outside supported assumptions are still welcome but may be classified as hardening rather than a vulnerability.
