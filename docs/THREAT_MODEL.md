# 部署威胁模型

本文说明 Ram 在不同部署方式下保护什么、信任谁，以及哪些风险必须由操作系统、代理或部署
架构承担。它不是“启用 TLS 就安全”的清单；同一配置在单用户目录和不可信多租户写目录中的
攻击面完全不同。

## 共同资产与边界

需要保护的资产包括：

- 服务根内文件的机密性、完整性、可用性和名称信息；
- Basic/Digest 密码材料、Bearer token、token secret 与撤销状态；
- TLS 私钥、配置、auth rules、quota hook 和自定义静态资源；
- 服务进程、CPU、内存、fd、blocking worker、网络连接和磁盘配额；
- Release 二进制、checksum、SBOM、attestation 和发布凭据。

外部不可信输入包括 URI、headers、认证参数、请求正文、DAV XML、文件名、搜索词、Range、
Destination、Host、代理身份头和浏览器上传内容。服务树若可由其它进程修改，则目录项、symlink、
mount、inode 替换、xattr 和权限变化也都是并发不可信输入。

Ram 的核心服务边界是 Linux 进程及其预先打开的根目录 descriptor。`openat2`、descriptor
派生真实路径复核和原子暂存/rename 只防止请求越过配置的 root/ACL；它们不替代 Unix 权限、
MAC、磁盘配额、备份、主机隔离或可信内核。root、具有 `CAP_DAC_OVERRIDE`/ptrace 权限的进程、
能修改 Ram 二进制/配置/私钥的账户以及被攻陷的内核均在信任边界之外。

## 所有部署的基线

- Linux 5.6+，允许 `openat2`，`/proc/self/fd` 可读；不支持时启动失败，不安全回退不受支持。
- 生产配置、auth/token/TLS 文件由专用管理员拥有、最小权限、不可被服务目录写用户修改。
- 默认 loopback；公网或不可信网络必须使用直接 TLS 或经过正确配置的可信 TLS 代理。
- 使用具名账户、最小路径 ACL 和最小 `allow-*` capability；不要把 `--allow-all` 当生产默认。
- 对服务树施加 Unix 权限、独立服务账户、磁盘/project quota、备份和监控。
- 固定并验证反向代理路径/Host/客户端身份策略；订阅安全公告并及时升级。
- 不共享生产 token secret、撤销文件或写目录的备份给低信任环境。

## 1. 单用户部署

### 假设

唯一远程用户和主机管理员互相信任；其它本地非特权进程不能修改服务目录、配置或秘密。

### 主要风险

- 弱/复用密码、泄漏的命令行 `--auth`、长期 Bearer URL 或未加密网络；
- 误开上传/删除/search/hash/archive，或把错误目录作为 root；
- 浏览器打开不可信主动内容、磁盘被大上传填满、备份/撤销状态不一致。

### 建议

使用 `--auth-file`、直接 TLS/loopback、短 token TTL、最小 capability 和 XFS project quota。
单用户不等于匿名安全：恶意网页、泄漏 token 和同机进程仍可能代表用户发请求。

## 2. 多用户只读部署

### 假设

用户互不信任但都没有服务树写权限；管理员负责内容和 ACL。IndexOnly 用户不应获知未授权
名称，read-only 用户只能读取其 capability root。

### 主要风险

- ACL 前缀混淆、symlink 指向另一个用户目录、搜索/ZIP/DAV 侧信道；
- 认证用户名枚举、Digest replay、Bearer token 跨用户/路径复用；
- 大量列表/search/hash/ZIP 和 Range 请求耗尽 CPU、fd 或 worker。

### 建议

为每组使用最窄路径规则，测试直接 GET、列表、search、ZIP 和 DAV 的一致可见性；仅按需启用
昂贵能力并收紧条目/深度/大小/并发/超时预算。日志和指标不能记录目录内容或凭据。

## 3. 不可信写用户

### 假设

认证用户可以在其授权子树创建任意名称、内容、目录和 symlink（若显式允许），并可能并发执行
PUT/PATCH/COPY/MOVE/DELETE；用户会主动尝试竞态和资源耗尽。

### 主要风险

- symlink/rename/replace TOCTOU、硬链接与挂载边界、目标父目录替换；
- 覆盖别人的对象、绕过 If-Match、部分写、临时文件遗留或 crash 后错误清理；
- ZIP bomb/大稀疏文件、inode/磁盘耗尽、慢速/trickle 上传和 worker 占用；
- 上传 HTML/SVG 等主动内容后利用同源凭据攻击管理 UI。

### 建议

这是最高风险模式。优先为不同信任域运行不同 Ram 实例、Unix 用户和文件系统/project quota，
不要仅靠路径 ACL 构造强多租户。保持 symlink 默认关闭；分配写用户独占子树；启用上传、复制、
连接、请求、目录和昂贵任务全部预算。将主动内容以 attachment 或隔离 origin 提供，不允许写用户
修改 custom assets、auth、token、TLS、日志或 quota hook。定期演练崩溃恢复和候选清理。

## 4. 反向代理部署

### 假设

只有明确列入 `trusted-proxy` 的代理能直接连接 Ram；代理终止 TLS，可能添加真实客户端地址，
并把一个外部路径前缀映射到 Ram。

### 主要风险

- 未受信客户端伪造 `X-Forwarded-For` 等身份头以绕过 per-source 限制；
- Host、Destination、scheme、路径前缀或 percent encoding 在代理与 Ram 之间解释不一致；
- 代理缓存带认证/私有响应、剥离安全/截断头、缓冲无界正文或放宽方法；
- 代理超时与 Ram timeout 冲突，TLS 到代理安全但代理到 Ram 暴露。

### 建议

防火墙限制后端，只信任固定代理 CIDR并显式配置一个身份头；代理先删除客户端同名头再写入。
保持原始编码语义，不做二次 decode/normalize；固定 Host、scheme 和前缀，允许所需 DAV 方法及
Destination。私有响应不得公共缓存。代理到 Ram 使用 loopback/Unix socket或独立受保护网络，
并通过真实外部 URL 回归测试认证、Range、DAV、上传和失败头。

## 5. 多实例部署

### 假设

多个 Ram 进程可能共享负载均衡器、token identity、撤销状态或同一服务目录。

### 主要风险

- mutation lock、上传 permit、候选身份和进程内 precondition 序列化不跨进程；
- 两个实例同时覆盖/移动/清理对象，或把另一个实例的活跃候选误作陈旧文件；
- 撤销 generation、secret/audience、配置和时钟不一致；
- sticky session 掩盖不一致，健康探针无法证明共享状态一致。

### 支持结论

同一可写目录的 active-active 多实例当前**不受支持**。需要扩展时，应按实例分片为互不重叠的
写根，或在 Ram 外实现经过验证的分布式写锁/事务存储；普通负载均衡不能补足此边界。
只读副本可使用不可变快照，但更新快照必须原子切换且各实例配置一致。共享 Bearer identity 时，
secret、audience、撤销状态和时钟必须一致；无法提供强一致撤销存储时应使用独立 identity 或短 TTL。

## 6. NFS/FUSE/其它远程或用户态文件系统

### 假设

底层不是受信任的本地 Linux 文件系统，系统调用语义、inode/device 稳定性、`openat2` 标志、
rename/fsync、锁、配额和错误码可能与本地 ext4/XFS 不同或发生网络分区。

### 主要风险

- descriptor/目录项身份或 mount 边界语义不稳定；服务器缓存导致 ACL/内容过期；
- rename 并非预期原子性，file/parent fsync 不代表远端耐久，锁在断线后丢失；
- 阻塞 syscall 无法被 Tokio 取消，worker 与 permit 长时间占用；
- quota/ENOSPC 延迟或错误映射，候选清理观察到不一致目录；
- 恶意或被攻陷的 FUSE daemon 可向 Ram 伪造任意文件系统结果。

### 支持结论

安全写入只支持经过验证、能可靠返回系统调用的本地文件系统。NFS/FUSE 应视为实验性、不可信
存储，不能用于敌对多租户或依赖严格耐久性的写服务。若业务必须使用，应默认只读、在独立主机
和账户隔离，逐项验证 `openat2`/no-xdev、rename、fsync、锁、inode、quota、断线与恢复语义，
并用外部 watchdog 隔离不可取消的挂起。验证结果只适用于具体内核、挂载参数和服务版本。

## 明确不保证

Ram 不防御主机 root/内核、可修改二进制或配置的管理员、窃取终端明文密码的恶意客户端、
被授权用户读取其本来可读的数据，或底层文件系统直接丢失/篡改数据。它也不是 WAF、恶意软件
扫描器、DLP、备份系统、分布式锁服务或内容消毒器。

发现某个部署假设不成立时，应缩小权限、分离实例/Unix 用户/文件系统并停止写入，而不是在
同一进程中叠加更多路径字符串规则。

---

# Deployment Threat Model

This document states what Ram protects, who it trusts, and which risks belong to the OS, proxy, or
deployment architecture. “TLS enabled” is not a complete security model: the attack surface differs
substantially between a single-user directory and an untrusted multi-tenant writable tree.

## Shared assets and boundaries

Protected assets include:

- confidentiality, integrity, availability, and name metadata of served files;
- Basic/Digest password material, Bearer tokens, token secret, and revocation state;
- TLS keys, configuration, auth rules, quota hook, and custom static assets;
- process, CPU, memory, file descriptors, blocking workers, connections, and disk quota;
- release binaries, checksums, SBOMs, attestations, and publishing credentials.

Untrusted inputs include URIs, headers, authentication parameters, bodies, DAV XML, filenames,
search terms, Range, Destination, Host, proxy identity headers, and browser uploads. If another
process can mutate the served tree, directory entries, symlinks, mounts, inode replacement, xattrs,
and permission changes are concurrent untrusted input too.

Ram's core boundary is a Linux process plus its pre-opened root descriptor. `openat2`,
descriptor-derived path reauthorization, and atomic staging/rename keep requests within root and ACL;
they do not replace Unix permissions, MAC, quota, backup, host isolation, or a trusted kernel. Host
root, processes with `CAP_DAC_OVERRIDE`/ptrace, accounts able to change Ram/configuration/keys, and a
compromised kernel are outside the protected boundary.

## Baseline for every deployment

- Linux 5.6+, permitted `openat2`, and readable `/proc/self/fd`; unsupported systems fail startup
  with no insecure fallback.
- Production configuration/auth/token/TLS files have dedicated ownership, least permissions, and
  cannot be changed by served-tree writers.
- Bind loopback by default; untrusted networks require direct TLS or a correctly configured trusted
  TLS proxy.
- Use named accounts, narrow path ACLs, and minimal `allow-*`; do not make `--allow-all` a production default.
- Apply Unix permissions, a dedicated service account, filesystem/project quota, backups, and monitoring.
- Pin and validate reverse-proxy path/Host/client identity policy; subscribe to advisories and upgrade.
- Do not copy production token secrets, revocation state, or writable-tree backups into lower-trust environments.

## 1. Single-user deployment

### Assumptions

The sole remote user and host administrator trust each other, and other local unprivileged processes
cannot modify the served tree, configuration, or secrets.

### Main risks

- weak/reused passwords, leaked command-line `--auth`, long-lived Bearer URLs, or plaintext transport;
- accidentally enabling upload/delete/search/hash/archive or choosing the wrong root;
- opening untrusted active content, filling disk with uploads, or inconsistent backup/revocation state.

### Recommendations

Use `--auth-file`, direct TLS/loopback, short token TTL, minimal capabilities, and XFS project quota.
Single-user does not mean anonymous-safe: malicious pages, leaked tokens, and local processes may act
for the user.

## 2. Multi-user read-only deployment

### Assumptions

Users distrust one another but cannot write the tree; administrators own content and ACLs. An
IndexOnly user must not learn unauthorized names, and a read-only user reads only its capability root.

### Main risks

- ACL-prefix confusion, symlinks into another user's tree, and search/ZIP/DAV side channels;
- username enumeration, Digest replay, or Bearer reuse across users/paths;
- listing/search/hash/ZIP/Range requests exhausting CPU, descriptors, or workers.

### Recommendations

Use the narrowest path rules and test consistent visibility across direct GET, listing, search, ZIP,
and DAV. Enable expensive capabilities only when needed and tighten entry/depth/size/concurrency/time
budgets. Logs and metrics must not record directory contents or credentials.

## 3. Untrusted writers

### Assumptions

Authenticated users can create arbitrary names, content, directories, and—only if enabled—symlinks
inside their authorized subtree, while concurrently issuing PUT/PATCH/COPY/MOVE/DELETE and actively
probing races/resource exhaustion.

### Main risks

- symlink/rename/replace TOCTOU, hard links/mount boundaries, and destination-parent replacement;
- overwriting another object, bypassing If-Match, partial writes, temporary residue, or unsafe crash cleanup;
- ZIP bombs, large sparse files, inode/disk exhaustion, trickle uploads, and worker starvation;
- same-origin attacks after uploading active HTML/SVG beside the management UI.

### Recommendations

This is the highest-risk mode. Prefer separate Ram instances, Unix users, and filesystems/project
quotas per trust domain; path ACLs alone are not strong multi-tenancy. Keep symlinks off, allocate
exclusive writable subtrees, and bound uploads, copies, connections, requests, directories, and
expensive tasks. Serve active content as attachment or from an isolated origin. Writers must never
modify custom assets, auth/token/TLS material, logs, or quota hooks. Rehearse crash recovery.

## 4. Reverse proxy

### Assumptions

Only proxies explicitly listed in `trusted-proxy` directly connect. The proxy terminates TLS, may add
the real client address, and maps an external prefix to Ram.

### Main risks

- clients forging `X-Forwarded-For`-style identity to bypass per-source limits;
- disagreement over Host, Destination, scheme, prefix, or percent encoding;
- caching authenticated responses, stripping security/truncation headers, unbounded buffering, or method widening;
- conflicting proxy/Ram timeouts and an exposed plaintext proxy-to-Ram hop.

### Recommendations

Firewall the backend, trust only fixed proxy CIDRs and one explicit identity header, and have the proxy
remove any client-supplied copy before writing it. Preserve encoding without double decoding, and pin
Host/scheme/prefix and DAV methods/Destination. Never publicly cache private responses. Use loopback,
Unix socket, or a protected backend network and test auth, Range, DAV, upload, and error headers through
the real external URL.

## 5. Multiple instances

### Assumptions

Multiple Ram processes may share a load balancer, token identity/revocation state, or a served tree.

### Main risks

- mutation locks, upload permits, candidate identity, and precondition serialization are process-local;
- concurrent overwrite/move/cleanup, including mistaking another instance's active candidate for stale;
- inconsistent revocation generations, secrets/audience, configuration, or clocks;
- sticky sessions masking inconsistency and health probes failing to prove shared-state agreement.

### Support conclusion

Active-active instances over one writable directory are currently **unsupported**. Scale by sharding
non-overlapping writable roots or by adding a separately validated distributed lock/transaction layer;
ordinary load balancing is insufficient. Read-only replicas may use immutable snapshots atomically
switched under identical configuration. Shared Bearer identity requires identical secret, audience,
revocation state, and clocks; otherwise use separate identities or short TTLs.

## 6. NFS, FUSE, and remote/userspace filesystems

### Assumptions

Syscall semantics, device/inode stability, `openat2`, rename/fsync, locking, quota, and errors may
differ from local ext4/XFS or be interrupted by a network partition.

### Main risks

- unstable descriptor/entry identity or mount-boundary semantics and stale server caches;
- non-atomic rename, fsync without remote durability, or locks lost on disconnect;
- non-cancellable blocking syscalls retaining workers and permits;
- delayed quota/ENOSPC, inconsistent cleanup views, or a malicious FUSE daemon forging results.

### Support conclusion

Secure writes support only a validated local filesystem with reliable syscalls. Treat NFS/FUSE as
experimental untrusted storage, unsuitable for adversarial multi-tenancy or strict durability. If
required, default to read-only and isolate host/account; validate no-xdev/openat2, rename, fsync, locks,
inode, quota, disconnect, and recovery for the exact kernel/mount/service version, with an external
watchdog for non-cancellable hangs.

## Explicit non-guarantees

Ram does not defend against host root/kernel, administrators who can replace binaries/configuration,
malicious clients stealing terminal plaintext passwords, authorized reads, or direct storage loss and
corruption. It is not a WAF, malware scanner, DLP system, backup system, distributed lock service, or
content sanitizer. When an assumption fails, reduce privilege and separate instances, Unix users, and
filesystems; do not stack more path-string rules inside the same process.
