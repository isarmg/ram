# Ram 文件服务

[![CI](https://github.com/isarmg/ram/actions/workflows/ci.yaml/badge.svg)](https://github.com/isarmg/ram/actions/workflows/ci.yaml)

Ram 是一个以安全边界和可运维性为重点的 Linux 文件服务管理器。它将一个本地
文件或目录映射为 HTTP/WebDAV 资源，提供现代浏览器管理界面、适合 `curl`
和 WebDAV 客户端的接口、细粒度路径权限、TLS、断点传输、搜索、归档和哈希。

crates.io 包名是 `ram-fileserver`，安装后的命令名是 `ram`。项目源自
[dufs](https://github.com/sigoden/dufs)，当前由 Ram 贡献者维护。

> 服务端支持 Linux GNU 的 x86_64 与 ARM64 架构；官方制品要求 glibc 2.39 或更新
> 版本，x86_64 不要求 AVX、AVX2、BMI、FMA 等扩展。浏览器端只支持启用
> JavaScript 的最新 evergreen 浏览器。Linux 以外的服务端、旧浏览器和旧认证
> 兼容模式不属于支持范围。

## 1. 功能与非目标

主要能力：

- 浏览、下载、上传、覆盖、删除、移动和复制文件。
- 创建目录、搜索目录、将目录流式打包为 ZIP。
- Range/多 Range 下载、条件请求和断点续传上传。
- 内置现代 Web UI，可查看、编辑 UTF-8 文本并拖放上传目录。
- Basic、RFC 7616 SHA-256 Digest 和短期 Bearer 下载令牌。
- 按用户和路径配置只读/读写权限，并由全局能力开关设置权限上限。
- 有限、明确声明的 WebDAV 子集：`PROPFIND`、`PROPPATCH`、`MKCOL`、`COPY`、`MOVE`。
- 直接 TLS、反向代理、TCP、Unix domain socket 和 Linux abstract socket。
- 连接、遍历、搜索、归档、哈希、上传大小和超时限制。
- 异步访问日志、自动轮转、健康与就绪探针。

项目不是分布式存储、对象存储网关、数据库索引服务，也不提供 Windows/macOS
服务端、musl 官方制品、旧式浏览器降级包或官方容器镜像。内置 UI 负责交互，
所有安全决策仍在服务端执行。

## 2. 支持范围

### 2.1 服务端平台

官方构建和持续验证覆盖：

```text
x86_64-unknown-linux-gnu
aarch64-unknown-linux-gnu
```

项目自身不使用 x86 专用指令、intrinsic 或内联汇编。发布工作流显式把 x86_64
固定为 `target-cpu=x86-64`（x86-64 v1，不要求 AVX 等可选扩展），把 ARM64 固定为
Rust 的 `target-cpu=generic`；两种制品都在对应架构的原生 runner 上构建和运行。
其它 Linux 架构可从源码尝试构建，但未列入官方发布与 CI 支持矩阵。

Linux 限制是安全设计的一部分而不是架构限制：根目录能力边界依赖 Linux 5.6
引入的 `openat2`，打开文件身份复核依赖可读的 `/proc/self/fd`，监听还使用
Unix/abstract socket。运行环境必须提供这些 Linux 能力，并具有与下载制品匹配
的架构；官方 GNU 制品以 glibc 2.39 为最高允许符号版本，因此部署主机必须提供
glibc 2.39 或更新版本。容器的 seccomp 策略必须允许 `openat2`，且不能屏蔽
procfs。更旧的 GNU 用户空间需要在目标环境从源码构建，不能假定官方制品兼容。

### 2.2 Rust 与前端工具链

- Rust edition：`2024`。
- 固定 Rust 工具链：`1.97.1`。
- Cargo resolver：`3`。
- 前端源码：原生 ES modules / ESNext，无转译、无 polyfill、无旧版 bundle。
- 前端静态校验：Node.js `24.18.0` LTS、ESLint `10`、TypeScript `7`。

Node.js 只用于开发期 lint 和类型检查；运行 Ram 不需要 Node，也没有前端构建步骤。
`web/` 中的 HTML、CSS 和 JavaScript 源码直接嵌入 Rust 二进制。

### 2.3 浏览器基线

仅支持当前稳定版 Chrome/Chromium Edge、Firefox 和 Safari 等 evergreen 浏览器，
且必须启用 JavaScript。项目会直接使用现代 Web API 和语言特性，例如 ES modules、
`Uint8Array.fromBase64()`、`padStart()`、`classList` 和现代 DOM API。

项目不提供：

- 无 JavaScript 目录页。
- `<noscript>` 降级界面。
- IE、旧版 Edge、旧版 Safari/Firefox/Chrome 兼容代码。
- Babel 转译、兼容性 polyfill 或双份 legacy/modern 资源。

浏览器 UI 不工作时，应先升级浏览器并确认 JavaScript 未被策略禁用；协议客户端仍可
直接使用 HTTP/WebDAV API。

## 3. 获取、构建与快速启动

### 3.1 使用发布制品

GitHub Release 同时提供 x86_64 和 ARM64 GNU/glibc 2.39+ 制品。将 `TARGET` 设为
运行机对应的 Rust 目标三元组，核验 SHA-256 与 GitHub provenance attestation 后安装：

```sh
TARGET=x86_64-unknown-linux-gnu # ARM64 使用 aarch64-unknown-linux-gnu
sha256sum --check "ram-v0.47.0-${TARGET}.tar.gz.sha256"
tar -xzf "ram-v0.47.0-${TARGET}.tar.gz"
sudo install -m 0755 "ram-v0.47.0-${TARGET}/ram" /usr/local/bin/ram
```

示例版本号仅用于展示；应替换为实际发布版本。

### 3.2 从源码构建

```sh
rustup toolchain install 1.97.1 --component clippy --component rustfmt
cargo build --locked --release
sudo install -m 0755 target/release/ram /usr/local/bin/ram
```

Cargo 默认为当前 Linux 主机架构构建，不再覆盖目标三元组或 CPU 特性。交叉构建
时可显式传入 `--target <linux-target>`，并自行准备该目标所需的 linker/sysroot。
默认 TLS 会构建 AWS-LC，因而还需要目标架构的 C 编译器、汇编器和 `ar`；使用
`--no-default-features` 的生产构建不包含这条 TLS 原生依赖链。

正式发布使用 `opt-level=3`、LTO、单 codegen unit 和 `panic=unwind`，最终二进制按
`strip=symbols` 去除符号；当前不随 Release 发布独立 debug symbols。发布工作流会记录
ELF Build ID、运行时链接信息以及 archive/二进制 SHA-256，最终 tar 还会在对应架构的
原生 runner 上解压并完成协议冒烟。这个选择保持下载制品较小，但意味着生产 core dump
和原始地址目前不能做精确的离线符号化；从同一 tag 手工重建的符号不能假定与已发布地址
完全一致。

复现问题或获得源码行信息时，可从相同 tag 构建未 strip 的诊断版本：

```sh
CARGO_PROFILE_RELEASE_DEBUG=line-tables-only \
CARGO_PROFILE_RELEASE_STRIP=none \
cargo build --locked --release
```

若以后需要对发布二进制做精确 core/地址诊断，必须在发布构建中先生成 debug 信息，再用
`objcopy --only-keep-debug` 与 `--add-gnu-debuglink` 拆分，并把匹配的符号包作为独立的
带 SHA-256 和 provenance attestation 的制品发布；同时应验证 Build ID 和 debuglink CRC。
不能从已经 `strip=symbols` 的成品事后恢复符号。

### 3.3 最小启动

Ram 强制要求至少一个具名用户，匿名规则和示例口令 `change-me` 都会被拒绝：

```sh
install -m 0600 /dev/null ./ram.auth
printf '%s\n' 'admin:replace-with-a-long-random-password@/:rw' >./ram.auth
ram --auth-file ./ram.auth /srv/share
```

`--auth 'user:password@/...'` 只适合本机开发：argv 通常可被同机诊断工具、进程监控
和服务管理器记录。生产环境应使用 `--auth-file` 或 systemd LoadCredential。

默认只监听 `127.0.0.1:5000`，系统支持 IPv6 时也监听 `[::1]:5000`。打开：

```text
http://127.0.0.1:5000/
```

允许上传、删除和搜索的开发示例：

```sh
ram \
  --auth-file ./ram.auth \
  --allow-upload \
  --allow-delete \
  --allow-search \
  /srv/share
```

`--allow-all` 会同时打开上传、删除、搜索、符号链接、归档和哈希能力，生产环境应
改为逐项授权。

查看完整参数或生成 shell 补全：

```sh
ram --help
ram --completions bash
```

## 4. 配置模型

### 4.1 来源与优先级

普通配置按以下优先级合并：

1. 命令行参数。
2. `RAM_*` 环境变量。
3. 通过 `--config` 或 `RAM_CONFIG` 显式选择的 YAML（若未选择，则不存在这一来源）。
4. 内置默认值。

以上顺序适用于同一个配置项。`allow-all` 与具体 `allow-*` 是总项/具体项关系，按下述
专门顺序合并；这意味着环境中的具体例外会优先于 CLI 的总开关。

`--config <path>` 或 `RAM_CONFIG=<path>` 显式选择配置文件；两者同时存在时命令行选择器
优先。若两者均未设置，Ram 不加载 YAML，也不会扫描进程工作目录或可执行文件所在目录。
因此复制、移动或升级二进制不会因为同目录出现 `config.yaml` 而改变服务配置。显式路径
不存在或不安全会直接启动失败。配置文件使用 kebab-case，未知字段会导致启动失败，避免
拼错安全开关后静默运行。生产服务和打包脚本应使用显式绝对路径。

配置文件里的路径字段以该 YAML 所在目录为基准；`--config`、`RAM_CONFIG` 以及其它
命令行/环境路径以进程当前目录为基准。推荐生产环境使用绝对路径。

所有布尔开关都是完整三态：未提供、`true`、`false`。CLI 同时接受兼容写法
`--allow-upload` 和显式写法 `--allow-upload=false`；环境变量可写
`RAM_ALLOW_UPLOAD=false`。能力合并的精确顺序是：默认值 → YAML `allow-all` → YAML
具体 `allow-*` → CLI/环境 `allow-all` → CLI/环境具体 `allow-*`。因此更具体的 false
总能关闭同层或更低层总开关打开的能力，YAML true 也能被 CLI false 关闭。

每个 CLI 选项都有同名环境变量，规则是将长选项转成大写下划线形式，例如：

- `--serve-path` → `RAM_SERVE_PATH`
- `--config` → `RAM_CONFIG`
- `--auth-file` → `RAM_AUTH_FILE`
- `--allow-upload` → `RAM_ALLOW_UPLOAD`
- `--max-upload-size` → `RAM_MAX_UPLOAD_SIZE`
- `--token-secret-file` → `RAM_TOKEN_SECRET_FILE`
- `--cors-origins` → `RAM_CORS_ORIGINS`（逗号分隔；methods/headers 同理）

`--completions` 是即时命令，不是持久配置项。

部署或升级前可执行只读静态检查：

```sh
ram --check-config --config /etc/ram/config.yaml
# 等价的显式环境来源：
RAM_CONFIG=/etc/ram/config.yaml ram --check-config
```

成功时退出码为 0，并只向 stdout 输出：

```text
Configuration OK
```

该模式使用与真实启动相同的 YAML/CLI/环境合并和静态验证，读取并检查配置、认证、token 和
TLS 内容，检查 quota hook 的固定身份、元数据与可执行位，验证路径隔离、资源上限、危险组合、
TLS 证书与私钥匹配，并有界检查 custom-assets 树。它不会绑定 TCP/Unix socket，不会创建或轮转日志，
不会创建 token 撤销状态或锁，不会清理上传候选、执行 quota hook，也不会启动 runtime/server。
因此它是环境相关的启动前检查，而不是纯 YAML lint；它不会判断 quota hook 的 shebang/exec
能否成功或业务逻辑是否正确，也不能无副作用地证明所有输出父目录届时具备写入、创建或重命名
能力、端口届时可用、磁盘容量充足或反向代理正确。失败会以非零状态和 stderr 诊断
结束，自动化应判断退出码，不要匹配可能演进的错误文字。

### 4.2 完整配置示例

复制仓库的 `config.example.yaml` 到 `/etc/ram/config.yaml`，替换密码并通过
`ram --check-config --config /etc/ram/config.yaml` 后，再用同一个显式路径启动。仅复制配置
文件而不传入 `--config` 或 `RAM_CONFIG` 不会加载它。下面展示常用字段的完整组合：

```yaml
serve-path: /srv/ram/share
bind:
  - 127.0.0.1
port: 5000
path-prefix: files

unix-socket-mode: '0600'
# unix-socket-uid: 1000
# unix-socket-gid: 1000
allow-abstract-unix-socket: false

# 仅在直接 TCP peer 确为受控代理时同时启用：
# trusted-proxy:
#   - 127.0.0.1/32
# trusted-proxy-header: x-forwarded-for

hidden:
  - .git
  - '*.tmp'
  - '*.lock'

# 推荐：每行一条规则的独立凭据文件（与 auth 二选一）
auth-file: /run/credentials/ram.service/ram-auth

allow-insecure-http: false
allow-h2c: false
allow-filesystem-root: false
allow-active-content-risk: false

token-ttl: 15m
# token-secret-file: /etc/ram/token.secret
# token-audience: files-production
# token-revocation-file: /var/lib/ram/token-revocations.json

max-connections: 512
max-concurrent-requests: 64
max-concurrent-requests-per-source: 16
max-concurrent-requests-per-user: 16
max-request-queue: 64
request-queue-timeout: 5s
header-read-timeout: 30s
connection-idle-timeout: 60s
connection-max-lifetime: 1h
response-write-idle-timeout: 30s
h2-max-concurrent-streams: 32
max-blocking-threads: 32
max-expensive-tasks: 4
max-walk-entries: 1000000
max-walk-depth: 64
max-search-results: 10000
max-directory-entries: 10000
max-webdav-properties: 64
max-webdav-rendered-properties: 65536
max-webdav-response-size: 8M
max-archive-size: 4G
max-hash-size: 4G
expensive-task-timeout: 5m
copy-timeout: 5m
upload-idle-timeout: 30s
upload-total-timeout: 15m
max-concurrent-uploads: 4
max-concurrent-uploads-per-user: 2
max-concurrent-uploads-per-source: 2
stale-upload-cleanup-age: 24h
stale-upload-cleanup-max-entries: 100000
stale-upload-cleanup-max-depth: 64
stale-upload-cleanup-max-deletions: 1000
stale-upload-cleanup-timeout: 5s
write-lock-timeout: 5s
max-upload-size: 4G
max-copy-size: 4G
upload-file-mode: '0600'
upload-dir-mode: '0700'
storage-space-check: false
storage-reserve: 0
# storage-quota-hook: /usr/local/libexec/ram-storage-quota
storage-quota-hook-timeout: 5s

allow-all: false
allow-upload: false
allow-delete: false
allow-search: false
allow-symlink: false
allow-archive: false
allow-hash: false

enable-cors: false
cors-origins:
  - '*'
cors-methods: [GET, HEAD, OPTIONS, PUT, DELETE, PATCH, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, CHECKAUTH, LOGOUT]
cors-headers: [authorization, content-type, range, x-update-range, x-ram-if-mutation-version, destination, depth, overwrite, if-match, if-none-match, if-modified-since, if-unmodified-since, if-range]
render-index: false
render-try-index: false
render-spa: false

# assets: /opt/ram/assets
log-format: '$time_iso8601 $log_level request_id=$request_id - $remote_addr $remote_user "$request" $status bytes=$body_bytes outcome=$response_outcome request_time=$request_time'
# log-file: /var/log/ram/access.log
compress: low

# 非 loopback TCP 部署时同时启用：
# tls-cert: /etc/ram/tls/fullchain.pem
# tls-key: /etc/ram/tls/privkey.pem
# hsts-max-age: 31536000
```

`config.example.yaml` 是安全模板而不是可直接运行的生产配置：它绑定 loopback、
关闭特权能力，并故意使用会被程序拒绝的 `change-me` 占位密码。

### 4.3 配置项速查

| 类别 | 选项 | 作用 |
| --- | --- | --- |
| 服务根 | `serve-path` | 暴露的目录或单个文件，默认当前目录 |
| 监听 | `bind` / `port` | IP、Unix socket 或 Linux abstract socket；TCP 默认端口 5000 |
| 监听 | `unix-socket-mode` / `unix-socket-uid` / `unix-socket-gid` | pathname Unix socket 的精确权限与可选数值 owner/group |
| 监听 | `allow-abstract-unix-socket` | 危险开关：允许没有文件系统权限边界的 Linux abstract socket |
| URL | `path-prefix` | 将服务挂载到 URL 子路径 |
| 列表 | `hidden` | 按名称 glob 隐藏目录项和搜索结果 |
| 认证 | `auth-file` / `auth` | 互斥的凭据来源；生产优先可信私有文件，`auth` 主要用于开发 |
| 传输 | `allow-insecure-http` | 显式允许非 loopback 明文 HTTP，危险 |
| 传输 | `allow-h2c` | 显式允许明文 prior-knowledge HTTP/2；默认关闭 |
| 代理 | `trusted-proxy` / `trusted-proxy-header` | 成对配置直接代理 CIDR 与唯一接受的来源头；默认完全禁用 |
| 令牌 | `token-secret` / `token-secret-file` | 互斥的 HMAC 密钥来源，至少 32 字节 |
| 令牌 | `token-audience` / `token-ttl` | audience 与 1 秒至 7 天有效期 |
| 令牌 | `token-revocation-file` | 原子持久化已撤销 jti |
| 能力 | `allow-*` / `allow-all` | 设置全局操作上限 |
| 页面 | `render-index` / `render-try-index` / `render-spa` | 选择站点渲染模式 |
| 页面 | `assets` | 用外部现代 UI 覆盖内置资源 |
| CORS | `enable-cors` / `cors-*` | 默认关闭；配置 origin、method、request-header allowlist |
| 日志 | `log-format` / `log-file` | 格式和输出文件 |
| 归档 | `compress` | `none`、`low`、`medium` 或 `high` |
| 资源 | `max-*` / `*-timeout` | 限制连接、扫描、结果、大小和耗时 |
| TLS | `tls-cert` / `tls-key` | 必须同时设置的证书链和私钥 |
| TLS | `hsts-max-age` | 仅直连 TLS 可用的 HSTS 秒数；默认关闭，最大两年，`0` 用于清除旧策略 |

大小接受字节整数或 `K`、`M`、`G`、`T` 二进制后缀；时长接受秒数或
`s`、`m`、`h`、`d`。`max-upload-size: 0` 是唯一明确的无限模式，其它
资源上限必须为非零有效值。

## 5. 监听、TLS 与 URL

### 5.1 TCP 与 Unix socket

绑定 loopback：

```sh
ram -a 'user:password@/' -b 127.0.0.1 -p 5000 /srv/share
```

绑定 Unix socket：

```sh
ram -a 'user:password@/' \
  -b /run/ram/ram.sock \
  --unix-socket-mode 0660 \
  --unix-socket-gid 1000 \
  /srv/share
```

pathname socket 在日志器和 Tokio runtime 启动前、进程仍为单线程时完成 bind。创建期间临时
使用 `umask 0177`，先验证新 inode 确为私有 `0600` socket，再通过已 pin 的 inode 应用
`unix-socket-mode`（默认 `0600`）及可选数值 UID/GID，并逐项复核 mode、owner、group、
类型和 `st_dev/st_ino`。启动时只会在 pin 的父目录下清理由本服务能确认已经拒绝连接的
旧 socket；关停也只删除仍与本进程记录完全相同的 inode，路径被替换时宁可留下替换物，
不会按名字误删。从文件系统根到 socket immediate parent 的完整祖先链都必须由 root 或当前
非 root 服务账号拥有；任一级非 sticky 的 group/world-writable 祖先及启动期间/之后发生的
命名空间替换都会使启动失败。pathname 的每个组件还必须是规范目录而不能是符号链接；Ram
不会只验证链接解析后的目标，因为链接拼写本身也是客户端可达性边界。因而常见的
`/var/run` → `/run` 别名必须写成真实路径 `/run`，包含 `.`/`..` 的路径也应先规范化。YAML
中的相对 socket 路径按配置文件目录解析，CLI/环境变量中的相对路径按启动 cwd 解析，解析后
同样应用上述规则。socket 路径
也不能位于可由 HTTP 修改的 serve tree 或未认证 custom-assets tree 内。服务仍应由专用
非 root 账号运行；以 root 启动会显示高可见警告。在 `/tmp` 这类共享 sticky 父目录中，
socket 不能 chown 给 root/服务 euid 之外的 UID，旧 socket owner 也必须受信，避免该 owner
在“复核 inode—unlink”之间替换名字。旧 socket owner 的信任检查同样适用于私有父目录，
避免 root 服务把其他账号的断连 socket 当作自己的崩溃残留误删。需要把新 socket 交给另一个
UID 时应改用不可由该 UID 写入的私有父目录；此时显式 `unix-socket-uid` 被视为管理员的有意
授权，但异常退出留下的该 UID socket 不会在下次启动时自动清理，须由可信操作方先行移除。

每条 Unix 连接用 Linux `SO_PEERCRED` 得到 `uid/gid/pid`，访问日志保留完整
`unix:uid=...,gid=...,pid=...` 审计上下文。认证、请求和上传的安全来源分桶只按内核
UID 聚合，避免同一用户通过 fork、更换 PID 或获准的主组拆分预算；Unix 请求永远不会从
HTTP 转发头派生身份。

绑定 Linux abstract socket：

```sh
ram -a 'user:password@/' -b @ram --allow-abstract-unix-socket /srv/share
```

abstract namespace 没有 pathname mode/owner/group 边界，因此默认拒绝并需要上述危险开关；
管理员必须另行建立本机访问边界。同一进程可以配置多个监听地址。端口只适用于 IP 地址。

### 5.2 非 loopback 与 TLS

任何非 loopback TCP 地址（包括 `0.0.0.0` 和 `::`）在没有 TLS 时默认拒绝启动：

```sh
ram \
  -a 'user:password@/' \
  -b 0.0.0.0 \
  --tls-cert /etc/ram/tls/fullchain.pem \
  --tls-key /etc/ram/tls/privkey.pem \
  /srv/share
```

证书与私钥必须同时提供。使用 `--no-default-features` 构建的二进制不含 TLS；
如果仍提供 TLS 配置，程序会拒绝启动，不会静默退回明文。

HSTS 默认关闭。仅当 Ram 自己配置 `tls-cert`/`tls-key` 并直接终止 HTTPS 时，才可显式
设置 `hsts-max-age`（例如一年为 `31536000`）；响应只发送
`Strict-Transport-Security: max-age=...`，不会默认扩大到子域或加入 preload。设置为 `0`
可指示浏览器清除旧策略。若 TLS 在反向代理终止，Ram 拒绝启用该选项，HSTS 必须由真正
看到 HTTPS 的代理设置，以免明文后端根据错误的协议假设强制浏览器策略。

`--allow-insecure-http` 只适用于已经位于独立加密隧道内、且管理员明确接受风险的
部署。Basic 凭据在明文链路上可被观察者直接复用。

TLS 监听通过 ALPN 协商 HTTP/2 或 HTTP/1.1。明文 TCP 与 Unix socket 默认严格使用
HTTP/1；只有受信客户端确实需要 prior-knowledge h2c 时才应设置 `--allow-h2c`。
该开关不提供加密，也不改变非 loopback 明文监听必须显式接受的凭据风险。

反向代理应完整转发 `Authorization`、`Destination`、`Depth`、`Overwrite`、
条件请求头和所有 WebDAV 方法；不要缓存认证文件响应。代理终止 TLS 时，后端应
仅监听 loopback 或 Unix socket。

默认情况下 Ram 完全忽略来源转发头，TCP 来源就是内核 accept 得到的 direct peer IP。
只有同时配置 `trusted-proxy` CIDR allowlist 和 `trusted-proxy-header` 时，且当前连接的
direct peer 命中 allowlist，才会接受指定的 `x-forwarded-for` 或 `x-real-ip`。来自不可信
peer 的同名头连解析都不会解析，因而攻击者不能伪造日志，也不能拆分认证、请求或上传的
来源限流桶。两项缺一、重复 CIDR、非 canonical CIDR 或超过 256 个 CIDR 都会阻止启动。

例如代理只从本机连接并覆盖（而不是追加客户端传来的原始值）：

```yaml
trusted-proxy:
  - 127.0.0.1/32
  - '::1/128'
trusted-proxy-header: x-forwarded-for
```

`X-Forwarded-For` 限制为 4096 字节和 32 hop，严格解析每个 IP，再从内核确认的 direct
peer 向右到左剥离受信 hop；遇到的第一个非受信地址成为客户端，左侧攻击者数据不能覆盖。
`X-Real-IP` 必须恰好出现一次并且只包含一个 IP。受信代理缺失头、重复/空 hop、非 ASCII、
非法 IP 或超限时返回固定公开 `400 Invalid forwarding header`，具体原因只写内部日志。
Ram 不接受标准 `Forwarded` 或 PROXY protocol；若上游使用这些协议，必须先在受控代理层
转换并覆盖为所选头。

解析后的唯一 `SourceIdentity` 同时供 `$remote_addr`、认证失败/Digest replay、全局请求前
的 per-source 准入及上传分桶使用；不会出现日志身份与限流身份不同步。Unix socket 始终
从 `SO_PEERCRED` 取得完整 `uid/gid/pid` 供日志展示，但所有安全分桶只按 UID 聚合，且不进入
代理头路径。

### 5.3 路径前缀

```sh
ram -a 'user:password@/' --path-prefix files /srv/share
```

此时 `/files/` 对应服务根。反向代理转发路径必须与该前缀一致。

## 6. 认证与路径权限

### 6.1 ACL 语法

规则格式：

```text
user:password@path[:perm][,path[:perm]...]
```

`ro` 表示只读且可以省略，`rw` 表示读写：

```sh
umask 077
cat >./ram.auth <<'EOF'
admin:strong-admin-password@/:rw
guest:strong-guest-password@/public:ro
editor:strong-editor-password@/docs:rw,/releases:ro
EOF
chmod 0600 ./ram.auth
ram --auth-file ./ram.auth /srv/share
```

`auth-file` 每个非空、非注释行保存一条完整规则。文件最多 1 MiB、4096 行，单行最多
16 KiB；启动时使用 `O_NOFOLLOW` 打开，并在同一 fd 上完成 `fstat` 与有界读取。它必须
是 root/服务用户拥有的单链接普通文件，模式必须是 `0400` 或 `0600`，组和其他用户
不得读取或写入。空白行以及首个非空字符为 `#` 的行会被忽略；真实规则不能带首尾空白，
否则启动会拒绝，而不会静默改变用户名或密码字节。`auth` 与
`auth-file` 在 YAML、环境变量和 CLI 之间也严格互斥，防止误以为覆盖、实际却合并两套
账号；重复用户名同样会导致启动失败。错误和日志不会包含规则中的密码。

匿名规则会被拒绝。未授权的中间目录可能以“仅索引”形式出现，便于用户导航到
被授权的深层路径，但不会泄露该中间目录的其它内容。

权限由两层共同决定：

1. 用户路径 ACL 决定用户在目标路径上是 `ro` 还是 `rw`。
2. `allow-upload`、`allow-delete`、`allow-search` 等全局能力设置整个服务的上限。

即使用户具有 `rw`，未启用 `--allow-upload` 时仍不能上传。

### 6.2 Basic 与 SHA-256 Digest

服务支持：

- Basic。
- RFC 7616 Digest，算法严格为 `SHA-256`、`qop=auth`。

服务不宣告也不接受 Digest MD5，不存在 MD5 兼容开关。Digest nonce 和对应的重放
状态保留五分钟，请求目标会参与验证；已接受的 `(nonce, username, cnonce, nc)` 精确
组合不能再次使用。缓存按 nonce 和用户分桶，进程级总上限为 65,536 条，并分别限制
单用户 16,384 条、单 nonce 8,192 条和单来源 16,384 条；任一预算耗尽都会 fail closed
并记录拒绝原因及利用率，不会驱逐尚未过期的证明后重新放行重放请求。

用户名和 cnonce 分别限制为 256 与 128 字节，因此默认缓存中由远端输入控制的动态键
字节最多为 `65,536 × (256 + 128) = 24 MiB`；nonce、计数、来源、哈希表桶和过期堆均为
固定大小结构，数量同样受 65,536 条总上限约束。过期清理由最小堆逐条完成，不在认证热
路径扫描整张表。实现保留精确元组而未采用“只记最大 nc”、滑动位图或可驱逐 LRU：HTTP/2
请求可能乱序到达，只记最大值会误拒绝有效请求，而提前驱逐会让已接受的证明重新可重放。

Digest SHA-256 目前必须从账号的明文密码计算 A1；Ram 不接受预计算 HA1，也不会把 PHC
密码哈希伪装成 Digest 可用凭据。因此需要 Digest 的账号会在可信私有 auth-file 中保存
可复用明文，泄露影响大于单向密码验证器。若不接受这一存储风险，应只使用 TLS 上的
Basic + PHC，或把认证交给受信上游；不要仅因 Digest 不在网络上传送明文就误认为服务端
也不需要明文等价秘密。

```sh
curl --user 'admin:password' https://files.example/path/file
curl --digest --user 'admin:password' https://files.example/path/file
```

Basic 账号优先使用 Argon2id PHC。下面是受支持的默认 profile 示例（密码为
`password`，仅用于说明格式，生产必须使用独立随机 salt）：

```text
$argon2id$v=19$m=19456,t=2,p=1$YmFkIHNhbHQh$DqHGwv6NQV0VcaJi7jeF1E8IpfMXmXcpq4r2kKyqpXk
```

只接受 Argon2id v19，启动策略为 `m=19456..65536` KiB、`t=2..5`、`p=1..4`，
salt 解码后 8..32 字节、输出 16..64 字节，并且参数只能包含 `m/t/p`。四个并发 hash
worker 的 Argon2 工作内存因此最多为 256 MiB。Argon2i、Argon2d、未知 PHC、缺字段和
越界参数都会在启动时被拒绝，诊断不包含完整 hash。

为了让已知和未知用户名执行相同成本，本版本要求一个实例中的全部 Argon2id 账号使用
相同的 `m/t/p/输出长度`，且不能与明文或 SHA-512-crypt 账号混用。迁移必须一次性替换
全部账号，或先在独立 Ram 实例完成切换；当前不支持逐账号滚动混用。salt 可以且应当
每账号不同。Argon2id 只用于 Basic，不宣告 Digest，也不会把 PHC 字符串当作 Digest
密码。

兼容旧部署时，密码也可以存为 SHA-512 crypt：

```sh
openssl passwd -6
ram -a 'admin:$6$salt$hash@/:rw' /srv/share
```

SHA-512 crypt 凭据只能用于 Basic，不能用于 Digest；Basic 必须配合 TLS 或可信的
本机代理。包含 `$` 的规则在 shell 中必须使用单引号。Ram 把 SHA-512 crypt 视为兼容
验证器：默认 5,000 rounds 可用，显式 `rounds=` 的启动硬上限为 1,000,000；更大的值
会在启动时拒绝，避免误配置让单次请求长期独占 CPU。应在目标硬件上评估成本，并避免
把 rounds 直接推到硬上限。同一实例的所有 SHA-512 crypt 凭据必须使用完全相同的 rounds。

Basic/Digest 认证失败使用原子双层限流：`SourceIdentity + claimed username` 桶完全按声明
输入派生，不查询账号是否存在，成功只清该用户名；跨用户名来源预算累加所有失败，任何
成功登录都不能清零。这样既避免 known/unknown 分区枚举，也阻止低权账号成功清洗管理员
猜测或轮换假用户名绕过退避。deadline 到期会放行恰好一个恢复尝试，正确凭据可恢复，只有
实际失败才安排下一段指数退避；连续失败返回 `429 Too Many Requests` 和 `Retry-After`。
昂贵哈希在执行前原子预留两层失败预算；全局最多
4 个执行、8 个执行加排队中的请求，同一来源最多 2 个、同一 claimed username 最多 3 个。
username 上限严格大于 source 上限，所以一个来源占满自己的两个 Alice 槽后，另一来源仍有
一个 Alice 槽；同时 username 上限低于四个 worker，始终为其它账号保留至少一个执行容量。
仅活动的 admission 主体键始终从客户端声明用户名一致派生，不查询账号存在性。纯明文部署
的未知 Basic/Digest 使用启动时 CSPRNG 生成、不可预测且永不接受的 dummy secret 走同类
计算；含哈希的部署中，known hash、known plaintext 与 unknown Basic 都恰好执行一次 HMAC
常数时间比较和一次真实配置 profile 哈希。Argon2id 的 m/t/p/output 以及 SHA-512-crypt
的 rounds 都必须实例内统一，混合成本配置在启动时拒绝，而不是用不等价的补算近似隐藏。
上述值是本版本与 Tokio blocking-pool 安全模型共同验证的固定安全包络，暂不提供放大配置。
密码哈希或持久 token 撤销后端启用时，`max-blocking-threads` 必须至少为 5：四个昂贵认证
worker 之外始终为普通文件系统任务保留至少一个 blocking worker。只配置持久 token secret
时自动派生的默认撤销后端也计入该下限；启动与 `--check-config` 使用相同的 effective 拓扑。

来源、用户名或账号失败防洪返回 429；全局 admission 满、等待全局 hash permit 超时、
信号量关闭、状态不可用或 worker 故障返回 `503 Service Unavailable`。这些基础设施拒绝
只撤销预留，不计作错误密码。拒绝日志包含 `admission_outcome`、`mapped_status`、
`queued`、`active`、`in_flight`、键数量和逐原因计数；完成日志包含 `queue_wait_ms` 与
`hash_time_ms`，可直接用于队列和耗时监控。健康端点、无凭据 OPTIONS、Bearer 的有界
格式/MAC/claims 预检及内存撤销查询不取得 permit；持久撤销查询/写入与密码哈希共享同一
全局/来源预算，但主体 admission 使用互不碰撞的协议域。

### 6.3 短期 Bearer 下载令牌

已通过 Basic/Digest 完整认证的用户可以为当前规范路径签发令牌：

```sh
TOKEN=$(curl --fail --user 'admin:password' \
  'https://files.example/path/file?tokengen')

curl --fail \
  -H "Authorization: Bearer $TOKEN" \
  -o file \
  https://files.example/path/file
```

`GET` 或 `POST /path?tokengen` 可签发；Bearer 令牌只能通过
`Authorization: Bearer ...` 头用于 `GET`/`HEAD`。URL 查询参数令牌不受支持，
不存在 `?token=` 兼容模式，避免凭据进入浏览器历史、Referer、代理和监控日志。

令牌绑定版本、用户、精确路径、audience、签发时间、过期时间和唯一 `jti`，
默认有效期 15 分钟。Bearer 令牌不能签发新令牌或撤销令牌。

使用原账户凭据撤销指定令牌：

```sh
curl --fail -X POST \
  --user 'admin:password' \
  -H "X-Ram-Revoke-Token: $TOKEN" \
  https://files.example/path/file
```

成功返回 `204`。令牌签发、Bearer 下载和撤销响应均使用
`Cache-Control: no-store`。

默认 HMAC 密钥和 audience 每次启动随机生成，因此重启会使现有令牌失效。需要跨
重启稳定时，必须同时持久化密钥和 audience：

```yaml
token-secret-file: /etc/ram/token.secret
token-audience: files-production
token-ttl: 15m
token-revocation-file: /var/lib/ram/token-revocations.json
```

密钥文件至少 32 字节，权限必须为 `0400` 或 `0600`；所有者必须是 root 或当前服务用户，
最终路径不得为符号链接或多硬链接，组和其他用户不得访问。已有撤销状态文件执行普通
文件、所有者、单链接和不可被组/其他用户写入的完整性检查，新文件创建为 `0600`。配置
持久密钥但省略
撤销文件时，程序会在密钥旁选择默认撤销状态文件。

`--token-secret <value>` 只用于开发诊断，程序会输出强警告；生产应使用
`--token-secret-file`，最好由 systemd LoadCredential 提供。不要把 token secret 放入
argv、环境变量、日志或可被服务树读取的路径。

多个本机 Ram 进程可以共享同一个撤销状态。实现固定状态文件的父目录描述符，并使用稳定
的相邻 `<revocation-file>.lock`：校验事务取得共享 `flock`，撤销事务取得排他 `flock`。
每次事务都会确认锁路径仍指向所持有的同一个可信 inode，防止原子替换锁文件把实例分裂到
两把锁。撤销在锁内重新读取并合并最新一代，经过临时文件 `sync_all`、原子 rename 和父
目录 fsync 后才更新内存缓存，因此并发实例不会丢失更新。Bearer 校验会在 blocking worker
中检查状态文件的 dev/inode/mtime/ctime/size；发现另一实例发布的新 inode 后，在共享锁内
重载。它不依赖轮询线程，另一个实例的撤销最迟在下一次 Bearer 请求时生效。

撤销文件格式与 token claims 独立版本化：可读取旧 V1 文档，下一次写入升级为带单调
`generation` 的 V2；未知未来版本、generation 回退、坏 JSON、部分文件、状态/锁缺失、
不可信 owner/mode/link、超过 8 MiB 或 65,536 条都会拒绝。运行中任何 lock/read/write/
file-sync/rename/parent-fsync 错误都会让该实例永久进入 fail-closed degraded 状态：旧缓存不再
放行，Bearer 与撤销操作返回 `503`，需要修复文件系统后干净重启。即使错误发生在 rename
之后、调用方无法判断新状态是否已发布，也采用同一严格策略；不会假装回滚已经可能对其它
实例可见的撤销。

共享状态应放在支持本机 `flock`、原子 rename 和目录 fsync 的同一本地文件系统中；不要把
它放在锁/缓存一致性语义不明确的网络文件系统。所有实例还必须共享完全相同的 token secret
和 audience。备份/恢复令牌身份时必须把密钥、audience 和撤销状态视作同一一致性单元，
并在停止撤销写事务或取得同等外部排他锁后制作快照。

## 7. HTTP 接口

除健康检查和内置静态资源外，业务资源都需要认证。以下示例省略重复的
`--user`；在非本机环境中必须使用 HTTPS。

### 7.1 常用操作

读取、Range 续传和条件请求：

```sh
curl --user 'user:password' -O https://files.example/path/file
curl --user 'user:password' -C - -O https://files.example/path/file
curl --user 'user:password' \
  -H 'Range: bytes=0-1023' \
  https://files.example/path/file
```

服务支持 `ETag`、`Last-Modified`、`If-Match`、`If-None-Match`、
`If-Modified-Since`、`If-Unmodified-Since` 和 `If-Range`。合法 Range
返回 `206`，无法满足的 Range 返回 `416`。

条件请求采用固定的失败合同。认证/ACL 通过后，GET、HEAD、PUT、PATCH、DELETE、COPY、
MOVE、MKCOL 和 PROPPATCH 会在返回任何目标存在性状态、读取 PUT/PATCH 正文或执行任何副作用前，
一次性严格解析全部上述条件字段。非法/未闭合实体标签、非 UTF-8 标签、wildcard 与标签混用、
重复 wildcard、非法日期，以及重复的日期或 `If-Range` 单值字段一律返回 `400`；即使目标缺失也
不会漂移成 `404`。合法但不满足的 unsafe 条件统一返回 `412` 且不改变 inode、内容、ETag、
目录或临时候选；GET/HEAD 的缓存重验证命中返回 `304`，其余成功路径保持各方法的 `2xx`。
同时提供 ETag 与日期条件是合法组合而不是语法冲突：`If-Match` 优先于
`If-Unmodified-Since`，`If-None-Match` 优先于 `If-Modified-Since`；同时提供相互矛盾的
`If-Match`/`If-None-Match` 则按该顺序求值并稳定失败。

ETag 强度是显式合同：不超过 4 MiB（也是浏览器编辑器上限）的文件从已打开文件描述符
计算 SHA-256，返回 strong ETag，可用于 `If-Match` 和 `If-Range`；更大的文件返回
`W/"meta:..."` weak ETag，只用于 `If-None-Match` 缓存重验证。weak ETag 永远不能满足
`If-Match`，也不会让 `If-Range` 返回 `206`；文件系统时间只能编码到秒级 HTTP 日期，
因此日期形式的 `If-Range` 同样安全退回完整 `200`。这避免把 inode、长度和时间戳的组合
错误宣称为字节级 strong validator，同时避免为了大文件 HEAD/Range 再扫描整份内容。

strong ETag 的受支持模型是本地文件系统上由 Ram/协作者使用原子替换写入：同一个已打开
inode 在计算验证器和发送表示期间保持不变。NFS/FUSE 的属性一致性，以及绕过 Ram 对同一
inode 做原地修改的外部进程，不具备这项保证；此类部署应在服务外协调写入或使用只读快照。

普通认证下载使用 `Cache-Control: private, no-cache`，允许当前用户的浏览器保存但每次必须
重新验证；目录 HTML/JSON/simple、文件 JSON、编辑器、哈希、WebDAV XML 和令牌等敏感
动态/API 响应使用 `private, no-store`。因此共享缓存不能保存认证内容，登出或 ACL 更新后动态页面也不能从磁盘
缓存恢复。该策略不发送 `Vary: Authorization`：`private`/`no-store` 已排除共享缓存，而
`no-cache` 强制带当前凭据重新验证；`Vary` 只会无益地分裂浏览器私有缓存。

上传和断点追加：

```sh
curl --user 'user:password' \
  -T local.bin \
  https://files.example/upload/local.bin

offset=$(curl --user 'user:password' -I -s \
  https://files.example/big.bin |
  tr -d '\r' |
  sed -n 's/content-length: //p')

dd if=big.bin bs=1 skip="$offset" status=none |
  curl --user 'user:password' \
    -X PATCH \
    -H 'X-Update-Range: append' \
    --data-binary @- \
    https://files.example/big.bin
```

PUT/PATCH 先在写事务锁外把网络正文接收到私有临时文件；缺失的目标祖先不会在暂存阶段
提前创建。提交前会在有界事务锁内重新打开目标、重新鉴权并重新检查条件头，再原子发布，
避免慢请求体阻塞全部写入，也避免暂存期间的目标替换绕过 `If-Match`。上传受声明长度、
实际读取字节数、空闲超时、总时限、并发暂存数和最大上传大小共同约束。

`max-upload-size` 的声明长度快速拒绝、逐块流读取和最终 blocking 提交共用同一个 checked
计算：PUT 的最终大小是正文长度；PATCH 的最终大小是
`max(current_size, offset + incoming_len)`。边界值本身允许，边界加一返回 `413`；任何
`u64` 加法溢出也返回 `413`，即使显式配置无限模式也不会通过回绕绕过限制。

PUT/PATCH 暂存同时经过全局、认证用户和来源地址三层 RAII 准入；每用户/每来源的实际
上限是对应配置值与全局 `max-concurrent-uploads` 的较小值。全局槽位耗尽返回 `503`，
单用户或单来源槽位耗尽返回 `429`，并带 `Retry-After: 1`。“来源”与请求/认证/日志使用
同一个已验证 `SourceIdentity`：普通 TCP 是 direct peer IP；只有 allowlist 内的 direct
代理可以按所选严格转发头得到客户端 IP；Unix socket 日志保留内核 `SO_PEERCRED` 的完整
`uid/gid/pid`，安全分桶则按 UID 聚合。客户端断开、读取失败、超时、提交成功或失败都会由
所有权析构释放三层许可。

COPY 同样使用目标目录中的私有临时文件并原子提交，且按实际复制字节数执行独立上限；
源文件在检查后增长也不能绕过预算。全新 PUT 使用 `upload-file-mode`（默认 `0600`），
MKCOL 和 PUT 自动建立的祖先使用 `upload-dir-mode`（默认 `0700`）；两者均在已打开 fd 上
固定最终权限，因此结果不受进程偶然 umask 影响。目录模式必须包含 owner 的 `0700`：
新目录由服务 uid 拥有，而 POSIX 权限匹配 owner 后不会退回采用 group 位；缺少 owner 的
read/write/search 任一位都会让 Ram 无法列出、更新或遍历自己创建的目录。即使继承了
`umask 0777`，Ram 也先以 `O_PATH` 固定刚创建的目录 inode，再经 `/proc/self/fd/N` 对该
精确 inode 执行 `chmod`，复核身份后才以只读目录 fd 重新打开并同步。覆盖 PUT/PATCH 只保留旧目标的普通
`0777` 位，COPY 只保留源文件的普通 `0777` 位；setuid、setgid、sticky 等特殊位始终剥离。

原子替换会创建新 inode：旧目标的 owner、POSIX ACL、普通/安全 xattr、SELinux context、
capability、时间戳和 hardlink 关系都不复制，原 hardlink 别名继续指向旧 inode。新 inode
的 owner/group 由内核创建策略决定（通常为服务 uid，group 为进程 egid 或 setgid 父目录的
gid），不会从旧目标复制；父目录 default ACL 和内核 LSM 创建标签仍可能按系统策略继承，
随后 `fchmod` 固定普通 mode/ACL mask。Ram 不复制 `security.*` 或 capability xattr。
以 euid 0 启动会输出高可见警告；生产部署应使用没有额外 capability 的专用非 root 用户。
私有 candidate 在 rename 前始终保持 `0600`，rename 后才通过所持 fd 设置最终 mode；若进程
恰在这个窄窗口崩溃，已可见文件可能暂时保持更严格的 `0600`，绝不会比策略更宽，且 Ram
尚未向该请求返回成功。

上述 inode/mode 合同在 ext4 与 XFS 上相同：不复制旧 inode 的 ACL/xattr，父目录 default
ACL 与 LSM 创建标签仍由各自内核/挂载策略产生，随后固定普通 mode（以及相应 ACL mask）。
`tests/metadata.rs` 通过 Linux 原始 `system.posix_acl_*` xattr 编解码测试 default/access
ACL，不依赖 `setfacl`/`getfacl` 命令；同一组 HTTP PUT 验收还检查 owner、gid、mtime、
hardlink、新 inode、特殊位、普通 user xattr 丢弃和最终 ACL mask。CI 会建立隔离的 ext4
与 XFS loop 挂载并在两者上运行完全相同的测试。部署方也可在自己的挂载上复跑：

```sh
TMPDIR=/mnt/ram-test-ext4 RAM_METADATA_EXPECT_FS=ext2/ext3 \
  cargo test --all-features --test metadata --locked -- --nocapture
TMPDIR=/mnt/ram-test-xfs RAM_METADATA_EXPECT_FS=xfs \
  cargo test --all-features --test metadata --locked -- --nocapture
```

两个文件系统上的普通 mode 必须与配置完全相同、替换目标链接数为 1，旧目标 ACL/xattr
不得出现在新 inode；仅父 default ACL/LSM 创建策略允许产生系统定义的差异。

创建、删除、复制和移动：

```sh
curl --user 'user:password' -X MKCOL \
  https://files.example/path/new-dir

curl --user 'user:password' -X DELETE \
  https://files.example/path/file

curl --user 'user:password' -X COPY \
  -H 'Destination: https://files.example/path/copied' \
  https://files.example/path/source

curl --user 'user:password' -X MOVE \
  -H 'Destination: https://files.example/path/moved' \
  https://files.example/path/source
```

`MOVE` 需要源路径删除能力和目标路径上传能力；`COPY` 需要目标上传能力，覆盖现有
目标还需要相应删除授权。

目录列表、搜索、归档和哈希：

```sh
curl --user 'user:password' 'https://files.example/?simple'
curl --user 'user:password' 'https://files.example/?json'
curl --user 'user:password' 'https://files.example/?q=Cargo.toml'
curl --user 'user:password' -o dir.zip \
  'https://files.example/path/dir?zip'
curl --user 'user:password' \
  'https://files.example/path/file?hash'
```

`?hash` 返回 64 个十六进制字符的 SHA-256。搜索、归档和哈希分别需要对应的
`allow-*` 能力，并受独立资源预算约束。ZIP 中所有条目都位于固定且便携的
`archive/` 顶层目录内，并始终使用 `/` 分隔；普通 UTF-8 名称保持可读，反斜杠、冒号、
非 UTF-8 字节和 Windows 设备名等不便携名称会以无歧义的 `%HH` 形式编码。最终条目名
还会按 POSIX/Windows 共同安全规则独立验证，单个特殊文件名不会中断已经开始的流式
归档。每个文件只从 walker 已打开的 fd 读取，并以“剩余未压缩预算 + 1 个增长探测字节”
作为输入上界；ZIP64 判定还纳入 Deflate 对不可压缩输入的保守膨胀上界。输入或压缩输出
任一可能超过 ZIP32 时都会在写条目头前启用 ZIP64，因此默认 4 GiB 以及略低于它的自定义
预算都不会在 HTTP 200 已发出后才因 header 容量不足而失败。
服务路径为 `/` 时，下载文件名稳定回退为 `archive.zip`。

#### 非 UTF-8 Linux 文件名策略

Linux 文件名是字节串，而 HTTP URL、JSON、HTML 和 DAV XML 都要求可表示的 Unicode。
本项目只把 ZIP 作为这类名称的无损导出通道；其它接口**显式不支持**非 UTF-8 名称：

- HTML/JSON/simple 目录列表略过无法转成 UTF-8 的直接子项。
- 搜索略过非 UTF-8 文件，并且不会进入名称非 UTF-8 的目录子树。
- 直链路径在百分号解码后必须是合法 UTF-8；原始非 UTF-8 名称无法构造直链，请求返回
  `400`。
- `Depth: 1` DAV 列举复用目录列表，因此同样不会返回这些成员；XML 中不会放入有损替代名。
- ZIP 在固定 `archive/` 根内按原始字节生成无歧义 `%HH` 条目组件；这里的 `%HH` 是 ZIP
  导出表示，不是可复制回 HTTP 直链的 URL 编码。原文件名中的字面 `%` 会编码为 `%25`，
  因而 ZIP 中的 `raw-%FF` 与原名为 `%FF` 的 `archive/%25FF` 不会混淆。
- 单文件模式要求服务文件的 basename 是非空 UTF-8；不满足时配置检查和启动都会拒绝。
  如需导出该文件，应服务其父目录并使用 ZIP。

当 HTML/JSON/simple 列表、搜索或 `Depth: 1` DAV 省略当前用户可见的非 UTF-8 条目时，
响应带 `X-Ram-List-Omitted: non-utf8`。JSON/内嵌页面数据同时返回
`omitted_non_utf8: true`，管理 UI 会显示提示；启用归档时提示使用 ZIP 无损导出。
该信号只针对已经通过 ACL 可见性筛选的名字：IndexOnly 用户不会因未获授权的原始字节名
得到命名空间探测信号；显式授权的 UTF-8 符号链接若解析到非 UTF-8 真实路径，则会被省略并
返回信号。搜索和 ZIP 在开始遍历每个 IndexOnly 分支前，还会用已打开 descriptor 得到的
真实路径重新执行 ACL：授权一个 UTF-8 链接名不会授权它指向的其它 UTF-8/原始字节对象。
ZIP 只有在非 UTF-8 真实对象位于某个已授权可读祖先下时才会导出它；仅授权链接别名时会
生成完整但不含该别名的归档。所有相关列表响应都使用 `private, no-store`，CORS 启用后该
响应头在 expose 列表中。

`X-Ram-List-Truncated: true` 只表示条目、遍历或结果预算导致的提前停止；它与
`X-Ram-List-Omitted` 相互独立并可同时出现。客户端看到任一响应头都必须把结果视为不完整。
为避免把 HEAD 变成目录树扫描，HEAD 可以省略这些只有实际生成列表后才能确定的派生头。
无效 UTF-8 的百分号解码路径在进入任何读写路由前统一返回 `400`；可表示的符号链接别名也
不会绕过真实对象 ACL/UTF-8 复核。客户端不得从 ZIP `%HH` 名称自行推导 HTTP URL。

### 7.2 健康与就绪

```sh
curl https://files.example/__ram__/health
```

该端点无需认证。服务根仍可打开且类型与启动时一致时返回 `200`；否则返回
`503` 和 unavailable 状态。它不替代磁盘空间、inode、上游代理和凭据有效性监控。

### 7.3 状态码契约

错误正文默认是 UTF-8 纯文本；客户端应以状态码为准，诊断文字不承诺稳定。

| 状态 | 含义 |
| --- | --- |
| `200 OK` | 读取、列表、能力探测或哈希成功 |
| `201 Created` | PUT/MKCOL/COPY/MOVE 新建目标 |
| `204 No Content` | PATCH/DELETE 成功或 COPY/MOVE 替换目标 |
| `206 Partial Content` | 返回可满足的字节范围 |
| `207 Multi-Status` | WebDAV 属性响应 |
| `304 Not Modified` | 缓存验证器命中 |
| `400 Bad Request` | 路径、请求头、Range 或 WebDAV 输入非法 |
| `401 Unauthorized` | 缺少有效凭据，包含 `WWW-Authenticate` |
| `403 Forbidden` | 身份有效但缺少路径/全局权限 |
| `404 Not Found` | 资源不存在，或越界目标被有意隐藏 |
| `405 Method Not Allowed` | 方法不受支持，包含 `Allow` |
| `408 Request Timeout` | 上传正文超过空闲期限或暂存总时限 |
| `409 Conflict` | 父目录缺失或资源形状冲突 |
| `412 Precondition Failed` | 条件请求或覆盖前提失败 |
| `413 Content Too Large` | 上传或哈希大小超过上限 |
| `415 Unsupported Media Type` | MKCOL 携带了本实现不支持的非空请求实体 |
| `416 Range Not Satisfiable` | 没有可返回的字节范围 |
| `422 Unprocessable Content` | WebDAV XML 合法但属性数量或名称预算超限 |
| `429 Too Many Requests` | 认证失败/账号/来源/用户名哈希防洪，请求 per-source/per-account 准入，或单用户/单来源上传暂存上限生效；可能带 `Retry-After` |
| `500 Internal Server Error` | 非预期本地 I/O 或实现错误 |
| `503 Service Unavailable` | 就绪失败，全局请求队列已满/超时/关停、全局密码哈希/昂贵任务/上传暂存饱和，认证状态/worker 不可用，提交锁等待或本地 I/O 超时；可能带 `Retry-After` |
| `507 Insufficient Storage` | 磁盘/配额耗尽、COPY 大小超限或 WebDAV 响应预算超限 |

所有响应都设置 `X-Content-Type-Options: nosniff`、
`Referrer-Policy: no-referrer` 和 `X-Frame-Options: DENY`。认证和令牌相关响应
禁止缓存。

## 8. WebDAV 契约

Ram **不宣告数字 DAV compliance class**。当前实现没有集合 COPY、持久 dead
properties、锁及 class 1 的全部必选语义；发送 `DAV: 1` 会让客户端错误地依赖并不存在的
能力。它提供下表中的有限 DAV/HTTP 子集，`OPTIONS` 与 `405` 的 `Allow` 是唯一能力声明：

| 方法 | 支持情况 | 说明 |
| --- | --- | --- |
| `OPTIONS` | 支持 | `Allow` 按目标类型、全局开关和当前主体 ACL 动态收窄；不返回数字 `DAV` |
| `PROPFIND` | 支持 | 仅 `Depth: 0`、`Depth: 1`；缺失 Depth 按规范等于 infinity 并拒绝 |
| `PROPPATCH` | 只读响应 | 完整解析属性，但逐项拒绝修改 |
| `MKCOL` | 支持 | 父集合必须已存在；任何非空实体返回 `415` 且不创建目标 |
| `COPY` | 仅文件 | 校验 Destination、目标权限和 Overwrite |
| `MOVE` | 文件/目录 | 使用同文件系统 rename 语义 |
| `LOCK` / `UNLOCK` | 不支持 | 返回 `405`，不会伪造锁成功 |

`PROPFIND` 支持空正文、`allprop`、`propname` 和显式 `prop`。达到目录结果上限时
响应会带 `X-Ram-List-Truncated`；因非 UTF-8 Linux 文件名省略已授权成员时带
`X-Ram-List-Omitted: non-utf8`。WebDAV 没有通用分页扩展，客户端看到任一信号都必须把
结果视为不完整。

DAV XML 请求体硬上限为 64 KiB；namespace/local name 分别最多 256/128 字节，唯一
展开名合计最多 16 KiB。`max-webdav-properties`、`max-webdav-rendered-properties` 和
`max-webdav-response-size` 可按主机容量下调，默认分别为 64、65,536 和 8 MiB，且启动
校验不允许突破这些内建硬上限。allprop、propname、显式 prop 和 PROPPATCH 共用同一
渲染及响应预算。属性输入预算超限返回 `422`，无法在响应预算内表达则返回 `507`；
Depth 1 目录扫描会先按“渲染属性预算 ÷ 请求属性数”推导最多保留的条目数，并只多探测
一个用于判定超限的条目，因此内存不会随实际目录项数乘属性数无界增长。

`Depth: infinity`（大小写不敏感）以及缺失的 Depth 返回 `403` 和
`DAV:propfind-finite-depth` XML 错误；其它非法值或重复 Depth 返回 `400`。这一区分避免把
规范默认的无限遍历悄悄改成 Depth 1。需要数字 class 1、dead-property 持久化、集合 COPY
或 LOCK/UNLOCK 的挂载客户端不兼容，应在部署前用目标客户端验证；仓库集成测试使用真实
`curl` 进程对认证后的 Depth 1 PROPFIND 做 smoke。

兼容性基线使用 Debian `litmus 0.13-5+b1` 的真实客户端进程验证，并保留完整结果而不把
有限子集包装成 class 1：`basic` 为 15/16（唯一失败是 `options` 强制要求数字 DAV class；
PUT/GET、UTF-8、MKCOL/DELETE、缺失父集合和带实体 MKCOL 等支持项全部通过），`props`
执行项为 11/14（dead-property set/get 三项按契约失败，后续依赖项跳过），`copymove` 为
8/13（普通文件 COPY/MOVE、overwrite 前提和清理通过；集合 COPY、跨 file/collection
替换等 class 1 语义按契约失败）。file→collection COPY 会稳定返回 `409`，不会把受限
能力泄漏成 `500`。这些结果只证明表中对应的选定子集；不代表完整 litmus 或 class 1
合规。

### 8.1 CORS

CORS 默认关闭，也从不发送 `Access-Control-Allow-Credentials`。启用时，
`cors-origins` 只接受精确 `http(s)://host[:port]` origin，或仅含一个 `*`；不能把 `*` 与
其它 origin 混用。生产环境应优先列出精确 origin。`cors-methods` 会与当前目标类型及
`allow-upload`/`allow-delete` 等全局能力求交；`cors-headers` 是大小写不敏感的请求头
allowlist，不会反射任意 `Access-Control-Request-Headers`。

浏览器预检本身不携带随后请求的身份，因此成功预检只表示“该 origin、方法和头在此资源
形状上可能被接受”，不授予 ACL 权限；实际请求仍完整认证和逐路径授权。非法 origin、方法
或头的预检严格返回 `400`/`403`，成功返回 `204`、`Cache-Control: no-store`，并设置完整
`Vary`。普通响应只有在请求确实带 `Origin` 且命中 allowlist 时才发送 CORS 头。
默认请求头 allowlist 包含列表危险操作使用的 `X-Ram-If-Mutation-Version`，响应 expose
列表包含 `X-Ram-Mutation-Version`；自定义 `cors-headers` 时若跨源管理 UI 需要该机制，
必须显式保留前者。

要求持久锁的 WebDAV 客户端不兼容。需要强并发控制的写入方应使用
`If-Match` 等条件请求，或在服务外协调。反向代理必须保留 `Destination`、
`Depth`、`Overwrite`、Host 和认证头。

## 9. Web UI 与站点渲染

### 9.1 默认管理界面

内置 UI 编译进二进制，提供目录浏览、排序、搜索、上传队列、拖放文件夹、下载、
删除、创建目录、预览和文本编辑。它只面向最新浏览器并要求 JavaScript。

上传队列最多并发发送 2 个请求，页面最多保留 1,000 个可重试任务；新批次会先回收已完成
的展示行。文件夹选择和拖放遍历同样限制为 1,000 个条目与 32 层目录，超过边界会停止并
明确提示；文件与文件夹分别提供键盘可达的选择按钮。页面离开前会在仍有上传时提示。
编辑器的二次 GET 按实际接收字节再次执行 4 MiB 上限，只允许写回有效 UTF-8 文本并保留
已有 UTF-8 BOM。GBK、UTF-16 等文件仍可下载，但不会被浏览器编辑器静默转换。

Bearer 小文件下载的 JavaScript 缓冲严格限制为 16 MiB 且全页最多一个；已知较大文件、
大小未知的 ZIP，以及竞态增长后越界的文件回退到浏览器原生流式下载，不构造无界 Blob。

当列表/搜索达到上限时，响应带 `X-Ram-List-Truncated`；省略非 UTF-8 Linux 名称时带
`X-Ram-List-Omitted: non-utf8`，UI 会分别或合并提示结果不完整。
前端按钮是否显示只是交互反馈，服务端会重新执行全部权限检查。

完整且未与进程内变更重叠的目录列表会在 JSON/内嵌数据中携带 `mutation_version`，并在
响应头暴露 `X-Ram-Mutation-Version`。管理 UI 把该值作为严格单值
`X-Ram-If-Mutation-Version` 发送给列表来源的 `DELETE`/`MOVE`；服务端在取得全部相关
变更锁后原子比较启动 UUID 与单调 revision，过期则返回 `412` 且不产生副作用。所有经
Ram 执行的 PUT/PATCH/DELETE/MKCOL/COPY/MOVE 都会保守推进 revision，实际阻塞 worker
存活期间不签发列表版本。该机制**仅为进程内旧列表保护**：只有 Ram 是服务根的唯一写入者
时才成立；另一个进程、shell、同步程序或第二个 Ram 实例直接修改文件系统不会推进本进程
纪元。存在外部写入者时，必须使用文件级 `If-Match`、外部协调/锁或确保操作前刷新，不能把
`mutation_version` 当成通用文件系统事务版本。

### 9.2 渲染模式

`--render-index`：

```sh
ram -a 'user:password@/' --render-index /srv/site
```

目录请求返回同目录 `index.html`；不存在时返回 404。

`--render-try-index`：

```sh
ram -a 'user:password@/' --render-try-index /srv/site
```

优先返回 `index.html`，不存在时回退目录 UI。

`--render-spa`：

```sh
ram -a 'user:password@/' --render-spa /srv/app
```

找不到无扩展名路径时返回服务根 `index.html`，适合现代 SPA 路由。

HTML、XHTML、SVG 和 XML 等浏览器主动内容默认按附件处理，并添加 sandbox CSP，
避免用户上传的脚本继承文件服务 origin。渲染模式只会内联它选中的可信
`index.html`；直接访问其他主动内容仍然下载。`allow-upload` 与任一 `render-*`
组合默认拒绝启动，因为写入用户可能替换站点入口并继承高权限用户的同源凭据。
只有内容作者全部受信且已接受此风险时，才能显式使用
`--allow-active-content-risk`。

文件管理 UI 本身使用严格 CSP：脚本、样式、图片和 API 请求只能来自当前 origin，沙箱预览
只能使用本地 blob URL，禁止插件、`base` 重写、第三方 framing、内联脚本和 `eval`。
非文本预览由已认证的管理页先以流式方式读取并同时执行 16 MiB 实际字节上限，再生成
blob URL；iframe 使用空 `sandbox`，不授予脚本、同源、表单、弹窗或导航能力。超过上限、
响应失败或读取失败时不会内联，用户仍可选择下载。这道浏览器边界不能把同源
主动内容变成安全内容：Basic/Digest 凭据和同源 Bearer 操作仍可能被同一 origin 中的
恶意脚本继承。因此，不可信写用户与需要高权限浏览器会话的管理 UI 应部署在不同 origin；
显式启用 `--allow-active-content-risk` 只表示接受存储型 XSS/同源凭据滥用风险，并不提供
沙箱或权限降级。

### 9.3 自定义现代 UI

```sh
ram -a 'user:password@/' --assets /opt/ram-assets /srv/share
```

资源目录必须包含 `index.html`，可以包含 `404.html`。模板可使用：

- `__INDEX_DATA__`
- `__ASSETS_PREFIX__`

自定义 UI 必须遵守本项目的 evergreen/JavaScript 基线，并在服务升级后重新验证
数据结构兼容性；自定义脚本和样式也必须满足上述管理 UI CSP，不能依赖内联代码或
跨域资源。assets 不能包含服务根；开启上传或删除时，assets 也不能位于
服务树内。启动时会通过固定的目录能力遍历整棵 assets 树：assets 根、树内目录和文件必须
由 root 或当前服务用户拥有且不得允许组/其他用户写入，资源必须是单硬链接普通文件；
每次请求还会在已打开文件描述符上复核这些属性。自定义 `index.html` 上限为 1 MiB，
启动遍历同时受目录深度和条目预算约束。自定义页面不能绕过服务端 ACL。

## 10. 文件系统与安全边界

### 10.1 根目录和路径规范化

服务根 `/` 默认拒绝；只有完成独立服务账号、秘密路径隔离和系统目录审计后，才可
使用 `--allow-filesystem-root` 显式接受风险。配置文件、TLS 证书/私钥、auth-file、
token secret、撤销状态/锁、访问日志和 quota hook 若位于服务树内，进程会在监听端口前
拒绝启动；这些敏感对象同样不得位于无需认证即可读取的自定义 assets 根内。`hidden`
不是访问控制，不能用于隐藏秘密。

`serve-path` 启动时必须存在并会被规范化。若它是单个文件，服务进入单文件模式，
不提供目录搜索或目录写操作。若配置为文件系统根 `/`，程序会输出醒目警告。

Ram 不用规范化路径的字符串前缀充当秘密隔离边界。启动验证会从 `/` 开始逐级打开
目录，稳定双遍历记录规范命名空间中每一级对象的 `(st_dev, st_ino, 类型)`，并保留同一
条 fd 链；目录服务以祖先身份判断包含关系，单文件服务会比较最终对象身份。现存敏感
输入/输出还必须是单硬链接普通文件，因此不能另建一个服务树内的硬链接别名。验证所得
fd 会直接交给 `RootFs`、TLS/auth/token 输入读取器和 quota hook 消费者，不再按完整路径
重新打开；捕获后即使原命名空间被 rename 并放入同名替代对象，也不会把能力重定向到
替代对象。单文件模式同样持续从固定 inode 打开独立读句柄。

尚不存在的日志、撤销状态等输出绑定固定的父目录 fd 和 basename。日志创建、写入与轮转，
以及撤销状态/锁的创建、加锁和原子发布，都只使用相对该父 fd 的 `openat2`/`renameat`/
`unlinkat`；已有稳定输出要求精确 inode，撤销状态允许多实例在同一固定位置原子替换，
锁文件则始终绑定后端持有的精确 inode。后续同名父路径替换不会改变这些操作的落点。
任一敏感输入都不得与可变输出共享 inode；撤销状态/锁、日志本体及 `.1`–`.5`
轮转备份、pathname Unix listener 也必须占用彼此不同的“固定父目录 + basename”
命名空间槽，即使配置时它们尚不存在。

服务根和自定义 assets 根可以自身位于单独挂载点，但能力建立后，Ram 默认给所有
`openat2` 遍历增加 `RESOLVE_NO_XDEV`：根下面后来出现或原本存在的 bind mount、普通
子挂载和挂载别名都不可达，即使 bind mount 指向同一底层文件系统。这样，隔离判断
不需要枚举挂载点中的整棵外部树。当前版本没有允许请求跨子挂载的兼容开关；确实需要
跨挂载发布内容时，应把目标挂载本身作为独立 Ram 服务根，而不是在一个根下开放子挂载。

配置路径若通过符号链接或 bind mount 指向服务根，规范目标的祖先 inode 身份仍会触发
冲突；反过来，服务树内指向根外秘密的请求符号链接受 `RESOLVE_BENEATH` 约束，启用
`allow-symlink` 也不能越界。检测范围以进程所见的 Linux mount namespace 和捕获时刻为准：
另一个 namespace 中的别名不可见，之后由更高权限主体改变挂载拓扑也不在进程可证明的
静态身份内，因此部署必须撤销服务用户的 mount 能力并固定 namespace。NFS/FUSE 还可能
具有不稳定 inode、服务端别名或不可取消的阻塞 I/O，不属于受信本地文件系统基线。若必须
使用，应把 Ram 隔离到专用进程或容器，固定挂载拓扑，并由服务管理器提供最终超时和强制
终止。

请求路径必须：

- 能正确 percent-decode。
- 只包含普通相对路径组件。
- 不包含父目录跳转。
- 位于 `path-prefix` 和服务根边界内。

文件操作通过根目录能力和目录文件描述符约束；授权后仍会针对实际打开的规范目标
复核 ACL，减少路径替换和符号链接竞态。

每个 PUT/PATCH/DELETE/COPY/MOVE 事务会保留 HTTP 条件检查时对象的
`(dev, ino, ctime 秒/纳秒, 类型)`；发布、删除或 rename 前在固定 parent dirfd 下再次比较。
COPY 还在复制前后同时复核源 fd 与源目录项，MOVE 同时复核源和目标。版本变化时，有条件
的源/目标选择返回 `412`，无条件 namespace 冲突返回 `409`。这些复核能检测发生在最终检查
之前的对象替换；Linux 没有“比较版本并 unlink/rename”的单一 syscall，最终 `statat` 到
随后 `unlinkat`/`renameat` 之间仍存在不可消除的外部 writer 竞态，因而不能保证该窗口内
换入的 B 不会被操作。启用任何写能力时，可写 serve tree 必须由唯一一个 Ram 进程独占；
不得同时运行第二个可写 Ram，也不得由其他进程直接修改。外部维护只能在 Ram 停止后进行。

### 10.2 隐藏规则

```sh
ram -a 'user:password@/' --hidden '.git,*.tmp,*.lock' /srv/share
```

glob 只匹配文件/目录名称，不匹配完整路径。隐藏项不会进入列表和搜索，但“隐藏”
不是访问控制；敏感内容仍必须由 ACL 和服务根隔离。

### 10.3 符号链接

默认拒绝跟随符号链接。显式启用：

```sh
ram -a 'user:password@/' --allow-symlink /srv/share
```

启用后仍会通过固定根 fd、`RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS |
RESOLVE_NO_XDEV` 解析目标，并针对真实根内路径重新鉴权；指向根外或子挂载的目标继续
被拒绝。只有链接结构由管理员控制且经过审计时才应开启。

### 10.4 写入和存储风险

启用写入时应同时考虑：

- 磁盘空间和 inode 耗尽。
- 覆盖、删除和并发修改。
- 上传主动内容后对其他用户造成的风险。
- 超大树、归档和哈希造成的 I/O/CPU 压力。

`max-upload-size` 和 `max-copy-size` 只是单请求 HTTP 策略上限，**不是**文件系统、用户或
租户配额。应使用独立挂载点、文件系统 quota 和容量告警，并为原子上传临时文件预留与
目标文件相当的空间。`storage-space-check` 可在 COPY/PATCH 发布前读取目标文件系统的
`statvfs` 可用字节/inode，并用 `storage-reserve` 保留空闲字节；它只是容易发生 TOCTOU
竞争的容量提示，不是空间预留，也不能代替最终写入、flush、rename 所返回的
`ENOSPC`/`EDQUOT`。容量预检查、候选文件正文写入或发布前 rename 发生真实空间/配额耗尽
时返回 `507`，日志用 `reason=statvfs_preflight|enospc|edquot` 区分。正文写完后的候选文件
`flush`/`sync_data` 失败属于无法确认耐久性的内部错误，返回 `500`；rename 已成功后若文件
或父目录同步失败，新表示可能已经可见但耐久性不确定，同样返回 `500`，不会误报成
“未发布”的 `507`。

#### 可直接部署的 XFS project quota 示例

以下示例把整个 `/srv/ram/share` 限制为一个 XFS project，适合单租户服务树。命令需要 root，
示例假设 XFS 挂载点是 `/srv/ram`、服务用户是 `ram`，并选择尚未占用的 project ID `1001`。
先确认文件系统和挂载选项：

```sh
findmnt -no SOURCE,FSTYPE,OPTIONS --target /srv/ram/share
sudo xfs_quota -x -c 'state -p' /srv/ram
```

挂载选项必须含 `prjquota`（`pquota` 是同义旧写法）。若尚未启用，在 `/etc/fstab` 中为该
XFS 挂载加入类似下面的一行；把 UUID 替换为实际 `blkid` 输出：

```fstab
UUID=<xfs-filesystem-uuid> /srv/ram xfs defaults,nodev,nosuid,noexec,prjquota 0 2
```

应在维护窗口停止 Ram，并按本机存储流程卸载后重新挂载或重启；不要假定在线 remount 已经
启用 project quota。重新执行上面的 `findmnt` 和 `state -p`，确认内核会计处于开启状态。
然后确认 ID/名称未在现有文件中占用，并分别向 `/etc/projects`、`/etc/projid` **追加一次**：

```text
# /etc/projects
1001:/srv/ram/share

# /etc/projid
ram-share:1001
```

在 Ram 停止且服务树没有其它写入者时，标记现有树、设置目录继承位并配置软/硬上限：

```sh
sudo xfs_quota -x -c 'project -s ram-share' /srv/ram
sudo xfs_quota -x -c 'project -c ram-share' /srv/ram
sudo xfs_quota -x -c \
  'limit -p bsoft=90g bhard=100g isoft=900000 ihard=1000000 ram-share' \
  /srv/ram
sudo xfs_quota -x -c 'report -p -h' /srv/ram
sudo xfs_quota -x -c 'quota -p -h ram-share' /srv/ram
```

`project -s` 会给现有树设置 project ID，并让目录中的新对象继承该 ID。必须在启动 Ram 前
完成；之后若管理员从树外移入已有文件，也要停服并重新检查/标记。Ram 的
`.ram-upload-*.tmp` 和 `.ram-staging-*.tmp` 候选与最终文件位于同一受限树内，会从父目录
继承 project ID 并在写入时立即计入配额。覆盖期间旧目标和候选可能短暂共存，所以硬上限
必须为原子暂存保留余量，不能把 `bhard` 当作全部可交付净容量。

最终权威来自文件系统操作返回的 `EDQUOT`/`ENOSPC`；Ram 将真实配额/空间耗尽映射为
`507` 并记录对应 reason。`storage-space-check` 只是提前提示。不要把 quota hook 写成
“先运行 `du` 再决定”：`du` 无法原子覆盖并发写、稀疏文件、硬链接、reflink 和暂存文件，
检查与 rename 之间仍可超卖。需要按认证用户计费时，应让 hook/外部服务实现事务型预留，
同时仍保留 XFS project quota 作为内核硬边界。

可选 `storage-quota-hook` 为外部逻辑配额/记账接口。Ram 在 PUT/PATCH 正文完成私有暂存、
COPY 源大小复核之后，但在原子发布之前，以如下独立 argv 调用（不会经过 shell）：

```text
HOOK --user USER --operation PUT|PATCH|COPY --path ROOT_RELATIVE_PATH \
     --current-bytes N --final-bytes N
```

`current-bytes` 是目标当前逻辑大小，`final-bytes` 是本次成功后目标逻辑大小。退出 0 放行；
任何非零/信号退出都按策略拒绝并返回 `507`、记录 `reason=quota_hook`；没有认证用户时
同样 fail closed；启动/等待等内部错误返回 `500`；超过
`storage-quota-hook-timeout` 返回 `504`。超时、请求取消或 shutdown 会向 hook 的整个进程组
发送 kill 并回收直接子进程。hook 不得 daemonize、double-fork、调用 `setsid` 或以其它方式
主动逃离该进程组，否则 Ram 无法保证取消时回收其后代。hook 的环境被清空，
stdin/stdout/stderr 均连接 `/dev/null`，
不能依赖 PATH 或继承的 secret。Ram 从启动期固定的 hook inode 执行；为同时支持 ELF 和
shebang，内部单用途 helper 会把该 fd 作为 `/proc/self/fd/N` 执行，因此 hook 不得依赖
`$0` 所在目录定位相邻文件，应使用配置好的绝对路径。退出码 `125` 保留给 helper 的
dup/exec 基础设施失败，hook 不得用它表达配额拒绝；此类失败返回 `500`，不会误报为 `507`。

hook 是以 Ram 服务 uid 执行的任意代码，不是低权限声明文件。它必须是 root/服务用户拥有、
单链接、非 symlink、可执行且 group/other 不可写的普通文件，放在服务树之外由管理员控制且
不可替换的目录；不要把请求可写脚本或包管理器临时目录用作 hook。外部判定与随后 rename
不是一个原子事务，多实例部署若要求严格配额，必须让 hook/外部服务自己实现事务型预留、
幂等提交/回收与跨实例协调；仅查询数据库余额仍会超卖。

同文件系统 COPY 依次尝试 reflink、`copy_file_range` 和固定缓冲复制。只有明确的
“不支持/跨文件系统”错误才降级；`copy_file_range` 已复制部分数据后不会切换策略，避免重复或错位；
`ENOSPC`、`EDQUOT`、`EIO` 从不被当成“加速不可用”吞掉。每个循环边界都检查取消和实际
复制字节上限，源文件在检查后增长也不能绕过 `max-copy-size`。

递归 DELETE 先只读预扫整棵目标树，复用 `max-walk-entries`、`max-walk-depth`、请求取消和
执行期限；条目/深度超限返回 `422`，且预扫失败时删除数严格为零。预扫成功后才按后序计划
逐项复核 parent/entry 身份、unlink 并立即 fsync parent。进入删除阶段后的 I/O 错误、断连、
shutdown 或 deadline 可能留下已耐久化的部分删除，响应不会宣称整树仍完整；客户端应重新
列举并决定是否重试。MKCOL 成功会同步新目录及父目录，DELETE 同步每个被修改的父目录，
MOVE 同步目标父目录及不同的源父目录。PUT 发布前同步数据，发布后设置最终 mode、`sync_all`
并同步父目录；自动创建祖先若随后失败，会按固定 parent fd 逆序仅删除身份未变且仍为空的目录。

上传候选严格命名为 `.ram-upload-<小写连字符 UUID>.tmp`；缺失目标父目录时使用独立的
`.ram-staging-<小写连字符 UUID>.tmp`。候选在创建后通过文件描述符强制修正为 `0600`，
并从接收正文到提交完成一直持有非阻塞排他 `flock`。启动时及运行期间会从已固定的服务根
目录能力周期复扫超过年龄阈值的精确候选名；周期取年龄阈值与 1 小时的较小值（最低 1 秒）。
只有普通文件、当前服务用户所有、权限恰为 `0600`、链接数为 1 且能取得排他锁时才删除；
symlink、目录、硬链接、活跃上传、名称变体和不安全 owner/权限一律保留。遍历不跟随
symlink，删除前复核目录项 inode，并通过固定父目录 fd 执行 unlink 和 fsync。

异步 drop 的候选清理由容量 64 的专用 reaper 队列处理，绝不在 Tokio worker 上同步
unlink。队列饱和、worker 断开或 stat/unlink/fsync 失败时，reaper 保留未确认候选的
parent fd、文件 fd/flock、上传准入 guard 和祖先责任，并每 250 毫秒重试仍有完整目录能力的
瞬态失败。若连 parent fd 都无法复制，则只能保留文件 fd/flock 和准入责任并永久 fail closed；
进程内不会退回到不安全的路径名 unlink，候选只能由下次启动的能力扫描恢复。首次失败仍会把
本进程永久置为 fail-closed：即使稍后清理成功，也拒绝后续候选创建（HTTP `503`）直到重启。
关停会在有界期限内等待所有 cleanup ticket 释放。这样不会把“名字仍占空间或父目录尚未
持久化”错误呈现成“容量已释放”，也不能继续制造无界残留。

同一进程内，cleanup record 还持有本次自动创建祖先的固定 parent fd 与 inode 身份；候选
unlink 未确认时这份责任不会释放，稍后重试确认候选已消失后才逆序删除身份未变且仍为空的
祖先。进程崩溃后这份内存身份记录无法安全恢复：下次启动只会按严格候选规则删除临时文件，
不会猜测并删除可能已被其他进程采用的空祖先目录，因此极端崩溃场景可能保留空目录。

每次启动/周期清理受条目数、深度、删除数和总期限四个独立预算限制。扫描遇到不安全的保留
名称、I/O/持久化失败或任何预算上限，就不能证明恢复覆盖完整：可写启动会直接失败；运行期
出现则粘性关闭新候选，read-only 服务只记录告警。候选父目录深度也不得超过扫描深度，避免
创建出恢复器永远不可达的名字。失败告警最多逐项记录前 4 个能力根相对路径、失败阶段和完整原因
链，其余只汇总 suppressed 数量；路径和原因均有固定长度上限，不记录服务根绝对路径。
期限是“系统调用之间检查”的协作式期限，不会中断已经卡在
内核里的单次文件系统调用；失常的 NFS/FUSE 调用因此仍可能超过默认 5 秒。PUT、PATCH、
COPY、目录扫描、搜索、归档和哈希也采用相同模型：deadline/请求断开只设置取消原因并允许
HTTP 请求先结束，worker 会在系统调用或数据块边界观察取消；其
`max-expensive-tasks` 许可、mutation/upload guard 和临时文件所有权一直保留到 worker 真实
退出并确认清理。`max-blocking-threads`（默认 32、硬范围 1–256）是整个 Tokio blocking
pool 的运行 worker 上限，限制最坏卡住数量，但不能杀死一个内核 syscall；密码哈希
认证启用时至少为 5。

短文件系统操作还共享一层提交前 `FilesystemBlockingAdmission`，服务根和自定义资源根不会
各自放大上限。许可在 `spawn_blocking` 前取得并移入真实闭包，因此请求取消不能把排队或已进入
内核的工作变成未计数后台任务；等待超过 `request-queue-timeout` 时，响应头尚未发送的请求返回
`503`。文件下载不跨整个响应持有许可：metadata、每次 read 和 seek 分别准入，操作完成立即
释放，慢客户端与 HTTP/2 流量控制等待期间不占文件系统许可。响应体取消后，已经提交的 I/O
仍保留许可直到 worker 真正退出。完整文件、单 Range 和 multipart Range 均使用相同规则。

因此本版本只把受信任、能可靠返回系统调用的本地文件系统作为该线程池模型的支持基线。
对不可信或可能永久挂死的 NFS/FUSE 挂载，本进程没有专用可终止子进程池，不能提供硬请求
deadline 或可靠的进程内恢复保证；应把挂载放入独立 Ram 实例/容器/进程，配置内核挂载
超时和服务管理器 watchdog/强制终止，并把故障域与本地存储实例分开。

shutdown 的 30 秒只用于停止 accept 后等待 HTTP 连接任务优雅排空；到期会 abort 并 await
全部连接任务，然后才 flush 日志。其后 Tokio runtime 最多再等待 blocking pool 5 秒。
这两个值都不是进程硬退出 SLA：内核文件系统调用或日志目标可能永久阻塞，服务管理器仍应
配置独立的 stop deadline 与最终 SIGKILL。文档不承诺仅靠 graceful shutdown 能终止失常
NFS/FUSE syscall。

## 11. 资源限制

默认预算：

| 配置 | 默认值 | 作用 |
| --- | ---: | --- |
| `max-connections` | 512 | 同时连接数 |
| `max-concurrent-requests` | 64 | 全进程正在执行或仍在流式发送的请求数 |
| `max-concurrent-requests-per-source` | 16 | 单个 verified `SourceIdentity` 的执行/流式请求数；实际值不超过全局上限，饱和立即返回 429 |
| `max-concurrent-requests-per-user` | 16 | 单个成功认证账号的执行/流式请求数；实际值不超过全局上限，饱和立即返回 429 |
| `max-request-queue` | 64 | 等待全局请求名额的有界队列；范围 0–4096，`0` 表示全局满时立即 503 |
| `request-queue-timeout` | 5 秒 | 等待请求执行名额的最长时间，超时返回 503 |
| `header-read-timeout` | 30 秒 | HTTP/1 request head 与连接初始协议/H2 preface 的绝对接收期限 |
| `connection-idle-timeout` | 60 秒 | 无成功 transport I/O 的连接期限；活跃 handler 执行期间暂停，写停滞不暂停 |
| `connection-max-lifetime` | 1 小时 | 自 accept 起不因任何活动延长的连接绝对寿命 |
| `response-write-idle-timeout` | 30 秒 | pending socket write 的连接级期限，并独立约束每个响应/H2 stream；任一响应超时会关闭其连接 |
| `h2-max-concurrent-streams` | 32 | 单个 HTTP/2 连接的并发 stream 上限；同时受全局请求上限约束 |
| `max-blocking-threads` | 32 | 全进程 Tokio blocking worker 硬上限；范围 1–256，不能中断已进入内核的 syscall |
| `max-concurrent-uploads` | 4 | 同时接收/保留的 PUT/PATCH 私有暂存文件数；饱和时返回 503 |
| `max-concurrent-uploads-per-user` | 2 | 单个认证用户的暂存数；实际值不超过全局上限，饱和时返回 429 |
| `max-concurrent-uploads-per-source` | 2 | 单个 verified TCP/proxy IP 或 Unix 内核 UID（日志仍保留完整 `uid/gid/pid`）的暂存数；实际值不超过全局上限，饱和时返回 429 |
| `stale-upload-cleanup-age` | 24 小时 | 启动及周期清理候选必须达到的最小年龄（1 秒至 7 天） |
| `stale-upload-cleanup-max-entries` | 100,000 | 每次清理最多检查的条目数；硬上限 1,000,000 |
| `stale-upload-cleanup-max-depth` | 64 | 每次清理递归深度；同时约束候选可创建深度，硬上限 256 |
| `stale-upload-cleanup-max-deletions` | 1,000 | 每次最多删除的安全候选；硬上限 100,000 |
| `stale-upload-cleanup-timeout` | 5 秒 | 系统调用之间检查的协作式总期限；范围 1–60 秒 |
| `write-lock-timeout` | 5 秒 | 等待进程内提交事务锁的最长时间；超时返回 503 |
| `max-expensive-tasks` | 4 | 目录/搜索/归档/哈希及 PUT/PATCH/COPY 本地 worker 的共享并发准入 |
| `max-walk-entries` | 1,000,000 | 单次递归扫描条目数 |
| `max-walk-depth` | 64 | 递归深度 |
| `max-search-results` | 10,000 | 单次搜索结果数 |
| `max-directory-entries` | 10,000 | 单次目录列表条目数 |
| `max-webdav-properties` | 64 | 单次显式 PROPFIND/PROPPATCH 属性数；不可超过 64 |
| `max-webdav-rendered-properties` | 65,536 | 单次 DAV“资源数 × 属性数”；不可超过 65,536 |
| `max-webdav-response-size` | 8 MiB | 缓冲的 Multi-Status XML 总字节数；不可超过 8 MiB |
| `max-archive-size` | 4 GiB | 单个归档的未压缩输入总量 |
| `max-hash-size` | 4 GiB | `?hash` 可接受的文件大小 |
| `expensive-task-timeout` | 5 分钟 | 目录、搜索、归档、哈希的协作式总期限 |
| `copy-timeout` | 5 分钟 | PUT/PATCH/COPY/递归 DELETE 本地工作、hook 与发布的协作式期限 |
| `upload-idle-timeout` | 30 秒 | 上传正文空闲期限 |
| `upload-total-timeout` | 15 分钟 | PUT/PATCH 暂存阶段的总期限，阻止持续滴流 |
| `max-upload-size` | 4 GiB | 单个上传最大字节数 |
| `max-copy-size` | 4 GiB | WebDAV COPY 可复制的最大源文件 |
| `upload-file-mode` | `0600` | 全新 PUT 的普通权限位；覆盖保留旧目标、COPY 保留源文件的 `0777` 位 |
| `upload-dir-mode` | `0700` | MKCOL 与 PUT 自动创建祖先的普通权限位；必须包含 owner `0700` |
| `storage-space-check` | false | 启用目标文件系统 statvfs 字节/inode 提示性预检查 |
| `storage-reserve` | 0 | statvfs 预检查要求额外保留的空闲字节 |
| `storage-quota-hook` | 未设置 | 发布前调用的可信外部逻辑配额/记账程序 |
| `storage-quota-hook-timeout` | 5 秒 | hook 运行期限；范围 1–60 秒，执行超时返回 504 |

请求准入固定按以下顺序执行：verified source 非阻塞获取，饱和 `429`；全局名额不可用时
进入 `max-request-queue`，队列已满或等待超时 `503`；认证成功后账号非阻塞获取，饱和
`429`。source、全局和账号 owned permit 都转移到响应体，一直保留到 EOS、body error 或
客户端取消；关停会关闭两个全局 semaphore，使所有队列 waiter 立即以 `503` 醒来。
per-source、per-user 与 queue 配置的启动硬上限均为 4096，避免配置本身制造无界状态。

连接上限与请求上限是两层独立保护：一个 HTTP/2 连接可承载多个 stream，而请求许可仍按
stream 生命周期计数。`response-write-idle-timeout` 同时包含连接级 pending socket write
watchdog 和每响应 watchdog；后者由独立计时任务跟踪 body 进展，即使该 H2 stream 因 flow
control 不再被轮询，其他 stream 的活动也不能刷新它。任一响应超时会终止整条连接，以确保
对应 request permit 和 body 资源都能释放。`h2-max-concurrent-streams`、source/global/user
请求上限和 `connection-max-lifetime` 仍提供独立上界。动态目录 `HEAD` 不扫描目录，也不
伪造 `Content-Length`。其余操作预算彼此独立。生产值应根据存储吞吐、文件描述符上限、
最大目录规模和代理超时测量后设定，而不是简单放大。

## 12. 日志与监控

默认访问日志：

```text
$time_iso8601 $log_level request_id=$request_id - $remote_addr $remote_user "$request" $status bytes=$body_bytes outcome=$response_outcome request_time=$request_time
```

`$status` 是已经发送的响应头状态；它不能在流中途失败后改写。响应体真正结束时才写
访问日志，并用 `$response_outcome` 区分 `complete`、`body_error`、`truncated`、
`length_mismatch` 和 `downstream_cancelled`。`$body_bytes`（也可写作
`$bytes_sent`）统计交给 Hyper 协议层的数据帧字节，不代表客户端 TCP ACK；
`$client_cancelled` 为 `0`/`1`，`$request_time` 是从请求进入服务到响应体终态的秒数，
`$response_ready_time` 是响应头构造完成前的秒数。每个响应都会返回服务端生成的
128 位 `X-Request-Id`，与 `$request_id` 一致。

其它可用变量包括 `$remote_addr`、认证后的 `$remote_user`、`$request`、`$status`、
`$expected_body_bytes` 和 `$http_<header>`。示例：

```sh
ram \
  -a 'user:password@/' \
  --log-format '$time_iso8601 $request_id $remote_addr $remote_user "$request" $status $body_bytes $response_outcome $request_time' \
  --log-file /var/log/ram/access.log \
  /srv/share
```

设置 `--log-format=''` 可关闭访问日志。

文件日志由容量 8192 的后台队列写入，单行上限 64 KiB。默认每 100 MiB 轮转，
保留 `.1` 到 `.5` 五个备份。队列满时请求线程不会被慢日志盘阻塞，后续日志会报告
丢弃数量。日志目标必须由 root 或当前服务用户拥有且为单链接普通文件；符号链接、
硬链接别名和设备节点会被拒绝。新建或已有日志都会收紧为 `0600`，轮转截断只会在
同一已打开 fd 完成信任检查后执行。关停时 flush barrier 的入队与确认共用 2 秒硬截止；
健康目的端会写完 barrier 前的记录，队列饱和或文件/控制台 I/O 卡死时可能丢失队尾日志，
但不会无限阻止进程退出。

至少监控：

- 空闲字节和 inode。
- 文件描述符和连接数。
- 认证 `429`。
- 健康端点 `503`。
- 4xx/5xx、请求延迟和日志丢弃警告。

`Authorization`、Cookie，以及名称中含 token、secret、password、credential、
signature 或 API key 的请求头不能加入格式串。查询参数中的 token、credential、
signature、password、secret 等可复用凭据会在逐参数解码前整值替换为 `***`；不得
记录 Bearer 令牌、密码、私钥或生产文件内容。

## 13. systemd 部署

建议使用专用用户，并让二进制、配置、TLS 私钥和数据目录具有最小权限。生产部署应
显式使用 `/usr/local/bin/ram --config /etc/ram/config.yaml`；Ram 不会根据二进制位置选择
配置。账号规则和 token 密钥通过 systemd credential 注入，避免进入 argv、环境变量或
长期可见的普通配置文件。

```ini
[Unit]
Description=Ram file server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ram
Group=ram
RuntimeDirectory=ram
RuntimeDirectoryMode=0750
StateDirectory=ram
StateDirectoryMode=0700
LogsDirectory=ram
LogsDirectoryMode=0700
LoadCredential=ram-auth:/etc/ram/auth.rules
LoadCredential=token-secret:/etc/ram/token.secret
ExecStart=/usr/local/bin/ram --config=/etc/ram/config.yaml --auth-file=%d/ram-auth --token-secret-file=%d/token-secret
Restart=on-failure
RestartSec=2s

LimitNOFILE=65536
TasksMax=512
MemoryMax=1G

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/srv/ram/share
CapabilityBoundingSet=
LockPersonality=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
```

`ProtectHome=true` 会阻止访问家目录；如果服务根位于 `/home`，应移动数据或针对
实际部署调整沙箱。监听 1024 以下端口时优先使用反向代理，不要无必要地授予能力。

推荐布局：

```text
/usr/local/bin/ram
/etc/ram/config.yaml
/etc/ram/auth.rules
/etc/ram/token.secret
/etc/ram/tls/fullchain.pem
/etc/ram/tls/privkey.pem
/srv/ram/share
/var/lib/ram/token-revocations.json
/var/log/ram/access.log
/run/ram/ram.sock
```

`RuntimeDirectory=ram`、`StateDirectory=ram` 和 `LogsDirectory=ram` 会在启动服务前分别创建
`/run/ram`、`/var/lib/ram` 和 `/var/log/ram`，设置为 `ram:ram`，并让它们在
`ProtectSystem=strict` 下保持可写；因此首次部署不需要先手工创建这些目录，也不会因
`ReadWritePaths` 引用了尚不存在的路径而在执行 Ram 前失败。上述名称必须与配置中的
`/run/ram/ram.sock`、`/var/lib/ram/token-revocations.json` 和
`/var/log/ram/access.log` 精确匹配。服务根 `/srv/ram/share` 不由这些指令管理，仍须在首次
启动前创建、赋予所需 owner/mode，并保留在 `ReadWritePaths` 中；只读部署则可进一步收紧。

配置和私钥建议仅 root 与服务用户可读；服务根的写权限应与启用的能力一致。
systemd 在启动命令中把 `%d` 展开为该 unit 的只读 credential 目录；Ram 收到的是普通
绝对路径，因此同样执行 owner、类型、链接数、权限和有界同 fd 读取检查。若发行版的
systemd 不支持 `%d`，可在 `ExecStart` 中使用具体的
`/run/credentials/ram.service/ram-auth` 路径。

## 14. 备份、升级与故障处理

### 14.1 备份与恢复

1. 在反向代理停止写流量，或停止 Ram。
2. 将服务树、`config.yaml`、token secret、audience 和撤销状态作为一个一致性
   单元快照。
3. 校验备份并在独立路径执行恢复演练。
4. 在 loopback 启动暂存实例，验证认证、ACL、列表、代表性读写和哈希。

只恢复文件而更换 token 身份会主动使旧链接失效；恢复 token 密钥却遗漏撤销状态
可能复活已撤销令牌，禁止这样操作。

### 14.2 升级与回滚

1. 阅读 GitHub Release notes 和安全公告。
2. 核验压缩包 SHA-256、provenance attestation、SBOM 和许可证清单。
3. 备份配置与 token 状态，保留不可变的旧二进制。
4. 在与生产机相同架构和 glibc 基线的暂存机验证 `ram --version`、启动配置和读写冒烟。
5. 原子替换二进制、重启，确认健康端点和认证请求后恢复流量。
6. 观察 4xx/5xx、延迟、磁盘、描述符和日志丢弃。

回滚时恢复旧二进制及与之配套的配置/token 快照。除非明确验证写入和令牌格式兼容，
不要让两个版本同时写同一目录。

### 14.3 常见故障

| 现象 | 排查 |
| --- | --- |
| 启动提示路径不存在 | 检查服务根、资源、证书、密钥和日志父目录及 Linux 权限 |
| 启动时报 `Exec format error` | 下载的制品架构与运行机不一致；改用 x86_64 或 ARM64 对应制品 |
| 浏览器页面空白 | 升级到最新稳定浏览器，启用 JavaScript，检查 CSP/代理 |
| 上传返回 403 | 同时检查用户 `rw`、`allow-upload` 和父目录文件系统权限 |
| 删除返回 403 | 检查用户 `rw`、`allow-delete` 和目标权限 |
| 搜索无结果 | 检查 `allow-search`、ACL、隐藏规则和截断提示 |
| WebDAV 无法挂载 | 检查 class 1/无锁兼容性、代理方法、Destination/Depth 和日志 |
| 大文件中断 | 检查 Range、代理超时、上传空闲期限、磁盘 I/O 和资源预算 |
| 非 loopback 启动失败 | 配置 TLS，或改用 loopback/Unix socket |

## 15. 源码结构

`src/`：

| 文件/模块 | 职责 |
| --- | --- |
| `main.rs` | 最小二进制入口 |
| `lib.rs` | 库入口、平台约束和模块边界 |
| `runtime/mod.rs` | Tokio 启动、监听、TLS 与优雅关停 |
| `config/mod.rs` | CLI、环境变量、YAML 合并和启动校验 |
| `auth/mod.rs` | Basic/Digest、ACL、Bearer token、限速与重放防护 |
| `identity/` | 文件系统对象身份与可信网络来源身份 |
| `http/body.rs` | 请求/响应流与长度限制 |
| `logging/mod.rs` / `access.rs` | 有界异步日志、轮转与访问日志模板 |
| `server/mod.rs` / `router.rs` | 请求包络、认证上下文、能力计算与方法路由 |
| `server/read_routes.rs` / `write_routes.rs` / `dav_routes.rs` | 一次性描述符、正文和事务 guard 的所有权分派 |
| `server/browse.rs` | 目录列表、搜索和 UI 数据 |
| `server/mutation_version.rs` | 稳定扫描签名和进程内变更纪元 |
| `server/content.rs` | 静态资源、下载、Range、哈希、令牌端点 |
| `server/write/mod.rs` | PUT/PATCH/DELETE/MKCOL/COPY/MOVE |
| `server/webdav/mod.rs` | PROPFIND/PROPPATCH 和 DAV 能力 |
| `server/filesystem/mod.rs` | 根目录能力、受限打开和原子文件操作 |
| `server/archive.rs` / `walk.rs` | 归档与有界遍历 |
| `server/range.rs` | multipart byte range 流 |
| `server/model.rs` / `reply.rs` | 序列化模型与响应构造 |
| `server/security_headers.rs` | 通用安全头和 CORS |
| `utils/mod.rs` | URI、TLS 和通用解析工具 |

完整物理目录与文件移动规则见 [项目文件结构](docs/PROJECT_STRUCTURE.md)。`web/` 是无需构建的现代浏览器源文件；
`scripts/check-web-assets.mjs` 执行前端安全结构检查；
`config.example.yaml` 是部署模板；`.github/workflows/` 定义质量与多架构发布流程。

请求主线：

```text
socket accept
  → 可选 TLS
  → Hyper 请求
  → URI/path-prefix 规范化
  → 内部资源或健康端点
  → Basic/Digest/Bearer 认证
  → 规范目标 ACL 与全局能力
  → HTTP/WebDAV 路由
  → 根目录受限文件操作
  → 安全响应头与访问日志
```

## 16. 开发与质量检查

开发机必须是受支持的 Linux 环境；x86_64 与 ARM64 都可直接构建。

Rust 检查：

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- --deny warnings
cargo clippy --all-targets --no-default-features --locked -- --deny warnings
cargo test --all-targets --all-features --locked
cargo test --all-targets --no-default-features --locked
RUSTDOCFLAGS='--deny warnings' cargo doc --no-deps --all-features --locked
```

覆盖率使用与常规测试隔离的插桩构建。Rust 报告合并默认 TLS 与
`--no-default-features` 两种生产配置；`fuzzing` 仅用于 fuzz harness，不计入常规覆盖率：

```sh
cargo install --locked cargo-llvm-cov --version 0.8.7
cargo llvm-cov clean --workspace
cargo llvm-cov --no-report --all-targets --locked --remap-path-prefix
cargo llvm-cov --no-report --all-targets --no-default-features --locked --remap-path-prefix
mkdir -p coverage
cargo llvm-cov report --json --summary-only --ignore-filename-regex '(^|/)(tests|fuzz)/' --output-path coverage/rust-summary.json
cargo llvm-cov report --lcov --ignore-filename-regex '(^|/)(tests|fuzz)/' --output-path coverage/rust.lcov
npm ci --ignore-scripts
npm run test:coverage
node scripts/report-coverage.mjs
```

CI 把 Rust 全局、前端全局以及 auth、filesystem、write preconditions、WebDAV、Range
安全组的加权结果写入 job summary，并保留 JSON/LCOV artifact。当前
`tests/coverage/policy.json` 处于 `trend` 模式：目标用于显示差距，百分比暂不让构建
失败。至少积累 10 次稳定的 main 运行后，维护者才可在本地使用
`node scripts/report-coverage.mjs --update-baseline` 更新基线、设置经评审的 floors 并切换为
`enforce`；CI 明确禁止自动更新基线。Rust branch coverage 仍属实验选项，不作为门槛。

解析器 fuzz 包含 Digest auth-param、URI percent decode/路径规范化、Range/If-Range、
WebDAV XML/属性名、Destination/Host/path-prefix、访问日志变量和 ZIP entry name 共 7 个
target；每个 target 都有独立的最小 corpus，`fuzz/Cargo.lock` 也纳入版本控制。CI 的短任务
对每个 target 固定运行 256 次，单输入 5 秒、输入 64 KiB、RSS 2 GiB；本地等价命令为：

```sh
rustup toolchain install nightly-2026-07-22
cargo install --locked cargo-fuzz --version 0.13.2
cargo +nightly-2026-07-22 check --manifest-path fuzz/Cargo.toml --locked
targets=(digest_auth_params uri_path range_if_range webdav_xml destination_host_prefix log_format zip_entry_name)
for target in "${targets[@]}"; do
  seed_dir="fuzz/corpus/$target"
  corpus_dir="target/fuzz-corpus/$target"
  test -n "$(find "$seed_dir" -maxdepth 1 -type f -print -quit)"
  rm -rf "$corpus_dir"
  mkdir -p "$corpus_dir"
  cp -a "$seed_dir/." "$corpus_dir/"
  mkdir -p "fuzz/artifacts/$target"
  cargo +nightly-2026-07-22 fuzz run "$target" "$corpus_dir" -- \
    -runs=256 -max_len=65536 -timeout=5 -rss_limit_mb=2048 \
    -artifact_prefix="fuzz/artifacts/$target/"
done
```

运行目录使用 `target/fuzz-corpus/` 下的临时副本，避免 libFuzzer 保存新发现时直接改动
经审阅并纳入版本控制的最小 corpus。

长任务对每个 target 使用 `-max_total_time=1800 -timeout=10 -max_len=65536
-rss_limit_mb=2048`。每周 cron 默认不消耗计算资源；只有仓库管理员显式设置 Actions 变量
`RAM_SCHEDULED_FUZZ=true` 后才运行，也可在手动 workflow dispatch 中勾选
`long_campaign`。每个 harness 的真实内部输入上限、文本 corpus framing、复现和 artifact
位置见 [fuzz/README.md](fuzz/README.md)。

现代前端源码检查：

```sh
npm ci --ignore-scripts
npm audit --audit-level=high
npm run check
npx playwright install chromium firefox webkit
npm run test:e2e
```

Playwright 的 Chromium、Firefox 和 WebKit 都是支持矩阵的一部分；首次运行或浏览器版本
变化后应安装三者。在需要补齐系统共享库的 CI/临时 Linux 主机上可使用
`npx playwright install --with-deps chromium firefox webkit`，日常开发不应无条件修改系统包。

供应链检查：

```sh
cargo audit --deny warnings
cargo deny --locked check
cargo package --locked
```

仓库跟踪 Rust 集成测试、前端模块/DOM 测试、浏览器可访问性测试及其专用 fixture；
不跟踪 `node_modules/`、`target/`、覆盖率或浏览器测试产物。提交前还应执行与改动
相关的本机协议/部署冒烟，但不得把真实凭据、生产私钥或生产数据加入仓库。测试用
证书和私钥仅用于 loopback 集成测试，禁止部署使用。

安全敏感改动必须保持以下原则：

- 先规范化资源，再验证身份，再对真实目标授权，最后执行文件系统副作用。
- 写操作同时受路径 ACL 和全局能力控制。
- 远程输入解析不得 panic。
- 大文件和目录使用流式/有界处理。
- UI 不承担权限判断。
- 不重新引入非 Linux 服务端或旧浏览器兼容分支。

## 17. 发布

推送与 Cargo/npm/README/CHANGELOG 版本严格一致、受 tag ruleset 保护、可从默认分支到达
且签名可由 GitHub 验证的 annotated `vX.Y.Z` tag 后，发布工作流会：

1. 使用 Rust 1.97.1 对 Rust 2024 源码执行 fmt、Clippy、双特性组合测试和文档检查。
2. 执行前端静态检查、模块/DOM 测试，以及 Chromium、Firefox、WebKit 三浏览器的交互与
   可访问性测试。
3. 执行 npm audit、RustSec 和 cargo-deny 供应链检查。
4. 验证 crates.io 源码包不包含测试目录、`node_modules` 或可疑私钥，并在验证与发布
   job 之间比较源码包 SHA-256，避免重新打包时静默漂移。
5. 生成并语义校验 CycloneDX、SPDX SBOM 和第三方许可证清单。
6. 以 x86-64 v1 与 generic ARM64 CPU 基线在原生 runner 上分别构建 Linux GNU 制品。
7. 对最终 tar 执行精确成员/类型策略、ELF 机器类型、PIE、RELRO、NX、动态库白名单、
   glibc 2.39 上限、版本绑定和原生协议冒烟，再生成 SHA-256 与 provenance/SBOM attestation。
8. 先将所有附件上传到私有 Release 草稿，并对草稿身份与精确附件清单做第二次校验；此时
   不公开 Release。
9. 预发布版本可直接进入最终发布；稳定版若 crates.io 尚无该版本，则用短期 OIDC 凭据发布
   已验证的源码包，并在有界轮询中读回完全相同的 SHA-256；若版本已存在，则复用验证阶段
   已完成的精确 checksum 比对。只有对应路径闭环后，独立 finalizer 才重新验证草稿并公开
   GitHub Release。

压缩包包含 `ram`、MIT 许可证、本文档、配置示例、依赖清单、运行时链接信息和供应链
元数据。不发布 musl、Windows 或 macOS 制品。

## 18. 安全策略与贡献

完整的支持版本、私密报告渠道、响应目标与协调披露流程见
[SECURITY.md](SECURITY.md)。支持最新稳定 minor 版本；前一个稳定 minor 仅接收关键安全
修复，旧版本和预发布版本不受支持。管理员应订阅 GitHub Security Advisories 并及时升级。

请不要在公开 issue 中披露漏洞。使用
[GitHub 私密安全报告](https://github.com/isarmg/ram/security/advisories/new)。
若问题也影响上游 dufs，请同时通过
[dufs 安全公告入口](https://github.com/sigoden/dufs/security/advisories/new)
协调报告。

报告中可包含受影响版本、去除秘密后的部署/认证方式、不可信本地进程是否可修改
服务树，以及最小请求序列。不要发送真实密码、私钥、Bearer token 或生产文件。

普通贡献应保持改动聚焦，说明兼容性和部署影响，并通过第 16 节全部检查。涉及认证、
路径、写操作、主动内容、TLS、资源上限或 WebDAV 的变更需要额外安全审查。
具体的双特性矩阵、`openat2` 不变量、测试要求和独立审阅规则见
[CONTRIBUTING.md](CONTRIBUTING.md)；用户可见变化记录在 [CHANGELOG.md](CHANGELOG.md)。
按启动、HTTP 管线、认证、读写/WebDAV、配额钩子、前端、日志终态与发布划分的多张
Mermaid 代码流程图见 [代码工作流程与模块作用](docs/CODE_FLOW.md)。

按单用户、多用户只读、不可信写用户、反向代理、多实例和 NFS/FUSE 分类的边界见
[部署威胁模型](docs/THREAT_MODEL.md)。CODEOWNERS、release workflow 和本地 CI 只能强制
仓库内规则；branch/tag ruleset、release environment reviewer、immutable releases 和私密报告
入口仍须管理员按 [仓库治理检查表](docs/REPOSITORY_GOVERNANCE.md) 在 GitHub 侧启用并审计。
Release workflow 会拒绝未受保护、无法从默认分支到达、轻量、未签名、签名无效或未直接
指向当前构建 commit 的 tag，也拒绝覆盖已经存在的 Release 附件。

## 19. 许可证

Ram 采用 MIT 许可证，完整条款见 [`LICENSE`](LICENSE)。使用者可以按照该许可证的条款
使用、修改和分发本项目。

---

# Ram File Server (English)

[![CI](https://github.com/isarmg/ram/actions/workflows/ci.yaml/badge.svg)](https://github.com/isarmg/ram/actions/workflows/ci.yaml)

Ram is a Linux file-service manager centered on security boundaries and operational clarity. It maps
one local file or directory to HTTP/WebDAV, with a modern browser manager, `curl`/DAV interfaces,
fine-grained path permissions, TLS, resumable transfers, search, archives, and hashing.

The crates.io package is `ram-fileserver`; the installed command is `ram`. The project originated
from [dufs](https://github.com/sigoden/dufs) and is maintained by Ram contributors.

> The server supports Linux GNU x86_64 and ARM64. Official binaries require glibc 2.39 or newer;
> x86_64 needs no AVX/AVX2/BMI/FMA extensions. The browser UI supports current evergreen browsers
> with JavaScript. Non-Linux servers, old browsers, and legacy authentication modes are unsupported.

## 1. Features and non-goals

Primary capabilities:

- browse, download, upload, replace, delete, move, and copy files;
- create/search directories and stream a directory as ZIP;
- single/multipart Range, conditional requests, and resumable PATCH uploads;
- an embedded modern UI for UTF-8 viewing/editing and directory drag-and-drop;
- Basic, RFC 7616 SHA-256 Digest, and short-lived Bearer download tokens;
- per-user/per-path read-only or read-write ACLs capped by global capability switches;
- a finite documented WebDAV subset: PROPFIND, PROPPATCH, MKCOL, COPY, and MOVE;
- direct TLS, reverse proxy, TCP, pathname/abstract Unix sockets;
- explicit connection, traversal, result, archive, hash, upload, and timeout budgets;
- bounded asynchronous access logs, rotation, health, and readiness.

Ram is not distributed storage, an object-store gateway, or a database index. It provides no
Windows/macOS server, official musl binary/container image, or legacy browser bundle. UI controls are
only interaction feedback; every security decision is made again by the server.

## 2. Support scope

### 2.1 Server platform

Official builds and continuous verification cover:

```text
x86_64-unknown-linux-gnu
aarch64-unknown-linux-gnu
```

Release builds fix x86_64 to `target-cpu=x86-64` (v1) and ARM64 to Rust's generic CPU, and build/run
each on a native runner. Other Linux targets may build from source but are not in the release matrix.

Linux is a security requirement: the root capability uses Linux 5.6 `openat2`; descriptor identity
requires readable `/proc/self/fd`; listeners include Unix sockets. Seccomp must allow `openat2`, and
procfs must be available. Official GNU artifacts enforce a glibc 2.39 symbol ceiling and consequently
need glibc 2.39+. Build on the deployment environment for older GNU userspace.

### 2.2 Toolchains

- Rust edition 2024, Rust 1.97.1, Cargo resolver 3.
- Native ES modules/ESNext frontend, without transpilation, polyfills, or a legacy bundle.
- Development checks use Node.js 24.18.0 LTS, ESLint 10, and TypeScript 7.

Node is development-only. `web/` HTML/CSS/JavaScript is embedded directly into the Rust binary; there
is no frontend build step at runtime.

### 2.3 Browser baseline

Only current stable Chrome/Chromium Edge, Firefox, Safari, and comparable evergreen browsers with
JavaScript are supported. The UI directly uses modern ES modules and Web/DOM APIs. There is no
no-script directory page, IE/legacy fallback, Babel output, polyfill, or dual legacy/modern asset set.
Protocol clients may still use HTTP/WebDAV when the browser UI is unavailable.

## 3. Obtain, build, and start

### 3.1 Release artifact

Select the matching target, verify SHA-256 and GitHub provenance, then install (replace the example
version with the actual release):

```sh
TARGET=x86_64-unknown-linux-gnu # use aarch64-unknown-linux-gnu on ARM64
sha256sum --check "ram-v0.47.0-${TARGET}.tar.gz.sha256"
tar -xzf "ram-v0.47.0-${TARGET}.tar.gz"
sudo install -m 0755 "ram-v0.47.0-${TARGET}/ram" /usr/local/bin/ram
```

### 3.2 Source build

```sh
rustup toolchain install 1.97.1 --component clippy --component rustfmt
cargo build --locked --release
sudo install -m 0755 target/release/ram /usr/local/bin/ram
```

Cargo targets the current Linux host unless `--target` is supplied. Cross-building default TLS also
needs a target C compiler, assembler, archiver, linker, and sysroot because AWS-LC is native code.
`--no-default-features` removes that TLS native chain.

Official release profile uses `opt-level=3`, LTO, one codegen unit, `panic=unwind`, and
`strip=symbols`. The release records ELF Build ID, runtime links, and archive/binary hashes, but does
not currently publish an exact matching debug-symbol package. For source-line diagnosis build the
same tag without stripping:

```sh
CARGO_PROFILE_RELEASE_DEBUG=line-tables-only \
CARGO_PROFILE_RELEASE_STRIP=none \
cargo build --locked --release
```

Exact offline symbolization of the published binary would require generating debug information in
the release build, splitting it with `objcopy --only-keep-debug`/`--add-gnu-debuglink`, and publishing
the matching symbol artifact with checksums/provenance. Symbols cannot be reconstructed afterward
from the stripped output.

### 3.3 Minimal start

Ram requires at least one named user and rejects anonymous rules and the `change-me` placeholder:

```sh
install -m 0600 /dev/null ./ram.auth
printf '%s\n' 'admin:replace-with-a-long-random-password@/:rw' >./ram.auth
ram --auth-file ./ram.auth /srv/share
```

Inline `--auth` is for local development only because argv is commonly observable. Production uses
`--auth-file` or systemd `LoadCredential`.

The default listener is `127.0.0.1:5000` and, when supported, `[::1]:5000`. A development instance
with upload/delete/search is:

```sh
ram \
  --auth-file ./ram.auth \
  --allow-upload \
  --allow-delete \
  --allow-search \
  /srv/share
```

`--allow-all` also enables symlinks, archives, and hashes; production should opt in individually.
Use `ram --help` and `ram --completions bash` for the complete interface.

## 4. Configuration model

### 4.1 Sources and precedence

Ordinary fields merge in this order: CLI, `RAM_*` environment, explicitly selected YAML, then
defaults. `--config <path>` or `RAM_CONFIG=<path>` selects YAML, with the CLI selector winning when
both are present. Without either selector, Ram loads no YAML and scans neither the process working
directory nor the executable directory. Copying, moving, or upgrading the binary therefore cannot
change configuration merely because a colocated `config.yaml` exists. An explicit path that is
missing or unsafe fails startup; YAML rejects unknown fields. Production should use an explicit
absolute path.

YAML-relative paths resolve against that YAML's directory; CLI/environment paths resolve against the
process cwd. Boolean sources are three-state: absent, true, false. CLI accepts both `--allow-upload`
and `--allow-upload=false`; environment accepts `RAM_ALLOW_UPLOAD=false`. Capability merge order is:
defaults → YAML `allow-all` → YAML specific fields → CLI/environment `allow-all` → CLI/environment
specific fields. A specific false therefore closes a broader true.

Each long CLI option has an upper-case underscore environment equivalent, for example
`RAM_SERVE_PATH`, `RAM_CONFIG`, `RAM_AUTH_FILE`, `RAM_ALLOW_UPLOAD`, `RAM_MAX_UPLOAD_SIZE`, and
`RAM_TOKEN_SECRET_FILE`. List values such as CORS origins/methods/headers are comma-separated.
`--completions` is an immediate command, not persistent configuration.

Validate the merged deployment configuration without listeners or runtime mutation:

```sh
ram --check-config --config /etc/ram/config.yaml
RAM_CONFIG=/etc/ram/config.yaml ram --check-config
```

Success is exactly `Configuration OK` on stdout and exit 0. The check reads and statically validates
configuration, credentials, token/TLS input, the pinned quota hook, isolation, budgets, dangerous
combinations, certificate/key matching, and a bounded custom-assets tree. It does not bind sockets,
create/rotate logs or revocation state, clean candidates, run the hook, or start the runtime. It cannot
prove the hook's business logic/exec success, future output-directory writability, port availability,
disk capacity, or proxy correctness. Automation must use the exit status, not unstable diagnostic text.

### 4.2 Example and option reference

Copy [config.example.yaml](config.example.yaml) to `/etc/ram/config.yaml`, replace the rejected
placeholder password, run `--check-config`, and start with the same explicit path. Merely copying the
file does not load it without `--config` or `RAM_CONFIG`. The file is a safe template: loopback-only,
privileged operations off, and deliberately not runnable until credentials are replaced.

Core categories are:

| Category | Options | Contract |
| --- | --- | --- |
| Root/URL | `serve-path`, `path-prefix`, `hidden` | File/directory root, URL mount, name-only listing glob |
| Listen | `bind`, `port`, `unix-socket-*`, `allow-abstract-unix-socket` | TCP/pathname/abstract Unix policy |
| Auth | `auth-file` or `auth` | Mutually exclusive credentials; private file preferred |
| Transport/proxy | `tls-*`, `hsts-max-age`, `allow-insecure-http`, `allow-h2c`, `trusted-proxy*` | Explicit secure transport and source identity |
| Token | `token-secret[-file]`, `token-audience`, `token-ttl`, `token-revocation-file` | HMAC identity and revocation |
| Capability/UI | `allow-*`, `allow-all`, `render-*`, `assets` | Global operation ceiling and rendering |
| CORS/logging | `enable-cors`, `cors-*`, `log-*`, `compress` | Explicit allowlists, output, ZIP level |
| Resources | `max-*`, `*-timeout`, upload modes, storage checks/hook | Size/count/concurrency/time/storage bounds |

Sizes accept integer bytes or binary `K/M/G/T`; durations accept seconds or `s/m/h/d`.
`max-upload-size: 0` is the only documented unlimited mode; other resource limits must be nonzero.

## 5. Listening, TLS, proxy, and URL

### 5.1 TCP and Unix sockets

A pathname Unix socket is bound before the logger/runtime while the process is single-threaded. It is
created as private 0600 under temporary umask 0177, pinned by inode, then assigned exact configured
mode and optional numeric uid/gid. Every ancestor through the immediate parent must be a canonical
real directory owned by root or the non-root service user; unsafe writable ancestors, symlinks, and
namespace replacement fail startup. Write `/run`, not the `/var/run` symlink. Socket paths cannot lie
inside the HTTP-writable tree or unauthenticated assets tree.

Only a stale socket whose owner and pinned identity are trusted and whose connections are refused can
be removed. Shutdown removes it only if identity still matches. In a shared sticky parent, it cannot
be chowned to an unrelated uid; use a private non-writable parent when deliberately delegating it.

Linux `SO_PEERCRED` supplies the complete `unix:uid=...,gid=...,pid=...` audit value. Source-keyed
authentication, request, and upload budgets group Unix peers by kernel UID so fork/PID or permitted-group
churn cannot split a budget. Unix requests never derive identity from forwarding headers.

Abstract sockets have no pathname permission boundary and are rejected unless
`--allow-abstract-unix-socket` explicitly accepts that risk. One process may configure several
listeners; `port` applies only to IP addresses.

### 5.2 Non-loopback and TLS

A non-loopback TCP bind fails without `tls-cert`/`tls-key` unless dangerous
`--allow-insecure-http` is explicitly set. Certificate and key are a pair. A `--no-default-features`
binary rejects TLS settings instead of silently serving plaintext.

Direct TLS negotiates HTTP/2 or HTTP/1.1 by ALPN. HSTS is off by default and may be set only when Ram
itself terminates TLS; `0` clears old policy, the hard maximum is two years, and Ram does not add
includeSubDomains/preload. A TLS-terminating proxy sets HSTS itself. Plain TCP/Unix is HTTP/1 by
default; `--allow-h2c` is only for trusted prior-knowledge h2c and provides no encryption.

A proxy must forward Authorization, Destination, Depth, Overwrite, conditional headers, and DAV
methods, and must not cache authenticated file responses. The backend listens on loopback, Unix, or a
separately protected network.

Forwarded source identity is completely disabled unless both a canonical `trusted-proxy` CIDR list
and one `trusted-proxy-header` (`x-forwarded-for` or `x-real-ip`) are configured and the kernel direct
peer matches. Untrusted peer headers are not parsed. XFF is capped at 4096 bytes/32 hops and strictly
parsed right-to-left through trusted hops; X-Real-IP must occur exactly once and contain one IP.
Malformed trusted-proxy input returns a fixed public 400 with details only in internal logs. Standard
`Forwarded` and PROXY protocol are not accepted. One immutable `SourceIdentity` drives logs, replay/
failure limits, request admission, and uploads.

### 5.3 Path prefix

`--path-prefix files` maps `/files/` to the root. A reverse proxy must preserve the same prefix and
encoding semantics.

## 6. Authentication and path permissions

### 6.1 ACL grammar

```text
user:password@path[:perm][,path[:perm]...]
```

`ro` is the default and `rw` grants write permission. `auth-file` stores one rule per nonempty,
non-comment line and is capped at 1 MiB, 4096 lines, and 16 KiB/line. It is opened with `O_NOFOLLOW`,
bounded-read from the same fd, and must be a single-link regular file owned by root/service with exact
0400 or 0600 mode. Blank/indented-comment lines are ignored; real rules with leading/trailing
whitespace are rejected rather than silently changing credentials. `auth`/`auth-file` are mutually
exclusive across YAML/environment/CLI, and duplicate usernames fail startup. Passwords never enter
errors or logs.

Anonymous rules are rejected. Unauthorized ancestors may appear IndexOnly so a user can navigate to
an authorized deep path without seeing other contents. Effective permission is the intersection of
the user's path ACL and global `allow-*`; `rw` alone cannot enable upload.

### 6.2 Basic and SHA-256 Digest

Digest is strictly RFC 7616 `SHA-256` with `qop=auth`; MD5 and a legacy opt-in do not exist. Nonces and
replay state live five minutes and bind the exact request target. An accepted
`(nonce, username, cnonce, nc)` cannot be reused. The process stores at most 65,536 entries, with
per-user 16,384, per-nonce 8,192, and per-source 16,384 caps; saturation fails closed without evicting
unexpired proof. Username/cnonce are capped at 256/128 bytes, limiting dynamic key payload to 24 MiB.
Expiry uses a heap rather than hot-path full-map scans. Exact tuples are necessary because HTTP/2
requests can arrive out of order; “highest nc” would reject valid traffic and eviction would reopen replay.

Digest needs plaintext-equivalent password material to calculate A1. It does not accept precomputed
HA1 or pretend PHC is Digest-compatible. If that server-side secret risk is unacceptable, use TLS
Basic with PHC or a trusted upstream authenticator.

Basic should use Argon2id v19 PHC with `m=19456..65536` KiB, `t=2..5`, `p=1..4`, 8..32-byte salt,
16..64-byte output, and only m/t/p parameters. Up to four hash workers therefore use at most 256 MiB.
All Argon2 accounts in one instance must share m/t/p/output length and cannot mix with plaintext or
SHA-512-crypt; migrate all accounts together or use a separate instance. Salts should differ.

Legacy `$6$` SHA-512-crypt is Basic-only. Default 5,000 rounds is accepted and explicit rounds are
hard-capped at 1,000,000. Every SHA-512-crypt credential in one instance must use identical rounds.
Quote `$` rules in the shell and use TLS.

Basic/Digest use an atomic two-layer throttle. A source+claimed-name bucket is derived without account
lookup and is cleared only by that name's success; a cross-name source budget accumulates every failure
and is never reset by any successful login. This prevents known/unknown partition oracles,
low-privilege-success laundering, and fake-name rotation. After a deadline, exactly one recovery attempt
is admitted; correct credentials recover and only an evaluated failure schedules the next backoff.
Active-only expensive admission still uses the claimed username consistently: at most four jobs execute,
eight execute/queue, two per source, and three per claimed name. In a plaintext-only deployment,
unknown Basic/Digest performs equivalent work with an unpredictable non-accepting startup dummy. In
a hashed deployment, known hash, known plaintext, and unknown Basic each perform exactly one HMAC
comparison plus one configured-profile hash.
Argon2 m/t/p/output and SHA-512-crypt rounds must each be uniform within an instance; mixed-cost startup
is rejected. Infrastructure/global admission failure is 503 and does not count as bad credentials.
Password hashing or persistent token revocation requires `max-blocking-threads >= 5`, preserving one
ordinary filesystem worker. A default revocation backend derived from a persistent token secret counts
too, and startup and `--check-config` validate the same effective topology. Health, credential-free OPTIONS, bounded bearer MAC/claims preflight, and
in-memory revocation need no permit; persistent revocation reads/writes share global/source admission
with hashes while using protocol-separated subject slots.

### 6.3 Short-lived Bearer download tokens

Only a fully Basic/Digest-authenticated user may issue a token for the current canonical path through
GET or POST `?tokengen`. Tokens are accepted only in `Authorization: Bearer ...` for GET/HEAD; query
tokens are unsupported. Claims bind version, user, exact path, audience, issued/expiry time, and unique
`jti`; default TTL is 15 minutes. A Bearer credential cannot issue or revoke another token.

Revocation uses original credentials with `POST` and `X-Ram-Revoke-Token`, returns 204, and—like issue
and Bearer download—uses `Cache-Control: no-store`.

By default secret/audience are random per start, invalidating tokens on restart. Stable identity
requires both a 32+ byte private `token-secret-file` and `token-audience`; revocation state defaults
beside the secret or may be configured. Secrets/state are pinned, owner/mode/link checked, and excluded
from served/assets roots.

Multiple local processes may share one revocation file only on a local filesystem with reliable flock,
atomic rename, and directory fsync, with identical secret/audience. A stable sibling lock serializes
shared validation and exclusive revocation; lock identity is rechecked, updates merge under lock and
publish through synced temp rename/parent fsync, and readers reload changed inode metadata on the next
Bearer request. V1 state is read and upgraded to monotonic-generation V2. Unknown version, rollback,
corruption, missing/untrusted state, >8 MiB, or >65,536 entries fails closed. Runtime lock/read/write/
sync/rename ambiguity permanently degrades that instance: Bearer/revocation returns 503 until a clean
restart. Back up secret, audience, and revocation state as one consistency unit.

## 7. HTTP interface

Except health and embedded static assets, resources require authentication. Use HTTPS outside a
trusted local hop.

### 7.1 Reads, conditions, and mutations

GET/HEAD support ETag, Last-Modified, If-Match, If-None-Match, If-Modified-Since,
If-Unmodified-Since, If-Range, and single/multipart Range. Satisfiable ranges return 206; an otherwise
valid unsatisfiable range returns 416.

After authentication/ACL but before any existence response, PUT/PATCH body read, or side effect, Ram
strictly parses all conditional fields for GET, HEAD, PUT, PATCH, DELETE, COPY, MOVE, MKCOL, and
PROPPATCH. Malformed/unclosed/non-UTF-8 tags, wildcard/tag mixing, duplicate wildcards, bad dates, and
duplicate single-value dates/If-Range return 400 even when the target is absent. Valid failed unsafe
conditions return 412 without changing inode, contents, ETag, directory, or candidates. GET/HEAD cache
hits return 304. If-Match takes precedence over If-Unmodified-Since; If-None-Match over
If-Modified-Since.

Files no larger than 4 MiB receive a content SHA-256 strong ETag, valid for If-Match/If-Range. Larger
files receive a metadata-derived `W/"meta:..."` weak ETag for cache revalidation only; it never
satisfies If-Match or If-Range. Second-resolution dates also fall back to full 200 for If-Range. The
supported strong-validator writer model is local storage with Ram/cooperating writers using atomic
replacement; external in-place mutation and NFS/FUSE do not provide that guarantee.

Authenticated file downloads use `Cache-Control: private, no-cache`; directory HTML/JSON/simple,
file JSON, editor, hash, DAV XML, token, and other sensitive dynamic responses use
`private, no-store`. Shared caches cannot store authenticated content.

PUT/PATCH receive the network body into a private candidate outside the mutation lock, without
creating missing ancestors. Under a bounded commit lock they reopen/re-authorize the target, recheck
conditions, and atomically publish. Limits jointly cover declared length, actual bytes, idle/total
deadline, staging concurrency, and final size. PUT final size is body length; PATCH is
`max(current_size, offset + incoming_len)`. The inclusive limit passes, N+1 and arithmetic overflow
return 413 even in explicit unlimited upload mode.

Upload staging holds global, authenticated-user, and verified-source RAII permits. Global exhaustion
is 503; user/source exhaustion is 429 with `Retry-After: 1`. Disconnect, read error, timeout, and every
commit outcome release ownership only after real cleanup.

COPY uses a private destination candidate, counts actual copied bytes, and rechecks source identity
before/after transfer. It tries reflink, then `copy_file_range`, then fixed-buffer copy, falling back
only on explicit unsupported/cross-filesystem errors; partial copies and ENOSPC/EDQUOT/EIO never
silently switch strategy. MOVE requires source delete and destination upload rights. COPY requires
destination upload and additionally delete permission when replacing an existing target.

New PUT uses `upload-file-mode` (0600 default); MKCOL and auto-created ancestors use
`upload-dir-mode` (0700 default and must include owner rwx). Descriptor-pinned chmod makes this
independent of umask. Replacement preserves only the old target's ordinary 0777 bits; COPY preserves
only the source's ordinary 0777 bits. Special bits, old owner, ACL/xattrs, capabilities, timestamps,
and hardlink relationship are not copied. Kernel parent-default ACL/LSM creation policy may apply,
then ordinary mode/ACL mask is fixed. Private candidates remain 0600 until rename; a crash in the
narrow post-rename/pre-mode window leaves a stricter visible file, never a more permissive one.

The metadata contract is tested on isolated ext4 and XFS using raw POSIX ACL xattr encoding. The same
test may be run on a deployment mount with `TMPDIR` and `RAM_METADATA_EXPECT_FS`, as shown in the
Chinese section above.

MKCOL, DELETE, COPY, and MOVE use their standard methods and Destination/Overwrite semantics. A
recursive DELETE performs a bounded read-only prescan first; entry/depth failure returns 422 with zero
deletions. Only then does it execute a post-order identity-checked unlink plan with immediate parent
fsync. Cancellation or I/O failure after deletion starts may leave a documented durably partial tree;
clients re-list before retrying.

Directory query forms are `?simple`, `?json`, `?q=...`, `?zip`, and file `?hash`. Hash returns 64
lowercase/uppercase-insensitive hexadecimal SHA-256 characters and needs `allow-hash`. Search/archive/
hash each need their capability and separate budgets. ZIP places every entry under portable
`archive/`, uses `/`, and encodes backslash, colon, non-UTF-8 bytes, Windows device names, and other
nonportable components with unambiguous `%HH`. Each file is read only from the walker's opened fd,
with the remaining uncompressed budget plus one growth sentinel as its input ceiling. ZIP64 selection
also includes a conservative Deflate expansion ceiling for incompressible input. If either input or
compressed output can exceed ZIP32, ZIP64 is declared before the local header, so the default 4 GiB
and slightly smaller custom budgets cannot discover insufficient capacity after HTTP 200 has started.
A root archive downloads as `archive.zip`.

#### Non-UTF-8 Linux filenames

Linux names are bytes while URL/JSON/HTML/DAV require Unicode. ZIP is the sole lossless export; every
other interface explicitly omits or rejects unrepresentable names rather than inventing a lossy alias:

- HTML/JSON/simple omit such direct children; search omits them and does not enter a non-UTF-8-named directory.
- Percent-decoded request paths must be valid UTF-8 and return 400 otherwise.
- Depth:1 DAV uses listing policy and does not put replacement names in XML.
- ZIP encodes raw bytes as `%HH`; literal `%` becomes `%25`, so byte names remain unambiguous. This is
  an archive notation, not an HTTP URL.
- Single-file mode requires a nonempty UTF-8 basename; serve the parent and export ZIP otherwise.

When an ACL-visible name is omitted, list/search/Depth:1 responses carry
`X-Ram-List-Omitted: non-utf8`; JSON/page data also sets `omitted_non_utf8: true`. IndexOnly cannot use
the signal to probe unauthorized names. Search/ZIP reauthorize the descriptor-derived real path before
each branch, so an authorized UTF-8 symlink alias does not authorize another raw/UTF-8 object.
`X-Ram-List-Truncated: true` independently signals result/budget truncation and may appear together.
HEAD may omit generation-derived listing flags to avoid scanning. Clients must not derive HTTP paths
from ZIP `%HH` names.

### 7.2 Health and readiness

Unauthenticated `/__ram__/health` returns 200 only while the retained root can be opened with its
startup type, otherwise 503. It does not replace disk/inode, proxy, or credential monitoring.

### 7.3 Status contract

Clients rely on status, not diagnostic wording:

| Status | Meaning |
| --- | --- |
| 200/201/204/206/207/304 | Successful read/create/no-content/range/DAV/cache result |
| 400 | Invalid path/header/Range/DAV syntax |
| 401 | No valid credential; includes WWW-Authenticate |
| 403 | Valid identity without path/global permission, or finite-depth DAV rejection |
| 404 | Missing object or deliberately hidden escaping target |
| 405 | Unsupported/inapplicable method; includes Allow |
| 408 | Upload idle or total staging timeout |
| 409 | Missing parent or resource-shape/namespace conflict |
| 412 | Failed conditional/overwrite precondition |
| 413 | Upload/hash payload too large |
| 415 | Nonempty unsupported MKCOL entity |
| 416 | No satisfiable byte range |
| 422 | Semantically over-budget DAV input or bounded recursive plan |
| 429 | Per-source/account/user upload or authentication/hash flood limit; may include Retry-After |
| 500 | Unexpected local I/O/implementation or ambiguous durability failure |
| 503 | Readiness, global queue/admission/worker/lock/local-timeout/degraded-state failure |
| 504 | Trusted quota hook execution timeout |
| 507 | Disk/quota exhaustion, COPY limit, quota denial, or DAV response budget |

Every response has `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and
`X-Frame-Options: DENY`; authentication/token responses are not cached.

## 8. WebDAV contract

Ram deliberately advertises **no numeric DAV compliance class**. It lacks collection COPY, persisted
dead properties, locks, and all mandatory class-1 semantics. `OPTIONS` and resource-specific 405
`Allow` are the capability declaration.

| Method | Support |
| --- | --- |
| OPTIONS | Dynamic Allow narrowed by target, global switches, and caller ACL; no numeric DAV |
| PROPFIND | Depth 0/1 only; missing Depth is RFC infinity and rejected |
| PROPPATCH | Fully parsed but each modification rejected; no dead-property store |
| MKCOL | Parent must exist; any body yields 415 with no creation |
| COPY | Files only, with same-origin Destination, ACL, and Overwrite |
| MOVE | File/directory through same-filesystem rename semantics |
| LOCK/UNLOCK | 405; lock success is never fabricated |

PROPFIND supports empty body, allprop, propname, and explicit prop. Request XML is capped at 64 KiB;
namespace/local names at 256/128 bytes; unique expanded-name total at 16 KiB. Configurable limits may
lower but not exceed 64 requested properties, 65,536 rendered item×property values, and 8 MiB complete
Multi-Status XML. Input semantic overflow is 422; an unrenderable response is 507. Depth:1 derives a
retained-item bound from property count and probes only one rejection sentinel, preventing directory ×
property memory amplification.

Explicit or implicit infinity returns 403 with `DAV:propfind-finite-depth`; invalid/duplicate Depth is
400. Debian litmus 0.13-5+b1 real-client baseline is intentionally partial: basic 15/16 (numeric DAV
expectation fails), props 11/14 (dead properties fail/skip), copymove 8/13 (file operations pass;
collection/class-1 replacements fail). File-to-collection COPY is stable 409, not 500. This proves only
the documented subset, not class-1 compliance.

### 8.1 CORS

CORS is off by default and never sends `Access-Control-Allow-Credentials`. Origins are exact
`http(s)://host[:port]` or a sole `*`; wildcard cannot mix with exact origins. Configured methods are
intersected with target/global capabilities and request headers are matched case-insensitively against
an explicit allowlist, never reflected. A credential-free preflight indicates only possible shape/
method/header acceptance; the actual request still authenticates and authorizes. Invalid preflight is
400/403; success is 204, no-store, and has complete Vary. Ordinary responses emit CORS only for an
actual allowed Origin.
The default request-header allowlist includes `X-Ram-If-Mutation-Version`, and response exposure
includes `X-Ram-Mutation-Version`. A custom `cors-headers` list must retain the former when a
cross-origin manager uses listing-version protection.

Clients requiring persistent locks are incompatible; use If-Match or external coordination.

## 9. Web UI and site rendering

### 9.1 Default manager

The embedded JavaScript-only UI provides browse/sort/search, bounded upload queue, directory drag/drop,
download/delete/mkdir, preview, and UTF-8 editing. It runs two uploads concurrently, retains at most
1,000 retryable tasks, and bounds folder traversal to 1,000 entries/32 levels. File and folder controls
are keyboard reachable; navigation warns about active uploads.

The editor's second GET enforces actual received bytes at 4 MiB, accepts only valid UTF-8 on save, and
preserves an existing UTF-8 BOM. GBK/UTF-16 remains downloadable but is not silently converted.
JavaScript Bearer downloads buffer at most one known-small file and 16 MiB; known-large, ZIP/unknown,
or racing growth uses native browser streaming. Listing omission/truncation is visibly reported.

A complete directory scan that did not overlap a process-local mutation carries `mutation_version`
in JSON/embedded state and `X-Ram-Mutation-Version` in response headers. The manager sends it as the
strict singleton `X-Ram-If-Mutation-Version` on listing-originated DELETE/MOVE. After all relevant
mutation locks are held, the server atomically compares boot UUID and monotonic revision; stale
conditions return 412 without side effects. Every PUT/PATCH/DELETE/MKCOL/COPY/MOVE entering Ram's
final transaction conservatively advances the revision, and no version is signed while its blocking
worker remains active. This is **process-local stale-listing protection only** and is sound only when
Ram is the sole writer of the served root. Direct writes by another process, shell, synchronizer, or
second Ram instance do not advance this epoch; deployments with external writers need If-Match,
external coordination/locking, or a fresh authoritative read instead of treating this token as a
general filesystem transaction version.

### 9.2 Rendering and active content

- `--render-index`: serve a directory's `index.html`, otherwise 404.
- `--render-try-index`: prefer index, otherwise the directory manager.
- `--render-spa`: unresolved extensionless routes serve the root index.

HTML/XHTML/SVG/XML and other active content is attachment plus sandbox CSP by default. Rendering
inlines only the selected trusted index; direct access to other active content downloads it. Upload
combined with any render mode fails startup unless `--allow-active-content-risk` explicitly accepts
stored-XSS/same-origin credential abuse. Untrusted writers and privileged browser sessions belong on
different origins.

The manager has a strict same-origin CSP with no inline/eval/third-party framing/base rewrite. Non-text
preview is first fetched by the authenticated page with an actual-byte 16 MiB cap, converted to a
local blob, and placed in an iframe with an empty sandbox granting no script, same-origin, forms,
popups, or navigation. Failure/oversize is not inlined. This does not make arbitrary same-origin active
content safe.

### 9.3 Custom assets

`--assets` requires `index.html` and optionally `404.html`; templates may use `__INDEX_DATA__` and
`__ASSETS_PREFIX__`. Assets execute before authentication and must be outside every network-writable
tree. Startup traverses a pinned capability: every directory/file has trusted root/service ownership,
no group/world write, and served files are single-link regular files. Requests recheck the opened
descriptor; index is capped at 1 MiB and traversal is depth/entry bounded. Custom UI obeys the same
evergreen/CSP contract and never bypasses server ACL.

## 10. Filesystem and security boundary

### 10.1 Root capability and path normalization

Serving `/` is rejected unless `--allow-filesystem-root` explicitly accepts the audited risk. Config,
TLS keys, auth file, token secret/state/lock, access log, and quota hook must be outside both served and
unauthenticated-assets trees. `hidden` is not access control.

At startup Ram opens a stable canonical ancestor fd chain from `/`, double-walks identities
`(st_dev, st_ino, type)`, and passes those retained descriptors to RootFs and config/TLS/auth/token/
hook consumers. It never trusts canonical string prefixes. Later rename plus same-spelled replacement
cannot redirect capability. Existing sensitive inputs/outputs are single-link regular files; outputs
not yet created retain a pinned parent fd and basename for openat2/renameat/unlinkat. Single-file mode
keeps the exact inode and reopens independent offsets from it.

No sensitive input may share an inode with a mutable output. Revocation state/lock, the active log and
its `.1`–`.5` rotation backups, and pathname Unix listeners must occupy distinct pinned-parent-plus-
basename namespace slots, including when those outputs do not yet exist at configuration time.

Root and custom-assets traversal uses `RESOLVE_NO_XDEV`; submounts and bind mounts below a root are
unreachable. There is no cross-mount compatibility switch—serve the mount as a separate Ram root.
Configured symlink/bind aliases are compared by canonical ancestor identity in this mount namespace.
Later privileged mount changes and aliases in another namespace cannot be proven, so the service user
must have no mount capability and topology stays fixed. NFS/FUSE instability is outside the trusted baseline.

Request paths must percent-decode, contain only normal relative components, have no parent escape, and
stay below path-prefix/root. Filesystem access is dirfd/capability-relative. After authentication Ram
reauthorizes the descriptor-derived real path.

Every PUT/PATCH/DELETE/COPY/MOVE transaction retains `(dev, ino, ctime sec/nsec, type)` from the
conditional check and compares it again through a pinned parent before publication/removal/rename.
COPY checks source fd and entry before/after transfer; MOVE checks both endpoints. Races before the
final check map to 412 (conditional) or 409. Linux has no atomic “compare version and unlink/rename,”
so an external writer can still swap an entry between final statat and unlinkat/renameat. A writable
tree must consequently have exactly one Ram writer process and no direct external writer; maintenance
occurs only while Ram is stopped.

### 10.2 Hidden names and symlinks

`hidden` globs match names, omit them from listing/search, and do not secure direct access. Symlinks are
off by default. When enabled, targets still resolve through pinned root with
`RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV` and are reauthorized by real path; outside-root
and submount targets remain forbidden.

### 10.3 Storage, quota, durability, and recovery

`max-upload-size`/`max-copy-size` are request policy, not tenant/filesystem quota. Use a dedicated
mount, kernel/project quota, headroom for old+candidate coexistence, backup, and alerts.
`storage-space-check` is a racy statvfs byte/inode hint with `storage-reserve`; authoritative
ENOSPC/EDQUOT still returns 507. Candidate data flush/sync failure is ambiguous durability and 500.
After rename, file/parent sync failure may mean the new representation is already visible and returns
500 rather than falsely claiming an unpublished 507.

For XFS, mount with `prjquota`, assign the whole served tree an inherited project ID through
`/etc/projects`, `/etc/projid`, and `xfs_quota project -s`, then set block/inode hard limits. The exact
copyable root commands are in Chinese section 10.4 above. Kernel EDQUOT is authoritative; `du` cannot
atomically account for concurrent/reflink/sparse/hardlink/candidate state.

An optional trusted `storage-quota-hook` runs after PUT/PATCH staging or COPY source validation and
before publication, directly (no shell):

```text
HOOK --user USER --operation PUT|PATCH|COPY --path ROOT_RELATIVE_PATH \
     --current-bytes N --final-bytes N
```

Exit 0 allows; policy nonzero/signal denies with 507; reserved helper exit 125 or startup/exec/wait
infrastructure failure is 500; timeout is 504. Missing authenticated user fails closed. Environment and
stdio are cleared. Ram executes the pinned inode via `/proc/self/fd/N`; the hook must use configured
absolute paths rather than `$0` siblings. Timeout, request cancellation, and shutdown kill the hook
process group and reap the direct child. The hook **must not daemonize, double-fork, call setsid, or
otherwise escape that process group**, because such descendants cannot be reliably supervised.

The hook is arbitrary code running as the Ram uid. It must be trusted root/service-owned, single-link,
regular, executable, group/world non-writable, outside served data, and in a nonreplaceable directory.
Its decision and rename are not one transaction. Strict per-user/multi-instance quota needs an external
transactional reservation with idempotent commit/release, while kernel quota remains the hard boundary.

MKCOL, DELETE, MOVE, and PUT publication sync changed directories/files as described above. Failed
auto-created ancestors roll back in reverse order only while pinned parent and inode still match and
the directory remains empty.

Private names are exact `.ram-upload-<lower-hyphenated-uuid>.tmp` or root staging equivalents. They are
forced to 0600 and hold nonblocking exclusive flock throughout reception/commit. Startup and periodic
capability-root scans remove only old exact candidates that are regular, service-owned, 0600,
single-link, and exclusively lockable. Symlinks, hardlinks, directories, active files, unsafe metadata,
and name variants remain. Traversal does not follow links and rechecks inode before parent-relative
unlink/fsync.

Async Drop uses a dedicated 64-entry reaper, never synchronous unlink on Tokio workers. Queue/worker/
stat/unlink/fsync degradation retains available parent/file fds, flock, admission guard, and ancestor
responsibility, retries transient capable cleanup every 250 ms, and permanently disables new
candidates (503) until restart. No unsafe pathname-unlink fallback exists. Shutdown waits a bounded
time for cleanup tickets. Confirmed candidate removal precedes reverse rollback of unchanged empty
ancestors. A process crash cannot recover in-memory ancestor identity and may conservatively leave an
empty directory.

Each recovery scan has entry, depth, deletion, and cooperative-time budgets. Unsafe reserved names,
I/O/durability ambiguity, or budget exhaustion makes writable startup fail or stickily disables later
candidate creation; read-only startup warns. Diagnostics report at most four bounded root-relative
paths plus suppressed count and never the absolute root. Cooperative deadlines check between syscalls
and cannot interrupt a kernel call. A stuck NFS/FUSE syscall may retain a blocking worker and permit
beyond the request deadline. `max-blocking-threads` caps the count, not duration. Isolate unreliable
remote mounts in a separate process/container with kernel mount timeouts and service-manager watchdog.

Short filesystem operations additionally share pre-submission
`FilesystemBlockingAdmission` across the served and custom-assets roots. A permit is acquired before
`spawn_blocking` and moved into the real closure, so request cancellation cannot turn queued or
in-kernel work into unaccounted background tasks. Waiting beyond `request-queue-timeout` returns 503
when headers have not started. Downloads do not retain a permit for the whole response: metadata and
each read/seek are admitted independently and release immediately on completion, so slow clients and
HTTP/2 flow-control waits consume no filesystem permit. Submitted I/O retains its permit after body
cancellation until the worker really exits. Full, single-range, and multipart-range responses share
this behavior.

Graceful shutdown waits 30 seconds for connection tasks after stopping accept, aborts/awaits them,
then flushes logs; Tokio waits up to another five seconds for its blocking pool. Neither is a hard
process-exit SLA for stuck kernel/log I/O; configure a service-manager stop deadline and final SIGKILL.

## 11. Resource limits

Default budgets are:

| Configuration | Default | Purpose |
| --- | ---: | --- |
| `max-connections` | 512 | Simultaneous accepted connections |
| `max-concurrent-requests` | 64 | Executing or still-streaming requests process-wide |
| `max-concurrent-requests-per-source` | 16 | Requests per verified source; immediate 429 |
| `max-concurrent-requests-per-user` | 16 | Requests per authenticated account; immediate 429 |
| `max-request-queue` | 64 | Bounded waiters for global execution; 0 means immediate 503 |
| `request-queue-timeout` | 5 s | Maximum global-slot wait |
| `header-read-timeout` | 30 s | Absolute HTTP/1 head / initial protocol-H2 preface deadline |
| `connection-idle-timeout` | 60 s | No successful transport-I/O deadline |
| `connection-max-lifetime` | 1 h | Absolute lifetime since accept |
| `response-write-idle-timeout` | 30 s | Pending connection write and independent response/H2-stream progress |
| `h2-max-concurrent-streams` | 32 | Streams per H2 connection, still capped globally |
| `max-blocking-threads` | 32 | Tokio blocking-worker hard count, range 1–256 |
| `max-concurrent-uploads` | 4 | Retained PUT/PATCH candidates; global saturation 503 |
| `max-concurrent-uploads-per-user` | 2 | Candidates per authenticated user; 429 |
| `max-concurrent-uploads-per-source` | 2 | Candidates per verified TCP/proxy/Unix source; 429 |
| `stale-upload-cleanup-age` | 24 h | Minimum candidate age, range 1 s–7 d |
| `stale-upload-cleanup-max-entries` | 100,000 | Entries inspected per pass, hard maximum 1,000,000 |
| `stale-upload-cleanup-max-depth` | 64 | Scan and candidate depth, hard maximum 256 |
| `stale-upload-cleanup-max-deletions` | 1,000 | Safe deletions per pass, hard maximum 100,000 |
| `stale-upload-cleanup-timeout` | 5 s | Cooperative scan deadline, range 1–60 s |
| `write-lock-timeout` | 5 s | Commit transaction-lock wait; 503 |
| `max-expensive-tasks` | 4 | Shared directory/search/archive/hash/local-publication workers |
| `max-walk-entries` | 1,000,000 | Recursive traversal entries |
| `max-walk-depth` | 64 | Recursive depth |
| `max-search-results` | 10,000 | Results per search |
| `max-directory-entries` | 10,000 | Entries per directory representation |
| `max-webdav-properties` | 64 | Explicit PROPFIND/PROPPATCH properties |
| `max-webdav-rendered-properties` | 65,536 | DAV resource×property products |
| `max-webdav-response-size` | 8 MiB | Complete buffered Multi-Status XML |
| `max-archive-size` | 4 GiB | Uncompressed input per archive |
| `max-hash-size` | 4 GiB | File accepted by `?hash` |
| `expensive-task-timeout` | 5 min | Cooperative directory/search/archive/hash deadline |
| `copy-timeout` | 5 min | Cooperative publication/COPY/delete/hook work deadline |
| `upload-idle-timeout` | 30 s | Upload-body idle deadline |
| `upload-total-timeout` | 15 min | Entire PUT/PATCH staging deadline |
| `max-upload-size` | 4 GiB | Upload final-size cap |
| `max-copy-size` | 4 GiB | DAV COPY source cap |
| `upload-file-mode` | 0600 | New PUT mode; replacements/COPY preserve ordinary bits |
| `upload-dir-mode` | 0700 | MKCOL/auto-created parent mode; owner 0700 required |
| `storage-space-check` | false | Advisory destination statvfs bytes/inodes preflight |
| `storage-reserve` | 0 | Extra free bytes required by preflight |
| `storage-quota-hook` | unset | Trusted pre-publication accounting executable |
| `storage-quota-hook-timeout` | 5 s | Hook deadline, range 1–60 s; timeout 504 |

Admission order is: nonblocking verified-source permit (429), bounded global queue/permit (full or
timeout 503), then nonblocking authenticated-account permit (429). Owned source/global/account permits
move into the response body and remain until EOS, body error, or cancellation. Shutdown closes global
semaphores and wakes waiters with 503. Source/user/queue configured hard maximums are 4096.

Connections and requests are independent layers: one H2 connection carries several streams, each
counted for its response lifetime. The write-idle policy has both connection-level pending-write and
per-response watchdogs; an unpolled flow-control-stalled stream cannot be kept alive by another active
stream. Timeout closes the connection to release body/request resources. Directory HEAD does not scan
or fabricate Content-Length. Tune production limits from measured storage, fd limits, tree size, and
proxy deadlines rather than simply increasing them.

## 12. Logging and monitoring

Default access format is:

```text
$time_iso8601 $log_level request_id=$request_id - $remote_addr $remote_user "$request" $status bytes=$body_bytes outcome=$response_outcome request_time=$request_time
```

Logging occurs when the response body truly completes, errors, truncates/mismatches length, or is
cancelled downstream. `$status` is the already-sent head and cannot change afterward. `$body_bytes`
(alias `$bytes_sent`) counts frames handed to Hyper, not TCP acknowledgments; `$client_cancelled` is
0/1; `$request_time` reaches the body terminal state and `$response_ready_time` reaches head creation.
Each response carries a server-generated 128-bit `X-Request-Id` equal to `$request_id`.

Other variables include remote address/user, request, status, expected body bytes, and approved
`$http_<header>` fields. `--log-format=''` disables access logs.

File logs use an 8,192-entry background queue and 64 KiB/line cap, rotate at 100 MiB by default, and
retain `.1`–`.5`. A full queue never blocks request threads and later reports drops. The target must be
a trusted root/service-owned single-link regular file; links/devices are rejected, new/existing files
are tightened to 0600, and rotation truncation happens only after same-fd trust checks. Shutdown gets
one two-second total deadline to enqueue and acknowledge its flush barrier. A healthy destination
drains preceding records; saturation or stuck file/console I/O may lose tail records but cannot block
process exit indefinitely.

Monitor free bytes/inodes, descriptors/connections, auth 429, health 503, 4xx/5xx, latency, cleanup/
degraded warnings, and log drops. Logging configuration cannot include Authorization, Cookie, or header
names containing token/secret/password/credential/signature/API key. Sensitive query parameter values
are replaced with `***` before per-parameter decoding. Never log Bearer tokens, passwords, keys, or
production contents.

## 13. systemd deployment

Use a dedicated non-root user and explicit `/usr/local/bin/ram --config /etc/ram/config.yaml`. Inject
auth rules/token secret with `LoadCredential` rather than argv/environment. The complete unit in the
Chinese section above uses:

- `RuntimeDirectory=ram`, `StateDirectory=ram`, and `LogsDirectory=ram` with private modes;
- `LoadCredential=ram-auth:...` and `token-secret:...`, referenced through `%d`;
- `LimitNOFILE`, `TasksMax`, `MemoryMax`, empty capabilities, `NoNewPrivileges`, private tmp,
  strict system/home protection, and a narrow `ReadWritePaths=/srv/ram/share`;
- restart-on-failure with a small delay.

Managed-directory directives create `/run/ram`, `/var/lib/ram`, and `/var/log/ram` before exec and
keep them writable under `ProtectSystem=strict`; their names must match configured socket/revocation/
log paths. `/srv/ram/share` remains operator-managed and must exist with correct ownership/mode.
`ProtectHome=true` means roots under `/home` need relocation or deliberate policy adjustment. Prefer a
proxy to granting low-port capabilities. Older systemd without `%d` can use the explicit
`/run/credentials/ram.service/...` path; Ram still checks owner/type/link/mode and bounded same-fd input.

## 14. Backup, upgrade, and troubleshooting

### 14.1 Backup and restore

Stop write traffic or Ram, snapshot the served tree plus configuration, token secret, audience, and
revocation state as one unit, verify/restore-rehearse it separately, then run a loopback staging
instance to test auth, ACL, listing, representative writes, and hashes. Restoring files with a new
token identity intentionally invalidates links; restoring a secret without its revocations can revive
revoked tokens and is prohibited.

### 14.2 Upgrade and rollback

Read release/security notes; verify archive SHA-256, provenance, SBOM, and licenses; back up config/
token state and retain the immutable old binary; stage on the same architecture/glibc; verify version,
configuration, and smoke; atomically replace/restart and check health/auth; monitor errors, latency,
disk, descriptors, and log drops. Rollback restores the matching binary and configuration/token
snapshot. Never let two versions write one tree unless write/token compatibility has been explicitly proven.

### 14.3 Common symptoms

| Symptom | Check |
| --- | --- |
| Startup path missing | Root/assets/cert/key/log parent and Linux permissions |
| `Exec format error` | Artifact architecture versus host |
| Blank browser UI | Current browser, JavaScript, CSP/proxy |
| Upload/delete 403 | User rw, corresponding global capability, filesystem parent/target permissions |
| Empty search | allow-search, ACL, hidden rules, truncation notice |
| DAV mount failure | No class-1/locks, proxy methods, Destination/Depth, logs |
| Large transfer interruption | Range, proxy/deadlines, disk I/O, budgets |
| Non-loopback startup failure | Configure TLS or use loopback/Unix |

## 15. Source layout

| Module | Responsibility |
| --- | --- |
| `main.rs`, `lib.rs` | Minimal binary/library entry, platform and module boundaries |
| `runtime/mod.rs` | Tokio startup, listeners, TLS, graceful shutdown |
| `config/` | CLI/environment/YAML merge, identity capture, startup validation |
| `auth/` | Basic/Digest, ACL, Bearer, rate/replay control |
| `identity/` | Filesystem-object and trusted network-source identity |
| `http/` | Method/body streaming and I/O deadline primitives |
| `logging/` | Bounded async output, rotation, access templates |
| `server/router.rs` | Normalized request/auth/capability dispatch |
| `server/{read_routes,write_routes,dav_routes}.rs` | Single-use descriptor/body/transaction-guard ownership dispatch |
| `server/browse.rs`, `content.rs` | Directory/UI and download/Range/hash/token endpoints |
| `server/mutation_version.rs` | Stable-scan signing and process-local mutation epochs |
| `server/write/mod.rs`, `filesystem/mod.rs` | Mutations, root capability, atomic/durable operations |
| `server/webdav/mod.rs`, `dav_routes.rs` | Bounded DAV subset and dispatch |
| `server/archive.rs`, `walk.rs` | Archive and descriptor-authorized bounded traversal |
| `server/range.rs`, `model.rs`, `reply.rs` | Multipart ranges, serialization, responses |
| `server/security_headers.rs` | Common security headers and CORS |
| `web/` | Directly embedded modern browser source |

See [Project Structure](docs/PROJECT_STRUCTURE.md) for the complete physical tree and file-move rules.

Request flow is accept → optional TLS → Hyper → URI/prefix normalization → internal/health fast path
→ Basic/Digest/Bearer → canonical ACL/global capabilities → registered HTTP/DAV route → root-relative
filesystem operation → security headers/access log.

## 16. Development and quality checks

Run on supported Linux. Required Rust matrix:

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- --deny warnings
cargo clippy --all-targets --no-default-features --locked -- --deny warnings
cargo test --all-targets --all-features --locked
cargo test --all-targets --no-default-features --locked
RUSTDOCFLAGS='--deny warnings' cargo doc --no-deps --all-features --locked
```

Coverage uses isolated instrumentation and combines default TLS/no-default production tests; harness-
only fuzzing is not regular coverage. `scripts/report-coverage.mjs` groups global/frontend/auth/
filesystem/write-precondition/DAV/Range totals. `tests/coverage/policy.json` remains trend-only
until at least ten stable main runs; only a reviewed local `--update-baseline` may set floors/enforce.

Seven fuzz targets cover Digest parameters, URI/path normalization, Range/If-Range, DAV XML/names,
Destination/Host/prefix, log format, and ZIP names. Each has checked-in corpus and standalone lockfile.
CI runs 256 inputs/target with 5-second input, 64 KiB, and 2 GiB RSS caps. Long campaigns use 1,800
seconds/target and only run when manually requested or `RAM_SCHEDULED_FUZZ=true`; full commands and
framing are in [fuzz/README.md](fuzz/README.md).

Frontend and supply-chain checks:

```sh
npm ci --ignore-scripts
npm audit --audit-level=high
npm run check
npx playwright install chromium firefox webkit
npm run test:e2e
cargo audit --deny warnings
cargo deny --locked check
cargo package --locked
```

Chromium, Firefox, and WebKit are all required. Tests use dedicated fixtures and never track
`node_modules`, target/coverage/browser output, production secrets, or real data. Security-sensitive
changes normalize first, authenticate second, authorize the real target third, and only then mutate;
remote parsing never panics; large data stays streamed/bounded; UI never grants authority.

## 17. Release

A release workflow is triggered only by a ruleset-protected, GitHub-validly-signed annotated
`vX.Y.Z` tag reachable from the default branch, directly targeting the build commit, with matching
Cargo/npm/README/CHANGELOG versions. It:

1. runs fmt, Clippy, both Rust feature matrices, rustdoc, frontend static/module/DOM tests, and
   Chromium/Firefox/WebKit interaction/accessibility;
2. runs npm audit, RustSec, cargo-deny, governance, license, and release-policy checks;
3. validates the crates.io source package for exact version/content/no test keys or node_modules and
   preserves its SHA-256 between validation and publication;
4. generates and semantically validates CycloneDX/SPDX SBOMs and third-party licenses;
5. builds x86-64 v1 and generic ARM64 GNU artifacts on native runners;
6. validates exact tar names/types, ELF machine, PIE/RELRO/NX, dynamic-library allowlist, glibc 2.39
   ceiling, version binding, native health/auth/TLS/Range/write/shutdown smoke, checksums, and
   provenance/SBOM attestations;
7. uploads every attachment to a private draft and revalidates the draft identity and exact asset
   inventory without publishing it;
8. for a stable version absent from crates.io, uses short-lived OIDC to publish the verified source
   package and polls within a fixed bound until crates.io reports the identical SHA-256. An existing
   version reuses the exact checksum comparison completed during validation. Only after the applicable
   path closes does an independent finalizer reverify and publish the GitHub Release; prereleases skip
   the crates.io branch.

Archives contain `ram`, the MIT license, README, example configuration, dependency/licenses, runtime
links, and supply-chain metadata. There are no official musl, Windows, or macOS artifacts.

## 18. Security and contributing

See [SECURITY.md](SECURITY.md) for supported versions, private reporting, response goals, and
coordinated disclosure. Do not disclose vulnerabilities in public issues. Use
[GitHub private reporting](https://github.com/isarmg/ram/security/advisories/new), coordinating
separately with upstream dufs if applicable. Never send real credentials, keys, Bearer tokens, or
production data.

Contributions remain focused, document compatibility/deployment impact, update CHANGELOG for public
behavior, and pass section 16. Authentication, paths, writes, active content, TLS, budgets, WebDAV,
dependencies, and releases need independent security review. Detailed invariants and test/ownership
rules are in [CONTRIBUTING.md](CONTRIBUTING.md).
For source-level navigation, see the bilingual [code-flow and module-responsibility
diagrams](docs/CODE_FLOW.md), covering startup, HTTP, authentication, reads/writes,
WebDAV, quota hooks, the browser UI, terminal logging, and release verification.

Deployment-specific boundaries are in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). GitHub external
branch/tag rulesets, environment reviewers, immutable releases, personnel, and private-reporting state
must be enabled/audited using [docs/REPOSITORY_GOVERNANCE.md](docs/REPOSITORY_GOVERNANCE.md); workflow
files and CODEOWNERS alone cannot enforce them.

## 19. License

Ram is licensed under the MIT License; see [`LICENSE`](LICENSE) for the complete terms. Users may use,
modify, and distribute it under those terms.
