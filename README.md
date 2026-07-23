# Ram

Ram 是一个面向个人内网、多设备浏览器访问的 Linux 文件管理器。它由单个 Rust
可执行文件提供网页和 HTTP 接口，适合在一台服务器上管理一个共享目录。

本项目源自 [dufs](https://github.com/sigoden/dufs) 0.46.0，并在其基础上收缩功能、
强化 Linux 文件系统隔离和有界资源控制。命令名是 `ram`，Cargo 包名是
`ram-fileserver`。

## 功能范围

保留的能力：

- 浏览目录以及普通文件下载；
- Range、条件请求和浏览器断点下载；
- 文件与目录上传；
- 新建目录、移动、重命名和删除；
- 有界搜索与目录 ZIP 流式下载；
- 有界、安全的只读文件预览；
- Basic 与 RFC 7616 SHA-256 Digest 认证、按用户和路径配置读写权限；
- 连接、请求、来源、用户、上传和昂贵任务的并发限制；
- Linux `openat2`/dirfd 根目录隔离、原子 PUT、失败清理和 `fsync`；
- stdout/stderr 结构化访问日志和优雅关闭。

有意不支持：

- 在线编辑文件；
- 临时分享链接或 Bearer 下载令牌；
- WebDAV 挂载及 Rclone、Finder、Cyberduck 等第三方客户端；
- `PATCH`、`COPY`、`PROPFIND`、`PROPPATCH`；
- 应用内 TLS、H2C、Unix socket、可信代理来源头；
- CORS、SPA 渲染、外部前端资源覆盖和文件 hash。

网页使用的 `PUT`、`DELETE`、`MKCOL` 和 `MOVE` 是 Ram 的内部文件管理接口，不代表
WebDAV 兼容。

## 运行环境

- Linux x86_64；
- 本地受信任文件系统；
- 由网关或反向代理提供域名和私有 TLS；
- 一个 Ram 进程独占一个可写服务目录。

不要让两个 Ram 实例同时写入同一目录。进程内路径锁、目录版本和候选文件回收不能在
多个独立进程之间协调。

## 安装

### 从 GitHub Release 安装

下载与版本标签对应的
`ram-vVERSION-x86_64-unknown-linux-gnu.tar.gz` 和 `.sha256`：

```sh
sha256sum --check ram-vVERSION-x86_64-unknown-linux-gnu.tar.gz.sha256
tar -xzf ram-vVERSION-x86_64-unknown-linux-gnu.tar.gz
sudo install -m 0755 \
  ram-vVERSION-x86_64-unknown-linux-gnu/ram \
  /usr/local/bin/ram
ram --version
```

发布包同时包含 `README.md`、`LICENSE` 和 `config.example.yaml`。

### 从源码构建

需要仓库指定的 Rust 工具链：

```sh
cargo build --release --locked
sudo install -m 0755 target/release/ram /usr/local/bin/ram
```

## 快速配置

1. 创建数据、配置和认证文件。以下假定低权限服务账号为 `ram`；若实际账号不同，请
   同步替换 owner/group：

```sh
sudo install -d -o ram -g ram -m 0750 /srv/ram
sudo install -d -o root -g ram -m 0750 /etc/ram
sudo install -o root -g ram -m 0640 config.example.yaml /etc/ram/config.yaml
sudo install -o ram -g ram -m 0600 /dev/null /etc/ram/auth.rules
IFS= read -r -s -p 'Ram admin password: ' RAM_ADMIN_PASSWORD
printf '\n'
test -n "$RAM_ADMIN_PASSWORD"
printf 'admin:%s@/:rw\n' "$RAM_ADMIN_PASSWORD" | sudo tee /etc/ram/auth.rules >/dev/null
unset RAM_ADMIN_PASSWORD
```

2. 修改 `/etc/ram/config.yaml`：

- `serve-path` 指向 `/srv/ram`；
- `bind` 和 `port` 只暴露给本机网关或受信任内网；
- 保持 `auth-file: /etc/ram/auth.rules`，确认认证文件归实际 Ram 服务账号所有且权限为
  `0600`，不要把真实密码提交到仓库；
- 保持存储空间检查开启，并按磁盘容量设置 `storage-reserve`；
- 从示例中的个人内网资源限制开始，只有观察到实际瓶颈后再调整。

默认 `personal-intranet` 档允许 32 个全局并发请求，并把每来源、每用户请求上限同样设为
32。原因是同机 TLS 网关会让多台设备显示为同一个来源，共享账号也会汇聚到同一个用户键；
全局上限仍保证总资源有界。上传另有更低的全局、来源和用户上限。

3. 启动前检查配置：

```sh
ram --check-config --config /etc/ram/config.yaml
```

成功时 stdout 输出 `Configuration OK`。检查模式不会监听端口或修改服务目录。

4. 运行：

```sh
ram --config /etc/ram/config.yaml
```

浏览器通过网关配置的域名访问。网关负责证书、TLS 和域名路由；Ram 只提供 HTTP/1.x，
不提供 HTTP/2。
不要把 Ram 的明文监听端口直接暴露到不受信任网络。

## 认证和权限

认证文件每行一条规则：

```text
admin:strong-password@/:rw
reader:another-password@/:ro
```

`rw` 用户可使用网页的上传、新建目录、移动、重命名和删除；`ro` 用户只能浏览、预览、
搜索和下载。权限路径始终相对于服务根。

认证文件应仅由 root 和 Ram 服务账号读取。Basic 可使用 Argon2id 密码哈希；Digest
需要明文密码，不能与哈希账户混用。完整格式和当前可用选项以
`ram --help`、`config.example.yaml` 及 `ram --check-config` 的结果为准。

## 数据安全

Ram 对请求路径使用 Linux dirfd 能力和 `openat2` 约束，拒绝路径穿越、magic link、
越出根目录的符号链接、子挂载和特殊文件。上传先写入不可见的私有候选文件，验证大小和
存储空间后再原子发布；失败、取消和重启清理不会留下可见半文件。

这些保护不能替代主机权限：

- 使用独立的低权限服务账号；
- 服务账号只应写入服务目录；
- 配置和认证文件不得放在服务目录内；
- 不要让其他不受信任进程修改服务目录；
- 日志由 journald 或容器运行时收集和轮转。

详细边界见 [安全说明](docs/SECURITY.md) 和
[部署威胁模型](docs/THREAT_MODEL.md)。

## 备份与恢复

备份前停止 Ram，或先在网关阻断写请求，然后同时备份：

- 完整服务目录；
- `config.yaml`；
- 认证文件；
- 当前 Ram 二进制或准确版本号。

恢复时先恢复到独立目录，校验所有者和权限，再运行
`ram --check-config --config ...`。启动后检查登录、目录列表、下载、上传、移动和删除，
确认无误后再切换域名流量。

## 升级与回滚

1. 阅读 [变更记录](docs/CHANGELOG.md) 和 GitHub Release notes。
2. 备份数据、配置和认证文件。
3. 校验下载包 SHA-256，保留旧二进制。
4. 用新二进制执行 `--check-config`。
5. 停止服务、原子替换二进制并重新启动。
6. 验证登录和代表性读写；失败时恢复旧二进制和匹配的配置。

不要在同一服务目录上同时启动新旧版本进行“并行验证”。

## 开发和测试

常规检查：

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked

npm ci --ignore-scripts
npm run check
npx playwright install --with-deps chromium
npm run test:e2e -- --project=chromium
```

常规 CI 仅运行 Linux x86_64、前端模块测试和 Chromium E2E。Firefox 与 WebKit
兼容性测试、解析器 fuzz 分别通过 GitHub Actions 每月运行一次，也可手动触发。
性能测试按需在实际部署环境手动完成，不作为每次提交的门禁。

## 发布

将 `Cargo.toml` 的包版本设为完整 SemVer，然后推送同版本标签：

```sh
git tag v0.1.0
git push origin v0.1.0
```

Release workflow 会验证标签与 Cargo 版本一致，构建 Linux x86_64 二进制，打包必要文件，
生成 SHA-256，并自动创建公开 GitHub Release。项目不会发布到 crates.io 或其他软件包
注册表。

## 上游和许可证

Ram 保留 dufs 上游作者和贡献者的归属。项目按仓库根目录
[LICENSE](LICENSE) 中的 MIT 许可证发布。

贡献说明见 [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md)。
