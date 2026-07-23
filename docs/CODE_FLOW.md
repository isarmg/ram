# 代码流程与模块职责

本文只描述当前保留的浏览器文件管理流程。

## 启动

```text
main
  -> config：合并显式 YAML、环境变量和 CLI
  -> validation/path_resolution：校验预算、认证文件和路径隔离
  -> runtime：创建有界 Tokio runtime
  -> logging：启动有界 stdout/stderr 日志队列
  -> server：打开并固定服务根 dirfd
  -> runtime：绑定 TCP HTTP/1.1、等待关闭信号并优雅排空
```

`--check-config` 在路径和静态安全验证后停止，不监听端口、不启动服务器，也不修改运行
状态。

## 请求

```text
TCP HTTP/1.1
  -> 连接与请求头超时
  -> 全局/来源请求准入
  -> 路径规范化
  -> Basic/Digest 认证与退避
  -> 用户请求准入
  -> ACL 与全局能力检查
  -> read_routes 或 write_routes
  -> 安全响应头
  -> 访问日志
```

来源身份只使用直接 TCP 对端。Ram 不解析转发来源头。

## 读取路径

`read_routes` 负责：

- 目录 HTML/JSON 列表；
- 普通文件、ETag、条件请求和 Range；
- 有界只读预览；
- 搜索；
- 目录 ZIP 流式下载；
- 健康端点和内置静态网页资源。

路径解析通过 `server/filesystem` 中保存的根目录能力完成。每个真实对象都会重新执行类型、
根目录和 ACL 检查。响应体按块读取，等待网络时不持有文件系统阻塞任务许可。

## 写入路径

`write_routes` 只接受网页文件管理器使用的四种方法：

```text
PUT     上传文件
DELETE  删除文件或目录
MKCOL   新建目录
MOVE    移动或重命名
```

PUT 先把请求体写入服务根中的不可见私有候选文件，执行大小、超时、存储空间和前置条件
检查，再在路径锁内原子发布并同步父目录。失败、取消或重启会清理候选文件。

DELETE、MKCOL 和 MOVE 使用同一能力相对路径解析、ACL、条件请求、路径锁和目录变更版本，
避免浏览器在过期目录快照上误操作。

## 资源限制

连接、请求、来源、用户、上传、阻塞任务和昂贵任务各有独立许可。目录、搜索、ZIP、
请求体和响应体也有数量或字节上限。任何一层饱和都返回有界错误，而不是创建无界任务或
缓冲。

## 关闭

收到终止信号后停止接受新连接，等待已有请求到达截止时间，清理未发布候选文件，并在固定
期限内排空日志队列。日志目的端故障不能无限阻塞退出。

## 主要目录

- `src/config/`：配置来源、schema、路径固定和校验；
- `src/auth/`：Basic/Digest 认证、ACL 和失败限流；
- `src/http/`：HTTP body、方法分类和 I/O 看门狗；
- `src/identity/`：路径对象与直接 TCP 来源身份；
- `src/runtime/`：HTTP/1.1 监听、资源限制和优雅关闭；
- `src/server/`：路由、文件系统、读取、写入、Range、ZIP 和安全响应；
- `src/logging/`：有界访问日志；
- `web/`：无需单独构建的浏览器模块；
- `tests/`：Rust、前端和 Chromium 集成测试。
