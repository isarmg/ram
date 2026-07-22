# Ram performance baseline

This directory contains an end-to-end benchmark rather than a microbenchmark.
It starts real debug and release Ram binaries, drives authenticated requests,
and records a machine-readable JSON result. It covers:

- sequential large-file GET, PUT, and SHA-256;
- list, full-tree no-match search, and ZIP over an exact 10,000-entry directory;
- persistent HTTP/1.1 and HTTP/2 transfers at server stream limits 1, 8, and 32;
- server RSS, file-descriptor, and thread peaks sampled from `/proc`;
- expensive-worker saturation using hashes. `blocking_queue_delay_proxy_ms` is
  the measured excess request latency over a single-request run. Tokio does
  not expose an internal blocking-queue length, so the report does not invent
  one; it also records offered concurrency and configured expensive-task slots;
- matched debug/release values and their fractional difference.

The harness uses warm-cache measurements after explicit scenario warmups. It
does not drop the host page cache because that would mutate unrelated workloads
and require privileged, host-wide operations. Storage performance should be
benchmarked separately if cold-cache disk throughput is the intended contract.

## Local smoke

Build a debug binary and run the small endpoint-only smoke when `h2load` is not
installed:

```sh
cargo build --locked
python3 benchmarks/run.py \
  --preset smoke \
  --skip-load \
  --binary debug=target/debug/ram \
  --output /tmp/ram-performance-smoke.json
python3 benchmarks/compare.py candidate \
  --allow-smoke \
  --result /tmp/ram-performance-smoke.json \
  --thresholds benchmarks/thresholds.json \
  --output /tmp/ram-performance-smoke-candidate.json
```

A smoke candidate is marked `review.status: smoke-candidate`. The comparator
categorically refuses it as a formal baseline. Local results are useful for
checking the harness, not for claiming production performance.

The scripts also have dependency-free parser/comparator tests:

```sh
python3 benchmarks/run.py --self-test
python3 benchmarks/compare.py self-test
```

## Formal runner contract

Formal measurements run only in `.github/workflows/performance.yaml` on a
dedicated runner carrying all labels below:

```text
self-hosted, linux, x64, ram-benchmark
```

The runner is not shared with build or application jobs. Its `ram-benchmark`
label is an operator assertion that the machine provides:

- at least eight online logical CPUs; CPUs 2-5 are reserved for Ram and 6-7
  for curl/h2load, with no other workload pinned to them;
- the `performance` governor on those CPUs, stable firmware/SMT/NUMA settings,
  no overcommit, and enough local disk space and RAM for the fixture;
- a local filesystem with stable mount options under `RUNNER_TEMP` (not NFS,
  FUSE, overlay-on-shared-storage, or a network home directory);
- Rust 1.96.0, curl with HTTP/2, and nghttp2 `h2load` with `--h1`,
  `--alpn-list`, and `--max-concurrent-streams` support;
- no concurrent benchmark job. Workflow concurrency serializes repository
  runs, while machine ownership prevents unrelated runner noise.

Scheduled jobs remain disabled until an administrator verifies every item in
this contract and creates the repository variable
`RAM_BENCHMARK_ENABLED=true`. Without that exact value the scheduled workflow
skips before requesting a self-hosted runner, so repositories that have not
provisioned the label do not accumulate permanently queued jobs. A manual
dispatch is an explicit operator action and can still wait for an offline
runner; cancel it if the runner is not going to become available.

`--strict-environment` rejects missing/disjoint CPU sets, a non-performance
governor, the default local runner ID, an unspecified binary build contract,
and incompatible tools. Every result
contains the kernel, CPU model/count, memory, filesystem, affinity, governors,
tool versions, binary hashes, and a derived environment fingerprint. A kernel,
tool, mount, affinity, or hardware change therefore requires a new reviewed
baseline instead of comparing unlike hosts.

## Candidate, review, and enforcement

The repository intentionally contains no fabricated numeric baseline. The
first full run on the dedicated runner produces a candidate artifact:

```sh
python3 benchmarks/compare.py candidate \
  --result performance-result.json \
  --thresholds benchmarks/thresholds.json \
  --output performance-baseline-candidate.json
```

Review the raw result, runner conditions, repeated-run variance, debug/release
differences, and threshold policy in a pull request. To approve it, copy the
candidate into `benchmarks/baselines/dedicated-linux-x86_64-v1.json` and change
only the review block to include all of the following:

```json
{
  "status": "approved",
  "approved_by": ["github-reviewer"],
  "approved_at_utc": "2026-07-21T00:00:00Z",
  "evidence_url": "https://github.com/OWNER/REPOSITORY/pull/NUMBER",
  "notes": "Three stable full runs reviewed; this file selects the median run."
}
```

The comparator rejects a baseline unless it is a full run with a 40-character
source commit, approved review metadata, an HTTPS evidence URL, the exact
runner/environment fingerprint, and the SHA-256 of the current threshold
policy. It compares only metrics present in the reviewed baseline and reports
new metrics without silently turning them into gates.

```sh
python3 benchmarks/compare.py compare \
  --result performance-result.json \
  --baseline benchmarks/baselines/dedicated-linux-x86_64-v1.json \
  --thresholds benchmarks/thresholds.json \
  --output performance-comparison.json
```

The scheduled workflow records candidates until that approved file exists.
After it is merged, `auto` mode enforces it; manual `enforce` mode fails if the
baseline is absent. Shared GitHub-hosted runners never enforce these thresholds.

## Result stability

Do not approve the first available number. Run the full suite at least three
times after rebooting into the documented runner configuration, reject runs
with unrelated load or thermal throttling, and select a representative median
run. A deliberate optimization should normally keep the old baseline for at
least one merge so the reported gain is visible. Update the baseline only in a
separate reviewed change with the old/new comparison artifact attached.

---

# Ram 性能基线

本目录提供端到端基准而非微基准。它启动真实 debug/release Ram 二进制，发送已认证请求并
输出机器可读 JSON，覆盖：顺序大文件 GET/PUT/SHA-256；精确 10,000 条目目录的列表、全树
无匹配搜索和 ZIP；服务器流上限为 1/8/32 的持久 HTTP/1.1 与 HTTP/2 传输；从 `/proc`
采样 RSS、fd 和线程峰值；用哈希制造昂贵工作线程饱和；以及 debug/release 配对值和差异。

`blocking_queue_delay_proxy_ms` 是相对单请求运行的额外延迟。Tokio 不暴露内部阻塞队列长度，
报告不会虚构精确计数，而会同时记录提供并发和所配昂贵任务槽。

基准在显式预热后测量热缓存。它不会清空主机页缓存，因为那会需要特权且影响无关工作负载；
若契约关注冷缓存磁盘吞吐量，应单独测试存储。

## 本地烟测

构建 debug 二进制；未安装 `h2load` 时运行小型仅端点烟测：

```sh
cargo build --locked
python3 benchmarks/run.py \
  --preset smoke \
  --skip-load \
  --binary debug=target/debug/ram \
  --output /tmp/ram-performance-smoke.json
python3 benchmarks/compare.py candidate \
  --allow-smoke \
  --result /tmp/ram-performance-smoke.json \
  --thresholds benchmarks/thresholds.json \
  --output /tmp/ram-performance-smoke-candidate.json
```

烟测候选标为 `review.status: smoke-candidate`，比较器绝不接受其作为正式基线。它只用于验证
harness，不用于声称生产性能。无依赖自测命令为：

```sh
python3 benchmarks/run.py --self-test
python3 benchmarks/compare.py self-test
```

## 正式 Runner 契约

正式测量只在 `.github/workflows/performance.yaml` 的专用 runner 上执行，并要求标签：

```text
self-hosted, linux, x64, ram-benchmark
```

runner 不与构建/应用任务共享。`ram-benchmark` 标签表示运维人员保证：至少 8 个在线逻辑 CPU，
2-5 专用于 Ram、6-7 专用于 curl/h2load；这些 CPU 使用 performance governor，固件/SMT/NUMA
稳定且无超售；`RUNNER_TEMP` 位于空间与内存充足的稳定本地文件系统，而非 NFS/FUSE/共享
overlay/网络 home；工具为 Rust 1.96.0、支持 HTTP/2 的 curl，以及支持 `--h1`、`--alpn-list`、
`--max-concurrent-streams` 的 nghttp2 h2load；机器上无并发基准任务。

管理员逐项验证并设置 `RAM_BENCHMARK_ENABLED=true` 前，定时任务保持禁用，不会永久排队等待
未配置 runner。手动 dispatch 是显式操作，若 runner 不会上线应取消。

`--strict-environment` 拒绝缺失/相交 CPU 集、非 performance governor、默认本地 runner ID、
未指定构建契约和不兼容工具。结果记录内核、CPU、内存、文件系统、亲和性、governor、工具版本、
二进制哈希和环境指纹；这些条件变化都要求重新审查基线，不能比较不同主机。

## 候选、审阅与强制

仓库不包含虚构数值基线。专用 runner 首次完整运行生成候选：

```sh
python3 benchmarks/compare.py candidate \
  --result performance-result.json \
  --thresholds benchmarks/thresholds.json \
  --output performance-baseline-candidate.json
```

在 PR 中审查原始结果、runner 状态、重复方差、debug/release 差异和阈值。批准时把候选复制为
`benchmarks/baselines/dedicated-linux-x86_64-v1.json`，只修改 review 块，包含：

```json
{
  "status": "approved",
  "approved_by": ["github-reviewer"],
  "approved_at_utc": "2026-07-21T00:00:00Z",
  "evidence_url": "https://github.com/OWNER/REPOSITORY/pull/NUMBER",
  "notes": "Three stable full runs reviewed; this file selects the median run."
}
```

比较器只接受完整运行、40 字符源 commit、完整批准元数据、HTTPS 证据 URL、完全相同 runner/
环境指纹和当前阈值策略 SHA-256。它只比较已审查基线中的指标，新指标只报告、不自动成为门禁。

```sh
python3 benchmarks/compare.py compare \
  --result performance-result.json \
  --baseline benchmarks/baselines/dedicated-linux-x86_64-v1.json \
  --thresholds benchmarks/thresholds.json \
  --output performance-comparison.json
```

批准文件存在前，定时 workflow 只记录候选；合并后 `auto` 模式强制执行。手动 `enforce` 在基线
缺失时失败；共享 GitHub runner 从不强制这些阈值。

## 结果稳定性

不要批准第一个数值。以文档化配置重启后至少完整运行三次，排除无关负载/热降频，选择代表性
中位运行。优化通常至少保留旧基线一次合并以显示收益；只在独立审阅变更中更新基线，并附
新旧比较制品。
