# Parser fuzzing

The fuzz package is a separate, locked Cargo workspace. Production builds do
not expose parser internals; `ram-fileserver/fuzzing` only exports bounded
harness entry points to this package.

## Targets and checked-in corpus

| Target | Boundary exercised | Harness input cap | Corpus framing |
| --- | --- | ---: | --- |
| `digest_auth_params` | Digest auth-param token/quoted-string parser | 16 KiB | raw header bytes |
| `uri_path` | path prefix, percent decode, URI encoding and capability-relative normalization | 64 KiB (prefix: 1 KiB) | `prefix\nrequest-path` or NUL separator |
| `range_if_range` | byte Range plus If-Range parsing/evaluation | 16 KiB | `size\nRange\nIf-Range`; arbitrary input falls back to an 8-byte little-endian size |
| `webdav_xml` | bounded PROPFIND/PROPPATCH XML, expanded names and response rendering | 64 KiB | raw XML |
| `destination_host_prefix` | Destination/Host same-origin and URI-prefix routing | 64 KiB | `Destination\nHost\nprefix` or NUL separators |
| `log_format` | bounded access-log variables, headers and rendering | 64 KiB | raw UTF-8 format |
| `zip_entry_name` | lossless Linux filename encoding and cross-platform archive containment | 64 KiB | raw Linux path bytes |

Every target has a non-empty directory under `corpus/<target>/`. Seeds include
valid boundary examples and intentionally malformed/cross-boundary examples;
they contain no credentials or production data. `Cargo.lock` is committed so
the target dependency graph is reproducible.

## Local smoke

Install the same cargo-fuzz version used in CI, verify the locked target graph,
then run exactly 256 inputs per target. Each libFuzzer execution has a five
second per-input timeout, a 64 KiB mutation cap and a 2 GiB RSS cap:

```sh
rustup toolchain install nightly-2026-07-22
cargo install --locked cargo-fuzz --version 0.13.2
cargo +nightly-2026-07-22 check --manifest-path fuzz/Cargo.toml --locked

targets=(
  digest_auth_params uri_path range_if_range webdav_xml
  destination_host_prefix log_format zip_entry_name
)
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

`cargo-fuzz 0.13.2` does not expose Cargo's `--locked` flag on `fuzz run`.
The explicit locked `cargo check` above fails if the committed graph is stale;
the subsequent run uses the same standalone `fuzz/Cargo.lock` and manifest.
Checked-in seeds are copied into the ignored `target/fuzz-corpus/<target>/`
workspace before every run so libFuzzer can retain discoveries without
modifying the reviewed source corpus.

## Bounded long campaign

The long CI job uses seven independent matrix jobs. Each target stops after
1,800 seconds, each input after 10 seconds, and each process at the same 64 KiB
input/2 GiB RSS limits:

```sh
rm -rf target/fuzz-corpus/uri_path
mkdir -p target/fuzz-corpus/uri_path
cp -a fuzz/corpus/uri_path/. target/fuzz-corpus/uri_path/
cargo +nightly-2026-07-22 fuzz run uri_path target/fuzz-corpus/uri_path -- \
  -max_total_time=1800 -max_len=65536 -timeout=10 -rss_limit_mb=2048 \
  -artifact_prefix=fuzz/artifacts/uri_path/
```

`.github/workflows/fuzz.yaml` runs the 256-run smoke on relevant pull requests
and pushes. Its weekly schedule is intentionally disabled unless a repository
owner sets the Actions variable `RAM_SCHEDULED_FUZZ=true`; the same bounded long
campaign can be requested explicitly with the `long_campaign` workflow input.
Crash reproducers are uploaded from `fuzz/artifacts/<target>/` and must be
reviewed for sensitive input before they are checked in as new seeds.

---

# 解析器模糊测试

fuzz 包是独立且锁定的 Cargo workspace。生产构建不暴露解析器内部；
`ram-fileserver/fuzzing` 只向该包导出有界 harness 入口。

## 目标与检入语料

| 目标 | 覆盖边界 | 输入上限 | 语料分帧 |
| --- | --- | ---: | --- |
| `digest_auth_params` | Digest auth-param token/quoted-string 解析器 | 16 KiB | 原始请求头字节 |
| `uri_path` | 路径前缀、百分号解码、URI 编码、能力相对规范化 | 64 KiB（前缀 1 KiB） | `prefix\nrequest-path` 或 NUL |
| `range_if_range` | Range 与 If-Range 解析/求值 | 16 KiB | `size\nRange\nIf-Range`；任意输入回退 8 字节小端大小 |
| `webdav_xml` | 有界 PROPFIND/PROPPATCH XML、扩展名和响应渲染 | 64 KiB | 原始 XML |
| `destination_host_prefix` | Destination/Host 同源与 URI 前缀路由 | 64 KiB | 换行或 NUL 分隔三字段 |
| `log_format` | 有界访问日志变量、请求头和渲染 | 64 KiB | 原始 UTF-8 格式 |
| `zip_entry_name` | Linux 文件名无损编码和跨平台归档包含性 | 64 KiB | 原始 Linux 路径字节 |

每个目标在 `corpus/<target>/` 下都有非空目录，包含有效边界和畸形/跨边界种子，不含凭据或
生产数据。提交 `Cargo.lock` 以保证依赖图可复现。

## 本地烟测

安装 CI 同版 cargo-fuzz，校验锁定依赖图，并对每个目标运行精确 256 个输入。每个输入超时
5 秒，变异上限 64 KiB，RSS 上限 2 GiB：

```sh
rustup toolchain install nightly-2026-07-22
cargo install --locked cargo-fuzz --version 0.13.2
cargo +nightly-2026-07-22 check --manifest-path fuzz/Cargo.toml --locked

targets=(
  digest_auth_params uri_path range_if_range webdav_xml
  destination_host_prefix log_format zip_entry_name
)
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

`cargo-fuzz 0.13.2` 的 `fuzz run` 不暴露 Cargo `--locked`；前面的锁定 `cargo check` 会在提交图
过期时失败，后续运行使用同一独立 lockfile/manifest。每次把已审查种子复制到被忽略的
`target/fuzz-corpus/<target>/`，使 libFuzzer 能保留发现而不修改源语料。

## 有界长时间运行

长 CI 使用七个独立矩阵任务，每目标 1,800 秒、每输入 10 秒，保持 64 KiB/2 GiB 上限：

```sh
rm -rf target/fuzz-corpus/uri_path
mkdir -p target/fuzz-corpus/uri_path
cp -a fuzz/corpus/uri_path/. target/fuzz-corpus/uri_path/
cargo +nightly-2026-07-22 fuzz run uri_path target/fuzz-corpus/uri_path -- \
  -max_total_time=1800 -max_len=65536 -timeout=10 -rss_limit_mb=2048 \
  -artifact_prefix=fuzz/artifacts/uri_path/
```

`.github/workflows/fuzz.yaml` 在相关 PR/push 运行 256 次烟测。除非仓库所有者设置
`RAM_SCHEDULED_FUZZ=true`，每周计划有意禁用；也可用 `long_campaign` workflow 输入显式请求
相同长任务。崩溃复现器上传自 `fuzz/artifacts/<target>/`，检入新种子前必须审查敏感输入。
