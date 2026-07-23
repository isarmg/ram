# 解析器模糊测试

`fuzz/` 是独立且锁定的 cargo-fuzz workspace。生产构建不会公开解析器内部；只有启用
`fuzzing` feature 的 harness 构建可以调用这些有界入口。

## 目标

| 目标 | 边界 |
| --- | --- |
| `digest_auth_params` | Digest 认证参数解析 |
| `uri_path` | URI 编码、路径前缀和能力相对规范化 |
| `range_if_range` | Range 与 If-Range 解析和求值 |
| `destination_host_prefix` | MOVE Destination、Host 和 URI 前缀 |
| `log_format` | 访问日志格式变量和脱敏渲染 |
| `zip_entry_name` | Linux 文件名编码和 ZIP 路径包含性 |

每个目标在 `corpus/<target>/` 下有非空的已审查种子。语料不得包含生产数据或凭据。

## 本地运行

```sh
rustup toolchain install nightly-2026-07-22
cargo install --locked cargo-fuzz --version 0.13.2
cargo +nightly-2026-07-22 check --manifest-path fuzz/Cargo.toml --locked

targets=(
  digest_auth_params
  uri_path
  range_if_range
  destination_host_prefix
  log_format
  zip_entry_name
)

for target in "${targets[@]}"; do
  seed_dir="fuzz/corpus/$target"
  corpus_dir="target/fuzz-corpus/$target"
  rm -rf "$corpus_dir"
  mkdir -p "$corpus_dir" "fuzz/artifacts/$target"
  cp -a "$seed_dir/." "$corpus_dir/"
  cargo +nightly-2026-07-22 fuzz run "$target" "$corpus_dir" -- \
    -runs=256 \
    -max_len=65536 \
    -timeout=10 \
    -rss_limit_mb=2048 \
    -artifact_prefix="fuzz/artifacts/$target/"
done
```

`.github/workflows/fuzz.yaml` 只在每月计划任务或管理员手动触发时运行。每个目标的 CI
campaign 最长 600 秒，失败时上传复现器。将复现器加入语料前必须确认其中没有敏感数据。
