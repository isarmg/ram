#!/usr/bin/env bash
set -euo pipefail

# 让仅测试参考客户端远离所有受支持生产依赖图。`cargo tree` 检查目标时不需要其 Rust 标准库，
# 因此单个 CI runner 就能覆盖两种发布架构。
# Keep test-only reference clients out of every supported production graph. `cargo tree` does not need
# the target standard library, so one CI runner can cover both release architectures.
if (( $# == 0 )); then
  set -- x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu
fi

for target in "$@"; do
  tree=$(cargo tree \
    --locked \
    --all-features \
    --edges normal,build \
    --target "$target" \
    --prefix none \
    --format '{p}')

  violations=$(awk '$1 == "digest_auth" || $1 == "md-5"' <<<"$tree")
  if [[ -n "$violations" ]]; then
    printf 'test-only crates entered the %s production dependency graph:\n%s\n' \
      "$target" "$violations" >&2
    exit 1
  fi

  printf 'production dependency boundary ok: %s\n' "$target"
done
