#!/usr/bin/env bash
set -euo pipefail

# 从任意调用目录绑定到本脚本所属仓库，避免误查相邻 Cargo 项目。
# Bind to this script's repository from any caller directory so an adjacent Cargo project cannot be checked by mistake.
script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd -- "$repo_root"

# 让仅测试参考客户端远离唯一受支持的 Linux x86_64 生产依赖图。
# Keep test-only reference clients out of the only supported Linux x86_64 production graph.
if (( $# == 0 )); then
  set -- x86_64-unknown-linux-gnu
fi

for target in "$@"; do
  tree=$(cargo tree \
    --locked \
    --all-features \
    --edges normal,build \
    --target "$target" \
    --prefix none \
    --format '{p}')

  violations=$(awk '
    $1 == "digest_auth" ||
    $1 == "h2" ||
    $1 == "md-5" ||
    $1 == "quick-xml" ||
    $1 == "rustls" ||
    $1 == "rustls-pki-types" ||
    $1 == "tokio-rustls"
  ' <<<"$tree")
  if [[ -n "$violations" ]]; then
    printf 'removed or test-only crates entered the %s production dependency graph:\n%s\n' \
      "$target" "$violations" >&2
    exit 1
  fi

  printf 'production dependency boundary ok: %s\n' "$target"
done
