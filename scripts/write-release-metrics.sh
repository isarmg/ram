#!/usr/bin/env bash
set -euo pipefail

if (( $# != 3 )); then
  echo "usage: $0 <target> <release-binary> <output-file>" >&2
  exit 2
fi

target=$1
binary=$2
output=$3

if [[ ! -f "$binary" ]]; then
  echo "release binary does not exist: $binary" >&2
  exit 1
fi
if [[ ! -d "$(dirname -- "$output")" ]]; then
  echo "metrics output directory does not exist: $(dirname -- "$output")" >&2
  exit 1
fi

dependency_tree() {
  local edges=$1
  cargo tree \
    --locked \
    --edges "$edges" \
    --target "$target" \
    --prefix none \
    --format '{p}'
}

count_package_versions() {
  LC_ALL=C sort -u | awk 'NF { count += 1 } END { print count + 0 }'
}

count_unique_names() {
  awk 'NF { print $1 }' | LC_ALL=C sort -u |
    awk 'NF { count += 1 } END { print count + 0 }'
}

normal_tree=$(dependency_tree normal)
normal_build_tree=$(dependency_tree normal,build)
normal_package_versions=$(count_package_versions <<<"$normal_tree")
normal_unique_names=$(count_unique_names <<<"$normal_tree")
normal_build_package_versions=$(count_package_versions <<<"$normal_build_tree")
normal_build_unique_names=$(count_unique_names <<<"$normal_build_tree")
binary_size_bytes=$(stat --format='%s' -- "$binary")
rustc_version=$(rustc --version)
rustc_commit_hash=$(rustc --version --verbose |
  awk -F': ' '$1 == "commit-hash" { print $2 }')
cargo_version=$(cargo --version)

# 中文：工具链提交是发布可复现性证据，字段缺失或格式漂移不能静默生成
# 看似完整的指标文件。
# English: The toolchain commit is release-reproducibility evidence. A missing
# field or format drift must not silently produce an apparently complete report.
if [[ ! $rustc_commit_hash =~ ^[0-9a-f]{40}$ ]]; then
  echo "rustc returned an invalid commit-hash: ${rustc_commit_hash:-<missing>}" >&2
  exit 1
fi

temporary_output="${output}.tmp.$$"
trap 'rm -f -- "$temporary_output"' EXIT
{
  printf 'schema_version=2\n'
  printf 'target=%s\n' "$target"
  printf 'profile=release\n'
  printf 'features=default\n'
  printf 'opt_level=3\n'
  printf 'lto=true\n'
  printf 'codegen_units=1\n'
  printf 'panic=unwind\n'
  printf 'strip=symbols\n'
  printf 'debug=none\n'
  printf 'independent_debug_symbols=not_published\n'
  printf 'binary_size_bytes=%s\n' "$binary_size_bytes"
  printf 'normal_package_versions=%s\n' "$normal_package_versions"
  printf 'normal_unique_crate_names=%s\n' "$normal_unique_names"
  printf 'normal_build_package_versions=%s\n' "$normal_build_package_versions"
  printf 'normal_build_unique_crate_names=%s\n' "$normal_build_unique_names"
  printf 'rustc=%s\n' "$rustc_version"
  printf 'rustc_commit_hash=%s\n' "$rustc_commit_hash"
  printf 'cargo=%s\n' "$cargo_version"
  printf 'count_scope=target-filtered package graph including the workspace package\n'
} >"$temporary_output"
mv -- "$temporary_output" "$output"
trap - EXIT
