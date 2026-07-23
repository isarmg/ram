#!/usr/bin/env python3
"""可靠地把大量 LLVM raw coverage profile 合并为 cargo-llvm-cov 可复用的索引。

Rust 工具链附带的 llvm-profdata 曾在一次合并数百个 profile 时触发内部崩溃。这里先逐个
验证并索引 raw profile，再以平衡二叉树合并索引结果，使每次 llvm-profdata 调用最多读取
两个已验证输入。任何无法单独索引的 profile 都会使任务关闭失败并保留全部 raw profile，
避免成功报告悄然缺失覆盖率数据。

Reliably merge many LLVM raw coverage profiles into the indexed file cargo-llvm-cov reuses.

The llvm-profdata bundled with the Rust toolchain has crashed internally while merging hundreds of
profiles in one invocation. Validate and index every raw profile separately, then merge indexed
results as a balanced binary tree so each subsequent invocation reads at most two verified inputs.
Any profile that cannot be indexed alone fails the job and preserves every raw profile, preventing a
successful report from silently omitting coverage data.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--llvm-profdata", required=True, type=Path)
    parser.add_argument("--profile-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def merge(
    llvm_profdata: Path,
    inputs: list[Path],
    output: Path,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            str(llvm_profdata),
            "merge",
            "-sparse",
            "-o",
            str(output),
            *(str(path) for path in inputs),
            "--num-threads=1",
        ],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def failure_detail(result: subprocess.CompletedProcess[str]) -> str:
    detail = result.stderr.strip() or result.stdout.strip()
    if not detail:
        detail = f"llvm-profdata exited with status {result.returncode}"
    return detail[-4_000:]


def main() -> int:
    args = parse_args()
    llvm_profdata = args.llvm_profdata.resolve()
    profile_dir = args.profile_dir.resolve()
    output = args.output.resolve()

    if not llvm_profdata.is_file() or not os.access(llvm_profdata, os.X_OK):
        raise ValueError(f"llvm-profdata is not executable: {llvm_profdata}")
    if not profile_dir.is_dir():
        raise ValueError(f"coverage profile directory does not exist: {profile_dir}")
    if output.parent != profile_dir:
        raise ValueError("indexed coverage output must be directly inside the profile directory")

    raw_profiles = sorted(profile_dir.glob("*.profraw"))
    if not raw_profiles:
        raise ValueError(f"no LLVM raw profiles found in {profile_dir}")

    invalid_profiles: list[Path] = []
    with tempfile.TemporaryDirectory(prefix=".ram-profdata-", dir=profile_dir) as temporary:
        temporary_dir = Path(temporary)
        indexed: list[Path] = []
        for index, raw_profile in enumerate(raw_profiles):
            leaf = temporary_dir / f"leaf-{index:06}.profdata"
            result = merge(llvm_profdata, [raw_profile], leaf)
            if result.returncode == 0 and leaf.is_file() and leaf.stat().st_size > 0:
                indexed.append(leaf)
                continue
            invalid_profiles.append(raw_profile)
            print(
                f"error: unusable LLVM raw profile {raw_profile.name}: "
                f"{failure_detail(result)}",
                file=sys.stderr,
            )

        if invalid_profiles:
            names = ", ".join(profile.name for profile in invalid_profiles)
            raise RuntimeError(
                f"llvm-profdata rejected {len(invalid_profiles)} raw coverage "
                f"profile(s); inputs preserved: {names}"
            )

        level = 0
        while len(indexed) > 1:
            next_level: list[Path] = []
            for pair_index in range(0, len(indexed), 2):
                pair = indexed[pair_index : pair_index + 2]
                if len(pair) == 1:
                    next_level.append(pair[0])
                    continue
                merged = temporary_dir / f"level-{level:03}-{pair_index // 2:06}.profdata"
                result = merge(llvm_profdata, pair, merged)
                if result.returncode != 0 or not merged.is_file() or merged.stat().st_size == 0:
                    raise RuntimeError(
                        "llvm-profdata failed while merging two validated indexed profiles: "
                        f"{failure_detail(result)}"
                    )
                next_level.append(merged)
            indexed = next_level
            level += 1

        staged_output = temporary_dir / "final.profdata"
        shutil.copyfile(indexed[0], staged_output)
        if staged_output.stat().st_size == 0:
            raise RuntimeError("merged LLVM coverage profile is empty")
        os.replace(staged_output, output)

    for raw_profile in raw_profiles:
        raw_profile.unlink(missing_ok=True)

    print(f"merged {len(raw_profiles)} validated LLVM profiles into {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"coverage profile merge failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
