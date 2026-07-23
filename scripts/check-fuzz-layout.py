#!/usr/bin/env python3
"""阻止 fuzz target、harness、corpus、CI 矩阵和文档清单发生漂移。

Keep fuzz targets, harnesses, corpora, CI matrices, and documented shell lists in sync.
"""

from __future__ import annotations

import pathlib
import re
import shlex
import sys
import tomllib


ROOT = pathlib.Path(__file__).resolve().parent.parent


class FuzzLayoutError(ValueError):
    """fuzz 目录或其消费者不一致。 / The fuzz tree or one of its consumers is inconsistent."""


def read_text(relative: str) -> str:
    path = ROOT / relative
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise FuzzLayoutError(f"cannot read {relative}: {error}") from error


def manifest_targets() -> tuple[tuple[str, str], ...]:
    path = ROOT / "fuzz/Cargo.toml"
    try:
        with path.open("rb") as stream:
            document = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise FuzzLayoutError(f"cannot parse fuzz/Cargo.toml: {error}") from error
    bins = document.get("bin")
    if not isinstance(bins, list) or not bins:
        raise FuzzLayoutError("fuzz/Cargo.toml must define at least one [[bin]]")

    targets: list[tuple[str, str]] = []
    for index, value in enumerate(bins):
        if not isinstance(value, dict):
            raise FuzzLayoutError(f"fuzz/Cargo.toml bin {index} must be a table")
        name = value.get("name")
        harness = value.get("path")
        if not isinstance(name, str) or re.fullmatch(r"[a-z][a-z0-9_]*", name) is None:
            raise FuzzLayoutError(f"fuzz/Cargo.toml bin {index} has invalid name {name!r}")
        expected_path = f"fuzz_targets/{name}.rs"
        if harness != expected_path:
            raise FuzzLayoutError(
                f"fuzz target {name!r} path must be {expected_path!r}, got {harness!r}"
            )
        targets.append((name, harness))
    names = [name for name, _ in targets]
    if len(names) != len(set(names)):
        raise FuzzLayoutError("fuzz/Cargo.toml contains duplicate target names")
    return tuple(targets)


def workflow_target_matrices(contents: str) -> list[tuple[str, ...]]:
    """读取 matrix.target 的简单 YAML 序列，不引入第二个 YAML 解析依赖。

    Read plain matrix.target YAML sequences without adding another YAML parser dependency.
    """

    lines = contents.splitlines()
    matrices: list[tuple[str, ...]] = []
    for index, line in enumerate(lines):
        match = re.fullmatch(r"(\s*)target:\s*", line)
        if match is None:
            continue
        item_indent = len(match.group(1)) + 2
        values: list[str] = []
        for candidate in lines[index + 1 :]:
            item = re.fullmatch(rf"\s{{{item_indent}}}-\s+([a-z][a-z0-9_]*)\s*", candidate)
            if item is None:
                break
            values.append(item.group(1))
        if values:
            matrices.append(tuple(values))
    return matrices


def shell_target_lists(contents: str, relative: str) -> list[tuple[str, ...]]:
    blocks = re.findall(r"(?ms)^targets=\(\s*(.*?)\s*\)$", contents)
    parsed: list[tuple[str, ...]] = []
    for index, block in enumerate(blocks):
        try:
            values = tuple(shlex.split(block, comments=True, posix=True))
        except ValueError as error:
            raise FuzzLayoutError(
                f"{relative} targets block {index + 1} is invalid shell syntax: {error}"
            ) from error
        if not values:
            raise FuzzLayoutError(f"{relative} targets block {index + 1} is empty")
        parsed.append(values)
    return parsed


def table_target_lists(contents: str) -> tuple[str, ...]:
    return tuple(
        match.group(1)
        for line in contents.splitlines()
        if (match := re.match(r"^\| `([a-z][a-z0-9_]*)` \|", line)) is not None
    )


def require_equal(actual: tuple[str, ...], expected: tuple[str, ...], label: str) -> None:
    if actual != expected:
        raise FuzzLayoutError(
            f"{label} differs from fuzz/Cargo.toml: expected {expected!r}, got {actual!r}"
        )


def check() -> None:
    targets = manifest_targets()
    expected = tuple(name for name, _ in targets)

    harness_dir = ROOT / "fuzz/fuzz_targets"
    actual_harnesses = tuple(sorted(path.name for path in harness_dir.glob("*.rs")))
    expected_harnesses = tuple(sorted(f"{name}.rs" for name in expected))
    require_equal(actual_harnesses, expected_harnesses, "fuzz harness files")
    for name, harness in targets:
        if not (ROOT / "fuzz" / harness).is_file():
            raise FuzzLayoutError(f"fuzz target {name!r} has no harness file {harness}")

    corpus_root = ROOT / "fuzz/corpus"
    actual_corpora = tuple(sorted(path.name for path in corpus_root.iterdir() if path.is_dir()))
    require_equal(actual_corpora, tuple(sorted(expected)), "fuzz corpus directories")
    for name in expected:
        corpus = corpus_root / name
        if not any(path.is_file() for path in corpus.iterdir()):
            raise FuzzLayoutError(f"fuzz corpus {corpus.relative_to(ROOT)} is empty")

    matrices = workflow_target_matrices(read_text(".github/workflows/fuzz.yaml"))
    if len(matrices) != 2:
        raise FuzzLayoutError(
            f"fuzz workflow must contain exactly two target matrices, found {len(matrices)}"
        )
    for index, matrix in enumerate(matrices, start=1):
        require_equal(matrix, expected, f"fuzz workflow target matrix {index}")

    documentation = (
        ("README.md", 1),
        ("fuzz/README.md", 2),
    )
    for relative, expected_blocks in documentation:
        contents = read_text(relative)
        blocks = shell_target_lists(contents, relative)
        if len(blocks) != expected_blocks:
            raise FuzzLayoutError(
                f"{relative} must contain {expected_blocks} targets blocks, found {len(blocks)}"
            )
        for index, block in enumerate(blocks, start=1):
            require_equal(block, expected, f"{relative} targets block {index}")

    table_targets = table_target_lists(read_text("fuzz/README.md"))
    require_equal(table_targets, expected + expected, "fuzz/README.md bilingual target tables")
    print(f"fuzz layout verified: {len(expected)} targets are synchronized")


def main() -> int:
    try:
        check()
    except (FuzzLayoutError, OSError) as error:
        print(f"fuzz layout check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
