#!/usr/bin/env python3
"""验证发布 tar 的精确成员、条目类型和解压大小边界。

Validate the exact member inventory, entry types, and expansion bounds of a release tarball.
"""

from __future__ import annotations

import argparse
import gzip
import io
import pathlib
import stat
import sys
import tarfile
import tempfile
from typing import BinaryIO


MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 96 * 1024 * 1024
# 中文：普通文件预算之外只给 tar 头、对齐填充和扩展元数据 1 MiB。
# English: Allow only 1 MiB beyond regular-file content for tar headers, padding, and extensions.
MAX_EXPANDED_ARCHIVE_BYTES = MAX_TOTAL_BYTES + 1024 * 1024
TARGETS = ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu")
BASE_FILES = frozenset(
    {
        "ram",
        "LICENSE-APACHE",
        "LICENSE-MIT",
        "README.md",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "CHANGELOG.md",
        "config.example.yaml",
        "docs/CODE_FLOW.md",
        "docs/REPOSITORY_GOVERNANCE.md",
        "docs/THREAT_MODEL.md",
        "ram-fileserver.spdx.json",
        "THIRD-PARTY-LICENSES.html",
        "DEPENDENCIES.txt",
        "RELEASE-METRICS.txt",
        "RUNTIME-LINKAGE.txt",
    }
)


class ArchivePolicyError(ValueError):
    """归档不满足发布成员或资源策略。 / The archive violates the release inventory or resource policy."""


class BoundedExpandedReader:
    """在 tarfile 解析 PAX/GNU 元数据前限制整个解压字节流。

    Bound the complete decompressed stream before tarfile parses PAX/GNU metadata.
    """

    def __init__(self, source: BinaryIO, maximum: int) -> None:
        if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < 1:
            raise ArchivePolicyError(f"invalid expanded archive limit: {maximum!r}")
        self.source = source
        self.maximum = maximum
        self.received = 0

    def read(self, size: int = -1) -> bytes:
        # 中文：最多向下层多读 1 字节来证明越界，不能先按攻击者声明的
        # PAX 长度分配一个无界缓冲区。
        # English: Read at most one byte beyond the remaining budget to prove an
        # overflow; never allocate according to an attacker-declared PAX length.
        remaining = self.maximum - self.received
        requested = remaining + 1 if size < 0 else min(size, remaining + 1)
        data = self.source.read(requested)
        self.received += len(data)
        if self.received > self.maximum:
            raise ArchivePolicyError(
                f"archive expands beyond the {self.maximum}-byte complete-stream limit"
            )
        return data


def expected_members(stage: str) -> tuple[frozenset[str], frozenset[str]]:
    if (
        not stage
        or stage.startswith("/")
        or "/" in stage
        or stage in {".", ".."}
    ):
        raise ArchivePolicyError(f"invalid release stage name: {stage!r}")
    target = next(
        (candidate for candidate in TARGETS if stage.endswith(f"-{candidate}")), None
    )
    if target is None:
        raise ArchivePolicyError(f"release stage has an unsupported target: {stage!r}")
    allowed_files = BASE_FILES | {
        f"ram-fileserver-{target}.cdx.json",
        f"{stage}.supply-chain.json",
    }
    directories = frozenset({stage, f"{stage}/docs"})
    return directories, directories | frozenset(
        f"{stage}/{name}" for name in allowed_files
    )


def verify_archive(
    archive: pathlib.Path,
    stage: str,
    *,
    maximum_expanded_bytes: int = MAX_EXPANDED_ARCHIVE_BYTES,
) -> int:
    directories, expected = expected_members(stage)
    try:
        details = archive.lstat()
    except OSError as error:
        raise ArchivePolicyError(f"cannot inspect release archive {archive}: {error}") from error
    if not stat.S_ISREG(details.st_mode):
        raise ArchivePolicyError(f"release archive is not a regular file: {archive}")
    if details.st_size <= 0 or details.st_size > MAX_ARCHIVE_BYTES:
        raise ArchivePolicyError(
            f"release archive is {details.st_size} bytes; limit is {MAX_ARCHIVE_BYTES}"
        )

    seen: set[str] = set()
    total_bytes = 0
    try:
        # 中文：`tarfile` 会在返回成员前把 PAX/GNU 扩展头读入内存，故只统计
        # `member.size` 太晚。先显式解 gzip，再让流式 tar 解析器只能看到有界读取器。
        # English: tarfile consumes PAX/GNU extension bodies before yielding a
        # member, so summing member.size is too late. Decompress explicitly and
        # expose only a bounded reader to the streaming tar parser.
        with archive.open("rb") as compressed:
            with gzip.GzipFile(fileobj=compressed, mode="rb") as expanded:
                bounded = BoundedExpandedReader(expanded, maximum_expanded_bytes)
                with tarfile.open(fileobj=bounded, mode="r|") as bundle:
                    for member in bundle:
                        raw_name = member.name
                        name = raw_name.rstrip("/")
                        parts = name.split("/")
                        if (
                            not name
                            or raw_name.startswith("/")
                            or any(part in {"", ".", ".."} for part in parts)
                        ):
                            raise ArchivePolicyError(f"unsafe archive path: {raw_name!r}")
                        if name in seen:
                            raise ArchivePolicyError(f"duplicate archive member: {name!r}")
                        seen.add(name)
                        if name not in expected:
                            raise ArchivePolicyError(f"unexpected archive member: {name!r}")
                        if name in directories:
                            if not member.isdir():
                                raise ArchivePolicyError(
                                    f"archive directory has wrong type: {name!r}"
                                )
                            continue
                        if not member.isfile():
                            raise ArchivePolicyError(f"archive file is not regular: {name!r}")
                        if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                            raise ArchivePolicyError(
                                f"archive member {name!r} is {member.size} bytes; "
                                f"per-member limit is {MAX_MEMBER_BYTES}"
                            )
                        total_bytes += member.size
                        if total_bytes > MAX_TOTAL_BYTES:
                            raise ArchivePolicyError(
                                f"archive expands to more than {MAX_TOTAL_BYTES} regular-file bytes"
                            )
    except ArchivePolicyError:
        raise
    except (OSError, tarfile.TarError) as error:
        raise ArchivePolicyError(f"cannot parse release archive {archive}: {error}") from error

    missing = sorted(expected - seen)
    if missing:
        raise ArchivePolicyError(f"archive is missing required members: {missing!r}")
    return len(seen)


def write_fixture(
    path: pathlib.Path,
    stage: str,
    *,
    omitted: frozenset[str] = frozenset(),
    unexpected: str | None = None,
    link_member: str | None = None,
) -> None:
    """构造小型确定性归档，仅用于策略自测试。 / Build a small deterministic archive used only by policy self-tests."""

    directories, expected = expected_members(stage)
    with tarfile.open(path, "w:gz") as bundle:
        for name in sorted(directories):
            if name in omitted:
                continue
            entry = tarfile.TarInfo(name)
            entry.type = tarfile.DIRTYPE
            entry.mode = 0o755
            entry.mtime = 1
            bundle.addfile(entry)
        file_names = sorted(expected - directories)
        if unexpected is not None:
            file_names.append(f"{stage}/{unexpected}")
        for name in file_names:
            if name in omitted:
                continue
            entry = tarfile.TarInfo(name)
            entry.mode = 0o755 if name == f"{stage}/ram" else 0o644
            entry.mtime = 1
            if name == link_member:
                entry.type = tarfile.SYMTYPE
                entry.linkname = "README.md"
                bundle.addfile(entry)
            else:
                contents = b"fixture\n"
                entry.size = len(contents)
                bundle.addfile(entry, io.BytesIO(contents))


def expect_rejected(
    archive: pathlib.Path,
    stage: str,
    *,
    maximum_expanded_bytes: int = MAX_EXPANDED_ARCHIVE_BYTES,
) -> None:
    try:
        verify_archive(
            archive, stage, maximum_expanded_bytes=maximum_expanded_bytes
        )
    except ArchivePolicyError:
        return
    raise AssertionError(f"invalid release archive fixture was accepted: {archive.name}")


def self_test() -> None:
    stage = "ram-v1.2.3-x86_64-unknown-linux-gnu"
    if "docs/CODE_FLOW.md" not in BASE_FILES:
        raise AssertionError("code-flow documentation is absent from the release policy")
    with tempfile.TemporaryDirectory(prefix="ram-release-archive-") as directory:
        root = pathlib.Path(directory)
        valid = root / "valid.tar.gz"
        write_fixture(valid, stage)
        verify_archive(valid, stage)
        # 中文：低测试阈值确定边界覆盖整个 tar 流，而不只覆盖成员内容。
        # English: A low fixture limit proves the boundary covers the whole tar stream,
        # not merely the content sizes reported by yielded members.
        expect_rejected(valid, stage, maximum_expanded_bytes=1024)

        missing_flow = root / "missing-code-flow.tar.gz"
        write_fixture(
            missing_flow,
            stage,
            omitted=frozenset({f"{stage}/docs/CODE_FLOW.md"}),
        )
        expect_rejected(missing_flow, stage)

        unexpected = root / "unexpected.tar.gz"
        write_fixture(unexpected, stage, unexpected="docs/UNREVIEWED.md")
        expect_rejected(unexpected, stage)

        linked_binary = root / "linked-binary.tar.gz"
        write_fixture(linked_binary, stage, link_member=f"{stage}/ram")
        expect_rejected(linked_binary, stage)
    print("release archive policy self-test passed")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify", help="validate one packaged release archive")
    verify.add_argument("archive", type=pathlib.Path)
    verify.add_argument("stage")
    commands.add_parser("self-test", help="run deterministic positive and negative fixtures")
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "self-test":
            self_test()
        else:
            count = verify_archive(args.archive, args.stage)
            print(f"archive policy passed: {count} exact regular/directory members")
    except ArchivePolicyError as error:
        print(f"release archive policy failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
