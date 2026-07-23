#!/usr/bin/env python3
"""生成并验证把目标架构、二进制和 SBOM SHA-256 绑定在一起的发布清单。

Create and verify the release manifest binding target, binary, and SBOM SHA-256 digests.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import stat
import sys
import tempfile
from typing import Any


SCHEMA = "https://github.com/isarmg/ram/attestations/release-manifest/v1"
TARGETS = ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu")
VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?")
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")
MAX_INPUT_BYTES = 64 * 1024 * 1024


class ManifestError(ValueError):
    """清单或其绑定文件不符合发布策略。 / A manifest or bound file violates release policy."""


def file_record(path: pathlib.Path, expected_name: str) -> dict[str, Any]:
    if path.name != expected_name:
        raise ManifestError(f"expected file name {expected_name!r}, got {path.name!r}")
    try:
        details = path.lstat()
        if not stat.S_ISREG(details.st_mode):
            raise ManifestError(f"bound input is not a regular file: {path}")
        if details.st_size <= 0 or details.st_size > MAX_INPUT_BYTES:
            raise ManifestError(
                f"bound input {path} is {details.st_size} bytes; limit is {MAX_INPUT_BYTES}"
            )
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except ManifestError:
        raise
    except OSError as error:
        raise ManifestError(f"cannot read bound input {path}: {error}") from error
    return {"name": expected_name, "size": details.st_size, "sha256": digest}


def expected_manifest(
    version: str,
    target: str,
    repository: str,
    commit: str,
    binary: pathlib.Path,
    cyclonedx: pathlib.Path,
    spdx: pathlib.Path,
) -> dict[str, Any]:
    """从受信工作流参数与当前文件字节重建唯一允许的清单。校验绝不信任待检文档自报的
    名称、大小或摘要。

    Reconstruct the only admissible manifest from trusted workflow inputs and
    the current bytes of every bound file. Verification never trusts names,
    sizes, or digests copied out of the document being checked.
    """

    if VERSION_PATTERN.fullmatch(version) is None:
        raise ManifestError(f"invalid release version {version!r}")
    if target not in TARGETS:
        raise ManifestError(f"unsupported release target {target!r}")
    if repository != "https://github.com/isarmg/ram":
        raise ManifestError(f"unexpected source repository {repository!r}")
    if COMMIT_PATTERN.fullmatch(commit) is None:
        raise ManifestError(f"invalid source commit {commit!r}")
    return {
        "schema": SCHEMA,
        "version": version,
        "target": target,
        "source": {"repository": repository, "commit": commit},
        "binary": file_record(binary, "ram"),
        "sboms": [
            {
                "format": "CycloneDX-1.3",
                **file_record(cyclonedx, f"ram-fileserver-{target}.cdx.json"),
            },
            {
                "format": "SPDX-2.3",
                **file_record(spdx, "ram-fileserver.spdx.json"),
            },
        ],
    }


def write_manifest(path: pathlib.Path, manifest: dict[str, Any]) -> None:
    expected_name = f"ram-v{manifest['version']}-{manifest['target']}.supply-chain.json"
    if path.name != expected_name:
        raise ManifestError(f"manifest output must be named {expected_name!r}")
    try:
        path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except OSError as error:
        raise ManifestError(f"cannot write release manifest {path}: {error}") from error


def verify_manifest(path: pathlib.Path, expected: dict[str, Any]) -> None:
    """要求完整 JSON 值精确相等，拒绝缺字段、额外字段与陈旧摘要。

    Require exact whole-document equality, rejecting omitted/extra fields and
    stale digests rather than validating only a permissive schema subset.
    """

    try:
        if path.stat().st_size > MAX_INPUT_BYTES:
            raise ManifestError(f"release manifest exceeds {MAX_INPUT_BYTES} bytes")
        observed = json.loads(path.read_text(encoding="utf-8"))
    except ManifestError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ManifestError(f"cannot read release manifest {path}: {error}") from error
    if observed != expected:
        raise ManifestError("release manifest does not exactly match the bound files")


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="ram-release-manifest-") as directory:
        root = pathlib.Path(directory)
        target = TARGETS[0]
        binary = root / "ram"
        cyclonedx = root / f"ram-fileserver-{target}.cdx.json"
        spdx = root / "ram-fileserver.spdx.json"
        output = root / f"ram-v1.2.3-{target}.supply-chain.json"
        binary.write_bytes(b"binary\n")
        cyclonedx.write_text('{"bomFormat":"CycloneDX"}\n', encoding="utf-8")
        spdx.write_text('{"spdxVersion":"SPDX-2.3"}\n', encoding="utf-8")
        expected = expected_manifest(
            "1.2.3",
            target,
            "https://github.com/isarmg/ram",
            "a" * 40,
            binary,
            cyclonedx,
            spdx,
        )
        write_manifest(output, expected)
        verify_manifest(output, expected)
        observed = json.loads(output.read_text(encoding="utf-8"))
        for mutation in (
            lambda value: value.update({"target": TARGETS[1]}),
            lambda value: value["binary"].update({"sha256": "0" * 64}),
            lambda value: value["sboms"][0].update({"name": "wrong.json"}),
            lambda value: value.update({"unexpected": True}),
        ):
            invalid = json.loads(json.dumps(observed))
            mutation(invalid)
            output.write_text(json.dumps(invalid), encoding="utf-8")
            try:
                verify_manifest(output, expected)
            except ManifestError:
                continue
            raise AssertionError("invalid release manifest fixture was accepted")
        write_manifest(output, expected)
        binary.write_bytes(b"changed binary\n")
        changed_files = expected_manifest(
            "1.2.3",
            target,
            "https://github.com/isarmg/ram",
            "a" * 40,
            binary,
            cyclonedx,
            spdx,
        )
        try:
            verify_manifest(output, changed_files)
        except ManifestError:
            pass
        else:
            raise AssertionError("manifest accepted a changed bound binary")
    print("release supply-chain manifest self-test passed")


def add_binding_arguments(command: argparse.ArgumentParser) -> None:
    command.add_argument("--version", required=True)
    command.add_argument("--target", required=True)
    command.add_argument("--repository", required=True)
    command.add_argument("--commit", required=True)
    command.add_argument("--binary", type=pathlib.Path, required=True)
    command.add_argument("--cyclonedx", type=pathlib.Path, required=True)
    command.add_argument("--spdx", type=pathlib.Path, required=True)
    command.add_argument("--manifest", type=pathlib.Path, required=True)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    add_binding_arguments(commands.add_parser("create", help="write a deterministic manifest"))
    add_binding_arguments(commands.add_parser("verify", help="verify an existing manifest"))
    commands.add_parser("self-test", help="run deterministic positive and negative fixtures")
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "self-test":
            self_test()
            return 0
        expected = expected_manifest(
            args.version,
            args.target,
            args.repository,
            args.commit,
            args.binary,
            args.cyclonedx,
            args.spdx,
        )
        if args.command == "create":
            write_manifest(args.manifest, expected)
            print(f"wrote release supply-chain manifest {args.manifest}")
        else:
            verify_manifest(args.manifest, expected)
            print(f"verified release supply-chain manifest {args.manifest}")
    except ManifestError as error:
        print(f"release manifest verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
