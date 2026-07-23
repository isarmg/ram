#!/usr/bin/env python3
"""验证 GitHub 发布草稿只包含本地发布制品。

Verify that a GitHub release draft contains exactly the local release assets.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
import re
import stat
import sys
import tempfile
from typing import Any


TARGETS = (
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
)
METADATA_FILES = tuple(
    f"ram-fileserver-{target}.cdx.json" for target in TARGETS
) + tuple(
    f"ram-v{{version}}-{target}.supply-chain.json" for target in TARGETS
) + (
    "ram-fileserver.spdx.json",
    "THIRD-PARTY-LICENSES.html",
)
VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?")
REPOSITORY_PATTERN = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")
MAX_GITHUB_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_RELEASE_ASSET_BYTES = 64 * 1024 * 1024
MAX_CHECKSUM_FILE_BYTES = 512


class ReleaseAssetError(ValueError):
    """本地文件或远程发布草稿违反发布策略。 / Local files or the remote release draft violate release policy."""


def read_json(path: pathlib.Path) -> Any:
    try:
        size = path.stat().st_size
        if size > MAX_GITHUB_RESPONSE_BYTES:
            raise ReleaseAssetError(
                f"GitHub response {path} is {size} bytes; limit is {MAX_GITHUB_RESPONSE_BYTES}"
            )
        return json.loads(path.read_text(encoding="utf-8"))
    except ReleaseAssetError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseAssetError(f"cannot read JSON from {path}: {error}") from error


def expected_asset_names(version: str) -> tuple[str, ...]:
    if VERSION_PATTERN.fullmatch(version) is None:
        raise ReleaseAssetError(f"invalid release version {version!r}")
    archives = tuple(
        name
        for target in TARGETS
        for name in (
            f"ram-v{version}-{target}.tar.gz",
            f"ram-v{version}-{target}.tar.gz.sha256",
        )
    )
    metadata = tuple(name.format(version=version) for name in METADATA_FILES)
    return archives + metadata


def file_digest(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise ReleaseAssetError(f"cannot hash local release asset {path}: {error}") from error
    return f"sha256:{digest.hexdigest()}"


def verify_archive_checksum(archive: pathlib.Path, checksum: pathlib.Path) -> None:
    """将单行校验和的文件名与直接计算的归档摘要精确绑定。

    Bind a single-line checksum's filename exactly to the directly hashed archive.
    """

    if checksum.name != f"{archive.name}.sha256":
        raise ReleaseAssetError(
            f"checksum path {checksum} does not match archive name {archive.name!r}"
        )
    if any(character in archive.name for character in "\r\n"):
        raise ReleaseAssetError(f"archive filename contains a line break: {archive.name!r}")
    for path, label, maximum in (
        (archive, "release archive", MAX_RELEASE_ASSET_BYTES),
        (checksum, "release checksum", MAX_CHECKSUM_FILE_BYTES),
    ):
        try:
            details = path.lstat()
        except OSError as error:
            raise ReleaseAssetError(f"cannot inspect {label} {path}: {error}") from error
        if not stat.S_ISREG(details.st_mode):
            raise ReleaseAssetError(f"{label} is not a regular file: {path}")
        if details.st_size <= 0 or details.st_size > maximum:
            raise ReleaseAssetError(
                f"{label} {path} is {details.st_size} bytes; limit is {maximum}"
            )

    digest = file_digest(archive).removeprefix("sha256:")
    expected = f"{digest}  {archive.name}\n".encode("ascii")
    try:
        actual = checksum.read_bytes()
    except OSError as error:
        raise ReleaseAssetError(f"cannot read release checksum {checksum}: {error}") from error
    if actual != expected:
        raise ReleaseAssetError(
            f"release checksum {checksum} must contain exactly one lowercase SHA-256 line "
            f"for {archive.name!r}"
        )


def local_asset_inventory(dist: pathlib.Path, version: str) -> dict[str, tuple[int, str]]:
    expected_names = set(expected_asset_names(version))
    try:
        entries = tuple(dist.iterdir())
    except OSError as error:
        raise ReleaseAssetError(f"cannot list local release directory {dist}: {error}") from error

    observed_names = {entry.name for entry in entries}
    if observed_names != expected_names:
        missing = sorted(expected_names - observed_names)
        unexpected = sorted(observed_names - expected_names)
        raise ReleaseAssetError(
            f"local release assets do not exactly match policy: missing={missing!r}, "
            f"unexpected={unexpected!r}"
        )

    inventory: dict[str, tuple[int, str]] = {}
    for entry in entries:
        try:
            details = entry.lstat()
        except OSError as error:
            raise ReleaseAssetError(f"cannot inspect local release asset {entry}: {error}") from error
        if not stat.S_ISREG(details.st_mode):
            raise ReleaseAssetError(f"local release asset is not a regular file: {entry}")
        if details.st_size <= 0:
            raise ReleaseAssetError(f"local release asset is empty: {entry}")
        if details.st_size > MAX_RELEASE_ASSET_BYTES:
            raise ReleaseAssetError(
                f"local release asset {entry} is {details.st_size} bytes; "
                f"limit is {MAX_RELEASE_ASSET_BYTES}"
            )
        inventory[entry.name] = (details.st_size, file_digest(entry))
    for target in TARGETS:
        archive = dist / f"ram-v{version}-{target}.tar.gz"
        verify_archive_checksum(archive, archive.with_name(f"{archive.name}.sha256"))
    return inventory


def verify_release_assets(
    release: dict[str, Any],
    assets: list[Any],
    local: dict[str, tuple[int, str]],
    version: str,
    release_id: int,
    prerelease: bool,
) -> None:
    if release_id <= 0:
        raise ReleaseAssetError(f"invalid expected release id {release_id!r}")
    expected_release = {
        "id": release_id,
        "tag_name": f"v{version}",
        "draft": True,
        "prerelease": prerelease,
    }
    for field, expected in expected_release.items():
        actual = release.get(field)
        if type(actual) is not type(expected) or actual != expected:
            raise ReleaseAssetError(
                f"release field {field!r} is {actual!r}, expected {expected!r}"
            )

    remote: dict[str, dict[str, Any]] = {}
    for index, asset in enumerate(assets):
        if not isinstance(asset, dict):
            raise ReleaseAssetError(f"remote release asset {index} must be an object")
        name = asset.get("name")
        if not isinstance(name, str) or not name:
            raise ReleaseAssetError(f"remote release asset {index} has an invalid name")
        if name in remote:
            raise ReleaseAssetError(f"remote release contains duplicate asset name {name!r}")
        remote[name] = asset

    local_names = set(local)
    remote_names = set(remote)
    if remote_names != local_names:
        missing = sorted(local_names - remote_names)
        unexpected = sorted(remote_names - local_names)
        raise ReleaseAssetError(
            f"remote release assets do not exactly match local files: missing={missing!r}, "
            f"unexpected={unexpected!r}"
        )

    for name, (expected_size, expected_digest) in local.items():
        asset = remote[name]
        asset_id = asset.get("id")
        if isinstance(asset_id, bool) or not isinstance(asset_id, int) or asset_id <= 0:
            raise ReleaseAssetError(f"remote release asset {name!r} has an invalid id")
        if asset.get("state") != "uploaded":
            raise ReleaseAssetError(
                f"remote release asset {name!r} is not fully uploaded: {asset.get('state')!r}"
            )
        actual_size = asset.get("size")
        if isinstance(actual_size, bool) or not isinstance(actual_size, int) or actual_size != expected_size:
            raise ReleaseAssetError(
                f"remote release asset {name!r} size {actual_size!r} "
                f"does not match local size {expected_size}"
            )
        actual_digest = asset.get("digest")
        if actual_digest != expected_digest:
            raise ReleaseAssetError(
                f"remote release asset {name!r} digest {actual_digest!r} "
                f"does not match local digest {expected_digest!r}"
            )


def release_marker(repository: str, version: str, commit: str) -> str:
    """构造并验证仅属于本仓库、标签和提交的发布标记。

    Build and validate the release marker unique to this repository, tag, and commit.
    """

    if REPOSITORY_PATTERN.fullmatch(repository) is None:
        raise ReleaseAssetError(f"invalid GitHub repository {repository!r}")
    if VERSION_PATTERN.fullmatch(version) is None:
        raise ReleaseAssetError(f"invalid release version {version!r}")
    if COMMIT_PATTERN.fullmatch(commit) is None:
        raise ReleaseAssetError(f"invalid release commit {commit!r}")
    return f"<!-- ram-release-workflow:{repository}:v{version}:{commit} -->"


def verify_published_release(
    release: Any,
    release_id: int,
    version: str,
    commit: str,
    repository: str,
    prerelease: bool,
) -> None:
    """发布后重新绑定完整身份，避免只凭 ID/draft 接受错误的 Release。

    Rebind the complete identity after publication instead of accepting a release
    solely because its numeric ID is no longer a draft.
    """

    if not isinstance(release, dict):
        raise ReleaseAssetError("published GitHub release response must be an object")
    if isinstance(release_id, bool) or not isinstance(release_id, int) or release_id <= 0:
        raise ReleaseAssetError(f"invalid expected release id {release_id!r}")
    if not isinstance(prerelease, bool):
        raise ReleaseAssetError(f"invalid expected prerelease state {prerelease!r}")
    marker = release_marker(repository, version, commit)
    tag = f"v{version}"
    expected_release = {
        "id": release_id,
        "tag_name": tag,
        "draft": False,
        "prerelease": prerelease,
        "name": f"Ram {tag}",
        "target_commitish": commit,
    }
    for field, expected in expected_release.items():
        actual = release.get(field)
        if type(actual) is not type(expected) or actual != expected:
            raise ReleaseAssetError(
                f"published release field {field!r} is {actual!r}, expected {expected!r}"
            )
    published_at = release.get("published_at")
    if not isinstance(published_at, str) or not published_at.strip():
        raise ReleaseAssetError("published release has no publication timestamp")
    body = release.get("body")
    if not isinstance(body, str) or body.count(marker) != 1:
        raise ReleaseAssetError("published release lacks the exact workflow/commit marker")


def verify(
    release_path: pathlib.Path,
    assets_path: pathlib.Path,
    dist: pathlib.Path,
    version: str,
    release_id: int,
    prerelease: bool,
) -> None:
    release = read_json(release_path)
    assets = read_json(assets_path)
    if not isinstance(release, dict):
        raise ReleaseAssetError("GitHub release response must be an object")
    if not isinstance(assets, list):
        raise ReleaseAssetError("GitHub release assets response must be an array")
    local = local_asset_inventory(dist, version)
    verify_release_assets(release, assets, local, version, release_id, prerelease)


def expect_rejected(case: Any) -> None:
    try:
        case()
    except ReleaseAssetError:
        return
    raise AssertionError("invalid release asset fixture was accepted")


def self_test() -> None:
    version = "1.2.3"
    release_id = 42
    commit = "a" * 40
    repository = "example/project"
    with tempfile.TemporaryDirectory(prefix="ram-release-assets-") as directory:
        root = pathlib.Path(directory)
        dist = root / "dist"
        dist.mkdir()
        for index, name in enumerate(expected_asset_names(version), start=1):
            (dist / name).write_bytes(f"fixture-{index}\n".encode())
        for target in TARGETS:
            archive = dist / f"ram-v{version}-{target}.tar.gz"
            digest = file_digest(archive).removeprefix("sha256:")
            (dist / f"{archive.name}.sha256").write_text(
                f"{digest}  {archive.name}\n", encoding="ascii"
            )
        local = local_asset_inventory(dist, version)
        release = {
            "id": release_id,
            "tag_name": f"v{version}",
            "draft": True,
            "prerelease": False,
        }
        assets = [
            {
                "id": index,
                "name": name,
                "state": "uploaded",
                "size": size,
                "digest": digest,
            }
            for index, (name, (size, digest)) in enumerate(local.items(), start=1)
        ]
        verify_release_assets(release, assets, local, version, release_id, False)
        release_path = root / "release.json"
        assets_path = root / "assets.json"
        release_path.write_text(json.dumps(release), encoding="utf-8")
        assets_path.write_text(json.dumps(assets), encoding="utf-8")
        verify(release_path, assets_path, dist, version, release_id, False)
        marker = release_marker(repository, version, commit)
        published = {
            "id": release_id,
            "tag_name": f"v{version}",
            "draft": False,
            "prerelease": False,
            "name": f"Ram v{version}",
            "target_commitish": commit,
            "published_at": "2026-01-01T00:00:00Z",
            "body": f"Release notes\n\n{marker}\n",
        }
        verify_published_release(
            published, release_id, version, commit, repository, False
        )
        for field, value in (
            ("id", release_id + 1),
            ("id", float(release_id)),
            ("tag_name", "v1.2.4"),
            ("draft", True),
            ("prerelease", True),
            ("name", "Ram v1.2.4"),
            ("target_commitish", "b" * 40),
            ("published_at", None),
            ("published_at", "   \t"),
            ("body", "Release notes without the workflow marker"),
            ("body", f"{marker}\n{marker}"),
        ):
            invalid_published = dict(published)
            invalid_published[field] = value
            expect_rejected(
                lambda invalid_published=invalid_published: verify_published_release(
                    invalid_published,
                    release_id,
                    version,
                    commit,
                    repository,
                    False,
                )
            )
        for invalid_arguments in (
            (True, version, commit, repository, False),
            (release_id, "invalid", commit, repository, False),
            (release_id, version, "invalid", repository, False),
            (release_id, version, commit, "invalid", False),
            (release_id, version, commit, repository, 0),
        ):
            expect_rejected(
                lambda invalid_arguments=invalid_arguments: verify_published_release(
                    published, *invalid_arguments
                )
            )

        expect_rejected(
            lambda: verify_release_assets(release, assets, local, version, 0, False)
        )

        release_mutations = (
            ("id", release_id + 1),
            ("tag_name", "v1.2.4"),
            ("draft", False),
            ("prerelease", True),
        )
        for field, value in release_mutations:
            invalid_release = dict(release)
            invalid_release[field] = value
            expect_rejected(
                lambda invalid_release=invalid_release: verify_release_assets(
                    invalid_release, assets, local, version, release_id, False
                )
            )

        for field, value in (
            ("state", "new"),
            ("size", assets[0]["size"] + 1),
            ("size", float(assets[0]["size"])),
            ("digest", "sha256:" + "0" * 64),
        ):
            invalid_assets = copy.deepcopy(assets)
            invalid_assets[0][field] = value
            expect_rejected(
                lambda invalid_assets=invalid_assets: verify_release_assets(
                    release, invalid_assets, local, version, release_id, False
                )
            )

        expect_rejected(
            lambda: verify_release_assets(release, assets[:-1], local, version, release_id, False)
        )
        duplicated_assets = copy.deepcopy(assets)
        duplicated_assets.append(copy.deepcopy(assets[0]))
        expect_rejected(
            lambda: verify_release_assets(
                release, duplicated_assets, local, version, release_id, False
            )
        )

        archive = dist / f"ram-v{version}-{TARGETS[0]}.tar.gz"
        checksum = dist / f"{archive.name}.sha256"
        valid_checksum = checksum.read_bytes()
        checksum_mutations = (
            b"0" * 64 + valid_checksum[64:],
            valid_checksum[:64].upper() + valid_checksum[64:],
            valid_checksum.replace(archive.name.encode(), b"different.tar.gz"),
            valid_checksum + valid_checksum,
        )
        for invalid_checksum in checksum_mutations:
            checksum.write_bytes(invalid_checksum)
            expect_rejected(lambda: verify_archive_checksum(archive, checksum))
        checksum.write_bytes(valid_checksum)
        wrong_path = dist / "unbound.sha256"
        wrong_path.write_bytes(valid_checksum)
        expect_rejected(lambda: verify_archive_checksum(archive, wrong_path))
        wrong_path.unlink()

        unexpected = dist / "unexpected.txt"
        unexpected.write_text("unexpected\n", encoding="utf-8")
        expect_rejected(lambda: local_asset_inventory(dist, version))
        unexpected.unlink()
        oversized = dist / expected_asset_names(version)[0]
        oversized.write_bytes(b"")
        with oversized.open("r+b") as handle:
            handle.truncate(MAX_RELEASE_ASSET_BYTES + 1)
        expect_rejected(lambda: local_asset_inventory(dist, version))
    print("release asset verification self-test passed")


def parse_prerelease(value: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise argparse.ArgumentTypeError("prerelease must be 'true' or 'false'")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    verify_command = commands.add_parser("verify", help="verify a complete GitHub release draft")
    verify_command.add_argument("release", type=pathlib.Path)
    verify_command.add_argument("assets", type=pathlib.Path)
    verify_command.add_argument("dist", type=pathlib.Path)
    verify_command.add_argument("version")
    verify_command.add_argument("release_id", type=int)
    verify_command.add_argument("prerelease", type=parse_prerelease)
    published = commands.add_parser(
        "published", help="verify the response that publishes a release draft"
    )
    published.add_argument("release", type=pathlib.Path)
    published.add_argument("release_id", type=int)
    published.add_argument("version")
    published.add_argument("commit")
    published.add_argument("repository")
    published.add_argument("prerelease", type=parse_prerelease)
    checksum = commands.add_parser(
        "checksum", help="strictly bind one checksum file to one release archive"
    )
    checksum.add_argument("archive", type=pathlib.Path)
    checksum.add_argument("checksum", type=pathlib.Path)
    local = commands.add_parser(
        "local", help="verify the exact local asset inventory and archive checksums"
    )
    local.add_argument("dist", type=pathlib.Path)
    local.add_argument("version")
    commands.add_parser("self-test", help="run deterministic positive and negative fixtures")
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "self-test":
            self_test()
        elif args.command == "published":
            verify_published_release(
                read_json(args.release),
                args.release_id,
                args.version,
                args.commit,
                args.repository,
                args.prerelease,
            )
            print(
                f"release {args.release_id} is published with the exact identity "
                f"for v{args.version}"
            )
        elif args.command == "checksum":
            verify_archive_checksum(args.archive, args.checksum)
            print(f"release checksum is strictly bound to {args.archive.name}")
        elif args.command == "local":
            inventory = local_asset_inventory(args.dist, args.version)
            print(
                f"local release inventory has {len(inventory)} exact assets and bound checksums"
            )
        else:
            verify(
                args.release,
                args.assets,
                args.dist,
                args.version,
                args.release_id,
                args.prerelease,
            )
            print(
                f"release draft {args.release_id} has the exact verified asset inventory "
                f"for v{args.version}"
            )
    except ReleaseAssetError as error:
        print(f"release asset verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
