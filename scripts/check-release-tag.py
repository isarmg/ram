#!/usr/bin/env python3
"""校验发布版本与 GitHub Git Data API 标签文档。

Validate release versions and GitHub Git Data API tag documents.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import tomllib
from typing import Any

MAX_GITHUB_RESPONSE_BYTES = 2 * 1024 * 1024
README_ENGLISH_HEADING = "# Ram File Server (English)"
CHANGELOG_ENGLISH_HEADING = "# Changelog (English)"

# 这三条命令是用户从发布下载到安装的最小完整链路。按命令类型分别校验，
# 可防止“总数刚好是 6，但某种命令重复而另一种缺失”的假阳性。
# These three commands are the minimal complete download-to-install path. Validate each command kind
# independently so a total of six matches cannot hide a duplicate kind and a missing kind.
README_ARTIFACT_COMMANDS = (
    (
        "checksum",
        re.compile(
            r'^sha256sum --check "ram-v([0-9]+\.[0-9]+\.[0-9]+'
            r'(?:-[0-9A-Za-z.-]+)?)-(?:\$\{TARGET\}|(?:x86_64|aarch64)-unknown-linux-gnu)'
            r'\.tar\.gz\.sha256"$',
            flags=re.MULTILINE,
        ),
    ),
    (
        "archive extraction",
        re.compile(
            r'^tar -xzf "ram-v([0-9]+\.[0-9]+\.[0-9]+'
            r'(?:-[0-9A-Za-z.-]+)?)-(?:\$\{TARGET\}|(?:x86_64|aarch64)-unknown-linux-gnu)'
            r'\.tar\.gz"$',
            flags=re.MULTILINE,
        ),
    ),
    (
        "binary installation",
        re.compile(
            r'^sudo install -m 0755 "ram-v([0-9]+\.[0-9]+\.[0-9]+'
            r'(?:-[0-9A-Za-z.-]+)?)-(?:\$\{TARGET\}|(?:x86_64|aarch64)-unknown-linux-gnu)'
            r'/ram" /usr/local/bin/ram$',
            flags=re.MULTILINE,
        ),
    ),
)


class TagVerificationError(ValueError):
    """发布引用或附注标签不满足发布策略。 / The release ref or annotated tag violates release policy."""


def verify_readme_artifact_examples(readme: str, version: str) -> None:
    """要求中英文章节各自包含一组完整且版本一致的制品命令。

    Require one complete, version-aligned artifact command set in each language section.
    """

    sections = split_bilingual_document(
        readme, README_ENGLISH_HEADING, "README.md"
    )
    for language, section in sections:
        for command, pattern in README_ARTIFACT_COMMANDS:
            observed = pattern.findall(section)
            if observed != [version]:
                raise TagVerificationError(
                    f"README {language} section must contain exactly one {command} example "
                    f"for Cargo.toml version {version!r}, got {observed!r}"
                )


def split_bilingual_document(
    document: str, english_heading: str, document_name: str
) -> tuple[tuple[str, str], tuple[str, str]]:
    """在唯一英文镜像标题处分割双语文档。 / Split a bilingual document at its unique English mirror heading."""

    headings = tuple(
        re.finditer(rf"^{re.escape(english_heading)}$", document, re.MULTILINE)
    )
    if len(headings) != 1:
        raise TagVerificationError(
            f"{document_name} must contain exactly one English mirror heading "
            f"{english_heading!r}, got {len(headings)}"
        )
    heading = headings[0]
    return (
        ("Chinese", document[: heading.start()]),
        ("English", document[heading.end() :]),
    )


def verify_changelog_markers(changelog: str, version: str) -> None:
    """要求两个语言章节各有一个当前版本，共享的引用链接只定义一次。

    Require one current-version section per language and one shared set of reference links.
    """

    for language, section in split_bilingual_document(
        changelog, CHANGELOG_ENGLISH_HEADING, "CHANGELOG.md"
    ):
        markers = (
            ("Unreleased heading", r"## \[Unreleased\]"),
            ("current release heading", rf"## \[{re.escape(version)}\]"),
        )
        for description, pattern in markers:
            count = len(re.findall(rf"^{pattern}$", section, flags=re.MULTILINE))
            if count != 1:
                raise TagVerificationError(
                    f"CHANGELOG.md {language} section must contain exactly one "
                    f"{description}, got {count}"
                )

    shared_links = (
        rf"\[Unreleased\]: https://github\.com/isarmg/ram/compare/v{re.escape(version)}\.\.\.HEAD",
        rf"\[{re.escape(version)}\]: https://github\.com/isarmg/ram/releases/tag/v{re.escape(version)}",
    )
    for pattern in shared_links:
        if len(re.findall(rf"^{pattern}$", changelog, flags=re.MULTILINE)) != 1:
            raise TagVerificationError(
                "CHANGELOG.md must contain exactly one shared anchored current release link: "
                f"{pattern}"
            )


def read_object(path: pathlib.Path) -> dict[str, Any]:
    try:
        size = path.stat().st_size
        if size > MAX_GITHUB_RESPONSE_BYTES:
            raise TagVerificationError(
                f"GitHub API response in {path} is {size} bytes; limit is {MAX_GITHUB_RESPONSE_BYTES}"
            )
        value = json.loads(path.read_text(encoding="utf-8"))
    except TagVerificationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise TagVerificationError(f"cannot read GitHub API JSON from {path}: {error}") from error
    if not isinstance(value, dict):
        raise TagVerificationError(f"GitHub API response in {path} must be an object")
    return value


def annotated_tag_url(
    payload: dict[str, Any], repository: str, expected_tag: str
) -> str:
    expected_ref = f"refs/tags/{expected_tag}"
    if payload.get("ref") != expected_ref:
        raise TagVerificationError(
            f"release ref response identifies {payload.get('ref')!r}, expected {expected_ref!r}"
        )
    obj = payload.get("object")
    if not isinstance(obj, dict):
        raise TagVerificationError("release ref has no object")
    object_sha = obj.get("sha")
    if not isinstance(object_sha, str) or re.fullmatch(r"[0-9a-f]{40}", object_sha) is None:
        raise TagVerificationError("release ref has an invalid annotated-tag object SHA")
    expected_url = f"https://api.github.com/repos/{repository}/git/tags/{object_sha}"
    url = obj.get("url")
    if obj.get("type") != "tag" or url != expected_url:
        raise TagVerificationError(
            "release ref must be an annotated tag in the current repository, not a lightweight tag"
        )
    return url


def verify_annotated_tag(
    payload: dict[str, Any], expected_commit: str, expected_tag: str, expected_tag_sha: str
) -> None:
    if re.fullmatch(r"[0-9a-f]{40}", expected_tag_sha) is None:
        raise TagVerificationError("expected annotated-tag object SHA is invalid")
    target = payload.get("object")
    verification = payload.get("verification")
    if not isinstance(target, dict) or not isinstance(verification, dict):
        raise TagVerificationError("annotated tag response is missing target or verification data")
    if payload.get("sha") != expected_tag_sha:
        raise TagVerificationError(
            "annotated tag response SHA does not match the object selected by the release ref"
        )
    if payload.get("tag") != expected_tag:
        raise TagVerificationError(
            f"signed annotated tag name is {payload.get('tag')!r}, expected {expected_tag!r}"
        )
    if target.get("type") != "commit" or target.get("sha") != expected_commit:
        raise TagVerificationError(
            "annotated tag must point directly at the commit being built"
        )
    if verification.get("verified") is not True or verification.get("reason") != "valid":
        reason = verification.get("reason", "missing")
        raise TagVerificationError(
            f"release tag signature is not GitHub-verified: reason={reason}"
        )


def verify_version_documents(
    version: str,
    package_name: str,
    cargo_lock: dict[str, Any],
    package: dict[str, Any],
    package_lock: dict[str, Any],
    readme: str,
    changelog: str,
) -> None:
    """要求每个面向用户的发布版本与 Cargo.toml 一致。 / Require every user-facing release version to match Cargo.toml."""

    npm_lock_root = package_lock.get("packages")
    npm_lock_root = npm_lock_root.get("") if isinstance(npm_lock_root, dict) else None
    cargo_packages = cargo_lock.get("package")
    cargo_roots = (
        [item for item in cargo_packages if isinstance(item, dict) and item.get("name") == package_name]
        if isinstance(cargo_packages, list)
        else []
    )
    if len(cargo_roots) != 1:
        raise TagVerificationError(
            f"Cargo.lock must contain exactly one {package_name!r} package, got {len(cargo_roots)}"
        )
    observed = {
        "Cargo.lock": cargo_roots[0].get("version"),
        "package.json": package.get("version"),
        "package-lock.json": package_lock.get("version"),
        "package-lock.json packages['']": (
            npm_lock_root.get("version") if isinstance(npm_lock_root, dict) else None
        ),
    }
    for location, actual in observed.items():
        if actual != version:
            raise TagVerificationError(
                f"{location} version {actual!r} does not match Cargo.toml {version!r}"
            )

    verify_readme_artifact_examples(readme, version)

    verify_changelog_markers(changelog, version)


def verify_version_tree(root: pathlib.Path) -> str:
    try:
        with (root / "Cargo.toml").open("rb") as cargo_file:
            cargo_package = tomllib.load(cargo_file)["package"]
            version = cargo_package["version"]
            package_name = cargo_package["name"]
        with (root / "Cargo.lock").open("rb") as cargo_lock_file:
            cargo_lock = tomllib.load(cargo_lock_file)
        package = json.loads((root / "package.json").read_text(encoding="utf-8"))
        package_lock = json.loads((root / "package-lock.json").read_text(encoding="utf-8"))
        readme = (root / "README.md").read_text(encoding="utf-8")
        changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, tomllib.TOMLDecodeError) as error:
        raise TagVerificationError(f"cannot read project version documents under {root}: {error}") from error
    if (
        not isinstance(version, str)
        or not isinstance(package_name, str)
        or not isinstance(cargo_lock, dict)
        or not isinstance(package, dict)
        or not isinstance(package_lock, dict)
    ):
        raise TagVerificationError("project version documents have invalid top-level types")
    verify_version_documents(
        version, package_name, cargo_lock, package, package_lock, readme, changelog
    )
    return version


def self_test() -> None:
    repository = "owner/repository"
    commit = "a" * 40
    tag_name = "v1.2.3"
    tag_sha = "b" * 40
    url = f"https://api.github.com/repos/{repository}/git/tags/{tag_sha}"
    ref_response = {
        "ref": f"refs/tags/{tag_name}",
        "object": {"type": "tag", "sha": tag_sha, "url": url},
    }
    assert annotated_tag_url(ref_response, repository, tag_name) == url
    tag_response = {
        "sha": tag_sha,
        "tag": tag_name,
        "object": {"type": "commit", "sha": commit},
        "verification": {"verified": True, "reason": "valid"},
    }
    verify_annotated_tag(
        tag_response,
        commit,
        tag_name,
        tag_sha,
    )

    rejected = [
        lambda: annotated_tag_url(
            {
                "ref": f"refs/tags/{tag_name}",
                "object": {"type": "commit", "sha": tag_sha, "url": url},
            },
            repository,
            tag_name,
        ),
        lambda: annotated_tag_url(
            {
                "ref": f"refs/tags/{tag_name}",
                "object": {
                    "type": "tag",
                    "sha": tag_sha,
                    "url": f"https://api.github.com/repos/other/repository/git/tags/{tag_sha}",
                }
            },
            repository,
            tag_name,
        ),
        lambda: annotated_tag_url(
            {**ref_response, "ref": "refs/tags/v9.9.9"}, repository, tag_name
        ),
        lambda: annotated_tag_url(
            {
                **ref_response,
                "object": {**ref_response["object"], "sha": "not-a-sha"},
            },
            repository,
            tag_name,
        ),
        lambda: annotated_tag_url(
            {
                **ref_response,
                "object": {**ref_response["object"], "url": url + "/suffix"},
            },
            repository,
            tag_name,
        ),
        lambda: verify_annotated_tag(
            {
                **tag_response,
                "object": {"type": "commit", "sha": "c" * 40},
            },
            commit,
            tag_name,
            tag_sha,
        ),
        lambda: verify_annotated_tag(
            {
                **tag_response,
                "verification": {"verified": False, "reason": "unknown_key"},
            },
            commit,
            tag_name,
            tag_sha,
        ),
        lambda: verify_annotated_tag(
            {**tag_response, "tag": "v9.9.9"}, commit, tag_name, tag_sha
        ),
        lambda: verify_annotated_tag(
            {**tag_response, "sha": "c" * 40}, commit, tag_name, tag_sha
        ),
    ]
    for case in rejected:
        try:
            case()
        except TagVerificationError:
            continue
        raise AssertionError("invalid release tag fixture was accepted")

    version = "1.2.3"
    package_name = "example"
    cargo_lock = {"package": [{"name": package_name, "version": version}]}
    package = {"version": version}
    package_lock = {"version": version, "packages": {"": {"version": version}}}
    artifact_commands = "\n".join(
        (
            'sha256sum --check "ram-v1.2.3-${TARGET}.tar.gz.sha256"',
            'tar -xzf "ram-v1.2.3-${TARGET}.tar.gz"',
            'sudo install -m 0755 "ram-v1.2.3-${TARGET}/ram" /usr/local/bin/ram',
        )
    )
    readme = "\n".join(
        (
            "# 示例",
            artifact_commands,
            "",
            README_ENGLISH_HEADING,
            artifact_commands,
        )
    )
    changelog = "\n".join(
        (
            "# 变更记录",
            "## [Unreleased]",
            "## [1.2.3]",
            "",
            CHANGELOG_ENGLISH_HEADING,
            "## [Unreleased]",
            "## [1.2.3]",
            "",
            "[Unreleased]: https://github.com/isarmg/ram/compare/v1.2.3...HEAD",
            "[1.2.3]: https://github.com/isarmg/ram/releases/tag/v1.2.3",
        )
    )
    verify_version_documents(
        version, package_name, cargo_lock, package, package_lock, readme, changelog
    )
    english_offset = readme.index(README_ENGLISH_HEADING)
    english_wrong_version = (
        readme[:english_offset]
        + readme[english_offset:].replace("1.2.3", "1.2.4")
    )
    version_rejections = (
        (
            {"package": [{"name": package_name, "version": "1.2.4"}]},
            package,
            package_lock,
            readme,
            changelog,
        ),
        (cargo_lock, {"version": "1.2.4"}, package_lock, readme, changelog),
        (
            cargo_lock,
            package,
            {"version": version, "packages": {"": {"version": "1.2.4"}}},
            readme,
            changelog,
        ),
        (
            cargo_lock,
            package,
            package_lock,
            readme.replace("1.2.3", "1.2.4"),
            changelog,
        ),
        # 只改变英文镜像的版本必须失败。
        # Changing only the English mirror's version must fail.
        (
            cargo_lock,
            package,
            package_lock,
            english_wrong_version,
            changelog,
        ),
        (
            cargo_lock,
            package,
            package_lock,
            readme,
            changelog.replace("## [1.2.3]", "## [1.2.4]"),
        ),
    )
    for documents in version_rejections:
        try:
            verify_version_documents(version, package_name, *documents)
        except TagVerificationError:
            continue
        raise AssertionError("misaligned release version fixture was accepted")

    # 总匹配数仍是 6，但英文章节重复 checksum 并缺少 install；必须按语义拒绝。
    # The total is still six, but English duplicates checksum and omits install; reject by semantics.
    install_command = (
        'sudo install -m 0755 "ram-v1.2.3-${TARGET}/ram" /usr/local/bin/ram'
    )
    checksum_command = 'sha256sum --check "ram-v1.2.3-${TARGET}.tar.gz.sha256"'
    semantic_mismatch = (
        readme[:english_offset]
        + readme[english_offset:].replace(install_command, checksum_command, 1)
    )
    try:
        verify_version_documents(
            version,
            package_name,
            cargo_lock,
            package,
            package_lock,
            semantic_mismatch,
            changelog,
        )
    except TagVerificationError:
        pass
    else:
        raise AssertionError("semantically incomplete bilingual README fixture was accepted")

    duplicate_heading = readme + "\n" + README_ENGLISH_HEADING + "\n"
    try:
        verify_version_documents(
            version,
            package_name,
            cargo_lock,
            package,
            package_lock,
            duplicate_heading,
            changelog,
        )
    except TagVerificationError:
        pass
    else:
        raise AssertionError("README with duplicate English mirror headings was accepted")
    print("release tag verification self-test passed")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    url = commands.add_parser("tag-url", help="validate a ref response and print its tag URL")
    url.add_argument("response", type=pathlib.Path)
    url.add_argument("repository")
    url.add_argument("tag")
    verify = commands.add_parser("verify", help="validate an annotated-tag response")
    verify.add_argument("response", type=pathlib.Path)
    verify.add_argument("commit")
    verify.add_argument("tag")
    verify.add_argument("tag_sha")
    versions = commands.add_parser(
        "version-sync", help="validate Cargo, npm, README, and changelog versions"
    )
    versions.add_argument("root", nargs="?", type=pathlib.Path, default=pathlib.Path("."))
    commands.add_parser("self-test", help="run deterministic positive and negative fixtures")
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "self-test":
            self_test()
        elif args.command == "tag-url":
            print(annotated_tag_url(read_object(args.response), args.repository, args.tag))
        elif args.command == "version-sync":
            version = verify_version_tree(args.root.resolve())
            print(f"release version alignment verified: {version}")
        else:
            verify_annotated_tag(
                read_object(args.response), args.commit, args.tag, args.tag_sha
            )
            print("annotated release tag has a valid GitHub-verified signature")
    except TagVerificationError as error:
        print(f"release tag verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
