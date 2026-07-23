#!/usr/bin/env python3
"""对 GitHub Release 与草稿状态做关闭失败的发布判定。

Fail closed while classifying published GitHub Releases and resumable drafts.
"""

from __future__ import annotations

import argparse
import copy
import json
import pathlib
import re
import sys
from typing import Any


MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_RELEASE_PAGES = 100
VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?")
REPOSITORY_PATTERN = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")


class ReleaseStateError(ValueError):
    """远程状态不安全、身份不匹配或无法证明。 / Remote state is unsafe, mismatched, or unprovable."""


def read_json(path: pathlib.Path) -> Any:
    try:
        size = path.stat().st_size
        if size < 0 or size > MAX_RESPONSE_BYTES:
            raise ReleaseStateError(
                f"response {path} is {size} bytes; limit is {MAX_RESPONSE_BYTES}"
            )
        return json.loads(path.read_text(encoding="utf-8"))
    except ReleaseStateError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseStateError(f"cannot read JSON response {path}: {error}") from error


def validate_version(version: str) -> None:
    if VERSION_PATTERN.fullmatch(version) is None:
        raise ReleaseStateError(f"invalid release version {version!r}")


def release_marker(repository: str, tag: str, commit: str) -> str:
    if REPOSITORY_PATTERN.fullmatch(repository) is None:
        raise ReleaseStateError(f"invalid GitHub repository {repository!r}")
    if not tag.startswith("v"):
        raise ReleaseStateError(f"invalid release tag {tag!r}")
    validate_version(tag[1:])
    if COMMIT_PATTERN.fullmatch(commit) is None:
        raise ReleaseStateError(f"invalid release commit {commit!r}")
    return f"<!-- ram-release-workflow:{repository}:{tag}:{commit} -->"


def require_status(value: str) -> int:
    if re.fullmatch(r"[0-9]{3}", value) is None:
        raise ReleaseStateError(f"invalid HTTP status {value!r}")
    return int(value)


def verify_published_release_response(
    status: int, payload: Any | None, expected_tag: str
) -> None:
    """按标签查询必须返回 404；任何已公开 Release 都不可覆盖。

    A tag lookup must return 404; a published release is never replaceable.
    """

    if not expected_tag.startswith("v"):
        raise ReleaseStateError(f"invalid release tag {expected_tag!r}")
    validate_version(expected_tag[1:])
    if status == 404:
        return
    if status != 200:
        raise ReleaseStateError(
            f"cannot prove published release absence: HTTP {status}"
        )
    if not isinstance(payload, dict):
        raise ReleaseStateError("published release response must be an object")
    if payload.get("tag_name") != expected_tag or payload.get("draft") is not False:
        raise ReleaseStateError("published release response does not match the requested tag")
    raise ReleaseStateError(
        f"published release {expected_tag} already exists and must not be replaced"
    )


def classify_draft_page(
    payload: Any,
    expected_tag: str,
    expected_commit: str,
    repository: str,
    prerelease: bool,
    existing_draft_id: int | None = None,
    page_number: int = 1,
) -> str:
    """返回本页候选与终止状态；只认可全量分页中的唯一同 commit 草稿。调用方须把已找到的
    ID 传入所有后续页，且只能在短终止页停止，避免“只查近期页”漏掉重复或身份不符的 tag。

    Return this page's candidate and terminal state. Only one exactly marked draft
    across the complete pagination is resumable. The caller carries a previously
    found ID into every later page and may stop only on a short terminal page;
    this prevents a recent-page lookup from missing a duplicate or mismatched tag.
    """

    release_marker(repository, expected_tag, expected_commit)
    if existing_draft_id is not None and (
        isinstance(existing_draft_id, bool)
        or not isinstance(existing_draft_id, int)
        or existing_draft_id <= 0
    ):
        raise ReleaseStateError("existing GitHub release draft id is invalid")
    if (
        isinstance(page_number, bool)
        or not isinstance(page_number, int)
        or page_number <= 0
        or page_number > MAX_RELEASE_PAGES
    ):
        raise ReleaseStateError(f"invalid GitHub releases page number {page_number!r}")
    if not isinstance(payload, list):
        raise ReleaseStateError("GitHub releases page must be an array")
    if len(payload) > 100:
        raise ReleaseStateError("GitHub releases page exceeds per_page=100")
    matches: list[dict[str, Any]] = []
    for index, raw_release in enumerate(payload):
        if not isinstance(raw_release, dict):
            raise ReleaseStateError(f"GitHub releases page entry {index} is not an object")
        tag_name = raw_release.get("tag_name")
        if not isinstance(tag_name, str) or not tag_name:
            raise ReleaseStateError(
                f"GitHub releases page entry {index} has an invalid tag_name"
            )
        if tag_name == expected_tag:
            matches.append(raw_release)
    if len(matches) > 1:
        raise ReleaseStateError(f"multiple GitHub releases use tag {expected_tag}")
    terminal = len(payload) < 100
    if not terminal and page_number == MAX_RELEASE_PAGES:
        raise ReleaseStateError(
            f"GitHub release lookup exceeded {MAX_RELEASE_PAGES} full pages"
        )
    if not matches:
        return "done" if terminal else "next"

    release = matches[0]
    release_id = release.get("id")
    if isinstance(release_id, bool) or not isinstance(release_id, int) or release_id <= 0:
        raise ReleaseStateError("matching GitHub release has an invalid id")
    if existing_draft_id is not None:
        raise ReleaseStateError(
            f"multiple GitHub releases use tag {expected_tag}: "
            f"{existing_draft_id} and {release_id}"
        )
    verify_draft_identity(
        release,
        release_id,
        expected_tag,
        expected_commit,
        repository,
        prerelease,
    )
    state = "done" if terminal else "next"
    return f"draft-{state}={release_id}"


def verify_draft_identity(
    release: Any,
    release_id: int,
    expected_tag: str,
    expected_commit: str,
    repository: str,
    prerelease: bool,
) -> None:
    """在创建后和最终公开前重新验证不可混淆的 draft 身份。

    Revalidate an unambiguous draft identity after creation and before publication.
    """

    marker = release_marker(repository, expected_tag, expected_commit)
    if not isinstance(release, dict):
        raise ReleaseStateError("GitHub release draft must be an object")
    actual_id = release.get("id")
    if (
        release_id <= 0
        or isinstance(actual_id, bool)
        or not isinstance(actual_id, int)
        or actual_id != release_id
        or release.get("tag_name") != expected_tag
    ):
        raise ReleaseStateError("GitHub release draft id/tag does not match this run")
    if release.get("draft") is not True or release.get("published_at") is not None:
        raise ReleaseStateError(
            f"release {release_id} for {expected_tag} is not an unpublished draft"
        )
    if release.get("prerelease") is not prerelease:
        raise ReleaseStateError(
            f"release draft {release_id} prerelease state does not match this run"
        )
    if release.get("name") != f"Ram {expected_tag}":
        raise ReleaseStateError(
            f"release draft {release_id} name does not identify this workflow"
        )
    if release.get("target_commitish") != expected_commit:
        raise ReleaseStateError(
            f"release draft {release_id} target_commitish does not match this run"
        )
    body = release.get("body")
    if not isinstance(body, str) or body.count(marker) != 1:
        raise ReleaseStateError(
            f"release draft {release_id} lacks the exact workflow/commit marker"
        )


def expect_rejected(case: Any) -> None:
    try:
        case()
    except ReleaseStateError:
        return
    raise AssertionError("unsafe release state fixture was accepted")


def self_test() -> None:
    version = "1.2.3"
    tag = f"v{version}"
    repository = "example/project"
    commit = "a" * 40
    marker = release_marker(repository, tag, commit)

    verify_published_release_response(404, None, tag)
    published = {"tag_name": tag, "draft": False}
    for status, payload in (
        (200, published),
        (200, {"tag_name": "v9.9.9", "draft": False}),
        (200, {"tag_name": tag, "draft": True}),
        (403, None),
        (500, None),
    ):
        expect_rejected(
            lambda status=status, payload=payload: verify_published_release_response(
                status, payload, tag
            )
        )

    draft = {
        "id": 42,
        "tag_name": tag,
        "target_commitish": commit,
        "draft": True,
        "published_at": None,
        "prerelease": False,
        "name": f"Ram {tag}",
        "body": marker + "\nGenerated notes",
    }
    if classify_draft_page([draft], tag, commit, repository, False) != "draft-done=42":
        raise AssertionError("matching workflow draft was not selected")
    verify_draft_identity(draft, 42, tag, commit, repository, False)
    if classify_draft_page([], tag, commit, repository, False) != "done":
        raise AssertionError("short empty page was not terminal")
    unrelated = [{"id": index, "tag_name": f"v0.0.{index}"} for index in range(100)]
    if classify_draft_page(unrelated, tag, commit, repository, False) != "next":
        raise AssertionError("full unrelated page did not request pagination")
    expect_rejected(
        lambda: classify_draft_page(
            unrelated,
            tag,
            commit,
            repository,
            False,
            page_number=MAX_RELEASE_PAGES,
        )
    )

    # 中文：即使第一页已找到精确草稿，也必须继续到短页；后续任意同 tag 项都使唯一性证明失败。
    # English: Even an exact first-page draft requires scanning to a short page; any later same-tag
    # entry invalidates the uniqueness proof.
    first_page = [draft] + [
        {"id": 1000 + index, "tag_name": f"v0.1.{index}"} for index in range(99)
    ]
    if (
        classify_draft_page(first_page, tag, commit, repository, False)
        != "draft-next=42"
    ):
        raise AssertionError("full page with a draft did not continue pagination")
    if classify_draft_page([], tag, commit, repository, False, 42) != "done":
        raise AssertionError("terminal page did not preserve the prior unique draft")

    second_exact = copy.deepcopy(draft)
    second_exact["id"] = 43
    second_mismatched = copy.deepcopy(second_exact)
    second_mismatched["body"] = "manual draft without the workflow marker"
    for second in (second_exact, second_mismatched):
        expect_rejected(
            lambda second=second: classify_draft_page(
                [second], tag, commit, repository, False, 42
            )
        )

    late_page_draft = copy.deepcopy(draft)
    late_page_draft["id"] = 44
    if (
        classify_draft_page(
            [late_page_draft], tag, commit, repository, False
        )
        != "draft-done=44"
    ):
        raise AssertionError("unique draft on the terminal page was not selected")

    mutations = (
        ("id", True),
        ("draft", False),
        ("published_at", "2026-01-01T00:00:00Z"),
        ("prerelease", True),
        ("name", "manual draft"),
        ("target_commitish", "b" * 40),
        ("body", "missing marker"),
        ("body", marker + marker),
    )
    for field, value in mutations:
        invalid = copy.deepcopy(draft)
        invalid[field] = value
        expect_rejected(
            lambda invalid=invalid: classify_draft_page(
                [invalid], tag, commit, repository, False
            )
        )
    wrong_commit = copy.deepcopy(draft)
    wrong_commit["body"] = release_marker(repository, tag, "b" * 40)
    expect_rejected(
        lambda: classify_draft_page(
            [wrong_commit], tag, commit, repository, False
        )
    )
    expect_rejected(
        lambda: classify_draft_page([draft, draft], tag, commit, repository, False)
    )
    print("release remote-state verification self-test passed")


def parse_prerelease(value: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise argparse.ArgumentTypeError("prerelease must be 'true' or 'false'")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    published = commands.add_parser(
        "published", help="reject any published GitHub release for a tag"
    )
    published.add_argument("status")
    published.add_argument("response", type=pathlib.Path)
    published.add_argument("tag")
    draft_page = commands.add_parser(
        "draft-page", help="classify one authenticated GitHub releases page"
    )
    draft_page.add_argument("response", type=pathlib.Path)
    draft_page.add_argument("tag")
    draft_page.add_argument("commit")
    draft_page.add_argument("repository")
    draft_page.add_argument("prerelease", type=parse_prerelease)
    draft_page.add_argument("--existing-draft-id", type=int)
    draft_page.add_argument("--page-number", type=int, default=1)
    draft = commands.add_parser(
        "draft", help="verify one release draft before it can be published"
    )
    draft.add_argument("response", type=pathlib.Path)
    draft.add_argument("release_id", type=int)
    draft.add_argument("tag")
    draft.add_argument("commit")
    draft.add_argument("repository")
    draft.add_argument("prerelease", type=parse_prerelease)
    commands.add_parser("self-test", help="run deterministic positive and negative fixtures")
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "self-test":
            self_test()
        elif args.command == "published":
            status = require_status(args.status)
            payload = None if status == 404 else read_json(args.response)
            verify_published_release_response(status, payload, args.tag)
            print(f"no published GitHub release exists for {args.tag}")
        elif args.command == "draft-page":
            print(
                classify_draft_page(
                    read_json(args.response),
                    args.tag,
                    args.commit,
                    args.repository,
                    args.prerelease,
                    args.existing_draft_id,
                    args.page_number,
                )
            )
        elif args.command == "draft":
            verify_draft_identity(
                read_json(args.response),
                args.release_id,
                args.tag,
                args.commit,
                args.repository,
                args.prerelease,
            )
            print(f"release draft {args.release_id} identity matches this workflow run")
    except ReleaseStateError as error:
        print(f"release state verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
