#!/usr/bin/env python3
"""验证 cargo-about 精确镜像 cargo-deny 许可证策略。

Verify that cargo-about exactly mirrors cargo-deny's license policy.
"""

from __future__ import annotations

import argparse
import difflib
import sys
import tomllib
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


class PolicyError(Exception):
    """许可证策略文件缺失、畸形或不一致。 / A license policy file is missing, malformed, or inconsistent."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compare about.toml accepted against the authoritative "
            "deny.toml [licenses].allow list."
        )
    )
    parser.add_argument(
        "--deny",
        type=Path,
        default=ROOT / "deny.toml",
        help="authoritative cargo-deny policy (default: repository deny.toml)",
    )
    parser.add_argument(
        "--about",
        type=Path,
        default=ROOT / "about.toml",
        help="cargo-about policy mirror (default: repository about.toml)",
    )
    return parser.parse_args()


def load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            value = tomllib.load(stream)
    except OSError as error:
        raise PolicyError(f"cannot read {path}: {error}") from error
    except tomllib.TOMLDecodeError as error:
        raise PolicyError(f"invalid TOML in {path}: {error}") from error

    if not isinstance(value, dict):
        raise PolicyError(f"{path} must contain a TOML table")
    return value


def require_license_list(value: Any, location: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise PolicyError(f"{location} must be a non-empty array of strings")
    if any(not isinstance(item, str) or not item for item in value):
        raise PolicyError(f"{location} must contain only non-empty strings")

    duplicates = sorted({item for item in value if value.count(item) > 1})
    if duplicates:
        raise PolicyError(
            f"{location} contains duplicate licenses: {', '.join(duplicates)}"
        )
    return value


def deny_allowlist(path: Path) -> list[str]:
    document = load_toml(path)
    licenses = document.get("licenses")
    if not isinstance(licenses, dict):
        raise PolicyError(f"{path} is missing the [licenses] table")
    return require_license_list(licenses.get("allow"), f"{path} [licenses].allow")


def about_allowlist(path: Path) -> list[str]:
    document = load_toml(path)
    return require_license_list(document.get("accepted"), f"{path} accepted")


def format_list(values: list[str]) -> list[str]:
    return [f"{index:02d}: {license}\n" for index, license in enumerate(values, 1)]


def verify(deny_path: Path, about_path: Path) -> None:
    expected = deny_allowlist(deny_path)
    actual = about_allowlist(about_path)
    if actual == expected:
        print(
            f"license policy aligned: {about_path} exactly mirrors "
            f"{deny_path} ({len(expected)} licenses)"
        )
        return

    missing = [license for license in expected if license not in actual]
    unexpected = [license for license in actual if license not in expected]
    details = [
        "cargo-about license policy does not exactly mirror cargo-deny",
        f"authoritative source: {deny_path} [licenses].allow",
        f"mirror: {about_path} accepted",
    ]
    if missing:
        details.append(f"missing from cargo-about: {', '.join(missing)}")
    if unexpected:
        details.append(f"not allowed by cargo-deny: {', '.join(unexpected)}")
    if not missing and not unexpected:
        details.append("the same licenses are present, but priority order differs")

    diff = difflib.unified_diff(
        format_list(expected),
        format_list(actual),
        fromfile=f"{deny_path} [licenses].allow (expected)",
        tofile=f"{about_path} accepted (actual)",
    )
    raise PolicyError("\n".join(details) + "\n" + "".join(diff).rstrip())


def main() -> int:
    args = parse_args()
    try:
        verify(args.deny, args.about)
    except PolicyError as error:
        print(f"license policy check failed:\n{error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
