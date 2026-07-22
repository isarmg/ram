#!/usr/bin/env python3
"""验证项目 MIT-only 声明和第三方许可证策略保持一致。

Verify the project's MIT-only declarations and cargo-about/cargo-deny policy alignment.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import sys
import tomllib
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PROJECT_LICENSE = "MIT"
# 保留从上游继承的 MIT 正文和版权行；修改许可证必须显式更新本策略。
# Preserve the inherited MIT text and copyright line; a license change must update this policy explicitly.
PROJECT_LICENSE_SHA256 = "4623d04ec401ec83c94b935d75d8b4329e860580e91ed777ef03a0aa3b31bb04"


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


def require_project_mit_only() -> None:
    """跨 Cargo、npm、fuzz 和 release 边界固定项目自身许可证。

    Pin the project's own license across Cargo, npm, fuzzing, and release boundaries.
    """

    candidates = sorted(
        path.name for path in ROOT.glob("LICENSE*") if path.is_file() or path.is_symlink()
    )
    if candidates != ["LICENSE"]:
        raise PolicyError(
            "repository root must contain exactly one license file named LICENSE; "
            f"found {candidates!r}"
        )
    license_path = ROOT / "LICENSE"
    if license_path.is_symlink():
        raise PolicyError("LICENSE must be a regular checked-in file, not a symlink")
    try:
        license_digest = hashlib.sha256(license_path.read_bytes()).hexdigest()
    except OSError as error:
        raise PolicyError(f"cannot read {license_path}: {error}") from error
    if license_digest != PROJECT_LICENSE_SHA256:
        raise PolicyError(
            "LICENSE no longer matches the reviewed MIT text and inherited copyright line: "
            f"expected sha256 {PROJECT_LICENSE_SHA256}, found {license_digest}"
        )

    cargo_package = load_toml(ROOT / "Cargo.toml").get("package")
    fuzz_package = load_toml(ROOT / "fuzz/Cargo.toml").get("package")
    for location, package in (
        ("Cargo.toml [package]", cargo_package),
        ("fuzz/Cargo.toml [package]", fuzz_package),
    ):
        if not isinstance(package, dict) or package.get("license") != PROJECT_LICENSE:
            actual = package.get("license") if isinstance(package, dict) else None
            raise PolicyError(
                f"{location}.license must be exactly {PROJECT_LICENSE!r}, found {actual!r}"
            )
        if "license-file" in package:
            raise PolicyError(f"{location} must not add a second license-file declaration")

    if not isinstance(cargo_package, dict):
        raise PolicyError("Cargo.toml is missing [package]")
    package_include = cargo_package.get("include")
    if not isinstance(package_include, list) or "/LICENSE" not in package_include:
        raise PolicyError("Cargo.toml package.include must contain /LICENSE")
    legacy_includes = [
        entry
        for entry in package_include
        if isinstance(entry, str) and entry.startswith("/LICENSE-")
    ]
    if legacy_includes:
        raise PolicyError(
            f"Cargo.toml package.include contains legacy license files: {legacy_includes!r}"
        )

    manifests: list[tuple[str, dict[str, Any]]] = []
    for relative in ("package.json", "package-lock.json"):
        path = ROOT / relative
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise PolicyError(f"cannot read {path}: {error}") from error
        if not isinstance(value, dict):
            raise PolicyError(f"{path} must contain a JSON object")
        manifests.append((relative, value))
    npm_license = manifests[0][1].get("license")
    lock_packages = manifests[1][1].get("packages")
    lock_root = lock_packages.get("") if isinstance(lock_packages, dict) else None
    lock_license = lock_root.get("license") if isinstance(lock_root, dict) else None
    for location, actual in (
        ("package.json license", npm_license),
        ("package-lock.json root package license", lock_license),
    ):
        if actual != PROJECT_LICENSE:
            raise PolicyError(
                f"{location} must be exactly {PROJECT_LICENSE!r}, found {actual!r}"
            )

    workflow = ROOT / ".github/workflows/release.yaml"
    try:
        release = workflow.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise PolicyError(f"cannot read {workflow}: {error}") from error
    if "LICENSE-" in release:
        raise PolicyError("release workflow still references a legacy split license file")
    if "cp LICENSE README.md SECURITY.md CONTRIBUTING.md" not in release:
        raise PolicyError("release workflow must package the single LICENSE file")


def verify(deny_path: Path, about_path: Path) -> None:
    require_project_mit_only()
    expected = deny_allowlist(deny_path)
    actual = about_allowlist(about_path)
    if actual == expected:
        print(
            f"project license is MIT-only and dependency policy is aligned: "
            f"{about_path} exactly mirrors {deny_path} ({len(expected)} licenses)"
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
