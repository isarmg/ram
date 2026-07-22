#!/usr/bin/env python3
"""根据 Cargo 锁定的 Linux 发布目标普通/构建依赖边界验证第三方许可证 HTML 报告。

根项目必须只映射到 Cargo.toml 声明的精确 SPDX 许可证段。

Validate the third-party-license HTML report against Cargo's locked normal/build boundary for the
supported Linux release targets.
The root project must map only to the exact SPDX license section declared by Cargo.toml.
"""

from __future__ import annotations

import argparse
import html
from html.parser import HTMLParser
import os
import pathlib
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field


MAX_REPORT_BYTES = 64 * 1024 * 1024
PackageKey = tuple[str, str]
RELEASE_TARGETS = (
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
)


class LicenseReportError(ValueError):
    """报告畸形、不完整或越过了生产依赖边界。 / The report is malformed, incomplete, or crosses the production boundary."""


def parse_tree_packages(output: str, label: str) -> set[PackageKey]:
    packages: set[PackageKey] = set()
    for line_number, line in enumerate(output.splitlines(), start=1):
        match = re.fullmatch(r"([^\s]+) v([^\s]+)(?: .*)?", line)
        if match is None:
            raise LicenseReportError(
                f"{label} line {line_number} is not a Cargo package: {line!r}"
            )
        packages.add((match.group(1), match.group(2)))
    if not packages:
        raise LicenseReportError(f"{label} returned no packages")
    return packages


def cargo_tree_packages(
    project: pathlib.Path, edges: str, target: str, label: str
) -> set[PackageKey]:
    """用 Cargo 自身的依赖种类过滤避免仅由 dev feature 激活的伪生产节点。

    Use Cargo's own edge filtering so dev-feature-only nodes cannot look like production packages.
    """

    cargo = os.environ.get("CARGO", "cargo")
    try:
        result = subprocess.run(
            [
                cargo,
                "tree",
                "--locked",
                "--all-features",
                "--edges",
                edges,
                "--target",
                target,
                "--prefix",
                "none",
                "--format",
                "{p}",
            ],
            cwd=project,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
    except OSError as error:
        raise LicenseReportError(f"cannot execute cargo tree: {error}") from error
    if result.returncode != 0:
        raise LicenseReportError(
            f"{label} failed with exit code {result.returncode}: "
            f"{result.stderr.strip()}"
        )
    return parse_tree_packages(result.stdout, label)


def dependency_boundary(
    project: pathlib.Path,
) -> tuple[set[PackageKey], set[PackageKey]]:
    production: set[PackageKey] = set()
    all_packages: set[PackageKey] = set()
    for target in RELEASE_TARGETS:
        production.update(
            cargo_tree_packages(
                project,
                "normal,build",
                target,
                f"Cargo normal/build dependency tree for {target}",
            )
        )
        all_packages.update(
            cargo_tree_packages(
                project,
                "normal,build,dev",
                target,
                f"Cargo complete dependency tree for {target}",
            )
        )
    if not production <= all_packages:
        raise LicenseReportError("Cargo complete dependency tree omits production packages")
    development_only = all_packages - production
    return production, development_only


def root_manifest_package(project: pathlib.Path) -> tuple[PackageKey, str]:
    """读取根清单的包身份和精确 SPDX 许可。 / Read the root identity and exact SPDX license."""

    manifest = project / "Cargo.toml"
    try:
        document = tomllib.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise LicenseReportError(
            f"cannot read root Cargo manifest {manifest}: {error}"
        ) from error
    package = document.get("package")
    if not isinstance(package, dict):
        raise LicenseReportError(f"root Cargo manifest {manifest} has no [package] table")

    values: dict[str, str] = {}
    for field_name in ("name", "version", "license"):
        value = package.get(field_name)
        if not isinstance(value, str) or not value.strip():
            raise LicenseReportError(
                f"root Cargo manifest {manifest} has no non-empty package.{field_name}"
            )
        values[field_name] = value.strip()
    return (values["name"], values["version"]), values["license"]


@dataclass
class LicenseSection:
    """单个许可证正文及其使用方。 / One license text and the packages that use it."""

    title_parts: list[str] = field(default_factory=list)
    anchor_parts: list[str] = field(default_factory=list)
    text_parts: list[str] = field(default_factory=list)
    packages: set[PackageKey] = field(default_factory=set)
    license_id: str | None = None
    in_title: bool = False
    in_anchor: bool = False
    in_text: bool = False


class ReportParser(HTMLParser):
    """只提取模板中可审计的 section/used_by/pre 结构。 / Extract the auditable section/used_by/pre structure."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.current: LicenseSection | None = None
        self.sections: list[LicenseSection] = []

    def handle_starttag(
        self, tag: str, attributes: list[tuple[str, str | None]]
    ) -> None:
        if tag == "section":
            if self.current is not None:
                raise LicenseReportError("license report contains nested sections")
            self.current = LicenseSection()
        elif self.current is not None and tag == "h3":
            license_ids = [
                value for name, value in attributes if name == "data-spdx-id"
            ]
            if (
                len(license_ids) != 1
                or not isinstance(license_ids[0], str)
                or not license_ids[0].strip()
            ):
                raise LicenseReportError("license section heading has no SPDX id")
            if self.current.license_id is not None:
                raise LicenseReportError("license section contains multiple headings")
            self.current.license_id = license_ids[0].strip()
            self.current.in_title = True
        elif self.current is not None and tag == "a":
            if self.current.in_anchor:
                raise LicenseReportError("license report contains nested package links")
            self.current.in_anchor = True
            self.current.anchor_parts = []
        elif self.current is not None and tag == "pre":
            self.current.in_text = True

    def handle_data(self, data: str) -> None:
        if self.current is None:
            return
        if self.current.in_title:
            self.current.title_parts.append(data)
        if self.current.in_anchor:
            self.current.anchor_parts.append(data)
        if self.current.in_text:
            self.current.text_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if self.current is None:
            return
        if tag == "h3":
            self.current.in_title = False
        elif tag == "a" and self.current.in_anchor:
            package_text = " ".join("".join(self.current.anchor_parts).split())
            name, separator, version = package_text.rpartition(" ")
            if not separator or not name or not version:
                raise LicenseReportError(
                    f"license report has an invalid used_by entry: {package_text!r}"
                )
            self.current.packages.add((name, version))
            self.current.in_anchor = False
            self.current.anchor_parts = []
        elif tag == "pre":
            self.current.in_text = False
        elif tag == "section":
            self.sections.append(self.current)
            self.current = None

    def finish(self) -> list[LicenseSection]:
        self.close()
        if self.current is not None:
            raise LicenseReportError("license report ends inside a section")
        return self.sections


def read_report(path: pathlib.Path) -> str:
    try:
        details = path.stat()
        if details.st_size <= 0 or details.st_size > MAX_REPORT_BYTES:
            raise LicenseReportError(
                f"license report {path} is {details.st_size} bytes; limit is {MAX_REPORT_BYTES}"
            )
        return path.read_text(encoding="utf-8")
    except LicenseReportError:
        raise
    except (OSError, UnicodeError) as error:
        raise LicenseReportError(f"cannot read license report {path}: {error}") from error


def verify_report(
    report: str,
    production: set[PackageKey],
    development_only: set[PackageKey],
    root: PackageKey,
    root_license: str,
) -> tuple[int, int]:
    parser = ReportParser()
    try:
        parser.feed(report)
        sections = parser.finish()
    except LicenseReportError:
        raise
    except Exception as error:
        raise LicenseReportError(f"cannot parse license report HTML: {error}") from error
    if not sections:
        raise LicenseReportError("license report has no license sections")

    observed: set[PackageKey] = set()
    package_licenses: dict[PackageKey, set[str]] = {}
    for index, section in enumerate(sections):
        title = " ".join("".join(section.title_parts).split())
        text = "".join(section.text_parts).strip()
        license_id = section.license_id
        if not title:
            raise LicenseReportError(f"license section {index} has no title")
        if license_id is None:
            raise LicenseReportError(f"license section {title!r} has no SPDX id")
        # cargo-about may emit several texts for the same SPDX expression because
        # packages can ship distinct copyright notices or license-file variants.
        # cargo-about 可能为同一 SPDX 表达式输出多个正文，因为不同包会携带不同的
        # 版权声明或许可证文件版本；这里按包累计映射，而不把重复表达式误判为冲突。
        if not section.packages:
            raise LicenseReportError(f"license section {title!r} has no used_by packages")
        if not text:
            raise LicenseReportError(f"license section {title!r} has no license text")
        observed.update(section.packages)
        for package in section.packages:
            package_licenses.setdefault(package, set()).add(license_id)

    leaked = observed & development_only
    if leaked:
        raise LicenseReportError(
            "license report contains development-only packages: "
            + ", ".join(f"{name}@{version}" for name, version in sorted(leaked))
        )
    unexpected = observed - production
    if unexpected:
        raise LicenseReportError(
            "license report contains packages outside the normal/build boundary: "
            + ", ".join(f"{name}@{version}" for name, version in sorted(unexpected))
        )
    missing = production - observed
    if missing:
        raise LicenseReportError(
            "license report omits production packages: "
            + ", ".join(f"{name}@{version}" for name, version in sorted(missing))
        )
    if root not in production:
        raise LicenseReportError(
            f"Cargo production boundary omits its root package {root[0]}@{root[1]}"
        )
    actual_root_licenses = package_licenses.get(root, set())
    if actual_root_licenses != {root_license}:
        raise LicenseReportError(
            f"root package {root[0]}@{root[1]} license sections do not match "
            f"Cargo.toml: expected {root_license!r}, found {sorted(actual_root_licenses)!r}"
        )
    return len(sections), len(observed)


def fixture_section(
    packages: tuple[PackageKey, ...],
    *,
    include_text: bool = True,
    license_id: str = "MIT",
) -> str:
    links = "".join(
        f"<li><a href='https://example.invalid'>{html.escape(name)} "
        f"{html.escape(version)}</a></li>"
        for name, version in packages
    )
    text = "Permission is granted." if include_text else ""
    return (
        "<section>"
        f"<h3 data-spdx-id='{html.escape(license_id)}'>MIT License</h3>"
        f"<p>Used by:</p><ul>{links}</ul><pre>{text}</pre></section>"
    )


def fixture_document(*sections: str) -> str:
    return "<!doctype html><html><body>" + "".join(sections) + "</body></html>"


def fixture_report(
    packages: tuple[PackageKey, ...],
    *,
    include_text: bool = True,
    license_id: str = "MIT",
) -> str:
    return fixture_document(
        fixture_section(
            packages, include_text=include_text, license_id=license_id
        )
    )


def self_test() -> None:
    valid_packages = (
        ("app", "1.2.3"),
        ("runtime", "2.0.0"),
        ("builder", "3.0.0"),
    )
    production = set(valid_packages)
    development_only = {("test-helper", "4.0.0")}
    parsed = parse_tree_packages(
        "app v1.2.3 (/project)\nruntime v2.0.0\nbuilder v3.0.0 (*)\n",
        "fixture tree",
    )
    if parsed != production:
        raise AssertionError(f"Cargo tree fixture parsed incorrectly: {parsed!r}")
    root = ("app", "1.2.3")
    verify_report(
        fixture_report(valid_packages), production, development_only, root, "MIT"
    )
    # Real cargo-about output commonly has multiple texts with the same SPDX ID.
    # 真实 cargo-about 输出通常会为同一 SPDX ID 保留多个许可证正文。
    verify_report(
        fixture_document(
            fixture_section(valid_packages[:2]),
            fixture_section(valid_packages[2:]),
        ),
        production,
        development_only,
        root,
        "MIT",
    )

    invalid_reports = (
        "<!doctype html><html><body><h1>Non-empty shell</h1></body></html>",
        fixture_report(valid_packages[:-1]),
        fixture_report(valid_packages + (("test-helper", "4.0.0"),)),
        fixture_report(valid_packages, include_text=False),
        fixture_report(()),
        fixture_report(valid_packages, license_id="Apache-2.0"),
    )
    for invalid in invalid_reports:
        try:
            verify_report(invalid, production, development_only, root, "MIT")
        except LicenseReportError:
            continue
        raise AssertionError("invalid third-party license report fixture was accepted")
    try:
        parse_tree_packages("not a cargo package line\n", "invalid fixture tree")
    except LicenseReportError:
        pass
    else:
        raise AssertionError("invalid Cargo tree fixture was accepted")
    print("third-party license report self-test passed")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify", help="validate a generated license report")
    verify.add_argument("report", type=pathlib.Path)
    verify.add_argument(
        "--project-directory", type=pathlib.Path, default=pathlib.Path(".")
    )
    commands.add_parser("self-test", help="run deterministic positive and negative fixtures")
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "self-test":
            self_test()
        else:
            project = args.project_directory.resolve()
            production, development_only = dependency_boundary(project)
            root_package, root_license = root_manifest_package(project)
            section_count, package_count = verify_report(
                read_report(args.report),
                production,
                development_only,
                root_package,
                root_license,
            )
            print(
                f"license report covers {package_count} normal/build packages "
                f"across {section_count} non-empty license sections"
            )
    except LicenseReportError as error:
        print(f"license report verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
