#!/usr/bin/env python3
"""根据 Cargo 锁定的普通/构建依赖边界验证第三方许可证 HTML 报告。

Validate the third-party-license HTML report against Cargo's locked normal/build boundary.
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
from dataclasses import dataclass, field


MAX_REPORT_BYTES = 64 * 1024 * 1024
PackageKey = tuple[str, str]


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
    project: pathlib.Path, edges: str, label: str
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
                "all",
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
    production = cargo_tree_packages(
        project, "normal,build", "Cargo normal/build dependency tree"
    )
    all_packages = cargo_tree_packages(
        project, "normal,build,dev", "Cargo complete dependency tree"
    )
    if not production <= all_packages:
        raise LicenseReportError("Cargo complete dependency tree omits production packages")
    development_only = all_packages - production
    return production, development_only


@dataclass
class LicenseSection:
    """单个许可证正文及其使用方。 / One license text and the packages that use it."""

    title_parts: list[str] = field(default_factory=list)
    anchor_parts: list[str] = field(default_factory=list)
    text_parts: list[str] = field(default_factory=list)
    packages: set[PackageKey] = field(default_factory=set)
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
        self, tag: str, _attributes: list[tuple[str, str | None]]
    ) -> None:
        if tag == "section":
            if self.current is not None:
                raise LicenseReportError("license report contains nested sections")
            self.current = LicenseSection()
        elif self.current is not None and tag == "h3":
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
    report: str, production: set[PackageKey], development_only: set[PackageKey]
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
    for index, section in enumerate(sections):
        title = " ".join("".join(section.title_parts).split())
        text = "".join(section.text_parts).strip()
        if not title:
            raise LicenseReportError(f"license section {index} has no title")
        if not section.packages:
            raise LicenseReportError(f"license section {title!r} has no used_by packages")
        if not text:
            raise LicenseReportError(f"license section {title!r} has no license text")
        observed.update(section.packages)

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
    return len(sections), len(observed)


def fixture_report(packages: tuple[PackageKey, ...], *, include_text: bool = True) -> str:
    links = "".join(
        f"<li><a href='https://example.invalid'>{html.escape(name)} "
        f"{html.escape(version)}</a></li>"
        for name, version in packages
    )
    text = "Permission is granted." if include_text else ""
    return (
        "<!doctype html><html><body><section><h3>MIT License</h3>"
        f"<p>Used by:</p><ul>{links}</ul><pre>{text}</pre></section></body></html>"
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
    verify_report(fixture_report(valid_packages), production, development_only)

    invalid_reports = (
        "<!doctype html><html><body><h1>Non-empty shell</h1></body></html>",
        fixture_report(valid_packages[:-1]),
        fixture_report(valid_packages + (("test-helper", "4.0.0"),)),
        fixture_report(valid_packages, include_text=False),
        fixture_report(()),
    )
    for invalid in invalid_reports:
        try:
            verify_report(invalid, production, development_only)
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
            production, development_only = dependency_boundary(
                args.project_directory.resolve()
            )
            section_count, package_count = verify_report(
                read_report(args.report), production, development_only
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
