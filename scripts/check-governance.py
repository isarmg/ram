#!/usr/bin/env python3
"""仓库侧治理控制发生漂移时关闭失败。

本检查器能验证提交到仓库的文件，但不会声称验证 GitHub 权限、规则集、环境审阅者、私密
报告可用性或不可变发布设置；管理员必须依据 docs/REPOSITORY_GOVERNANCE.md 审计这些外部控制。

Fail closed when repository-side governance controls drift.

This checker can validate files committed to the repository. It intentionally
does not claim to validate GitHub permissions, rulesets, environment reviewers,
private-reporting availability, or immutable-release settings; administrators
must audit those external controls using docs/REPOSITORY_GOVERNANCE.md.
"""

from __future__ import annotations

import pathlib
import sys
import tomllib


ROOT = pathlib.Path(__file__).resolve().parent.parent


def read(relative: str) -> str:
    path = ROOT / relative
    try:
        contents = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ValueError(f"cannot read {relative}: {error}") from error
    if not contents.strip():
        raise ValueError(f"{relative} is empty")
    return contents


def codeowner_rules(contents: str) -> dict[str, tuple[str, ...]]:
    rules: dict[str, tuple[str, ...]] = {}
    for line_number, raw_line in enumerate(contents.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) < 2:
            raise ValueError(f"CODEOWNERS:{line_number} has no owner")
        owners = tuple(dict.fromkeys(field for field in fields[1:] if field.startswith("@")))
        if len(owners) != len(fields) - 1:
            raise ValueError(f"CODEOWNERS:{line_number} contains an invalid owner token")
        rules[fields[0]] = owners
    return rules


def require_needles(relative: str, contents: str, needles: tuple[str, ...]) -> None:
    for needle in needles:
        if needle not in contents:
            raise ValueError(f"{relative} is missing required text: {needle}")


def require_bilingual_documents() -> None:
    pairs = {
        "README.md": ("# Ram 文件服务", "# Ram File Server (English)"),
        "CHANGELOG.md": ("# 变更记录", "# Changelog (English)"),
        "CONTRIBUTING.md": ("# 贡献指南", "# Contributing Guide"),
        "SECURITY.md": ("# 安全策略", "# Security Policy"),
        "todlist.md": (
            "# Ram 项目整改与优化 To-Do List",
            "# Ram Remediation and Optimization To-Do List",
        ),
        "docs/THREAT_MODEL.md": ("# 部署威胁模型", "# Deployment Threat Model"),
        "docs/REPOSITORY_GOVERNANCE.md": (
            "# 仓库治理与发布保护检查表",
            "# Repository Governance and Release Protection Checklist",
        ),
        "docs/CODE_FLOW.md": (
            "# 代码工作流程与模块作用",
            "# Code Flow and Module Responsibilities (English)",
        ),
        "benchmarks/README.md": ("# Ram 性能基线", "# Ram performance baseline"),
        "benchmarks/baselines/README.md": ("# 已批准基线", "# Approved baselines"),
        "fuzz/README.md": ("# 解析器模糊测试", "# Parser fuzzing"),
    }
    for relative, headings in pairs.items():
        require_needles(relative, read(relative), headings)

    example = read("config.example.yaml")
    require_needles(
        "config.example.yaml",
        example,
        (
            "# Ram 配置示例",
            "# Example Ram configuration",
            "# 特权能力均需显式启用",
            "# Privileged capabilities are opt-in",
        ),
    )


def check() -> None:
    require_bilingual_documents()
    codeowners = codeowner_rules(read(".github/CODEOWNERS"))
    sensitive_rules = (
        "/src/auth/",
        "/src/config/",
        "/src/http/",
        "/src/runtime/",
        "/src/server/",
        "/src/path_identity.rs",
        "/src/source_identity.rs",
        "/fuzz/",
        "/.github/workflows/",
        "/.github/actionlint.yaml",
        "/scripts/check-license-report.py",
        "/scripts/check-release-manifest.py",
        "/scripts/check-release-archive.py",
        "/scripts/check-release-assets.py",
        "/scripts/check-release-state.py",
        "/scripts/check-sbom.py",
        "/scripts/smoke-release-artifact.sh",
    )
    for pattern in sensitive_rules:
        owners = codeowners.get(pattern, ())
        if len(owners) < 2:
            raise ValueError(
                f"CODEOWNERS rule {pattern!r} needs at least two distinct owners, got {owners}"
            )

    security = read("SECURITY.md")
    require_needles(
        "SECURITY.md",
        security,
        (
            "## 支持版本",
            "## 私密报告渠道",
            "security/advisories/new",
            "## 响应目标",
            "## 协调披露流程",
        ),
    )

    contributing = read("CONTRIBUTING.md")
    require_needles(
        "CONTRIBUTING.md",
        contributing,
        (
            "cargo test --all-targets --all-features --locked",
            "cargo test --all-targets --no-default-features --locked",
            "openat2",
            "独立审阅",
            "docs/REPOSITORY_GOVERNANCE.md",
        ),
    )

    threat_model = read("docs/THREAT_MODEL.md")
    require_needles(
        "docs/THREAT_MODEL.md",
        threat_model,
        (
            "## 1. 单用户部署",
            "## 2. 多用户只读部署",
            "## 3. 不可信写用户",
            "## 4. 反向代理部署",
            "## 5. 多实例部署",
            "## 6. NFS/FUSE/其它远程或用户态文件系统",
        ),
    )

    governance = read("docs/REPOSITORY_GOVERNANCE.md")
    require_needles(
        "docs/REPOSITORY_GOVERNANCE.md",
        governance,
        (
            "branch ruleset",
            "tag ruleset",
            "immutable releases",
            "Private vulnerability reporting",
            "完全相同的恢复路径",
            "exactly matches the newly verified",
            "target-specific CycloneDX",
        ),
    )

    with (ROOT / "Cargo.toml").open("rb") as cargo_file:
        cargo_package = tomllib.load(cargo_file)["package"]
        version = cargo_package["version"]
        package_include = cargo_package["include"]
    if "/docs/CODE_FLOW.md" not in package_include:
        raise ValueError("Cargo.toml package.include must contain /docs/CODE_FLOW.md")
    if cargo_package.get("publish") != ["crates-io"]:
        raise ValueError("Cargo.toml package.publish must be exactly ['crates-io']")
    changelog = read("CHANGELOG.md")
    require_needles(
        "CHANGELOG.md",
        changelog,
        ("## [Unreleased]", f"## [{version}]"),
    )

    release = read(".github/workflows/release.yaml")
    require_needles(
        ".github/workflows/release.yaml",
        release,
        (
            "GITHUB_REF_PROTECTED",
            "git merge-base --is-ancestor",
            "Verify the annotated release tag signature",
            "scripts/check-release-tag.py version-sync",
            "scripts/check-release-tag.py verify",
            "tag_object_sha=${tag_url##*/}",
            "scripts/check-sbom.py verify-target",
            "scripts/check-sbom.py verify-spdx",
            "scripts/check-license-report.py verify",
            "cargo cyclonedx --all-features",
            "environment: release",
            "Preflight the crates.io version",
            "scripts/check-release-state.py crate-checksum",
            "Verify published crate visibility and checksum",
            "scripts/check-release-state.py post-publish",
            "for attempt in {1..12}",
            "scripts/check-release-state.py draft",
            "--existing-draft-id",
            "--page-number",
            "Reject a published release or clean an exact failed draft",
            "Verify the draft release asset inventory",
            "scripts/check-release-assets.py verify",
            "scripts/check-release-assets.py published",
            '"$GITHUB_SHA" "$GITHUB_REPOSITORY" "$PRERELEASE"',
            'scripts/check-release-assets.py local dist "$VERSION"',
            "verified-source-package",
            "draft: true",
            "prepare_release:",
            "finalize_release:",
            "needs.validate.outputs.prerelease == 'false'",
            "needs.validate.outputs.crate_exists != 'true'",
            "needs.publish-crate.result == 'success'",
            "scripts/check-release-manifest.py create",
            "predicate-path:",
            "cargo publish --locked --no-verify --registry crates-io",
            "ram-release-workflow:${{ github.repository }}",
        ),
    )

    ci = read(".github/workflows/ci.yaml")
    require_needles(
        ".github/workflows/ci.yaml",
        ci,
        (
            "ACTIONLINT_VERSION: 1.7.12",
            "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8",
            "rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}",
            '"$tool_dir/actionlint" -config-file .github/actionlint.yaml',
            "git ls-files -z -- '*.sh'",
            'bash -n "$script"',
            "scripts/check-license-report.py self-test",
            "scripts/check-release-manifest.py self-test",
            "scripts/check-release-archive.py self-test",
            "scripts/check-release-assets.py self-test",
            "scripts/check-release-state.py self-test",
            "scripts/check-sbom.py self-test",
        ),
    )

    archive_checker = read("scripts/check-release-archive.py")
    require_needles(
        "scripts/check-release-archive.py",
        archive_checker,
        (
            '"docs/CODE_FLOW.md"',
            "MAX_EXPANDED_ARCHIVE_BYTES",
            "BoundedExpandedReader",
            'mode="r|"',
            "maximum_expanded_bytes=1024",
            "def self_test()",
            "missing-code-flow.tar.gz",
        ),
    )
    smoke = read("scripts/smoke-release-artifact.sh")
    require_needles(
        "scripts/smoke-release-artifact.sh",
        smoke,
        (
            "scripts/check-release-archive.py verify",
            "scripts/check-release-assets.py checksum",
            "scripts/check-release-manifest.py verify",
            "grep -Eo 'GLIBC_",
            "|| true; }",
        ),
    )

    release_metrics = read("scripts/write-release-metrics.sh")
    require_needles(
        "scripts/write-release-metrics.sh",
        release_metrics,
        (
            "rustc_commit_hash=$(rustc --version --verbose",
            '[[ ! $rustc_commit_hash =~ ^[0-9a-f]{40}$ ]]',
        ),
    )

    release_tag_checker = read("scripts/check-release-tag.py")
    require_needles(
        "scripts/check-release-tag.py",
        release_tag_checker,
        (
            'verification.get("verified") is not True',
            'verification.get("reason") != "valid"',
            'payload.get("tag") != expected_tag',
            'payload.get("sha") != expected_tag_sha',
            "annotated tag must point directly at the commit being built",
            "verify_version_documents",
        ),
    )

    release_asset_checker = read("scripts/check-release-assets.py")
    require_needles(
        "scripts/check-release-assets.py",
        release_asset_checker,
        (
            "def verify_archive_checksum",
            "def verify_published_release",
            "release_marker(repository, version, commit)",
            '"published_at"',
            'expected = f"{digest}  {archive.name}\\n".encode("ascii")',
            "checksum_mutations",
        ),
    )

    license_template = read("about.hbs")
    require_needles(
        "about.hbs",
        license_template,
        (
            "Ram 第三方许可证",
            "Ram third-party licenses",
            "使用方",
            "Used by:",
            "{{text}}",
        ),
    )

    license_report_checker = read("scripts/check-license-report.py")
    require_needles(
        "scripts/check-license-report.py",
        license_report_checker,
        (
            'os.environ.get("CARGO", "cargo")',
            'project, "normal,build"',
            'project, "normal,build,dev"',
            "license report has no license sections",
            "has no license text",
            "contains development-only packages",
            "def self_test()",
        ),
    )

    release_state_checker = read("scripts/check-release-state.py")
    require_needles(
        "scripts/check-release-state.py",
        release_state_checker,
        (
            "verify_crates_version_response",
            "classify_post_publish_crate",
            "verify_published_release_response",
            "classify_draft_page",
            "body.count(marker) != 1",
            'release.get("target_commitish") != expected_commit',
            "MAX_RELEASE_PAGES",
            "checksum",
            "def self_test()",
        ),
    )

    release_manifest_checker = read("scripts/check-release-manifest.py")
    require_needles(
        "scripts/check-release-manifest.py",
        release_manifest_checker,
        (
            "release-manifest/v1",
            '"binary": file_record(binary, "ram")',
            '"format": "CycloneDX-1.3"',
            '"format": "SPDX-2.3"',
            "observed != expected",
            "def self_test()",
        ),
    )

    sbom_checker = read("scripts/check-sbom.py")
    require_needles(
        "scripts/check-sbom.py",
        sbom_checker,
        (
            "locked Cargo source id",
            "verify_cargo_purl",
            "download locations do not match locked Cargo sources",
            "verify_target_cyclonedx",
            "verify_global_spdx",
        ),
    )


def main() -> int:
    try:
        check()
    except (OSError, KeyError, TypeError, ValueError) as error:
        print(f"governance check failed: {error}", file=sys.stderr)
        return 1
    print("repository-side governance policy is internally consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
