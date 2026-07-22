#!/usr/bin/env python3
"""根据 Cargo 锁定依赖图对发布 SBOM 做语义校验。

固定 cargo-cyclonedx 生成器记录普通和构建依赖，而 cargo-sbom 有意省略构建及开发依赖。
因此本检查器要求 CycloneDX 精确覆盖普通/构建依赖图，SPDX 精确覆盖普通依赖图。已知
lib/bin 子组件匹配到 Cargo target，其他嵌套组件仍视为包；两份文档都不得含仅开发包。
根包许可证还必须与 Cargo 元数据精确一致；第三方依赖继续保留各自的许可证。

Semantically validate release SBOMs against Cargo's locked dependency graph.

The pinned cargo-cyclonedx generator records normal and build dependencies,
while cargo-sbom intentionally omits both build and development dependencies.
This checker therefore requires the CycloneDX document to exactly cover the
normal/build graph and the SPDX document to exactly cover the normal graph.
Known lib/bin subcomponents are matched to Cargo targets; every other nested
component is still treated as a package. Neither document may contain a
development-only package. The root package's license must also exactly match
Cargo metadata; dependency licenses remain governed by their own packages.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import pathlib
import subprocess
import sys
import urllib.parse
from collections import Counter
from typing import Any


MAX_SBOM_BYTES = 64 * 1024 * 1024
CYCLONEDX_TOOL = ("cargo-cyclonedx", "0.5.9")
SPDX_TOOL = "Tool: cargo-sbom-v0.10.0"
PackageKey = tuple[str, str]
PackageCounts = Counter[PackageKey]
DependencyEdge = tuple[PackageKey, PackageKey]
CargoTargetKey = tuple[str, str, str, str]
CargoIdentity = tuple[str, str, str]
SpdxIdentity = tuple[str, str, str]


class SbomVerificationError(ValueError):
    """清单畸形或与 Cargo 依赖图不一致。 / An inventory is malformed or disagrees with Cargo's dependency graph."""


def require_object(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SbomVerificationError(f"{location} must be an object")
    return value


def require_list(value: Any, location: str) -> list[Any]:
    if not isinstance(value, list):
        raise SbomVerificationError(f"{location} must be an array")
    return value


def require_string(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SbomVerificationError(f"{location} must be a non-empty string")
    return value


def package_key(value: dict[str, Any], location: str, version_field: str) -> PackageKey:
    return (
        require_string(value.get("name"), f"{location}.name"),
        require_string(value.get(version_field), f"{location}.{version_field}"),
    )


def read_json_object(path: pathlib.Path) -> dict[str, Any]:
    try:
        size = path.stat().st_size
        if size > MAX_SBOM_BYTES:
            raise SbomVerificationError(
                f"{path} is {size} bytes; the validation limit is {MAX_SBOM_BYTES}"
            )
        value = json.loads(path.read_text(encoding="utf-8"))
    except SbomVerificationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SbomVerificationError(f"cannot read JSON object from {path}: {error}") from error
    return require_object(value, str(path))


def cargo_metadata(project: pathlib.Path, target: str | None = None) -> dict[str, Any]:
    cargo = os.environ.get("CARGO", "cargo")
    try:
        command = [
            cargo,
            "metadata",
            "--locked",
            "--all-features",
            "--format-version",
            "1",
        ]
        if target is not None:
            if not target or any(character.isspace() for character in target):
                raise SbomVerificationError(f"invalid Cargo target {target!r}")
            command.extend(("--filter-platform", target))
        result = subprocess.run(
            command,
            cwd=project,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
    except OSError as error:
        raise SbomVerificationError(f"cannot execute cargo metadata: {error}") from error
    if result.returncode != 0:
        details = result.stderr.strip()
        raise SbomVerificationError(
            f"cargo metadata failed with exit code {result.returncode}: {details}"
        )
    try:
        return require_object(json.loads(result.stdout), "cargo metadata")
    except json.JSONDecodeError as error:
        raise SbomVerificationError(f"cargo metadata returned invalid JSON: {error}") from error


# 中文：从 Cargo resolve 图构造三个边界：普通依赖、普通+构建依赖，以及仅在包含 dev 边后
# 才可达的开发包；同时返回根包目标和两个边界内的精确包边。Counter 保留同名同版本的多份
# package ID，避免集合化后掩盖来源不同的锁定节点。
# English: Derive three boundaries from Cargo's resolve graph: normal, normal+build, and packages
# reachable only when dev edges are admitted. Also return root targets and exact package edges for
# both release boundaries. Counter preserves duplicate name/version package IDs instead of hiding
# distinct locked nodes through set conversion.
def dependency_sets(
    metadata: dict[str, Any],
) -> tuple[
    PackageKey,
    str,
    PackageCounts,
    PackageCounts,
    PackageCounts,
    Counter[CargoTargetKey],
    set[DependencyEdge],
    set[DependencyEdge],
    dict[str, PackageKey],
    dict[str, PackageKey],
    Counter[SpdxIdentity],
    Counter[SpdxIdentity],
]:
    packages_raw = require_list(metadata.get("packages"), "cargo metadata.packages")
    resolve = require_object(metadata.get("resolve"), "cargo metadata.resolve")
    nodes_raw = require_list(resolve.get("nodes"), "cargo metadata.resolve.nodes")
    root_id = require_string(resolve.get("root"), "cargo metadata.resolve.root")

    packages: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(packages_raw):
        package = require_object(raw, f"cargo metadata.packages[{index}]")
        package_id = require_string(package.get("id"), f"cargo metadata.packages[{index}].id")
        if package_id in packages:
            raise SbomVerificationError(
                f"cargo metadata contains duplicate package id {package_id}"
            )
        package_key(package, f"cargo metadata.packages[{index}]", "version")
        packages[package_id] = package

    nodes: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(nodes_raw):
        node = require_object(raw, f"cargo metadata.resolve.nodes[{index}]")
        node_id = require_string(node.get("id"), f"cargo metadata.resolve.nodes[{index}].id")
        if node_id in nodes:
            raise SbomVerificationError(
                f"cargo metadata contains duplicate resolve node {node_id}"
            )
        nodes[node_id] = node
    if root_id not in packages or root_id not in nodes:
        raise SbomVerificationError(
            "cargo metadata root is missing from packages or resolve nodes"
        )

    # 中文：保留一条依赖声明的全部 kind；同一目标同时以 normal/build 出现时，任一允许 kind
    # 即可使该边进入对应图，不能只看列表首项。
    # English: Preserve every kind on one dependency declaration. If a target appears under multiple
    # kinds, any admitted kind includes that edge; inspecting only the first item would be unsound.
    def dependencies(node_id: str) -> list[tuple[str, frozenset[str | None]]]:
        node = nodes.get(node_id)
        if node is None:
            raise SbomVerificationError(f"cargo metadata has no resolve node for {node_id}")
        parsed = []
        for dep_index, raw_dep in enumerate(
            require_list(node.get("deps"), f"cargo metadata resolve node {node_id}.deps")
        ):
            dep = require_object(
                raw_dep, f"cargo metadata resolve node {node_id}.deps[{dep_index}]"
            )
            dep_id = require_string(
                dep.get("pkg"), f"cargo metadata dependency from {node_id}.pkg"
            )
            dep_kinds = require_list(
                dep.get("dep_kinds"),
                f"cargo metadata dependency from {node_id}.dep_kinds",
            )
            kinds: set[str | None] = set()
            for kind_index, raw_kind in enumerate(dep_kinds):
                kind = require_object(
                    raw_kind,
                    f"cargo metadata dependency from {node_id}.dep_kinds[{kind_index}]",
                ).get("kind")
                if kind not in (None, "build", "dev"):
                    raise SbomVerificationError(
                        f"cargo metadata dependency from {node_id} has unknown kind {kind!r}"
                    )
                kinds.add(kind)
            if not kinds:
                raise SbomVerificationError(
                    f"cargo metadata dependency from {node_id} has no dependency kind"
                )
            parsed.append((dep_id, frozenset(kinds)))
        return parsed

    # 中文：从 workspace 根做闭包遍历，而非过滤全局 packages；Cargo metadata 可能包含对当前
    # 根不可达的记录，这些记录不属于发布清单。
    # English: Traverse the closure from the workspace root rather than filtering all packages;
    # metadata may contain records unreachable from this release root.
    def traverse(allowed_kinds: frozenset[str | None]) -> set[str]:
        seen = {root_id}
        pending = [root_id]
        while pending:
            node_id = pending.pop()
            for dep_id, kinds in dependencies(node_id):
                if kinds.isdisjoint(allowed_kinds) or dep_id in seen:
                    continue
                if dep_id not in packages:
                    raise SbomVerificationError(
                        f"cargo metadata dependency {dep_id} has no package record"
                    )
                seen.add(dep_id)
                pending.append(dep_id)
        return seen

    def count(package_ids: set[str]) -> PackageCounts:
        return Counter(
            package_key(packages[package_id], f"cargo package {package_id}", "version")
            for package_id in package_ids
        )

    def cargo_identities(package_ids: set[str]) -> dict[str, PackageKey]:
        return {
            package_id: package_key(
                packages[package_id], f"cargo package {package_id}", "version"
            )
            for package_id in package_ids
        }

    def spdx_identities(package_ids: set[str]) -> Counter[SpdxIdentity]:
        identities: Counter[SpdxIdentity] = Counter()
        for package_id in package_ids:
            package = packages[package_id]
            source = package.get("source")
            if source is None:
                download_location = "NONE"
            else:
                download_location = require_string(
                    source, f"cargo package {package_id}.source"
                )
            name, version = package_key(
                package, f"cargo package {package_id}", "version"
            )
            identities[(name, version, download_location)] += 1
        return identities

    # 中文：包计数相同仍不足以证明供应链图相同，因此单独构造边集合并要求 SBOM 精确匹配。
    # English: Equal package counts do not prove an equal supply-chain graph, so retain and later
    # require exact dependency-edge coverage.
    def edges(
        package_ids: set[str], allowed_kinds: frozenset[str | None]
    ) -> set[DependencyEdge]:
        result = set()
        for source_id in package_ids:
            source = package_key(packages[source_id], f"cargo package {source_id}", "version")
            for target_id, kinds in dependencies(source_id):
                if target_id not in package_ids or kinds.isdisjoint(allowed_kinds):
                    continue
                target = package_key(
                    packages[target_id], f"cargo package {target_id}", "version"
                )
                result.add((source, target))
        return result

    # 中文：lib/bin/proc-macro 是 CycloneDX 在根包下生成的 target 子组件，不是额外 Cargo 包；
    # 以名称、版本、组件类型和相对源路径联合识别，避免把同名子组件误计为依赖。
    # English: lib/bin/proc-macro entries are CycloneDX target children of the root, not additional
    # Cargo packages. Match name, version, component type, and relative source path together.
    def root_targets() -> Counter[CargoTargetKey]:
        root_package = packages[root_id]
        manifest_path = pathlib.Path(
            require_string(
                root_package.get("manifest_path"),
                "cargo metadata root package.manifest_path",
            )
        )
        version = require_string(
            root_package.get("version"), "cargo metadata root package.version"
        )
        targets = require_list(
            root_package.get("targets"), "cargo metadata root package.targets"
        )
        result: Counter[CargoTargetKey] = Counter()
        excluded_kinds = {"bench", "example", "test", "custom-build"}
        for index, raw_target in enumerate(targets):
            location = f"cargo metadata root package.targets[{index}]"
            target = require_object(raw_target, location)
            kinds = {
                require_string(kind, f"{location}.kind")
                for kind in require_list(target.get("kind"), f"{location}.kind")
            }
            if kinds & excluded_kinds:
                continue
            if "bin" in kinds:
                component_type = "application"
            elif "proc-macro" in kinds or any("lib" in kind for kind in kinds):
                component_type = "library"
            else:
                continue
            source_path = pathlib.Path(
                require_string(target.get("src_path"), f"{location}.src_path")
            )
            try:
                relative_source = source_path.relative_to(manifest_path.parent).as_posix()
            except ValueError as error:
                raise SbomVerificationError(
                    f"{location}.src_path is outside its Cargo package"
                ) from error
            result[
                (
                    require_string(target.get("name"), f"{location}.name"),
                    version,
                    component_type,
                    relative_source,
                )
            ] += 1
        return result

    normal_kinds = frozenset((None,))
    production_kinds = frozenset((None, "build"))
    normal_ids = traverse(normal_kinds)
    production_ids = traverse(production_kinds)
    all_ids = traverse(frozenset((None, "build", "dev")))
    root_package = packages[root_id]
    root = package_key(root_package, "cargo metadata root package", "version")
    root_license = require_string(
        root_package.get("license"), "cargo metadata root package.license"
    )
    return (
        root,
        root_license,
        count(normal_ids),
        count(production_ids),
        count(all_ids - production_ids),
        root_targets(),
        edges(normal_ids, normal_kinds),
        edges(production_ids, production_kinds),
        cargo_identities(normal_ids),
        cargo_identities(production_ids),
        spdx_identities(normal_ids),
        spdx_identities(production_ids),
    )


def verify_cargo_purl(purl: Any, name: str, version: str, location: str) -> str:
    """要求 purl 的 Cargo 类型、名称和版本规范对应组件，保留生成器限定符。

    Require the purl's Cargo type/name/version to canonically identify the component.
    """

    value = require_string(purl, f"{location}.purl")
    base = value.split("#", 1)[0].split("?", 1)[0]
    prefix = "pkg:cargo/"
    package, separator, encoded_version = base.removeprefix(prefix).rpartition("@")
    if (
        not base.startswith(prefix)
        or not separator
        or urllib.parse.unquote(package) != name
        or urllib.parse.unquote(encoded_version) != version
    ):
        raise SbomVerificationError(
            f"{location}.purl {value!r} does not identify {name}@{version}"
        )
    return value


def verify_spdx_purl(
    package: dict[str, Any], name: str, version: str, source: str, location: str
) -> None:
    external_refs = require_list(package.get("externalRefs", []), f"{location}.externalRefs")
    purls = []
    for index, raw_reference in enumerate(external_refs):
        reference_location = f"{location}.externalRefs[{index}]"
        reference = require_object(raw_reference, reference_location)
        if reference.get("referenceType") != "purl":
            continue
        if reference.get("referenceCategory") != "PACKAGE-MANAGER":
            raise SbomVerificationError(
                f"{reference_location} purl must use PACKAGE-MANAGER"
            )
        purls.append(
            verify_cargo_purl(
                reference.get("referenceLocator"), name, version, reference_location
            )
        )
    crates_io_source = source in (
        "registry+https://github.com/rust-lang/crates.io-index",
        "sparse+https://index.crates.io/",
    )
    if crates_io_source and len(purls) != 1:
        raise SbomVerificationError(
            f"{location} from crates.io must contain exactly one Cargo purl"
        )
    if len(purls) > 1:
        raise SbomVerificationError(f"{location} contains duplicate purl references")


def format_packages(packages: PackageCounts) -> str:
    values = []
    for (name, version), count in sorted(packages.items()):
        suffix = f" (x{count})" if count > 1 else ""
        values.append(f"{name}@{version}{suffix}")
    return ", ".join(values)


def verify_boundary(
    label: str,
    actual: PackageCounts,
    expected: PackageCounts,
    development_only: PackageCounts,
) -> None:
    missing = expected - actual
    unexpected = actual - expected
    leaked = unexpected & development_only
    if leaked:
        raise SbomVerificationError(
            f"{label} contains development-only packages: {format_packages(leaked)}"
        )
    if missing:
        raise SbomVerificationError(
            f"{label} is missing locked production packages: {format_packages(missing)}"
        )
    if unexpected:
        raise SbomVerificationError(
            f"{label} contains packages outside its production boundary: "
            f"{format_packages(unexpected)}"
        )


def format_edges(edges: set[DependencyEdge]) -> str:
    rendered = [
        f"{source[0]}@{source[1]} -> {target[0]}@{target[1]}"
        for source, target in sorted(edges)
    ]
    if len(rendered) > 20:
        return ", ".join(rendered[:20]) + f", ... ({len(rendered)} total)"
    return ", ".join(rendered)


def verify_edges(
    label: str, actual: set[DependencyEdge], expected: set[DependencyEdge]
) -> None:
    missing = expected - actual
    unexpected = actual - expected
    if missing:
        raise SbomVerificationError(
            f"{label} is missing locked dependency edges: {format_edges(missing)}"
        )
    if unexpected:
        raise SbomVerificationError(
            f"{label} contains dependency edges outside the locked graph: "
            f"{format_edges(unexpected)}"
        )


def nested_components(
    component: dict[str, Any], location: str
) -> list[tuple[dict[str, Any], str]]:
    values = [(component, location)]
    children = component.get("components", [])
    for index, raw_child in enumerate(require_list(children, f"{location}.components")):
        child_location = f"{location}.components[{index}]"
        child = require_object(raw_child, child_location)
        values.extend(nested_components(child, child_location))
    return values


def cyclonedx_target_key(
    component: dict[str, Any], location: str
) -> CargoTargetKey:
    purl = require_string(component.get("purl"), f"{location}.purl")
    _base, separator, fragment = purl.partition("#")
    if not separator or not fragment:
        raise SbomVerificationError(
            f"{location}.purl must identify the Cargo target source path"
        )
    return (
        require_string(component.get("name"), f"{location}.name"),
        require_string(component.get("version"), f"{location}.version"),
        require_string(component.get("type"), f"{location}.type"),
        urllib.parse.unquote(fragment),
    )


def optional_cyclonedx_target_key(
    component: dict[str, Any], location: str
) -> CargoTargetKey | None:
    purl = component.get("purl")
    if not isinstance(purl, str) or not purl.partition("#")[2]:
        return None
    return cyclonedx_target_key(component, location)


# 中文：CycloneDX 必须精确覆盖 normal+build 包及边。根 target 子组件先从包集合剥离；所有
# 其余嵌套组件仍按包校验，并要求唯一 bom-ref、license、purl 以及无悬空/重复依赖引用。
# English: CycloneDX must exactly cover normal+build packages and edges. Root target children are
# removed from package accounting first; every other nested component remains a package and must
# carry a unique bom-ref, license, purl, and non-dangling/non-duplicate dependency references.
def verify_cyclonedx(
    document: dict[str, Any],
    root: PackageKey,
    root_license: str,
    expected: PackageCounts,
    development_only: PackageCounts,
    expected_targets: Counter[CargoTargetKey],
    expected_edges: set[DependencyEdge],
    expected_identities: dict[str, PackageKey],
    expected_target: str | None = None,
) -> None:
    if document.get("bomFormat") != "CycloneDX":
        raise SbomVerificationError("CycloneDX bomFormat must be 'CycloneDX'")
    if document.get("specVersion") not in ("1.3", "1.4", "1.5"):
        raise SbomVerificationError("CycloneDX specVersion is unsupported")
    if document.get("version") != 1:
        raise SbomVerificationError("CycloneDX document version must be 1")
    serial = require_string(document.get("serialNumber"), "CycloneDX serialNumber")
    if not serial.startswith("urn:uuid:"):
        raise SbomVerificationError("CycloneDX serialNumber must be a UUID URN")

    metadata = require_object(document.get("metadata"), "CycloneDX metadata")
    tools = require_list(metadata.get("tools"), "CycloneDX metadata.tools")
    observed_tools = {
        (
            require_string(
                require_object(tool, "CycloneDX tool").get("name"),
                "CycloneDX tool.name",
            ),
            require_string(
                require_object(tool, "CycloneDX tool").get("version"),
                "CycloneDX tool.version",
            ),
        )
        for tool in tools
    }
    if CYCLONEDX_TOOL not in observed_tools:
        raise SbomVerificationError(
            f"CycloneDX document was not generated by {CYCLONEDX_TOOL[0]} {CYCLONEDX_TOOL[1]}"
        )
    properties = require_list(metadata.get("properties"), "CycloneDX metadata.properties")
    all_targets = any(
        isinstance(value, dict)
        and value.get("name") == "cdx:rustc:sbom:target:all_targets"
        and value.get("value") == "true"
        for value in properties
    )
    target_triples = {
        value.get("value")
        for value in properties
        if isinstance(value, dict)
        and value.get("name") == "cdx:rustc:sbom:target:triple"
        and isinstance(value.get("value"), str)
    }
    if expected_target is None:
        if not all_targets:
            raise SbomVerificationError("CycloneDX document does not cover all platforms")
    elif all_targets or target_triples != {expected_target}:
        raise SbomVerificationError(
            f"CycloneDX target platform does not exactly match {expected_target}"
        )

    root_component = require_object(metadata.get("component"), "CycloneDX metadata.component")
    if package_key(root_component, "CycloneDX root component", "version") != root:
        raise SbomVerificationError(
            "CycloneDX root component name/version does not match Cargo metadata"
        )
    root_licenses = require_list(
        root_component.get("licenses"), "CycloneDX root component.licenses"
    )
    if len(root_licenses) != 1:
        raise SbomVerificationError(
            "CycloneDX root component must contain exactly one Cargo license expression"
        )
    root_license_entry = require_object(
        root_licenses[0], "CycloneDX root component.licenses[0]"
    )
    observed_root_license = require_string(
        root_license_entry.get("expression"),
        "CycloneDX root component.licenses[0].expression",
    )
    if observed_root_license != root_license:
        raise SbomVerificationError(
            "CycloneDX root component license does not match Cargo metadata: "
            f"expected {root_license!r}, found {observed_root_license!r}"
        )
    top_components = require_list(document.get("components"), "CycloneDX components")
    package_components = [(root_component, "CycloneDX root component")]
    all_components = [(root_component, "CycloneDX root component")]
    target_refs: set[str] = set()
    remaining_targets = expected_targets.copy()

    root_children = require_list(
        root_component.get("components", []), "CycloneDX root component.components"
    )
    for index, raw_child in enumerate(root_children):
        location = f"CycloneDX root component.components[{index}]"
        child = require_object(raw_child, location)
        nested = nested_components(child, location)
        all_components.extend(nested)
        target = optional_cyclonedx_target_key(child, location)
        if target is not None and remaining_targets[target] > 0:
            remaining_targets[target] -= 1
            target_refs.add(require_string(child.get("bom-ref"), f"{location}.bom-ref"))
            package_components.extend(nested[1:])
        else:
            package_components.extend(nested)

    for index, value in enumerate(top_components):
        location = f"CycloneDX components[{index}]"
        component = require_object(value, location)
        nested = nested_components(component, location)
        all_components.extend(nested)
        package_components.extend(nested)

    missing_targets = +remaining_targets
    if missing_targets:
        details = ", ".join(
            f"{name}@{version} ({component_type}, {source})"
            for name, version, component_type, source in sorted(missing_targets)
        )
        raise SbomVerificationError(
            f"CycloneDX root component is missing Cargo targets: {details}"
        )

    actual: PackageCounts = Counter()
    known_refs: set[str] = set()
    package_refs: set[str] = set()
    package_by_ref: dict[str, PackageKey] = {}
    for component, location in package_components:
        key = package_key(component, location, "version")
        reference = require_string(component.get("bom-ref"), f"{location}.bom-ref")
        expected_key = expected_identities.get(reference)
        if expected_key is None:
            raise SbomVerificationError(
                f"{location}.bom-ref does not match a locked Cargo source id: {reference}"
            )
        if expected_key != key:
            raise SbomVerificationError(
                f"{location}.bom-ref source identity disagrees with its name/version"
            )
        require_string(component.get("type"), f"{location}.type")
        actual[key] += 1
        package_refs.add(reference)
        package_by_ref[reference] = key
        if not require_list(component.get("licenses"), f"{location}.licenses"):
            raise SbomVerificationError(f"{location}.licenses must not be empty")
        verify_cargo_purl(component.get("purl"), key[0], key[1], location)
    for component, location in all_components:
        reference = require_string(component.get("bom-ref"), f"{location}.bom-ref")
        if reference in known_refs:
            raise SbomVerificationError(f"CycloneDX contains duplicate bom-ref {reference}")
        known_refs.add(reference)

    dependencies = require_list(document.get("dependencies"), "CycloneDX dependencies")
    dependency_refs: set[str] = set()
    dependency_child_refs: set[str] = set()
    actual_edges: set[DependencyEdge] = set()
    for index, raw_dependency in enumerate(dependencies):
        location = f"CycloneDX dependencies[{index}]"
        dependency = require_object(raw_dependency, location)
        reference = require_string(dependency.get("ref"), f"{location}.ref")
        if reference in dependency_refs:
            raise SbomVerificationError(f"CycloneDX contains duplicate dependency ref {reference}")
        dependency_refs.add(reference)
        depends_on = dependency.get("dependsOn", [])
        child_refs: set[str] = set()
        for child_index, child in enumerate(require_list(depends_on, f"{location}.dependsOn")):
            child_ref = require_string(child, f"{location}.dependsOn[{child_index}]")
            if child_ref in child_refs:
                raise SbomVerificationError(
                    f"CycloneDX dependency {reference} repeats child ref {child_ref}"
                )
            child_refs.add(child_ref)
            dependency_child_refs.add(child_ref)
            if child_ref not in known_refs:
                raise SbomVerificationError(
                    f"CycloneDX dependency {reference} refers to unknown component {child_ref}"
                )
            if reference in package_by_ref and child_ref in package_by_ref:
                actual_edges.add((package_by_ref[reference], package_by_ref[child_ref]))
    unknown_dependency_refs = dependency_refs - known_refs
    if unknown_dependency_refs:
        raise SbomVerificationError(
            "CycloneDX dependency graph contains unknown refs: "
            + ", ".join(sorted(unknown_dependency_refs))
        )
    target_dependency_refs = (dependency_refs | dependency_child_refs) & target_refs
    if target_dependency_refs:
        raise SbomVerificationError(
            "CycloneDX dependency graph must not treat Cargo targets as packages: "
            + ", ".join(sorted(target_dependency_refs))
        )
    missing_dependency_refs = package_refs - dependency_refs
    if missing_dependency_refs:
        raise SbomVerificationError(
            "CycloneDX dependency graph omits package refs: "
            + ", ".join(sorted(missing_dependency_refs))
        )
    missing_source_ids = set(expected_identities) - package_refs
    if missing_source_ids:
        raise SbomVerificationError(
            "CycloneDX omits locked Cargo source ids: "
            + ", ".join(sorted(missing_source_ids))
        )
    verify_boundary("CycloneDX SBOM", actual, expected, development_only)
    verify_edges("CycloneDX SBOM", actual_edges, expected_edges)


# 中文：SPDX 只允许普通运行时依赖。除精确包/边覆盖外，文档必须 DESCRIBES 至少一个生成
# 文件，并用 GENERATED_FROM 把该文件绑定到唯一根 Cargo 包，避免校验一份结构正确却与本
# 构建无关的清单。
# English: SPDX admits normal runtime dependencies only. Beyond exact package/edge coverage, the
# document must DESCRIBE a generated file and bind it via GENERATED_FROM to the unique root Cargo
# package, preventing acceptance of a well-formed inventory unrelated to this build.
def verify_spdx(
    document: dict[str, Any],
    root: PackageKey,
    root_license: str,
    expected: PackageCounts,
    development_only: PackageCounts,
    expected_edges: set[DependencyEdge],
    expected_source_identities: Counter[SpdxIdentity],
) -> None:
    if document.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise SbomVerificationError("SPDX document id must be SPDXRef-DOCUMENT")
    if document.get("spdxVersion") != "SPDX-2.3":
        raise SbomVerificationError("SPDX document version must be SPDX-2.3")
    if document.get("dataLicense") != "CC0-1.0":
        raise SbomVerificationError("SPDX dataLicense must be CC0-1.0")
    namespace = require_string(document.get("documentNamespace"), "SPDX documentNamespace")
    if not namespace.startswith("https://spdx.org/spdxdocs/"):
        raise SbomVerificationError("SPDX documentNamespace must use the SPDX document namespace")
    creation = require_object(document.get("creationInfo"), "SPDX creationInfo")
    creators = require_list(creation.get("creators"), "SPDX creationInfo.creators")
    if SPDX_TOOL not in creators:
        raise SbomVerificationError(f"SPDX document was not generated by {SPDX_TOOL}")

    packages = require_list(document.get("packages"), "SPDX packages")
    actual: PackageCounts = Counter()
    actual_source_identities: Counter[SpdxIdentity] = Counter()
    known_ids = {"SPDXRef-DOCUMENT"}
    package_by_id: dict[str, PackageKey] = {}
    root_ids: set[str] = set()
    root_count = 0
    for index, raw_package in enumerate(packages):
        location = f"SPDX packages[{index}]"
        package = require_object(raw_package, location)
        key = package_key(package, location, "versionInfo")
        actual[key] += 1
        download_location = require_string(
            package.get("downloadLocation"), f"{location}.downloadLocation"
        )
        actual_source_identities[(key[0], key[1], download_location)] += 1
        verify_spdx_purl(
            package, key[0], key[1], download_location, location
        )
        root_count += int(key == root)
        package_id = require_string(package.get("SPDXID"), f"{location}.SPDXID")
        if package_id in known_ids:
            raise SbomVerificationError(f"SPDX contains duplicate element id {package_id}")
        known_ids.add(package_id)
        package_by_id[package_id] = key
        if key == root:
            root_ids.add(package_id)
        for license_field in ("licenseDeclared", "licenseConcluded"):
            license_value = require_string(
                package.get(license_field), f"{location}.{license_field}"
            )
            if license_value in ("NONE", "NOASSERTION"):
                raise SbomVerificationError(
                    f"{location}.{license_field} must identify the package license"
                )
            if key == root and license_value != root_license:
                raise SbomVerificationError(
                    f"SPDX root package {license_field} does not match Cargo metadata: "
                    f"expected {root_license!r}, found {license_value!r}"
                )
    if root_count != 1:
        raise SbomVerificationError(
            f"SPDX must contain the Cargo root package exactly once, found {root_count}"
        )

    files = require_list(document.get("files"), "SPDX files")
    file_ids: set[str] = set()
    for index, raw_file in enumerate(files):
        location = f"SPDX files[{index}]"
        file_record = require_object(raw_file, location)
        file_id = require_string(file_record.get("SPDXID"), f"{location}.SPDXID")
        if file_id in known_ids:
            raise SbomVerificationError(f"SPDX contains duplicate element id {file_id}")
        known_ids.add(file_id)
        file_ids.add(file_id)

    relationships = require_list(document.get("relationships"), "SPDX relationships")
    describes = 0
    actual_edges: set[DependencyEdge] = set()
    parsed_relationships: list[tuple[str, str, str]] = []
    unique_relationships: set[tuple[str, str, str]] = set()
    for index, raw_relationship in enumerate(relationships):
        location = f"SPDX relationships[{index}]"
        relationship = require_object(raw_relationship, location)
        source = require_string(relationship.get("spdxElementId"), f"{location}.spdxElementId")
        target = require_string(
            relationship.get("relatedSpdxElement"), f"{location}.relatedSpdxElement"
        )
        kind = require_string(relationship.get("relationshipType"), f"{location}.relationshipType")
        parsed = (source, target, kind)
        if parsed in unique_relationships:
            raise SbomVerificationError(
                f"SPDX contains duplicate relationship: {source} {kind} {target}"
            )
        unique_relationships.add(parsed)
        parsed_relationships.append(parsed)
        describes += int(source == "SPDXRef-DOCUMENT" and kind == "DESCRIBES")
    for source, target, _kind in parsed_relationships:
        if source not in known_ids or target not in known_ids:
            raise SbomVerificationError(
                f"SPDX relationship refers to an unknown element: {source} -> {target}"
            )
    if describes == 0:
        raise SbomVerificationError("SPDX document does not describe any generated target")
    described_files = {
        target
        for source, target, kind in parsed_relationships
        if source == "SPDXRef-DOCUMENT" and kind == "DESCRIBES" and target in file_ids
    }
    if not described_files:
        raise SbomVerificationError("SPDX document must describe at least one generated file")
    generated_from_root = any(
        source in described_files and target in root_ids and kind == "GENERATED_FROM"
        for source, target, kind in parsed_relationships
    )
    if not generated_from_root:
        raise SbomVerificationError(
            "SPDX described files are not bound to the Cargo root package"
        )
    for source, target, kind in parsed_relationships:
        if kind != "DEPENDS_ON":
            continue
        if source not in package_by_id or target not in package_by_id:
            raise SbomVerificationError(
                f"SPDX DEPENDS_ON relationship must connect packages: {source} -> {target}"
            )
        actual_edges.add((package_by_id[source], package_by_id[target]))
    verify_boundary("SPDX SBOM", actual, expected, development_only)
    missing_sources = expected_source_identities - actual_source_identities
    unexpected_sources = actual_source_identities - expected_source_identities
    if missing_sources or unexpected_sources:
        raise SbomVerificationError(
            "SPDX package download locations do not match locked Cargo sources: "
            f"missing={list(missing_sources.elements())!r}, "
            f"unexpected={list(unexpected_sources.elements())!r}"
        )
    verify_edges("SPDX SBOM", actual_edges, expected_edges)


# 中文：生成器边界刻意不同：cargo-cyclonedx 的期望图是 normal+build，cargo-sbom/SPDX 的
# 期望图仅为 normal；dev-only 集合对两者都是显式拒绝项。
# English: Generator boundaries intentionally differ: cargo-cyclonedx expects normal+build, whereas
# cargo-sbom/SPDX expects normal only. Development-only packages are explicit rejections for both.
def verify_documents(
    metadata: dict[str, Any],
    cyclonedx: dict[str, Any],
    spdx: dict[str, Any],
    target: str | None = None,
) -> tuple[PackageKey, int, int]:
    (
        root,
        root_license,
        normal,
        production,
        development_only,
        cargo_targets,
        normal_edges,
        production_edges,
        normal_cargo_identities,
        production_cargo_identities,
        normal_spdx_identities,
        _production_spdx_identities,
    ) = dependency_sets(metadata)
    verify_cyclonedx(
        cyclonedx,
        root,
        root_license,
        production,
        development_only,
        cargo_targets,
        production_edges,
        production_cargo_identities,
        target,
    )
    verify_spdx(
        spdx,
        root,
        root_license,
        normal,
        development_only,
        normal_edges,
        normal_spdx_identities,
    )
    return root, sum(production.values()), sum(normal.values())


def verify_target_cyclonedx(
    metadata: dict[str, Any], cyclonedx: dict[str, Any], target: str
) -> tuple[PackageKey, int]:
    (
        root,
        root_license,
        _normal,
        production,
        development_only,
        cargo_targets,
        _normal_edges,
        production_edges,
        _normal_cargo_identities,
        production_cargo_identities,
        _normal_spdx_identities,
        _production_spdx_identities,
    ) = dependency_sets(metadata)
    verify_cyclonedx(
        cyclonedx,
        root,
        root_license,
        production,
        development_only,
        cargo_targets,
        production_edges,
        production_cargo_identities,
        target,
    )
    return root, sum(production.values())


def verify_global_spdx(
    metadata: dict[str, Any], spdx: dict[str, Any]
) -> tuple[PackageKey, int]:
    (
        root,
        root_license,
        normal,
        _production,
        development_only,
        _cargo_targets,
        normal_edges,
        _production_edges,
        _normal_cargo_identities,
        _production_cargo_identities,
        normal_spdx_identities,
        _production_spdx_identities,
    ) = dependency_sets(metadata)
    verify_spdx(
        spdx,
        root,
        root_license,
        normal,
        development_only,
        normal_edges,
        normal_spdx_identities,
    )
    return root, sum(normal.values())


def fixtures() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    package_ids = {
        "root": "path+file:///project#app@1.2.3",
        "runtime": "registry#runtime@2.0.0",
        "builder": "registry#builder@3.0.0",
        "test-helper": "registry#test-helper@4.0.0",
    }
    metadata = {
        "packages": [
            {
                "id": package_ids["root"],
                "name": "app",
                "version": "1.2.3",
                "license": "MIT",
                "source": None,
                "manifest_path": "/project/Cargo.toml",
                "targets": [
                    {
                        "name": "app_lib",
                        "kind": ["lib"],
                        "src_path": "/project/src/lib.rs",
                    }
                ],
            },
            {
                "id": package_ids["runtime"],
                "name": "runtime",
                "version": "2.0.0",
                "source": "registry+https://github.com/rust-lang/crates.io-index",
            },
            {
                "id": package_ids["builder"],
                "name": "builder",
                "version": "3.0.0",
                "source": "registry+https://github.com/rust-lang/crates.io-index",
            },
            {
                "id": package_ids["test-helper"],
                "name": "test-helper",
                "version": "4.0.0",
                "source": "registry+https://github.com/rust-lang/crates.io-index",
            },
        ],
        "resolve": {
            "root": package_ids["root"],
            "nodes": [
                {
                    "id": package_ids["root"],
                    "deps": [
                        {"pkg": package_ids["runtime"], "dep_kinds": [{"kind": None}]},
                        {"pkg": package_ids["builder"], "dep_kinds": [{"kind": "build"}]},
                        {"pkg": package_ids["test-helper"], "dep_kinds": [{"kind": "dev"}]},
                    ],
                },
                {"id": package_ids["runtime"], "deps": []},
                {"id": package_ids["builder"], "deps": []},
                {"id": package_ids["test-helper"], "deps": []},
            ],
        },
    }

    def component(name: str, version: str, reference: str) -> dict[str, Any]:
        return {
            "type": "library",
            "bom-ref": reference,
            "name": name,
            "version": version,
            "licenses": [{"expression": "MIT"}],
            "purl": f"pkg:cargo/{name}@{version}",
        }

    cyclonedx = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.3",
        "version": 1,
        "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000000",
        "metadata": {
            "tools": [{"name": CYCLONEDX_TOOL[0], "version": CYCLONEDX_TOOL[1]}],
            "properties": [
                {"name": "cdx:rustc:sbom:target:all_targets", "value": "true"}
            ],
            "component": {
                **component("app", "1.2.3", package_ids["root"]),
                "components": [
                    {
                        **component("app_lib", "1.2.3", "root-target-ref"),
                        "purl": "pkg:cargo/app@1.2.3#src/lib.rs",
                    }
                ],
            },
        },
        "components": [
            component("runtime", "2.0.0", package_ids["runtime"]),
            component("builder", "3.0.0", package_ids["builder"]),
        ],
        "dependencies": [
            {
                "ref": package_ids["root"],
                "dependsOn": [package_ids["runtime"], package_ids["builder"]],
            },
            {"ref": package_ids["runtime"], "dependsOn": []},
            {"ref": package_ids["builder"], "dependsOn": []},
        ],
    }

    def spdx_package(name: str, version: str, source: str) -> dict[str, Any]:
        package = {
            "SPDXID": f"SPDXRef-Package-{name}-{version}",
            "name": name,
            "versionInfo": version,
            "downloadLocation": source,
            "licenseDeclared": "MIT",
            "licenseConcluded": "MIT",
        }
        if source == "registry+https://github.com/rust-lang/crates.io-index":
            package["externalRefs"] = [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": f"pkg:cargo/{name}@{version}",
                }
            ]
        return package

    spdx = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "documentNamespace": "https://spdx.org/spdxdocs/app-test",
        "creationInfo": {"creators": [SPDX_TOOL]},
        "packages": [
            spdx_package("app", "1.2.3", "NONE"),
            spdx_package(
                "runtime",
                "2.0.0",
                "registry+https://github.com/rust-lang/crates.io-index",
            ),
        ],
        "files": [{"SPDXID": "SPDXRef-File-app"}],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": "SPDXRef-File-app",
                "relationshipType": "DESCRIBES",
            },
            {
                "spdxElementId": "SPDXRef-File-app",
                "relatedSpdxElement": "SPDXRef-Package-app-1.2.3",
                "relationshipType": "GENERATED_FROM",
            },
            {
                "spdxElementId": "SPDXRef-Package-app-1.2.3",
                "relatedSpdxElement": "SPDXRef-Package-runtime-2.0.0",
                "relationshipType": "DEPENDS_ON",
            },
        ],
    }
    return metadata, cyclonedx, spdx


def self_test() -> None:
    metadata, cyclonedx, spdx = fixtures()
    verify_documents(metadata, cyclonedx, spdx)
    targeted = copy.deepcopy(cyclonedx)
    targeted["metadata"]["properties"] = [
        {
            "name": "cdx:rustc:sbom:target:triple",
            "value": "x86_64-unknown-linux-gnu",
        }
    ]
    verify_target_cyclonedx(metadata, targeted, "x86_64-unknown-linux-gnu")
    verify_global_spdx(metadata, spdx)
    expect_wrong_target = copy.deepcopy(targeted)
    expect_wrong_target["metadata"]["properties"][0]["value"] = (
        "aarch64-unknown-linux-gnu"
    )
    try:
        verify_target_cyclonedx(
            metadata, expect_wrong_target, "x86_64-unknown-linux-gnu"
        )
    except SbomVerificationError:
        pass
    else:
        raise AssertionError("wrong target-specific CycloneDX fixture was accepted")

    invalid_documents: list[tuple[dict[str, Any], dict[str, Any]]] = []
    wrong_root = copy.deepcopy(cyclonedx)
    wrong_root["metadata"]["component"]["version"] = "9.9.9"
    invalid_documents.append((wrong_root, spdx))

    wrong_cyclonedx_root_license = copy.deepcopy(cyclonedx)
    wrong_cyclonedx_root_license["metadata"]["component"]["licenses"] = [
        {"expression": "MIT OR Apache-2.0"}
    ]
    invalid_documents.append((wrong_cyclonedx_root_license, spdx))

    wrong_spdx_declared_license = copy.deepcopy(spdx)
    wrong_spdx_declared_license["packages"][0]["licenseDeclared"] = (
        "MIT OR Apache-2.0"
    )
    invalid_documents.append((cyclonedx, wrong_spdx_declared_license))

    wrong_spdx_concluded_license = copy.deepcopy(spdx)
    wrong_spdx_concluded_license["packages"][0]["licenseConcluded"] = (
        "MIT OR Apache-2.0"
    )
    invalid_documents.append((cyclonedx, wrong_spdx_concluded_license))

    wrong_cyclonedx_source = copy.deepcopy(cyclonedx)
    old_reference = wrong_cyclonedx_source["components"][0]["bom-ref"]
    new_reference = "registry+https://example.invalid/index#runtime@2.0.0"
    wrong_cyclonedx_source["components"][0]["bom-ref"] = new_reference
    for dependency in wrong_cyclonedx_source["dependencies"]:
        if dependency["ref"] == old_reference:
            dependency["ref"] = new_reference
        dependency["dependsOn"] = [
            new_reference if reference == old_reference else reference
            for reference in dependency["dependsOn"]
        ]
    invalid_documents.append((wrong_cyclonedx_source, spdx))

    wrong_cyclonedx_purl = copy.deepcopy(cyclonedx)
    wrong_cyclonedx_purl["components"][0]["purl"] = "pkg:cargo/impostor@2.0.0"
    invalid_documents.append((wrong_cyclonedx_purl, spdx))

    wrong_spdx_source = copy.deepcopy(spdx)
    wrong_spdx_source["packages"][1]["downloadLocation"] = (
        "registry+https://example.invalid/index"
    )
    invalid_documents.append((cyclonedx, wrong_spdx_source))

    wrong_spdx_purl = copy.deepcopy(spdx)
    wrong_spdx_purl["packages"][1]["externalRefs"][0]["referenceLocator"] = (
        "pkg:cargo/impostor@2.0.0"
    )
    invalid_documents.append((cyclonedx, wrong_spdx_purl))

    missing_build = copy.deepcopy(cyclonedx)
    missing_build["components"] = missing_build["components"][:-1]
    missing_build["dependencies"] = missing_build["dependencies"][:-1]
    missing_build["dependencies"][0]["dependsOn"] = ["registry#runtime@2.0.0"]
    invalid_documents.append((missing_build, spdx))

    leaked_dev = copy.deepcopy(cyclonedx)
    leaked_dev["components"].append(
        {
            "type": "library",
            "bom-ref": "registry#test-helper@4.0.0",
            "name": "test-helper",
            "version": "4.0.0",
            "licenses": [{"expression": "MIT"}],
            "purl": "pkg:cargo/test-helper@4.0.0",
        }
    )
    leaked_dev["dependencies"].append(
        {"ref": "registry#test-helper@4.0.0", "dependsOn": []}
    )
    leaked_dev["dependencies"][0]["dependsOn"].append(
        "registry#test-helper@4.0.0"
    )
    invalid_documents.append((leaked_dev, spdx))

    nested_dev = copy.deepcopy(cyclonedx)
    nested_dev["metadata"]["component"]["components"][0]["components"] = [
        {
            "type": "library",
            "bom-ref": "registry#test-helper@4.0.0",
            "name": "test-helper",
            "version": "4.0.0",
            "licenses": [{"expression": "MIT"}],
            "purl": "pkg:cargo/test-helper@4.0.0",
        }
    ]
    nested_dev["dependencies"].append(
        {"ref": "registry#test-helper@4.0.0", "dependsOn": []}
    )
    nested_dev["dependencies"][0]["dependsOn"].append(
        "registry#test-helper@4.0.0"
    )
    invalid_documents.append((nested_dev, spdx))

    direct_nested_dev = copy.deepcopy(cyclonedx)
    direct_nested_dev["metadata"]["component"]["components"].append(
        {
            "type": "library",
            "bom-ref": "registry#test-helper@4.0.0",
            "name": "test-helper",
            "version": "4.0.0",
            "licenses": [{"expression": "MIT"}],
            "purl": "pkg:cargo/test-helper@4.0.0",
        }
    )
    direct_nested_dev["dependencies"].append(
        {"ref": "registry#test-helper@4.0.0", "dependsOn": []}
    )
    direct_nested_dev["dependencies"][0]["dependsOn"].append(
        "registry#test-helper@4.0.0"
    )
    invalid_documents.append((direct_nested_dev, spdx))

    build_in_spdx = copy.deepcopy(spdx)
    build_in_spdx["packages"].append(
        {
            "SPDXID": "SPDXRef-Package-builder-3.0.0",
            "name": "builder",
            "versionInfo": "3.0.0",
            "licenseDeclared": "MIT",
            "licenseConcluded": "MIT",
        }
    )
    invalid_documents.append((cyclonedx, build_in_spdx))

    leaked_dev_spdx = copy.deepcopy(spdx)
    leaked_dev_spdx["packages"].append(
        {
            "SPDXID": "SPDXRef-Package-test-helper-4.0.0",
            "name": "test-helper",
            "versionInfo": "4.0.0",
            "licenseDeclared": "MIT",
            "licenseConcluded": "MIT",
        }
    )
    invalid_documents.append((cyclonedx, leaked_dev_spdx))

    missing_cyclonedx_edge = copy.deepcopy(cyclonedx)
    missing_cyclonedx_edge["dependencies"][0]["dependsOn"].remove(
        "registry#builder@3.0.0"
    )
    invalid_documents.append((missing_cyclonedx_edge, spdx))

    missing_spdx_edge = copy.deepcopy(spdx)
    missing_spdx_edge["relationships"] = missing_spdx_edge["relationships"][:-1]
    invalid_documents.append((cyclonedx, missing_spdx_edge))

    bad_ref = copy.deepcopy(cyclonedx)
    bad_ref["dependencies"][0]["dependsOn"].append("unknown-ref")
    invalid_documents.append((bad_ref, spdx))

    bad_relationship = copy.deepcopy(spdx)
    bad_relationship["relationships"][0]["relatedSpdxElement"] = "SPDXRef-Unknown"
    invalid_documents.append((cyclonedx, bad_relationship))

    for invalid_cyclonedx, invalid_spdx in invalid_documents:
        try:
            verify_documents(metadata, invalid_cyclonedx, invalid_spdx)
        except SbomVerificationError:
            continue
        raise AssertionError("invalid SBOM fixture was accepted")
    print("SBOM semantic verification self-test passed")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify", help="validate generated CycloneDX and SPDX files")
    verify.add_argument("cyclonedx", type=pathlib.Path)
    verify.add_argument("spdx", type=pathlib.Path)
    verify.add_argument(
        "--project-directory", type=pathlib.Path, default=pathlib.Path(".")
    )
    verify_target = commands.add_parser(
        "verify-target", help="validate one target-specific CycloneDX file"
    )
    verify_target.add_argument("cyclonedx", type=pathlib.Path)
    verify_target.add_argument("--target", required=True)
    verify_target.add_argument(
        "--project-directory", type=pathlib.Path, default=pathlib.Path(".")
    )
    verify_spdx_command = commands.add_parser(
        "verify-spdx", help="validate the global cargo-sbom SPDX file"
    )
    verify_spdx_command.add_argument("spdx", type=pathlib.Path)
    verify_spdx_command.add_argument(
        "--project-directory", type=pathlib.Path, default=pathlib.Path(".")
    )
    commands.add_parser("self-test", help="run deterministic positive and negative fixtures")
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "self-test":
            self_test()
        elif args.command == "verify":
            project = args.project_directory.resolve()
            root, production_count, normal_count = verify_documents(
                cargo_metadata(project),
                read_json_object(args.cyclonedx),
                read_json_object(args.spdx),
            )
            print(
                f"SBOM semantics verified for {root[0]} {root[1]}: "
                f"CycloneDX {production_count} normal/build packages; "
                f"SPDX {normal_count} normal packages"
            )
        elif args.command == "verify-target":
            project = args.project_directory.resolve()
            root, production_count = verify_target_cyclonedx(
                cargo_metadata(project, args.target),
                read_json_object(args.cyclonedx),
                args.target,
            )
            print(
                f"target SBOM semantics verified for {root[0]} {root[1]} "
                f"on {args.target}: CycloneDX {production_count} normal/build packages"
            )
        else:
            project = args.project_directory.resolve()
            root, normal_count = verify_global_spdx(
                cargo_metadata(project), read_json_object(args.spdx)
            )
            print(
                f"global SPDX semantics verified for {root[0]} {root[1]}: "
                f"{normal_count} normal packages"
            )
    except SbomVerificationError as error:
        print(f"SBOM verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
