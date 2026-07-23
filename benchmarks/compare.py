#!/usr/bin/env python3
"""创建并比较可审查的 Ram 性能基线。 / Create and compare reviewable Ram performance baselines."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import math
import os
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1


class ComparisonError(RuntimeError):
    """结果、策略或基线不适合比较。 / A result, policy, or baseline is invalid for comparison."""


def read_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as stream:
            value = json.load(stream)
    except (OSError, json.JSONDecodeError) as error:
        raise ComparisonError(f"cannot read JSON from {path}: {error}") from error
    if not isinstance(value, dict):
        raise ComparisonError(f"{path} must contain a JSON object")
    return value


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def atomic_json_write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(
            value,
            stream,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def require_string(document: dict[str, Any], key: str, location: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value:
        raise ComparisonError(f"{location}.{key} must be a non-empty string")
    return value


def require_schema(document: dict[str, Any], kind: str, location: str) -> None:
    if document.get("schema_version") != SCHEMA_VERSION:
        raise ComparisonError(f"{location} has an unsupported schema_version")
    if document.get("kind") != kind:
        raise ComparisonError(f"{location}.kind must be {kind!r}")


def require_metrics(document: dict[str, Any], key: str, location: str) -> dict[str, float]:
    value = document.get(key)
    if not isinstance(value, dict) or not value:
        raise ComparisonError(f"{location}.{key} must be a non-empty object")
    metrics: dict[str, float] = {}
    for name, raw in value.items():
        if not isinstance(name, str) or not name:
            raise ComparisonError(f"{location}.{key} contains an invalid metric name")
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            raise ComparisonError(f"metric {name!r} must be numeric")
        numeric = float(raw)
        if not math.isfinite(numeric) or numeric < 0:
            raise ComparisonError(f"metric {name!r} must be finite and non-negative")
        metrics[name] = numeric
    return metrics


def validate_result(document: dict[str, Any], *, allow_smoke: bool) -> dict[str, float]:
    require_schema(document, "ram-performance-result", "result")
    runner_id = require_string(document, "runner_id", "result")
    metrics = require_metrics(document, "regression_metrics", "result")
    preset = document.get("preset")
    if preset == "smoke":
        if not allow_smoke:
            raise ComparisonError("only a full result can create or check a formal baseline")
    elif preset == "full":
        configuration = document.get("configuration")
        if not isinstance(configuration, dict) or configuration.get("strict_environment") is not True:
            raise ComparisonError(
                "a full baseline result must be captured with --strict-environment"
            )
        binary_contract = configuration.get("binary_contract")
        if not isinstance(binary_contract, str) or not binary_contract or binary_contract == "unspecified":
            raise ComparisonError("a full baseline result requires an explicit binary contract")
        if runner_id == "local":
            raise ComparisonError("a full baseline result requires a stable non-local runner ID")
        profiles = document.get("profiles")
        if not isinstance(profiles, dict) or set(profiles) != {"debug", "release"}:
            raise ComparisonError("a full baseline result requires exactly debug and release profiles")
        metric_profiles = {name.split("/", 1)[0] for name in metrics}
        if metric_profiles != {"debug", "release"}:
            raise ComparisonError(
                "a full baseline result must contain metrics for both debug and release"
            )
        profile_comparison = document.get("profile_comparison")
        if not isinstance(profile_comparison, dict) or not profile_comparison:
            raise ComparisonError("a full baseline result requires debug/release comparisons")
    else:
        raise ComparisonError("result.preset must be 'full' or 'smoke'")
    environment = document.get("environment")
    if not isinstance(environment, dict):
        raise ComparisonError("result.environment must be an object")
    require_string(environment, "environment_fingerprint", "result.environment")
    return metrics


def validate_thresholds(document: dict[str, Any]) -> list[dict[str, Any]]:
    require_schema(document, "ram-performance-threshold-policy", "thresholds")
    rules = document.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ComparisonError("thresholds.rules must be a non-empty array")
    validated: list[dict[str, Any]] = []
    for index, rule in enumerate(rules):
        location = f"thresholds.rules[{index}]"
        if not isinstance(rule, dict):
            raise ComparisonError(f"{location} must be an object")
        pattern = require_string(rule, "metric_pattern", location)
        direction = rule.get("direction")
        if direction not in {"higher", "lower"}:
            raise ComparisonError(f"{location}.direction must be 'higher' or 'lower'")
        fraction = rule.get("max_regression_fraction")
        if isinstance(fraction, bool) or not isinstance(fraction, (int, float)):
            raise ComparisonError(f"{location}.max_regression_fraction must be numeric")
        if not math.isfinite(float(fraction)) or not 0 <= float(fraction) < 1:
            raise ComparisonError(
                f"{location}.max_regression_fraction must be finite and in [0, 1)"
            )
        tolerance = rule.get("absolute_tolerance", 0)
        if isinstance(tolerance, bool) or not isinstance(tolerance, (int, float)):
            raise ComparisonError(f"{location}.absolute_tolerance must be numeric")
        if not math.isfinite(float(tolerance)) or float(tolerance) < 0:
            raise ComparisonError(f"{location}.absolute_tolerance must be non-negative")
        validated.append(
            {
                "metric_pattern": pattern,
                "direction": direction,
                "max_regression_fraction": float(fraction),
                "absolute_tolerance": float(tolerance),
            }
        )
    return validated


def matching_rule(metric: str, rules: list[dict[str, Any]]) -> dict[str, Any]:
    matches = [rule for rule in rules if fnmatch.fnmatchcase(metric, rule["metric_pattern"])]
    if not matches:
        raise ComparisonError(f"no threshold rule covers baseline metric {metric!r}")
    if len(matches) > 1:
        patterns = ", ".join(rule["metric_pattern"] for rule in matches)
        raise ComparisonError(f"multiple threshold rules cover {metric!r}: {patterns}")
    return matches[0]


def create_candidate(
    result: dict[str, Any], thresholds: dict[str, Any], *, allow_smoke: bool
) -> dict[str, Any]:
    metrics = validate_result(result, allow_smoke=allow_smoke)
    rules = validate_thresholds(thresholds)
    for metric in metrics:
        matching_rule(metric, rules)
    environment = result["environment"]
    candidate_status = "smoke-candidate" if result.get("preset") == "smoke" else "candidate"
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "ram-performance-baseline",
        "baseline_id": f"{result['runner_id']}-{result['source_commit'][:12]}",
        "runner_id": result["runner_id"],
        "environment_fingerprint": environment["environment_fingerprint"],
        "source_commit": result["source_commit"],
        "captured_at_utc": result["generated_at_utc"],
        "preset": result["preset"],
        "threshold_policy_sha256": canonical_digest(thresholds),
        "metrics": dict(sorted(metrics.items())),
        "review": {
            "status": candidate_status,
            "approved_by": [],
            "approved_at_utc": None,
            "evidence_url": None,
            "notes": "Candidate only; approval metadata must be supplied by code review.",
        },
    }


def validate_approved_baseline(
    baseline: dict[str, Any], thresholds: dict[str, Any]
) -> dict[str, float]:
    require_schema(baseline, "ram-performance-baseline", "baseline")
    require_string(baseline, "baseline_id", "baseline")
    require_string(baseline, "runner_id", "baseline")
    require_string(baseline, "environment_fingerprint", "baseline")
    source_commit = require_string(baseline, "source_commit", "baseline")
    if re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
        raise ComparisonError("baseline.source_commit must be a full 40-character Git commit")
    if baseline.get("preset") != "full":
        raise ComparisonError("an approved baseline must be captured with the full preset")
    if baseline.get("runner_id") == "local":
        raise ComparisonError("an approved baseline cannot use the local runner ID")
    expected_policy = canonical_digest(thresholds)
    if baseline.get("threshold_policy_sha256") != expected_policy:
        raise ComparisonError(
            "baseline was not reviewed with the current threshold policy; create and approve a new candidate"
        )
    review = baseline.get("review")
    if not isinstance(review, dict) or review.get("status") != "approved":
        raise ComparisonError("baseline review.status must be 'approved'")
    approved_by = review.get("approved_by")
    if (
        not isinstance(approved_by, list)
        or not approved_by
        or any(not isinstance(name, str) or not name.strip() for name in approved_by)
    ):
        raise ComparisonError("baseline review.approved_by must name at least one reviewer")
    approved_at = review.get("approved_at_utc")
    if not isinstance(approved_at, str) or re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", approved_at
    ) is None:
        raise ComparisonError("baseline review.approved_at_utc must be an RFC 3339 UTC timestamp")
    evidence_url = review.get("evidence_url")
    if not isinstance(evidence_url, str) or not evidence_url.startswith("https://"):
        raise ComparisonError("baseline review.evidence_url must be an HTTPS review/artifact URL")
    return require_metrics(baseline, "metrics", "baseline")


def compare(
    result: dict[str, Any], baseline: dict[str, Any], thresholds: dict[str, Any]
) -> tuple[dict[str, Any], bool]:
    current = validate_result(result, allow_smoke=False)
    rules = validate_thresholds(thresholds)
    expected = validate_approved_baseline(baseline, thresholds)
    if result["runner_id"] != baseline["runner_id"]:
        raise ComparisonError(
            f"runner mismatch: result={result['runner_id']!r}, baseline={baseline['runner_id']!r}"
        )
    current_fingerprint = result["environment"]["environment_fingerprint"]
    if current_fingerprint != baseline["environment_fingerprint"]:
        raise ComparisonError(
            "environment fingerprint differs from the approved baseline; do not compare across runner contracts"
        )

    comparisons: list[dict[str, Any]] = []
    passed = True
    for metric, baseline_value in sorted(expected.items()):
        if metric not in current:
            raise ComparisonError(f"result is missing baseline metric {metric!r}")
        current_value = current[metric]
        rule = matching_rule(metric, rules)
        fraction = rule["max_regression_fraction"]
        tolerance = rule["absolute_tolerance"]
        if rule["direction"] == "higher":
            boundary = baseline_value * (1.0 - fraction) - tolerance
            metric_passed = current_value >= boundary
            regression_fraction = (
                (baseline_value - current_value) / baseline_value
                if baseline_value > 0
                else None
            )
        else:
            boundary = baseline_value * (1.0 + fraction) + tolerance
            metric_passed = current_value <= boundary
            regression_fraction = (
                (current_value - baseline_value) / baseline_value
                if baseline_value > 0
                else None
            )
        passed = passed and metric_passed
        comparisons.append(
            {
                "metric": metric,
                "baseline": baseline_value,
                "current": current_value,
                "direction": rule["direction"],
                "max_regression_fraction": fraction,
                "absolute_tolerance": tolerance,
                "boundary": boundary,
                "observed_regression_fraction": regression_fraction,
                "passed": metric_passed,
            }
        )

    extra = sorted(set(current) - set(expected))
    report = {
        "schema_version": SCHEMA_VERSION,
        "kind": "ram-performance-comparison",
        "status": "passed" if passed else "regressed",
        "runner_id": result["runner_id"],
        "environment_fingerprint": current_fingerprint,
        "baseline_id": baseline["baseline_id"],
        "baseline_source_commit": baseline["source_commit"],
        "current_source_commit": result["source_commit"],
        "threshold_policy_sha256": canonical_digest(thresholds),
        "comparisons": comparisons,
        "current_metrics_not_in_baseline": extra,
    }
    return report, passed


def self_test() -> None:
    thresholds = {
        "schema_version": 1,
        "kind": "ram-performance-threshold-policy",
        "rules": [
            {
                "metric_pattern": "*/get/throughput",
                "direction": "higher",
                "max_regression_fraction": 0.1,
                "absolute_tolerance": 0,
            },
            {
                "metric_pattern": "*/get/latency",
                "direction": "lower",
                "max_regression_fraction": 0.2,
                "absolute_tolerance": 0,
            },
        ],
    }
    result = {
        "schema_version": 1,
        "kind": "ram-performance-result",
        "runner_id": "test-runner",
        "source_commit": "b" * 40,
        "generated_at_utc": "2026-01-01T00:00:00Z",
        "preset": "full",
        "configuration": {
            "strict_environment": True,
            "binary_contract": "self-test debug/release",
        },
        "profiles": {"debug": {}, "release": {}},
        "profile_comparison": {"get/throughput": {}},
        "environment": {"environment_fingerprint": "a" * 64},
        "regression_metrics": {
            "debug/get/throughput": 50.0,
            "debug/get/latency": 2.0,
            "release/get/throughput": 100.0,
            "release/get/latency": 1.0,
        },
    }
    candidate = create_candidate(result, thresholds, allow_smoke=False)
    candidate["review"] = {
        "status": "approved",
        "approved_by": ["reviewer"],
        "approved_at_utc": "2026-01-02T00:00:00Z",
        "evidence_url": "https://example.invalid/review/1",
        "notes": "self-test",
    }
    passing, ok = compare(result, candidate, thresholds)
    assert ok and passing["status"] == "passed"
    result["regression_metrics"]["release/get/throughput"] = 80.0
    failing, ok = compare(result, candidate, thresholds)
    assert not ok and failing["status"] == "regressed"

    smoke = dict(result)
    smoke["preset"] = "smoke"
    smoke["runner_id"] = "local"
    smoke["configuration"] = {"strict_environment": False, "binary_contract": "unspecified"}
    smoke["profiles"] = {"debug": {}}
    smoke_candidate = create_candidate(smoke, thresholds, allow_smoke=True)
    assert smoke_candidate["review"]["status"] == "smoke-candidate"
    try:
        compare(smoke, smoke_candidate, thresholds)
    except ComparisonError as error:
        assert "only a full result" in str(error)
    else:
        raise AssertionError("a smoke candidate was accepted as a formal baseline")
    print("performance comparison self-test passed")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    candidate = subparsers.add_parser("candidate", help="extract a non-enforcing baseline candidate")
    candidate.add_argument("--result", type=Path, required=True)
    candidate.add_argument("--thresholds", type=Path, required=True)
    candidate.add_argument("--output", type=Path, required=True)
    candidate.add_argument(
        "--allow-smoke",
        action="store_true",
        help="allow a smoke-candidate that can never be approved or used for enforcement",
    )

    compare_parser = subparsers.add_parser("compare", help="compare a full run to an approved baseline")
    compare_parser.add_argument("--result", type=Path, required=True)
    compare_parser.add_argument("--baseline", type=Path, required=True)
    compare_parser.add_argument("--thresholds", type=Path, required=True)
    compare_parser.add_argument("--output", type=Path, required=True)

    subparsers.add_parser("self-test", help="exercise passing and regressing comparisons")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "self-test":
            self_test()
            return 0
        result = read_json(args.result)
        thresholds = read_json(args.thresholds)
        if args.command == "candidate":
            candidate = create_candidate(result, thresholds, allow_smoke=args.allow_smoke)
            atomic_json_write(args.output, candidate)
            print(f"non-enforcing baseline candidate written to {args.output}")
            return 0
        baseline = read_json(args.baseline)
        report, passed = compare(result, baseline, thresholds)
        atomic_json_write(args.output, report)
        print(f"performance comparison {report['status']}: {args.output}")
        return 0 if passed else 1
    except ComparisonError as error:
        print(f"performance comparison failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
