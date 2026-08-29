#!/usr/bin/env python3
"""Deterministically audit the checked-in artifacts that establish C000."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]

VALIDATOR_PATH = ROOT / "tools/tracker/validate.py"
JAVA_SOURCE_REVISION = "4a21592f95e37908b21bc3f611c6e7a1a67f09f3"


def load_validator():
    spec = importlib.util.spec_from_file_location("c000_tracker_validator", VALIDATOR_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {VALIDATOR_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

TASK_ARTIFACTS: dict[str, tuple[str, ...]] = {
    "C000.01": ("rust-tron/Cargo.toml", "rust-tron/crates/*/Cargo.toml", "docs/architecture/crate-ownership.md"),
    "C000.02": ("rust-tron/rust-toolchain.toml", "java-tron/gradle/wrapper/gradle-wrapper.properties", "docs/architecture/toolchains-and-platforms.md", "docs/architecture/toolchains-platform-policy.md"),
    "C000.03": ("docs/architecture/runtime-dependency-lifecycle.md",),
    "C000.04": ("docs/oracles/manifest.v1.json", "docs/oracles/normalization-policy-v1.json", "docs/oracles/schemas/oracle-fixture-v1.schema.json", "docs/oracles/schemas/oracle-result-v1.schema.json", "docs/oracles/schemas/mismatch-report-v1.schema.json"),
    "C000.05": ("docs/oracles/runner-protocol.md", "tools/reference-runner/runner.py", "tools/reference-runner/java-runner", "tools/reference-runner/rust-runner", "docs/oracles/fixtures/v1/*.json"),
    "C000.06": ("docs/architecture/DR-001-rust-storage-boundary.md",),
    "C000.07": ("docs/architecture/security-threat-policy.md", "docs/architecture/license-provenance-policy.md", "docs/oracles/schemas/threat-model-v1.schema.json", "docs/oracles/schemas/security-finding-v1.schema.json", "docs/oracles/schemas/license-provenance-v1.schema.json"),
    "C000.08": ("docs/oracles/production-ownership.v1.json", "docs/oracles/schemas/ownership-ledger-v1.schema.json", "tools/reference-runner/generate-ledgers.py"),
    "C000.09": ("docs/oracles/java-test-ownership.v1.json", "docs/oracles/schemas/ownership-ledger-v1.schema.json", "tools/reference-runner/generate-ledgers.py"),
    "C000.10": ("docs/governance/tracker-v1.schema.json", "docs/governance/tracker-evidence-dependency-contract.md", "tools/tracker/validate.py"),
    "C000.11": ("docs/governance/DD-template.md", "docs/governance/dependency-decision-v1.schema.json", "docs/governance/dependency-decisions.v1.json", "docs/governance/adoption-inventory-v1.schema.json"),
    "C000.12": ("docs/architecture/DR-004-custom-actuator-extensions.md",),
    "C000.13": ("docs/governance/behavior-manifest-v1.schema.json", "docs/governance/evidence-v1.schema.json", "docs/governance/independent-review-v1.schema.json", "docs/architecture/cross-domain-seams.v1.json"),
    "C000.14": ("docs/architecture/platform-manifest.v1.json", "tools/platform/run", "tools/platform/c000_differential.py", "tools/platform/c000_unit.py", "tools/platform/c000_not_applicable.py"),
    "C000.15": ("docs/governance/adoption-inventory-v1.schema.json", "docs/governance/adoption-inventory.v1.json", "docs/governance/dependency-decisions.v1.json", "rust-tron/Cargo.toml", "rust-tron/Cargo.lock"),
}
EMITTED_TASKS = tuple(f"C000.{number:02d}" for number in range(1, 13)) + ("C000.15",)


def load_json(path: str) -> Any:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def expand(patterns: tuple[str, ...]) -> tuple[str, ...]:
    paths: set[str] = set()
    for pattern in patterns:
        if any(character in pattern for character in "*?["):
            paths.update(path.relative_to(ROOT).as_posix() for path in ROOT.glob(pattern) if path.is_file())
        else:
            paths.add(pattern)
    return tuple(sorted(paths))


def artifact(path: str) -> dict[str, str]:
    file_path = ROOT / path
    return {"path": path, "sha256": hashlib.sha256(file_path.read_bytes()).hexdigest()}


def json_issues(paths: tuple[str, ...]) -> list[str]:
    issues: list[str] = []
    for path in paths:
        if path.endswith(".json"):
            try:
                load_json(path)
            except (OSError, json.JSONDecodeError) as error:
                issues.append(f"invalid JSON {path}: {error}")
    return issues


def ledger_issues(path: str, expected_ledger: str) -> list[str]:
    try:
        ledger = load_json(path)
        tracker = load_json("docs/PORTING_TRACKER.json")
    except (OSError, json.JSONDecodeError) as error:
        return [f"cannot inspect {path}: {error}"]
    rows = ledger.get("rows")
    if not isinstance(rows, list):
        return [f"{path}: rows is not an array"]
    issues: list[str] = []
    if ledger.get("ledger") != expected_ledger:
        issues.append(f"{path}: unexpected ledger identity")
    if ledger.get("row_count") != len(rows):
        issues.append(f"{path}: row_count does not match rows")
    ids = [row.get("id") for row in rows if isinstance(row, dict)]
    if len(ids) != len(rows) or len(set(ids)) != len(ids) or any(not value for value in ids):
        issues.append(f"{path}: row IDs are missing or duplicated")
    regeneration = ledger.get("regeneration", {})
    generator = ledger.get("generator", {})
    generator_path = generator.get("path")
    if regeneration.get("unknown_policy") != "fail" or not regeneration.get("domain_inventory_sha256"):
        issues.append(f"{path}: regeneration is not fail-on-unknown or lacks its inventory digest")
    if generator.get("version") != 3 or not isinstance(generator_path, str) or not (ROOT / generator_path).is_file() or artifact(generator_path)["sha256"] != generator.get("sha256"):
        issues.append(f"{path}: generator identity or digest is stale")
    if ledger.get("java_source_revision") != JAVA_SOURCE_REVISION:
        issues.append(f"{path}: source revision differs from the java-tron gitlink")
    records = {record.get("id"): record for record in tracker.get("records", [])}
    source_hashes: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        owner = records.get(row.get("owning_item"))
        gate = records.get(row.get("acceptance_gate"))
        if owner is None or gate is None or gate.get("kind") != "verification" or owner.get("chunk") != gate.get("chunk"):
            issues.append(f"{path}: {row.get('id', '<unknown>')} has unknown or cross-chunk ownership")
            break
        source = row.get("source", {})
        source_path = source.get("path")
        if not isinstance(source_path, str) or not isinstance(source.get("line"), int) or source.get("line") < 1 or not (ROOT / source_path).is_file():
            issues.append(f"{path}: {row.get('id', '<unknown>')} has an invalid source location")
            break
        source_hashes.setdefault(source_path, artifact(source_path)["sha256"])
        if source_hashes[source_path] != source.get("sha256"):
            issues.append(f"{path}: source digest drift at {source_path}")
            break
    if expected_ledger == "java-test-ownership":
        coverage = ledger.get("coverage", "")
        required_terms = ("parameter", "inherited", "dynamic", "resources")
        rows_dict = [row for row in rows if isinstance(row, dict)]
        if any(term not in coverage for term in required_terms) or not all(any(key in row for row in rows_dict) for key in ("ignored", "assumption_gated", "nested", "generated")):
            issues.append(f"{path}: case-level test coverage contract is incomplete")
    return issues


def governance_model() -> tuple[Any | None, dict[str, Any], str | None, str | None, dict[str, tuple[str, str, str, str]], dict[str, tuple[str, str, str, str]], dict[str, tuple[str, str, str, str]], bool, list[str]]:
    issues: list[str] = []
    try:
        validator = load_validator()
        tracker = load_json("docs/PORTING_TRACKER.json")
    except (OSError, json.JSONDecodeError, RuntimeError) as error:
        return None, {}, None, None, {}, {}, {}, False, [f"cannot load governance model: {error}"]
    records = tracker.get("records", []) if isinstance(tracker, dict) else []
    by_id = {row.get("id"): row for row in records if isinstance(row, dict) and isinstance(row.get("id"), str)}
    current_revision = validator.repository_revision(issues)
    subject_revision, subject_closure, subject_tree = validator.manifest_subject_revision(current_revision, issues)
    descendant_tree = validator.committed_tree(current_revision, issues) if current_revision else {}
    tree_clean = validator.repository_tree_clean(issues)
    return validator, by_id, current_revision, subject_revision, subject_closure, subject_tree, descendant_tree or {}, tree_clean, issues


def oracle_issues() -> list[str]:
    path = "docs/oracles/manifest.v1.json"
    try:
        manifest = load_json(path)
    except (OSError, json.JSONDecodeError) as error:
        return [f"cannot inspect {path}: {error}"]
    issues: list[str] = []
    if manifest.get("schema_version") != 1 or manifest.get("java_source_revision") != JAVA_SOURCE_REVISION:
        issues.append(f"{path}: schema or java-tron source revision is stale")
    base = (ROOT / path).parent
    for field in ("fixture_schema", "result_schema", "mismatch_schema", "normalization_policy"):
        value = manifest.get(field)
        if not isinstance(value, str) or not (base / value).is_file():
            issues.append(f"{path}: missing {field} artifact")
    for field in ("governance_schemas", "fixtures", "implementations"):
        values = manifest.get(field)
        if not isinstance(values, list) or not values or any(not isinstance(value, str) or not (base / value).is_file() for value in values):
            issues.append(f"{path}: invalid or missing {field}")
    ledgers = manifest.get("ledgers")
    if not isinstance(ledgers, list) or {entry.get("ledger") for entry in ledgers if isinstance(entry, dict)} != {"production-ownership", "java-test-ownership"}:
        issues.append(f"{path}: ledger inventory is incomplete")
    else:
        for entry in ledgers:
            ledger_path = base / entry.get("path", "")
            if not ledger_path.is_file() or artifact(ledger_path.relative_to(ROOT).as_posix())["sha256"] != entry.get("sha256"):
                issues.append(f"{path}: ledger digest drift for {entry.get('path')}")
                continue
            try:
                ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                issues.append(f"{path}: malformed ledger {entry.get('path')}")
                continue
            if ledger.get("ledger") != entry.get("ledger") or ledger.get("row_count") != entry.get("row_count"):
                issues.append(f"{path}: ledger identity/count mismatch for {entry.get('path')}")
    regeneration = manifest.get("regeneration", {})
    if regeneration.get("generator_version") != 3 or regeneration.get("unknown_policy") != "fail" or not regeneration.get("domain_inventory_sha256"):
        issues.append(f"{path}: regeneration contract is incomplete")
    return issues


def adoption_issues(validator: Any, by_id: dict[str, Any], subject_tree: dict[str, tuple[str, str, str, str]]) -> list[str]:
    issues: list[str] = []
    records, valid = validator.adoption_contract(by_id, subject_tree, issues)
    if set(records) != valid:
        issues.append("adoption inventory contains non-current instances")
    return issues


def task_case(task_id: str, validator: Any | None = None, by_id: dict[str, Any] | None = None, revision: str | None = None, subject_tree: dict[str, tuple[str, str, str, str]] | None = None) -> dict[str, Any]:
    paths = expand(TASK_ARTIFACTS[task_id])
    missing = [path for path in paths if not (ROOT / path).is_file()]
    for pattern in TASK_ARTIFACTS[task_id]:
        if any(character in pattern for character in "*?[") and not any(path.is_file() for path in ROOT.glob(pattern)):
            missing.append(pattern)
    issues = [f"missing artifact {path}" for path in sorted(set(missing))]
    existing = tuple(path for path in paths if (ROOT / path).is_file())
    issues.extend(json_issues(existing))
    if task_id == "C000.04":
        issues.extend(oracle_issues())
    elif task_id == "C000.08":
        issues.extend(ledger_issues("docs/oracles/production-ownership.v1.json", "production-ownership"))
    elif task_id == "C000.09":
        issues.extend(ledger_issues("docs/oracles/java-test-ownership.v1.json", "java-test-ownership"))
    elif task_id == "C000.15":
        if validator is None or by_id is None:
            issues.append("governance validator unavailable")
        else:
            issues.extend(adoption_issues(validator, by_id, subject_tree or {}))
    return {
        "id": task_id,
        "outcome": "fail" if issues else "pass",
        "expected": {"artifacts_present": True, "documents_parse": True, "semantic_contracts_current": True},
        "observed": {"artifact_count": len(existing), "issues": sorted(set(issues))},
        "skip_disposition": None,
    }


def governed_artifact_paths() -> tuple[str, ...]:
    paths = {
        "tools/tracker/validate.py",
        "docs/governance/tracker-v1.schema.json",
        "docs/governance/tracker-evidence-dependency-contract.md",
        "docs/architecture/platform-manifest.v1.json",
        "docs/governance/adoption-inventory.v1.json",
        "docs/governance/dependency-decisions.v1.json",
    }

    def collect(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key in {"path", "identity", "source"} and isinstance(child, str) and (ROOT / child).is_file():
                    if not child.startswith("docs/governance/evidence/") and child not in {"docs/PORTING_TRACKER.json", "docs/PORTING_CHECKLIST.md"}:
                        paths.add(child)
                collect(child)
        elif isinstance(value, list):
            for child in value:
                collect(child)

    for directory in ("reviews",):
        for path in (ROOT / "docs/governance" / directory).glob("*.json"):
            paths.add(path.relative_to(ROOT).as_posix())
            try:
                collect(json.loads(path.read_text(encoding="utf-8")))
            except json.JSONDecodeError:
                pass
    for path in ("docs/governance/adoption-inventory.v1.json", "docs/governance/dependency-decisions.v1.json"):
        try:
            collect(load_json(path))
        except (OSError, json.JSONDecodeError):
            pass
    return tuple(sorted(path for path in paths if (ROOT / path).is_file()))


def internal_governance_cases(validator: Any, by_id: dict[str, Any], subject_revision: str | None, subject_tree: dict[str, tuple[str, str, str, str]], descendant_tree: dict[str, tuple[str, str, str, str]], tree_clean: bool) -> tuple[dict[str, dict[str, Any]], dict[str, str], list[dict[str, str]]]:
    evidence_issues: list[str] = []
    evidence, valid_evidence = validator.evidence_contract(subject_revision, subject_tree, descendant_tree, tree_clean, by_id, evidence_issues)
    review_issues: list[str] = []
    reviews, valid_reviews = validator.review_contract(subject_revision, subject_tree, tree_clean, by_id, evidence, valid_evidence, review_issues)
    platform_issues: list[str] = []
    platform_ok = validator.platform_contract(subject_revision, evidence, valid_evidence, reviews, valid_reviews, platform_issues)
    c13_evidence = {ident for ident, record in evidence.items() if record.get("owning_item") == "C000.13"}
    c13_issues: list[str] = []
    if not c13_evidence or not c13_evidence.issubset(valid_evidence) or any(evidence[ident].get("observed_status") != "pass" for ident in c13_evidence):
        c13_issues.append("C000.13 lacks current passing owned evidence")
    approvals: dict[str, str] = {}
    for ident, review in reviews.items():
        closure = review.get("closure", {}) if isinstance(review, dict) else {}
        review_class = review.get("review_class") if isinstance(review, dict) else None
        if ident in valid_reviews and review.get("owning_gate") == "C000.V" and closure.get("status") == "approved" and closure.get("approval") is True and review_class in {"architecture", "security", "license"}:
            if review_class in approvals:
                review_issues.append(f"duplicate current {review_class} approval")
            approvals[review_class] = ident
    missing_reviews = {"architecture", "security", "license"} - set(approvals)
    review_issues.extend(f"missing {review_class} approval" for review_class in sorted(missing_reviews))
    c14_issues = list(evidence_issues) + list(review_issues) + list(platform_issues)
    if not platform_ok:
        c14_issues.append("C000.14 platform predicate is incomplete")
    cases = {
        "C000.13": {"outcome": "fail" if c13_issues else "pass", "issues": sorted(set(c13_issues))},
        "C000.14": {"outcome": "fail" if c14_issues else "pass", "issues": sorted(set(c14_issues)), "platform_complete": platform_ok},
    }
    paths = governed_artifact_paths()
    return cases, approvals, [artifact(path) for path in paths]


def verification_case(validator: Any | None, by_id: dict[str, Any], current_revision: str | None, subject_revision: str | None, subject_tree: dict[str, tuple[str, str, str, str]], descendant_tree: dict[str, tuple[str, str, str, str]], tree_clean: bool, model_issues: list[str]) -> dict[str, Any]:
    task_results = {task_id: task_case(task_id, validator, by_id, current_revision, subject_tree) for task_id in TASK_ARTIFACTS}
    issues = list(model_issues)
    approvals: dict[str, str] = {}
    internal = {"C000.13": {"outcome": "fail", "issues": ["governance validator unavailable"]}, "C000.14": {"outcome": "fail", "issues": ["governance validator unavailable"], "platform_complete": False}}
    if validator is not None:
        internal, approvals, _ = internal_governance_cases(validator, by_id, subject_revision, subject_tree, descendant_tree, tree_clean)
    failed_tasks = [task_id for task_id, case in task_results.items() if case["outcome"] != "pass"]
    failed_internal = [task_id for task_id, case in internal.items() if case["outcome"] != "pass"]
    if failed_tasks:
        issues.append("artifact failures: " + ", ".join(failed_tasks))
    if failed_internal:
        issues.append("internal governance failures: " + ", ".join(failed_internal))
    issues.extend(issue for case in internal.values() for issue in case["issues"])
    passed = not issues and len(approvals) == 3
    return {
        "id": "C000.V",
        "outcome": "pass" if passed else "fail",
        "expected": {"required_tasks": list(TASK_ARTIFACTS), "internal_tasks": ["C000.13", "C000.14"], "platform_complete": True, "review_classes": ["architecture", "security", "license"]},
        "observed": {"task_outcomes": {key: value["outcome"] for key, value in task_results.items()}, "internal_outcomes": {key: value["outcome"] for key, value in internal.items()}, "platform_complete": internal["C000.14"].get("platform_complete", False), "review_approvals": approvals, "issues": sorted(set(issues))},
        "skip_disposition": None,
    }


def main() -> int:
    validator, by_id, current_revision, subject_revision, _subject_closure, subject_tree, descendant_tree, tree_clean, model_issues = governance_model()
    cases = [task_case(task_id, validator, by_id, current_revision, subject_tree) for task_id in EMITTED_TASKS]
    cases.append(verification_case(validator, by_id, current_revision, subject_revision, subject_tree, descendant_tree, tree_clean, model_issues))
    failed = any(case["outcome"] != "pass" for case in cases)
    payload = {"schema_version": 1, "audit": "C000-artifacts", "outcome": "fail" if failed else "pass", "cases": cases}
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
