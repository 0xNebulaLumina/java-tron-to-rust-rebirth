#!/usr/bin/env python3
"""Deterministically audit the retained C000 repository artifacts."""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
PIN = "4a21592f95e37908b21bc3f611c6e7a1a67f09f3"
REQUIRED = (
    "docs/PORTING_TRACKER.json",
    "docs/architecture/crate-ownership.md",
    "docs/architecture/runtime-dependency-lifecycle.md",
    "docs/architecture/toolchains-and-platforms.md",
    "docs/architecture/DR-001-rust-storage-boundary.md",
    "docs/architecture/DR-004-custom-actuator-extensions.md",
    "docs/architecture/security-threat-policy.md",
    "docs/architecture/license-provenance-policy.md",
    "docs/architecture/cross-domain-seams.v1.json",
    "docs/oracles/manifest.v1.json",
    "docs/oracles/runner-protocol.md",
    "docs/oracles/normalization-policy-v1.json",
    "docs/oracles/schemas/fixture-v1.schema.json",
    "docs/oracles/schemas/result-v1.schema.json",
    "docs/oracles/schemas/mismatch-report-v1.schema.json",
    "docs/oracles/production-ownership.v1.json",
    "docs/oracles/java-test-ownership.v1.json",
    "tools/reference-runner/generate-ledgers.py",
    "tools/reference-runner/runner.py",
    "tools/reference-runner/java-runner",
    "tools/reference-runner/rust-runner",
    "tools/tracker/validate.py",
    "tools/platform/c000_unit.py",
    "tools/platform/c000_differential.py",
    "tools/platform/c000_native_resource.py",
    "tools/platform/c000_smoke.py",
    "rust-tron/Cargo.toml",
    "rust-tron/Cargo.lock",
    "rust-tron/rust-toolchain.toml",
)
FORBIDDEN = (
    "docs/architecture/platform-manifest.v1.json",
    "docs/architecture/toolchains-platform-policy.md",
    "docs/oracles/production-ownership-ledger.v1.json",
    "docs/oracles/java-test-case-ownership-ledger.v1.json",
    "docs/oracles/schemas/oracle-fixture-v1.schema.json",
    "docs/oracles/schemas/oracle-result-v1.schema.json",
    "docs/oracles/schemas/ownership-ledger-v1.schema.json",
    "docs/oracles/schemas/threat-model-v1.schema.json",
    "docs/oracles/schemas/security-finding-v1.schema.json",
    "docs/oracles/schemas/license-provenance-v1.schema.json",
    "tools/platform/run",
    "tools/platform/c000_not_applicable.py",
)


def load(path: str) -> Any:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def ledger_issues(path: str, identity: str, tracker_ids: set[str]) -> list[str]:
    issues: list[str] = []
    try: ledger = load(path)
    except (OSError, json.JSONDecodeError) as error: return [f"{path}: {error}"]
    rows = ledger.get("rows")
    if ledger.get("ledger") != identity or ledger.get("java_source_revision") != PIN:
        issues.append(f"{path}: identity or Java pin is incorrect")
    if not isinstance(rows, list): return issues + [f"{path}: rows must be an array"]
    if ledger.get("row_count") != len(rows): issues.append(f"{path}: row_count mismatch")
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict): issues.append(f"{path}: row must be an object"); break
        row_id = row.get("id")
        if not isinstance(row_id, str) or not row_id or row_id in seen: issues.append(f"{path}: missing or duplicate row id"); break
        seen.add(row_id)
        if row.get("owning_item") not in tracker_ids or row.get("acceptance_gate") not in tracker_ids:
            issues.append(f"{path}: {row_id} has an unknown owner or gate"); break
        if row["owning_item"].split(".", 1)[0] != row["acceptance_gate"].split(".", 1)[0]:
            issues.append(f"{path}: {row_id} owner and gate cross chunks"); break
        source = row.get("source")
        if not isinstance(source, dict) or set(source) != {"path", "line"} or not isinstance(source.get("line"), int) or source["line"] < 1 or not (ROOT / source.get("path", "")).is_file():
            issues.append(f"{path}: {row_id} has an invalid source location"); break
        if "dependencies" in row or "adoptions" in row: issues.append(f"{path}: {row_id} contains retired governance arrays"); break
    return issues


def main() -> int:
    issues = [f"missing retained artifact: {path}" for path in REQUIRED if not (ROOT / path).is_file()]
    issues.extend(f"stale artifact remains: {path}" for path in FORBIDDEN if (ROOT / path).exists())
    fixtures = sorted((ROOT / "docs/oracles/fixtures/v1").glob("*.json"))
    if len(fixtures) != 8: issues.append(f"expected 8 oracle fixtures, found {len(fixtures)}")
    try:
        manifest = load("docs/oracles/manifest.v1.json")
        if manifest.get("java_source_revision") != PIN: issues.append("oracle manifest Java pin is incorrect")
        for key in ("fixture_schema", "result_schema", "mismatch_schema", "normalization_policy"):
            value = manifest.get(key)
            if not isinstance(value, str) or not (ROOT / "docs/oracles" / value).is_file(): issues.append(f"oracle manifest has invalid {key}")
        if manifest.get("fixtures") != [f"fixtures/v1/{path.name}" for path in fixtures]: issues.append("oracle manifest fixture inventory is not deterministic")
        retired = {"subject_ref", "subject_tag_object", "subject_revision", "attestation", "approval", "governance_schemas", "fixture_provenance"}
        if retired & set(manifest): issues.append("oracle manifest contains retired governance fields")
    except (OSError, json.JSONDecodeError) as error: issues.append(f"oracle manifest: {error}")
    try:
        tracker = load("docs/PORTING_TRACKER.json")
        tracker_ids = {value["id"] for chunk in tracker["chunks"] for value in [chunk, *chunk["items"], chunk["gate"]]}
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        issues.append(f"tracker: {error}"); tracker_ids = set()
    issues.extend(ledger_issues("docs/oracles/production-ownership.v1.json", "production-ownership", tracker_ids))
    issues.extend(ledger_issues("docs/oracles/java-test-ownership.v1.json", "java-test-ownership", tracker_ids))
    manifests = sorted((ROOT / "rust-tron/crates").glob("*/Cargo.toml"))
    if len(manifests) != 15: issues.append(f"expected 15 Rust crate manifests, found {len(manifests)}")
    try:
        staged = subprocess.run(["git", "ls-files", "--stage", "java-tron"], cwd=ROOT, check=True, text=True, capture_output=True).stdout.strip()
        if not re.fullmatch(rf"160000 {PIN} 0\s+java-tron", staged): issues.append("java-tron gitlink does not match the manifest pin")
    except (OSError, subprocess.CalledProcessError) as error: issues.append(f"cannot inspect java-tron gitlink: {error}")
    result = {"cell": "artifacts", "outcome": "fail" if issues else "pass", "issues": sorted(set(issues))}
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 1 if issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
