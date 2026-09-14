#!/usr/bin/env python3
"""Exhaustive C004 provenance, pinned-Java oracle, artifact, and Rust-dispatch gate."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE_MANIFEST = ROOT / "docs/oracles/c004-crypto-source-manifest.v1.json"
FIXTURE = ROOT / "docs/oracles/c004-crypto-fixture-manifest.v1.json"
RUST_TEST = ROOT / "rust-tron/crates/tron-crypto/tests/c004_vectors.rs"
OWNERSHIP = ROOT / "docs/oracles/java-test-ownership.v1.json"
ORACLE = ROOT / "tools/crypto/c004_oracle.py"
JAVA_REVISION = "4a21592f95e37908b21bc3f611c6e7a1a67f09f3"
REQUIRED_SEAMS = {("C005", "keystore"), ("C006", "zksnark/shielded crypto"), ("C015", "Blake2 precompile")}
REQUIRED_PREFIXES = {
    "C004.HASH.", "C004.KEY.", "C004.SIG.", "C004.BASE58.", "C004.ADDRESS.",
    "C004.WIRE.", "C004.PERMISSION.", "C004.FORMULA.",
}
REPLACEMENT_FIELDS = {
    "stable_id", "source_identity", "case_id", "behavior_slices", "observable_result",
    "fixture_links", "rust_symbol", "rust_case_id", "selector", "canonical_command",
    "ignored_disposition",
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path, errors: list[str]) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        errors.append(f"{path.relative_to(ROOT)}: {error}")
        return {}
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        errors.append(f"{path.relative_to(ROOT)} must be a schema_version 1 object")
        return {}
    return value


def main() -> int:
    errors: list[str] = []
    source = load(SOURCE_MANIFEST, errors)
    fixture = load(FIXTURE, errors)
    ownership = json.loads(OWNERSHIP.read_text(encoding="utf-8"))

    if source.get("java_revision") != JAVA_REVISION:
        errors.append("source manifest Java revision is not the pinned gitlink")
    try:
        actual_revision = subprocess.check_output(
            ["git", "-C", str(ROOT / "java-tron"), "rev-parse", "HEAD"], text=True
        ).strip()
        if actual_revision != JAVA_REVISION:
            errors.append(f"java-tron gitlink drift: {actual_revision}")
    except (OSError, subprocess.CalledProcessError) as error:
        errors.append(f"cannot authenticate java-tron revision: {error}")

    whitelist = source.get("whitelist", [])
    paths: set[str] = set()
    for row in whitelist:
        if not isinstance(row, dict) or set(row) != {"path", "sha256", "covers"} or not row.get("covers"):
            errors.append(f"invalid source whitelist row: {row!r}")
            continue
        path_text = row["path"]
        if path_text in paths:
            errors.append(f"duplicate source whitelist path: {path_text}")
        paths.add(path_text)
        path = ROOT / path_text
        if not path.is_file() or digest(path) != row["sha256"]:
            errors.append(f"pinned Java source missing or drifted: {path_text}")
    seams = {
        (row.get("owner"), row.get("domain"))
        for row in source.get("scope_seams", [])
        if isinstance(row, dict) and row.get("status") == "excluded" and row.get("reason")
    }
    if seams != REQUIRED_SEAMS:
        errors.append(f"scope seams must be exactly {sorted(REQUIRED_SEAMS)}")

    try:
        oracle = subprocess.run(
            [sys.executable, str(ORACLE)], cwd=ROOT, text=True, capture_output=True, timeout=60
        )
        if oracle.returncode:
            errors.append((oracle.stderr or oracle.stdout).strip() or "pinned Java oracle failed")
    except (OSError, subprocess.TimeoutExpired) as error:
        errors.append(f"pinned Java oracle failed: {error}")

    vectors = fixture.get("vectors", [])
    dispatch = fixture.get("rust_dispatch", {})
    ids = [row.get("id") for row in vectors if isinstance(row, dict)]
    if len(ids) != len(vectors) or len(ids) != len(set(ids)) or set(ids) != set(dispatch):
        errors.append("every unique Java vector must have exactly one Rust dispatch entry")
    for prefix in REQUIRED_PREFIXES:
        if not any(vector_id.startswith(prefix) for vector_id in ids if isinstance(vector_id, str)):
            errors.append(f"oracle lacks required vector family {prefix}")
    canonical = json.dumps(vectors, sort_keys=True, separators=(",", ":")).encode()
    if fixture.get("vectors_sha256") != hashlib.sha256(canonical).hexdigest():
        errors.append("mechanically-derived vector payload digest drift")

    test_text = RUST_TEST.read_text(encoding="utf-8") if RUST_TEST.is_file() else ""
    functions = set(re.findall(r"(?m)^fn ([a-z0-9_]+)\(\) \{", test_text))
    for vector_id, case in dispatch.items():
        if not isinstance(case, str) or case not in functions:
            errors.append(f"vector {vector_id} dispatches to missing Rust test {case!r}")
    if "c004-crypto-fixture-manifest.v1.json" not in test_text:
        errors.append("Rust C004 test must deserialize the single generated fixture artifact")
    if "rust_dispatch" not in test_text:
        errors.append("Rust C004 test must assert explicit every-vector dispatch")
    owned_rows = [row for row in ownership.get("rows", []) if row.get("acceptance_gate") == "C004.V"]
    replacements = fixture.get("java_replacements", [])
    owned_by_id = {row.get("id"): row for row in owned_rows}
    replacement_by_id = {row.get("stable_id"): row for row in replacements if isinstance(row, dict)}
    if fixture.get("java_replacement_count") != 245 or len(owned_rows) != 245 or len(replacements) != 245:
        errors.append("C004 Java replacement accounting must contain exactly 245 rows")
    if len(owned_by_id) != 245 or len(replacement_by_id) != 245 or set(owned_by_id) != set(replacement_by_id):
        errors.append("C004 replacements must exactly match every C004.V stable ID")
    generic = re.compile(r"catchall|covered by|generic|placeholder|todo|tbd", re.IGNORECASE)
    for stable_id, replacement in replacement_by_id.items():
        owned = owned_by_id.get(stable_id, {})
        source_identity = replacement.get("source_identity", {})
        expected_identity = {
            "id": stable_id,
            "path": owned.get("source", {}).get("path"),
            "line": owned.get("source", {}).get("line"),
            "case": owned.get("case"),
            "kind": owned.get("kind"),
        }
        if set(replacement) != REPLACEMENT_FIELDS or source_identity != expected_identity:
            errors.append(f"C004 replacement {stable_id} lacks exact source identity or fields")
            continue
        symbol = replacement.get("rust_symbol", "")
        function = symbol.rsplit("::", 1)[-1]
        expected_command = ["cargo", "test", "-p", "tron-crypto", "--test", "c004_vectors", function, "--", "--exact"]
        text_values = (
            replacement.get("case_id"), replacement.get("observable_result"), symbol,
            replacement.get("rust_case_id"), replacement.get("selector"),
        )
        if any(not isinstance(value, str) or not value or generic.search(value) for value in text_values):
            errors.append(f"C004 replacement {stable_id} has a missing or catchall proof field")
        if replacement.get("case_id") != stable_id or replacement.get("rust_case_id") != stable_id or replacement.get("selector") != stable_id:
            errors.append(f"C004 replacement {stable_id} must use its stable ID as every case selector")
        if replacement.get("behavior_slices") != [f"{stable_id}:{owned.get('case')}"]:
            errors.append(f"C004 replacement {stable_id} lacks its exact behavior slice")
        if replacement.get("ignored_disposition") != "not_ignored":
            errors.append(f"C004 replacement {stable_id} has invalid ignored disposition")
        if replacement.get("canonical_command") != expected_command or function not in functions:
            errors.append(f"C004 replacement {stable_id} lacks a canonical executable Rust dispatch")
        fixture_links = replacement.get("fixture_links")
        if not isinstance(fixture_links, list) or not fixture_links or not all(stable_id in link for link in fixture_links):
            errors.append(f"C004 replacement {stable_id} lacks per-ID fixture selectors")

    if errors:
        for error in errors:
            print(f"C004 gate: {error}", file=sys.stderr)
        return 1
    print(
        f"C004 gate passed: {len(paths)} pinned Java sources, {len(vectors)} authenticated Java vectors, "
        f"{len(set(dispatch.values()))} explicit Rust test dispatches, zero C004-scope gaps"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
