#!/usr/bin/env python3
"""Run the complete C000 behavior-neutral Java/Rust oracle comparison matrix."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "tools/reference-runner/runner.py"
FIXTURES = ROOT / "docs/oracles/fixtures/v1"
CASES = (
    ("positive.json", True),
    ("negative.json", True),
    ("mismatch-output.json", False),
    ("mismatch-state.json", False),
    ("mismatch-error.json", False),
    ("mismatch-forbidden-normalization.json", False),
    ("mismatch-normalization-forbidden-class.json", False),
    ("mismatch-normalization-forbidden-pointer.json", False),
)


def run(*args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(RUNNER), *args], cwd=ROOT, check=False, capture_output=True
    )


def main() -> int:
    outcomes = []
    failed = False
    with tempfile.TemporaryDirectory(prefix="c000-differential-") as directory:
        work = Path(directory)
        for filename, expected_match in CASES:
            fixture = FIXTURES / filename
            java = run("--runner", "java", "run", "--fixture", str(fixture))
            rust = run("--runner", "rust", "run", "--fixture", str(fixture))
            java_path, rust_path = work / f"{filename}.java", work / f"{filename}.rust"
            java_path.write_bytes(java.stdout)
            rust_path.write_bytes(rust.stdout)
            comparison = run("compare", "--java-result", str(java_path), "--rust-result", str(rust_path))
            try:
                result = json.loads(comparison.stdout)
                observed_match = result.get("match")
                mismatch_kinds = sorted({row.get("kind") for row in result.get("mismatches", [])})
            except (json.JSONDecodeError, AttributeError, TypeError):
                observed_match, mismatch_kinds = None, []
            expected_compare_code = 0 if expected_match else 20
            passed = (
                java.returncode in (0, 10)
                and rust.returncode in (0, 10)
                and comparison.returncode == expected_compare_code
                and observed_match is expected_match
            )
            failed |= not passed
            outcomes.append({
                "case": filename.removesuffix(".json"),
                "outcome": "pass" if passed else "fail",
                "expected_match": expected_match,
                "observed_match": observed_match,
                "java_exit": java.returncode,
                "rust_exit": rust.returncode,
                "compare_exit": comparison.returncode,
                "mismatch_kinds": mismatch_kinds,
                "fixture_sha256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
            })
    print(json.dumps({"schema_version": 1, "cell": "differential", "cases": outcomes}, sort_keys=True, separators=(",", ":")))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
