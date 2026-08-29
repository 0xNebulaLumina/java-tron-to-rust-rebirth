#!/usr/bin/env python3
"""Focused C000 oracle schema and runner smoke checks."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = ROOT / "tools/reference-runner/runner.py"
FIXTURES = ROOT / "docs/oracles/fixtures/v1"


def main() -> int:
    spec = importlib.util.spec_from_file_location("c000_reference_runner", RUNNER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load reference runner")
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    outcomes = []
    failed = False
    for fixture_path in sorted(FIXTURES.glob("*.json")):
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        errors = runner.validate_schema(fixture, runner.FIXTURE_SCHEMA)
        passed = not errors
        failed |= not passed
        outcomes.append({"case": f"fixture-schema:{fixture_path.stem}", "outcome": "pass" if passed else "fail", "errors": errors})
    for implementation in ("java", "rust"):
        completed = subprocess.run(
            [sys.executable, str(RUNNER_PATH), "--runner", implementation, "identify"],
            cwd=ROOT, check=False, capture_output=True,
        )
        try:
            identity = json.loads(completed.stdout)
            passed = completed.returncode == 0 and identity.get("implementation") == f"c000-{implementation}-protocol-adapter"
        except (json.JSONDecodeError, AttributeError):
            passed = False
        failed |= not passed
        outcomes.append({"case": f"runner-identify:{implementation}", "outcome": "pass" if passed else "fail", "exit_code": completed.returncode})
    print(json.dumps({"schema_version": 1, "cell": "unit", "cases": outcomes}, sort_keys=True, separators=(",", ":")))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
