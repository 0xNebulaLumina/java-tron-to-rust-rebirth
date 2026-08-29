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
SUBPROCESS_TIMEOUT_SECONDS = 10


def invoke(*args: str, stdin: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            [sys.executable, str(RUNNER_PATH), *args], cwd=ROOT, input=stdin,
            check=False, capture_output=True, timeout=SUBPROCESS_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(args, 124, exc.stdout or b"", exc.stderr or b"")


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
        completed = invoke("--runner", implementation, "identify")
        try:
            identity = json.loads(completed.stdout)
            passed = completed.returncode == 0 and identity.get("implementation") == f"c000-{implementation}-protocol-adapter"
        except (json.JSONDecodeError, AttributeError):
            passed = False
        failed |= not passed
        outcomes.append({"case": f"runner-identify:{implementation}", "outcome": "pass" if passed else "fail", "exit_code": completed.returncode})
    adversarial = (
        ("oversize-input", b" " * (runner.MAX_INPUT_BYTES + 1)),
        ("deep-input", (b'{"x":' * (runner.MAX_JSON_DEPTH + 1)) + b"null" + (b"}" * (runner.MAX_JSON_DEPTH + 1))),
        ("duplicate-key", b'{"schema_version":1,"schema_version":1}'),
    )
    for name, payload in adversarial:
        completed = invoke("--runner", "java", "run", stdin=payload)
        try:
            result = json.loads(completed.stdout)
            passed = completed.returncode == 64 and result.get("status") == "invalid_fixture" and result.get("error", {}).get("code") == "INVALID_FIXTURE"
        except (json.JSONDecodeError, AttributeError, UnicodeDecodeError):
            passed = False
        failed |= not passed
        outcomes.append({"case": f"resource:{name}", "outcome": "pass" if passed else "fail", "exit_code": completed.returncode})
    print(json.dumps({"schema_version": 1, "cell": "unit", "cases": outcomes}, sort_keys=True, separators=(",", ":")))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
