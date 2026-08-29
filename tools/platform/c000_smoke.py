#!/usr/bin/env python3
"""Exercise the governed C000 command surfaces with bounded subprocesses."""
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "docs/oracles/fixtures/v1/positive.json"
TIMEOUT_SECONDS = 10
MAX_CAPTURE_BYTES = 2_097_152


def invoke(argv: list[str], *, stdin: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(argv, cwd=ROOT, input=stdin, capture_output=True, check=False, timeout=TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(argv, 124, (exc.stdout or b"")[:MAX_CAPTURE_BYTES], (exc.stderr or b"")[:MAX_CAPTURE_BYTES])
    if len(completed.stdout) > MAX_CAPTURE_BYTES or len(completed.stderr) > MAX_CAPTURE_BYTES:
        return subprocess.CompletedProcess(argv, 70, completed.stdout[:MAX_CAPTURE_BYTES], b"resource limit exceeded: captured output")
    return completed


def main() -> int:
    cases: list[dict[str, object]] = []
    commands = (
        ("java-file", [str(ROOT / "tools/reference-runner/java-runner"), "run", "--fixture", str(FIXTURE)], 0),
        ("rust-stdin", [str(ROOT / "tools/reference-runner/rust-runner"), "run"], 0),
        ("invalid-invocation", [str(ROOT / "tools/reference-runner/java-runner"), "bogus"], 64),
        ("platform-invalid", [str(ROOT / "tools/platform/run"), "UNKNOWN", "smoke"], 64),
    )
    fixture_bytes = FIXTURE.read_bytes()
    for name, argv, expected in commands:
        completed = invoke(argv, stdin=fixture_bytes if name == "rust-stdin" else None)
        try:
            payload = json.loads(completed.stdout)
            structured = isinstance(payload, dict) and payload.get("schema_version") == 1
        except (json.JSONDecodeError, UnicodeDecodeError):
            structured = False
        passed = completed.returncode == expected and structured
        cases.append({"case": name, "outcome": "pass" if passed else "fail", "exit_code": completed.returncode})
    with tempfile.TemporaryDirectory(prefix="c000-smoke-") as directory:
        marker = Path(directory)
        cleanup_path = str(marker)
    cleanup = not Path(cleanup_path).exists()
    cases.append({"case": "private-temp-cleanup", "outcome": "pass" if cleanup else "fail"})
    print(json.dumps({"schema_version": 1, "cell": "smoke", "cases": cases}, sort_keys=True, separators=(",", ":")))
    return 0 if all(case["outcome"] == "pass" for case in cases) else 1


if __name__ == "__main__":
    raise SystemExit(main())
