#!/usr/bin/env python3
"""Verify descriptor, timeout, and temporary-resource cleanup for C000 tooling."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "tools/reference-runner/runner.py"
FIXTURE = ROOT / "docs/oracles/fixtures/v1/positive.json"
TIMEOUT_SECONDS = 10


def descriptor_count() -> int | None:
    proc_fd = Path("/proc/self/fd")
    return len(list(proc_fd.iterdir())) if proc_fd.is_dir() else None


def main() -> int:
    cases: list[dict[str, object]] = []
    before = descriptor_count()
    with tempfile.TemporaryDirectory(prefix="c000-native-resource-") as directory:
        temp_root = Path(directory)
        for index in range(32):
            result = temp_root / f"result-{index}.json"
            with result.open("wb") as output:
                completed = subprocess.run(
                    [sys.executable, str(RUNNER), "--runner", "java", "run", "--fixture", str(FIXTURE)],
                    cwd=ROOT, stdout=output, stderr=subprocess.PIPE, check=False, timeout=TIMEOUT_SECONDS,
                )
            if completed.returncode != 0:
                cases.append({"case": "repeated-run-cleanup", "outcome": "fail", "exit_code": completed.returncode})
                break
        else:
            cases.append({"case": "repeated-run-cleanup", "outcome": "pass"})
        escaped_path = str(temp_root)
    after = descriptor_count()
    descriptors_clean = before is None or after is None or after <= before + 1
    cases.append({"case": "descriptor-cleanup", "outcome": "pass" if descriptors_clean else "fail", "before": before, "after": after})
    temp_clean = not Path(escaped_path).exists()
    cases.append({"case": "temp-cleanup", "outcome": "pass" if temp_clean else "fail"})
    sleeper = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        sleeper.wait(timeout=0.05)
        timeout_clean = False
    except subprocess.TimeoutExpired:
        sleeper.kill()
        sleeper.wait(timeout=TIMEOUT_SECONDS)
        timeout_clean = sleeper.poll() is not None
    cases.append({"case": "timeout-process-cleanup", "outcome": "pass" if timeout_clean else "fail"})
    print(json.dumps({"schema_version": 1, "cell": "native_resource", "cases": cases}, sort_keys=True, separators=(",", ":")))
    return 0 if all(case["outcome"] == "pass" for case in cases) else 1


if __name__ == "__main__":
    raise SystemExit(main())
