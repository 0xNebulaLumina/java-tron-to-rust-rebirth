#!/usr/bin/env python3
"""Exercise C000 subprocess, stream, timeout, and temporary-resource ceilings."""
from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

from c000_smoke import MAX_STREAM_BYTES, invoke

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "tools/reference-runner/runner.py"
FIXTURE = ROOT / "docs/oracles/fixtures/v1/positive.json"
MAX_SUBPROCESSES = 40
REPEATED_RUNS = 32
MAX_TEMP_FILES = REPEATED_RUNS
MAX_TOTAL_TEMP_BYTES = REPEATED_RUNS * MAX_STREAM_BYTES


def descriptor_count() -> int | None:
    proc_fd = Path("/proc/self/fd")
    return len(list(proc_fd.iterdir())) if proc_fd.is_dir() else None


def case(name: str, passed: bool, **details: object) -> dict[str, object]:
    return {"case": name, "outcome": "pass" if passed else "fail", **details}


def main() -> int:
    cases: list[dict[str, object]] = []
    planned_subprocesses = REPEATED_RUNS + 3
    if planned_subprocesses > MAX_SUBPROCESSES or REPEATED_RUNS > MAX_TEMP_FILES:
        raise RuntimeError("resource limit exceeded: native-resource subprocess or temporary-file count")

    before = descriptor_count()
    total_temp_bytes = 0
    with tempfile.TemporaryDirectory(prefix="c000-native-resource-") as directory:
        temp_root = Path(directory)
        repeated_ok = True
        for index in range(REPEATED_RUNS):
            completed = invoke([
                sys.executable, str(RUNNER), "--runner", "java", "run", "--fixture", str(FIXTURE),
            ])
            total_temp_bytes += len(completed.stdout)
            if total_temp_bytes > MAX_TOTAL_TEMP_BYTES:
                repeated_ok = False
                break
            result = temp_root / f"result-{index}.json"
            result.write_bytes(completed.stdout)
            if completed.returncode != 0 or len(completed.stdout) > MAX_STREAM_BYTES:
                repeated_ok = False
                break
        cases.append(case("repeated-run-cleanup", repeated_ok, subprocesses=REPEATED_RUNS, temporary_bytes=total_temp_bytes))
        escaped_path = str(temp_root)

    after = descriptor_count()
    cases.append(case("descriptor-cleanup", before is None or after is None or after <= before + 1, before=before, after=after))
    cases.append(case("temp-cleanup", not Path(escaped_path).exists()))

    overflow_before = descriptor_count()
    overflow = invoke([
        sys.executable, "-c", f"import os; os.write(1, b'x' * ({MAX_STREAM_BYTES} + 1)); import time; time.sleep(60)",
    ])
    overflow_after = descriptor_count()
    cases.append(case(
        "stdout-overflow-kills-and-reaps", overflow.returncode == 70 and len(overflow.stdout) == MAX_STREAM_BYTES
        and overflow.stderr == b"resource limit exceeded: subprocess output"
        and (overflow_before is None or overflow_after is None or overflow_after <= overflow_before),
        exit_code=overflow.returncode, captured_bytes=len(overflow.stdout), before=overflow_before, after=overflow_after,
    ))

    stderr_overflow = invoke([
        sys.executable, "-c", f"import os; os.write(2, b'x' * ({MAX_STREAM_BYTES} + 1)); import time; time.sleep(60)",
    ])
    cases.append(case(
        "stderr-overflow-kills-and-reaps", stderr_overflow.returncode == 70
        and stderr_overflow.stderr == b"resource limit exceeded: subprocess output",
        exit_code=stderr_overflow.returncode,
    ))

    timeout_before = descriptor_count()
    started = time.monotonic()
    timeout = invoke([sys.executable, "-c", "import time; time.sleep(60)"])
    elapsed = time.monotonic() - started
    timeout_after = descriptor_count()
    cases.append(case(
        "timeout-kills-and-reaps", timeout.returncode == 124 and elapsed < 15
        and timeout.stderr == b"resource limit exceeded: subprocess timeout"
        and (timeout_before is None or timeout_after is None or timeout_after <= timeout_before),
        exit_code=timeout.returncode, elapsed_milliseconds=int(elapsed * 1000), before=timeout_before, after=timeout_after,
    ))

    print(json.dumps({"schema_version": 1, "cell": "native_resource", "cases": cases}, sort_keys=True, separators=(",", ":")))
    return 0 if all(row["outcome"] == "pass" for row in cases) else 1


if __name__ == "__main__":
    raise SystemExit(main())
