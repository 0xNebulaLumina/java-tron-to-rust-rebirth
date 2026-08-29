#!/usr/bin/env python3
"""Run the complete C000 behavior-neutral Java/Rust oracle comparison matrix."""
from __future__ import annotations

import hashlib
import json
import os
import selectors
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "tools/reference-runner/runner.py"
FIXTURES = ROOT / "docs/oracles/fixtures/v1"
SUBPROCESS_TIMEOUT_SECONDS = 10
MAX_STREAM_BYTES = 2_097_152
MAX_CASES = 32
MAX_SUBPROCESSES = 96
MAX_TEMP_FILES = 2 * MAX_CASES
MAX_TEMP_BYTES = 2 * MAX_CASES * MAX_STREAM_BYTES
READ_CHUNK_BYTES = 65_536
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
    argv = [sys.executable, str(RUNNER), *args]
    process = subprocess.Popen(argv, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    streams = (process.stdout, process.stderr)
    selector = selectors.DefaultSelector()
    buffers = [bytearray(), bytearray()]
    for index, stream in enumerate(streams):
        if stream is None:
            process.kill(); process.wait()
            return subprocess.CompletedProcess(argv, 70, b"", b"failed to open bounded subprocess streams")
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, index)
    deadline = time.monotonic() + SUBPROCESS_TIMEOUT_SECONDS
    returncode = 0
    error = None
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                error, returncode = b"resource limit exceeded: subprocess timeout", 124
                break
            for key, _ in selector.select(min(remaining, 0.05)):
                chunk = os.read(key.fileobj.fileno(), READ_CHUNK_BYTES)
                if not chunk:
                    selector.unregister(key.fileobj); key.fileobj.close(); continue
                target = buffers[key.data]
                if len(target) + len(chunk) > MAX_STREAM_BYTES:
                    target.extend(chunk[:MAX_STREAM_BYTES - len(target)])
                    error, returncode = b"resource limit exceeded: subprocess output", 70
                    break
                target.extend(chunk)
            if error is not None:
                break
        if error is not None:
            process.kill()
        try:
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            error, returncode = b"resource limit exceeded: subprocess timeout", 124
            process.kill(); process.wait()
        if error is None:
            returncode = process.returncode
    finally:
        selector.close()
        if process.poll() is None:
            process.kill(); process.wait()
        for stream in streams:
            if stream is not None and not stream.closed:
                stream.close()
    return subprocess.CompletedProcess(argv, returncode, bytes(buffers[0]), bytes(buffers[1]) if error is None else error)


def main() -> int:
    outcomes = []
    if len(CASES) > MAX_CASES or len(CASES) * 2 > MAX_TEMP_FILES or len(CASES) * 3 > MAX_SUBPROCESSES:
        raise RuntimeError("resource limit exceeded: differential case, subprocess, or temporary-file count")
    failed = False
    with tempfile.TemporaryDirectory(prefix="c000-differential-") as directory:
        temporary_bytes = 0
        work = Path(directory)
        for filename, expected_match in CASES:
            fixture = FIXTURES / filename
            java = run("--runner", "java", "run", "--fixture", str(fixture))
            rust = run("--runner", "rust", "run", "--fixture", str(fixture))
            java_path, rust_path = work / f"{filename}.java", work / f"{filename}.rust"
            temporary_bytes += len(java.stdout) + len(rust.stdout)
            if temporary_bytes > MAX_TEMP_BYTES:
                raise RuntimeError("resource limit exceeded: differential temporary bytes")
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
        cleanup_path = str(work)
    cleanup_passed = not Path(cleanup_path).exists()
    failed |= not cleanup_passed
    outcomes.append({"case": "temp-cleanup", "outcome": "pass" if cleanup_passed else "fail"})
    print(json.dumps({"schema_version": 1, "cell": "differential", "cases": outcomes}, sort_keys=True, separators=(",", ":")))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
