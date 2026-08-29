#!/usr/bin/env python3
"""Focused C000 oracle schema and runner smoke checks."""
from __future__ import annotations

import importlib.util
import json
import os
import selectors
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = ROOT / "tools/reference-runner/runner.py"
FIXTURES = ROOT / "docs/oracles/fixtures/v1"
SUBPROCESS_TIMEOUT_SECONDS = 10
MAX_STREAM_BYTES = 2_097_152
MAX_STDIN_BYTES = 1_048_576 + 1
MAX_FIXTURES = 64
MAX_INVOCATIONS = 16
READ_CHUNK_BYTES = 65_536


def invoke(*args: str, stdin: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    argv = [sys.executable, str(RUNNER_PATH), *args]
    if stdin is not None and len(stdin) > MAX_STDIN_BYTES:
        return subprocess.CompletedProcess(argv, 70, b"", b"resource limit exceeded: stdin bytes")
    with tempfile.TemporaryFile() as input_file:
        if stdin is not None:
            input_file.write(stdin); input_file.seek(0)
        process = subprocess.Popen(argv, cwd=ROOT, stdin=input_file if stdin is not None else subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        streams = (process.stdout, process.stderr)
        selector = selectors.DefaultSelector()
        buffers = [bytearray(), bytearray()]
        for index, stream in enumerate(streams):
            if stream is None:
                process.kill(); process.wait()
                return subprocess.CompletedProcess(argv, 70, b"", b"failed to open bounded subprocess streams")
            os.set_blocking(stream.fileno(), False); selector.register(stream, selectors.EVENT_READ, index)
        deadline = time.monotonic() + SUBPROCESS_TIMEOUT_SECONDS
        returncode, error = 0, None
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    returncode, error = 124, b"resource limit exceeded: subprocess timeout"; break
                for key, _ in selector.select(min(remaining, 0.05)):
                    chunk = os.read(key.fileobj.fileno(), READ_CHUNK_BYTES)
                    if not chunk:
                        selector.unregister(key.fileobj); key.fileobj.close(); continue
                    target = buffers[key.data]
                    if len(target) + len(chunk) > MAX_STREAM_BYTES:
                        target.extend(chunk[:MAX_STREAM_BYTES - len(target)])
                        returncode, error = 70, b"resource limit exceeded: subprocess output"; break
                    target.extend(chunk)
                if error is not None: break
            if error is not None: process.kill()
            try:
                process.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                returncode, error = 124, b"resource limit exceeded: subprocess timeout"
                process.kill(); process.wait()
            if error is None: returncode = process.returncode
        finally:
            selector.close()
            if process.poll() is None: process.kill(); process.wait()
            for stream in streams:
                if stream is not None and not stream.closed: stream.close()
        return subprocess.CompletedProcess(argv, returncode, bytes(buffers[0]), bytes(buffers[1]) if error is None else error)


def main() -> int:
    spec = importlib.util.spec_from_file_location("c000_reference_runner", RUNNER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load reference runner")
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    outcomes = []
    fixture_paths = sorted(FIXTURES.glob("*.json"))
    if len(fixture_paths) > MAX_FIXTURES:
        raise RuntimeError(f"resource limit exceeded: fixture count > {MAX_FIXTURES}")
    invocation_count = 2 + 3
    if invocation_count > MAX_INVOCATIONS:
        raise RuntimeError(f"resource limit exceeded: subprocess count > {MAX_INVOCATIONS}")
    failed = False
    for fixture_path in fixture_paths:
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
        ("oversize-input", b" " * (runner.MAX_FIXTURE_INPUT_BYTES + 1)),
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
