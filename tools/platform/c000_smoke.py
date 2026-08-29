#!/usr/bin/env python3
"""Exercise the governed C000 command surfaces with bounded subprocesses."""
from __future__ import annotations

import json
import os
import selectors
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "docs/oracles/fixtures/v1/positive.json"
TIMEOUT_SECONDS = 10
MAX_STREAM_BYTES = 2_097_152
MAX_STDIN_BYTES = 1_048_576
MAX_COMMANDS = 8
READ_CHUNK_BYTES = 65_536


def invoke(argv: list[str], *, stdin: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    if stdin is not None and len(stdin) > MAX_STDIN_BYTES:
        return subprocess.CompletedProcess(argv, 70, b"", b"resource limit exceeded: stdin bytes")
    with tempfile.TemporaryFile() as input_file:
        if stdin is not None:
            input_file.write(stdin)
            input_file.seek(0)
        process = subprocess.Popen(
            argv, cwd=ROOT, stdin=input_file if stdin is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        streams = (process.stdout, process.stderr)
        if any(stream is None for stream in streams):
            process.kill(); process.wait()
            return subprocess.CompletedProcess(argv, 70, b"", b"failed to open bounded subprocess streams")
        selector = selectors.DefaultSelector()
        buffers = [bytearray(), bytearray()]
        for index, stream in enumerate(streams):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, index)
        deadline = time.monotonic() + TIMEOUT_SECONDS
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
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
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
        stderr = bytes(buffers[1]) if error is None else error
        return subprocess.CompletedProcess(argv, returncode, bytes(buffers[0]), stderr)


def main() -> int:
    cases: list[dict[str, object]] = []
    commands = (
        ("java-file", [str(ROOT / "tools/reference-runner/java-runner"), "run", "--fixture", str(FIXTURE)], 0),
        ("rust-stdin", [str(ROOT / "tools/reference-runner/rust-runner"), "run"], 0),
        ("invalid-invocation", [str(ROOT / "tools/reference-runner/java-runner"), "bogus"], 64),
        ("platform-invalid", [str(ROOT / "tools/platform/run"), "UNKNOWN", "smoke"], 64),
    )
    if len(commands) > MAX_COMMANDS:
        raise RuntimeError(f"resource limit exceeded: command count > {MAX_COMMANDS}")
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
