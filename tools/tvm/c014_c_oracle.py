#!/usr/bin/env python3
"""Replay the dependency-free C014C Java vector emitter against the committed oracle."""
from __future__ import annotations
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/reference-runner"))
from java_reference_guard import install_java_reference_guard
SESSION = install_java_reference_guard(ROOT)
ORACLE = ROOT / "docs/oracles/c014-opcodes-c.v1.json"
JAVA = Path(__file__).with_name("C014COracle.java")

def main() -> None:
    expected = json.loads(ORACLE.read_text())["rows"]
    with tempfile.TemporaryDirectory(prefix="c014c-") as output:
        SESSION.run([str(SESSION.java_home / "bin/javac"), "-d", output, str(JAVA)], check=True)
        text = SESSION.run([str(SESSION.java_home / "bin/java"), "-cp", output, "C014COracle"], classpath=output, check=True).stdout.decode()
    actual = []
    for line in text.splitlines():
        opcode, name, required, resulting, activation, energy = line.split("\t")
        if energy == "call": parsed_energy: object = energy
        elif "," in energy: parsed_energy = [int(value) for value in energy.split(",")]
        else: parsed_energy = int(energy)
        actual.append({"opcode": opcode, "name": name, "required": int(required), "resulting": int(resulting), "activation": activation, "energy": parsed_energy})
    if actual != expected:
        raise SystemExit("C014C pinned-Java oracle mismatch")
    print(f"C014C oracle replayed {len(actual)} rows")

if __name__ == "__main__":
    main()
