#!/usr/bin/env python3
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/reference-runner"))
from java_reference_guard import install_java_reference_guard

SESSION = install_java_reference_guard(ROOT)
JAVA = Path(__file__).with_name("C014BOracle.java")
OUTPUT = ROOT / "docs/oracles/c014-opcodes-b.v1.json"
SOURCES = [
    "actuator/src/main/java/org/tron/core/vm/Op.java",
    "actuator/src/main/java/org/tron/core/vm/OperationRegistry.java",
    "actuator/src/main/java/org/tron/core/vm/OperationActions.java",
    "actuator/src/main/java/org/tron/core/vm/EnergyCost.java",
]

with tempfile.TemporaryDirectory(prefix="c014-b-") as temp:
    SESSION.run([str(SESSION.java_home / "bin/javac"), "-d", temp, str(JAVA)], check=True)
    completed = SESSION.run([str(SESSION.java_home / "bin/java"), "-cp", temp, "C014BOracle"], classpath=temp, check=True)
    raw = completed.stdout.decode()
lines = raw.splitlines()
java_rows = [line.split("\t")[1:] for line in lines if line.startswith("ROW\t")]
manifest = json.loads(OUTPUT.read_text())
actual = [(row["hex"][2:], row["name"], str(row["required_before"]),
           str(row["resulting_window"]), row["activation"]) for row in manifest["rows"]]
expected = [tuple(row[:5]) for row in java_rows]
if actual != expected:
    raise SystemExit("oracle row drift")
if manifest["row_count"] != 88 or len(actual) != 88:
    raise SystemExit("expected 88 C014.03B rows")
for item in manifest["java_sources"]:
    source = SESSION.tree / item["path"].removeprefix("java-tron/")
    if hashlib.sha256(source.read_bytes()).hexdigest() != item["sha256"]:
        raise SystemExit(f"pinned Java source drift: {item['path']}")
vectors = {line.split("\t")[1]: line.split("\t")[2] for line in lines if line.startswith("VECTOR\t")}
expected_vectors = {"mcopy":"18","log4_32":"2134","sstore_set":"20000",
                    "sstore_delete":"5000","push2_truncated":"aa00"}
if vectors != expected_vectors:
    raise SystemExit(f"Java vector drift: {vectors}")
print("C014.03B pinned-Java oracle: 88 rows, 5 boundary vectors")
