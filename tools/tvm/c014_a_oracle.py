#!/usr/bin/env python3
"""Compile/run the dependency-free pinned-Java C014.03A oracle."""
from pathlib import Path
import sys, tempfile
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"tools/reference-runner"))
from java_reference_guard import install_java_reference_guard
SESSION=install_java_reference_guard(ROOT)
src=Path(__file__).with_name("C014AOracle.java")
out=ROOT/"docs/oracles/c014-opcodes-a.v1.json"
with tempfile.TemporaryDirectory() as d:
    SESSION.run([str(SESSION.java_home/"bin/javac"),"-d",d,str(src)],check=True)
    data=SESSION.run([str(SESSION.java_home/"bin/java"),"-cp",d,"C014AOracle"],classpath=d,check=True).stdout.decode()
if data != out.read_text(encoding="utf-8"):
    raise SystemExit("C014A pinned-Java oracle mismatch")
print("C014A oracle replayed 54 rows")
