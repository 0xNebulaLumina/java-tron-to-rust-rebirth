#!/usr/bin/env python3
"""Run the pinned Java C012 test oracle and persist its raw observations.

The launcher deliberately accepts only a closed request manifest. Expected result, error, fee,
asset-id, and store bytes are never command-line inputs to Java.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
JAVA_TRON = ROOT / "java-tron"
SOURCE = Path(__file__).with_name("C012Oracle.java")
OVERLAY = Path(__file__).with_name("overlay") / "org/tron/core/actuator/AbstractActuator.java"
JAVA_HOME = Path("/usr/lib/jvm/java-8-openjdk-amd64")
REVISION = "4a21592f95e37908b21bc3f611c6e7a1a67f09f3"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(argv: list[str], *, cwd: Path, env: dict[str, str], timeout: int = 1800) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, check=False)


def runtime_classpath(work: Path, env: dict[str, str]) -> str:
    init = work / "classpath.gradle"
    init.write_text("""allprojects { p ->
  if (p.path == ':framework') { p.afterEvaluate {
    p.tasks.register('c012RuntimeClasspath') { doLast { println p.sourceSets.test.runtimeClasspath.asPath } }
  } }
}
""")
    common = [str(JAVA_TRON / "gradlew"), "--no-daemon", "--no-build-cache", "--console=plain",
              "--dependency-verification=strict", "-I", str(init)]
    built = run(common + [":framework:testClasses"], cwd=JAVA_TRON, env=env)
    if built.returncode:
        raise SystemExit("C012 Gradle testClasses failed:\n" + built.stderr.decode("utf-8", "replace"))
    queried = run(common + ["-q", ":framework:c012RuntimeClasspath"], cwd=JAVA_TRON, env=env)
    if queried.returncode:
        raise SystemExit("C012 Gradle classpath query failed:\n" + queried.stderr.decode("utf-8", "replace"))
    lines = [line.strip() for line in queried.stdout.decode().splitlines() if os.pathsep in line]
    if not lines:
        raise SystemExit("Gradle omitted the C012 test runtime classpath")
    return lines[-1]


def main() -> int:
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--requests", type=Path)
    source.add_argument("--fixtures", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--update-fixtures", action="store_true")
    args = parser.parse_args()
    generated_requests = None
    if args.fixtures:
        fixture_document = json.loads(args.fixtures.read_text())
        rows = fixture_document.get("rows")
        if rows is None:
            rows = fixture_document["fixture_namespaces"]["built_in_java_differential"]["rows"]
        generated_requests = tempfile.TemporaryDirectory(prefix="c012-java-requests-")
        request_root = Path(generated_requests.name)
        for index, row in enumerate(rows):
            execution = row["java_execution"]["selected_test_run"]
            request = {
                "schema": "c012-java-oracle-request-v2",
                "variant_id": row["variant_id"],
                "java_test_class": execution["java_test_class"],
                "java_test_method": execution["java_test_method"],
                "non_actuator": bool(not execution["java_test_class"].endswith("ActuatorTest")
                                     or execution["java_test_method"] in {
                                         "nullDbManager", "noContract", "checkAvailableContractType"
                                     }),
            }
            (request_root / f"{index:03d}.json").write_text(json.dumps(request, sort_keys=True) + "\n")
        args.requests = request_root
    requests = sorted(args.requests.glob("*.json"))
    if not requests:
        raise SystemExit("closed C012 built-in manifest contains no requests")
    ids = []
    for path in requests:
        value = json.loads(path.read_text())
        if value.get("schema") not in {"c012-java-oracle-request-v1", "c012-java-oracle-request-v2"}:
            raise SystemExit(f"invalid request schema: {path}")
        ids.append(value["variant_id"])
    if ids != sorted(set(ids)):
        raise SystemExit("variant IDs must be sorted and unique")
    if any("extension" in value.lower() or "dr004" in value.lower() for value in ids):
        raise SystemExit("DR-004 extension request present in built-in oracle")

    with tempfile.TemporaryDirectory(prefix="c012-java-oracle-") as temporary:
        work = Path(temporary)
        classes = work / "classes"
        classes.mkdir()
        env = {"PATH": f"{JAVA_HOME / 'bin'}:/usr/bin:/bin", "JAVA_HOME": str(JAVA_HOME),
               "HOME": str(work / "home"), "GRADLE_USER_HOME": str(work / "gradle-home"),
               "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
        classpath = runtime_classpath(work, env)
        compiled = run([str(JAVA_HOME / "bin/javac"), "-encoding", "UTF-8", "-source", "8", "-target", "8",
                        "-cp", classpath, "-d", str(classes), str(OVERLAY), str(SOURCE)], cwd=ROOT, env=env)
        if compiled.returncode:
            raise SystemExit(compiled.stderr.decode("utf-8", "replace"))
        members = []
        java_command = [str(JAVA_HOME / "bin/java"), "-Duser.timezone=UTC", "-Dfile.encoding=UTF-8",
                        "-cp", str(classes) + os.pathsep + classpath,
                        "org.tron.core.actuator.C012Oracle", "--requests"]
        isolated_request = work / "request"
        isolated_request.mkdir()
        for request in requests:
            target = isolated_request / request.name
            target.write_bytes(request.read_bytes())
            executed = run(java_command + [str(isolated_request)], cwd=ROOT, env=env)
            target.unlink()
            if executed.returncode:
                raise SystemExit(f"C012 request {json.loads(request.read_text())['variant_id']} failed:\n"
                                 + executed.stderr.decode("utf-8", "replace"))
            stdout = executed.stdout.decode("utf-8", "replace")
            marker = stdout.rfind('{"schema":"c012-java-test-batch-v2"')
            if marker < 0:
                raise SystemExit("C012 Java oracle emitted no batch JSON:\n" + stdout[-4000:])
            one = json.loads(stdout[marker:])
            if len(one.get("members", [])) != 1:
                raise SystemExit(f"isolated Java request produced {len(one.get('members', []))} members")
            members.append(one["members"][0])
        batch = {"schema": "c012-java-test-batch-v2", "members": members}
        batch["provenance"] = {"java_revision": REVISION, "oracle_sha256": digest(SOURCE),
                               "overlay_sha256": digest(OVERLAY), "request_count": len(requests),
                               "process_isolation": "one fresh JVM per selected case",
                               "jdk_home": str(JAVA_HOME)}
        rendered = json.dumps(batch, indent=2, sort_keys=True) + "\n"
        args.output.write_text(rendered)
        if args.update_fixtures:
            if not args.fixtures:
                raise SystemExit("--update-fixtures requires --fixtures")
            by_variant = {member["variant_id"]: member for member in members}
            for row in rows:
                observation = by_variant[row["variant_id"]]
                row["request"] = observation["request_capture"]
                row["java_execution"]["selected_test_run"] = {
                    key: value for key, value in observation.items() if key != "request_capture"
                }
            args.fixtures.write_text(json.dumps(fixture_document, indent=2, sort_keys=True) + "\n")
    if generated_requests is not None:
        generated_requests.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
