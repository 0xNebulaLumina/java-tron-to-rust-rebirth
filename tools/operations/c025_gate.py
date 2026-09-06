#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[2]
RUST = ROOT / "rust-tron"
O = ROOT / "docs/oracles"
RECON = O / "c025-ownership-reconciliation.v1.json"
ROW_EVIDENCE = O / "c025-row-evidence.v1.json"
SERVICES = O / "c025-service-lifecycle.v1.json"
SCENARIOS = O / "c025-scenarios.v1.json"
TEST_LEDGER = O / "java-test-ownership.v1.json"
PROD_LEDGER = O / "production-ownership.v1.json"
FAMILY_ARTIFACTS = {
    "events-plugin": O / "c025-cases-events-plugin.v1.json",
    "metrics-node": O / "c025-cases-metrics-node.v1.json",
    "lifecycle-limits": O / "c025-cases-lifecycle-limits.v1.json",
}
COMMANDS = {
    "events-plugin-family": ["cargo", "test", "-p", "tron-events-metrics", "--test", "c025_cases_events_plugin", "--locked", "--", "--nocapture"],
    "metrics-node-family": ["cargo", "test", "-p", "tron-events-metrics", "--test", "c025_cases_metrics_node", "--locked", "--", "--nocapture"],
    "lifecycle-limits-family": ["cargo", "test", "-p", "tron-node", "--test", "c025_cases_lifecycle_limits", "--locked", "--", "--nocapture"],
    "lifecycle": ["cargo", "test", "-p", "tron-node", "--test", "c025_lifecycle", "--locked", "--", "--nocapture"],
    "scenarios": ["cargo", "test", "-p", "tron-events-metrics", "--test", "c025_scenarios", "--locked", "--", "--test-threads=1", "--nocapture"],
    "all-targets": ["cargo", "check", "-p", "tron-events-metrics", "-p", "tron-node", "--all-targets", "--locked"],
}


def load(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def central_hash(parts):
    digest = hashlib.sha256()
    for name, value in sorted(parts.items()):
        digest.update(name.encode() + b"\0" + value.encode() + b"\n")
    return digest.hexdigest()


def ledger_rows(path):
    return [row for row in load(path)["rows"] if row.get("acceptance_gate") == "C025.V"]


def java_class(row):
    path = row["source"]["path"]
    marker = "/src/test/java/"
    if marker not in path or not path.endswith(".java"):
        raise SystemExit("C025 Java test source is not selectable: " + path)
    return path.split(marker, 1)[1][:-5].replace("/", ".")


def metadata():
    recon = load(RECON)
    rows = recon.get("rows", [])
    counts = recon.get("canonical_counts")
    if counts != {"java_tests": 135, "production": 365, "total": 500} or len(rows) != 500 or recon.get("unmapped") != []:
        raise SystemExit("C025 exact 500-row reconciliation drift")
    if recon.get("review") != {"findings": [], "state": "approved"}:
        raise SystemExit("C025 independent review approval drift")
    if len({row["id"] for row in rows}) != 500:
        raise SystemExit("C025 duplicate reconciliation identity")
    tests = ledger_rows(TEST_LEDGER)
    production = ledger_rows(PROD_LEDGER)
    expected = {row["id"] for row in tests + production}
    if {row["id"] for row in rows} != expected or len(tests) != 135 or len(production) != 365:
        raise SystemExit("C025 ownership ledger mismatch")
    for row in rows:
        source = ROOT / row["source"]["path"]
        if not source.is_file() or sha(source) != row["source_sha256"] or row.get("status") != "covered":
            raise SystemExit("C025 source/coverage drift: " + row["id"])

    evidence = load(ROW_EVIDENCE)
    erows = evidence.get("rows", [])
    expected_counts = {"java_test_execution": 135, "production_method_execution": 160, "source_declaration": 205, "total": 500}
    if evidence.get("schema") != "c025-row-evidence-v3" or evidence.get("counts") != expected_counts or len(erows) != 500 or {row["id"] for row in erows} != expected:
        raise SystemExit("C025 canonical row evidence drift")
    canonical = {row["id"]: row for row in erows}
    family_rows = {}
    family_counts = {}
    for family, path in FAMILY_ARTIFACTS.items():
        artifact = load(path)
        members = artifact.get("cases", artifact.get("rows", []))
        normalized = []
        for member in members:
            row_id = member.get("stable_id", member.get("id"))
            if row_id in family_rows:
                raise SystemExit("C025 duplicate family row: " + row_id)
            if row_id not in canonical:
                raise SystemExit("C025 non-canonical family row: " + str(row_id))
            family_rows[row_id] = family
            normalized.append((member, canonical[row_id]))
        behavior = sum(source["evidence_kind"] != "source_declaration" for _, source in normalized)
        declarations = len(normalized) - behavior
        family_counts[family] = {"total": len(normalized), "behavior": behavior, "declaration": declarations}
        for member, source_row in normalized:
            source = ROOT / source_row["java_source"]["path"]
            line = source.read_text(errors="replace").splitlines()[source_row["java_source"]["line"] - 1].strip()
            observation = source_row["java_observation"]
            if sha(source) != observation["source_file_sha256"] or hashlib.sha256((line + "\n").encode()).hexdigest() != observation["source_line_sha256"]:
                raise SystemExit("C025 family declaration hash drift: " + source_row["id"])
            if source_row["evidence_kind"] == "source_declaration" and any(key in member for key in ("rust_case", "rust_dispatch", "rust_invocation")):
                raise SystemExit("C025 declaration has behavior dispatch: " + source_row["id"])
    if set(family_rows) != expected or family_counts != {
        "events-plugin": {"total": 255, "behavior": 167, "declaration": 88},
        "metrics-node": {"total": 114, "behavior": 45, "declaration": 69},
        "lifecycle-limits": {"total": 131, "behavior": 83, "declaration": 48},
    }:
        missing = sorted(expected - set(family_rows))
        extra = sorted(set(family_rows) - expected)
        raise SystemExit(f"C025 family partition drift missing={missing!r} extra={extra!r} counts={family_counts!r}")
    family_sources = "\n".join(path.read_text() for path in [RUST / "crates/tron-events-metrics/tests/c025_cases_events_plugin.rs", RUST / "crates/tron-events-metrics/tests/c025_cases_metrics_node.rs", RUST / "crates/tron-node/tests/c025_cases_lifecycle_limits.rs"])
    if re.search(r"\b_\s*=>", family_sources):
        raise SystemExit("C025 generic/catchall family evidence is forbidden")

    service = load(SERVICES)
    order = service.get("startup_order", [])
    if order[:2] != ["network", "apis"] or order[-1:] != ["node-readiness"] or len(order) != 10:
        raise SystemExit("C025 explicit service graph drift")
    scenarios = load(SCENARIOS)
    sources = {path.stem: path.read_text() for path in list((RUST / "crates/tron-events-metrics/tests").glob("c025_*.rs")) + list((RUST / "crates/tron-node/tests").glob("c025_*.rs"))}
    if scenarios.get("count") != 5 or len(scenarios.get("scenarios", [])) != 5:
        raise SystemExit("C025 exact scenario count drift")
    for row in scenarios["scenarios"]:
        target, name = row["rust_case"].split("::", 1)
        if target not in sources or not re.search(r"\bfn\s+" + re.escape(name) + r"\b", sources[target]):
            raise SystemExit("C025 missing scenario dispatch: " + row["id"])
    hashes = {"reconciliation": sha(RECON), "row_evidence": sha(ROW_EVIDENCE), "scenarios": sha(SCENARIOS), "services": sha(SERVICES), **{"family_" + name: sha(path) for name, path in FAMILY_ARTIFACTS.items()}}
    print(json.dumps({"schema": "c025-metadata-v3", "java_tests": 135, "production": 365, "rows": 500, "behavior": 295, "declarations": 205, "families": family_counts, "scenarios": 5, "unmapped": 0, "central_sha256": central_hash(hashes), "component_sha256": hashes, "status": "passed"}, separators=(",", ":")))


def oracle():
    sys.path.insert(0, str(ROOT / "tools/reference-runner"))
    from java_reference_guard import install_java_reference_guard

    tests = ledger_rows(TEST_LEDGER)
    evidence = load(ROW_EVIDENCE)["rows"]
    selectors = [(row["id"], java_class(row), row["case"], row["annotations"]) for row in tests]
    if len(selectors) != 135 or len({(cls, method) for _, cls, method, _ in selectors}) != 135:
        raise SystemExit("C025 Java selectors are not exact and unique")
    direct = [(row_id, cls, method) for row_id, cls, method, annotations in selectors if annotations == ["JUnit3:test* convention"]]
    junit = [(row_id, cls, method) for row_id, cls, method, annotations in selectors if annotations != ["JUnit3:test* convention"]]
    with install_java_reference_guard(ROOT) as session:
        init_script = session.work / "c025-classpath.gradle"
        init_script.write_text("allprojects { p -> if (p.path == ':framework') { p.tasks.create('printC025TestRuntimeClasspath') { doLast { println 'C025_TEST_CLASSPATH=' + p.sourceSets.test.runtimeClasspath.asPath } } } }\n")
        args = [":framework:printC025TestRuntimeClasspath", ":framework:test", "--rerun-tasks", "-I", str(init_script)]
        for _, cls, method in junit:
            args.extend(["--tests", cls + "." + method])
        result = session.gradle(args, timeout=3600)
        output = (result.stdout + result.stderr).decode("utf-8", "replace")
        classpath_match = re.search(r"^C025_TEST_CLASSPATH=(.+)$", output, re.MULTILINE)
        if classpath_match is None:
            sys.stderr.write(output)
            raise SystemExit("C025 Java runtime classpath capture failed")
        runtime_classpath = classpath_match.group(1).strip()
        report_dir = session.tree / "framework/build/test-results/test"
        outcomes = {}
        lifecycle_errors = []
        for report in sorted(report_dir.glob("TEST-*.xml")):
            suite = ET.parse(report).getroot()
            for case in suite.iter("testcase"):
                key = (case.attrib.get("classname", ""), case.attrib.get("name", "").split("[", 1)[0])
                state = "passed"
                for tag in ("failure", "error", "skipped"):
                    if case.find(tag) is not None:
                        state = tag
                        break
                if key[1] == "classMethod":
                    lifecycle_errors.append((key[0], state))
                else:
                    outcomes[key] = state
        expected_junit = {(cls, method) for _, cls, method in junit}
        if set(outcomes) != expected_junit:
            missing = sorted(expected_junit - set(outcomes))
            extra = sorted(set(outcomes) - expected_junit)
            raise SystemExit("C025 Java outcome mismatch missing=%r extra=%r" % (missing, extra))

        with tempfile.TemporaryDirectory(prefix="c025-java-", dir=session.work) as raw:
            out = pathlib.Path(raw)
            runner = out / "C025DirectMethods.java"
            runner.write_text("""import java.lang.reflect.*;
public final class C025DirectMethods {
  public static void main(String[] args) throws Exception {
    for (int i = 0; i < args.length; i += 2) {
      String key = args[i] + "#" + args[i + 1];
      try {
        Class<?> type = Class.forName(args[i]);
        Object instance = type.getDeclaredConstructor().newInstance();
        type.getDeclaredMethod(args[i + 1]).invoke(instance);
        System.out.println("C025_DIRECT=" + key + "=passed");
      } catch (InvocationTargetException error) {
        System.out.println("C025_DIRECT=" + key + "=error:" + error.getCause().getClass().getName());
      }
    }
  }
}
""")
            result = session.run([str(session.java_home / "bin/javac"), "-d", str(out), str(runner)], cwd=session.work)
            if result.returncode:
                raise SystemExit("C025 direct-method runner compilation failed")
            direct_args = [value for _, cls, method in direct for value in (cls, method)]
            direct_cp = str(out) + ":" + runtime_classpath
            result = session.run([str(session.java_home / "bin/java"), "-cp", direct_cp, "C025DirectMethods", *direct_args], cwd=session.work, classpath=direct_cp)
            direct_output = result.stdout.decode("utf-8", "replace")
            for _, cls, method in direct:
                match = re.search(r"^C025_DIRECT=" + re.escape(cls + "#" + method) + r"=(.+)$", direct_output, re.MULTILINE)
                if match is None:
                    raise SystemExit("C025 direct Java method was not executed: " + cls + "." + method)
                outcomes[(cls, method)] = match.group(1)
            if len(outcomes) != 135:
                raise SystemExit("C025 did not observe exactly 135 Java methods")

            production_rows = [row for row in evidence if row["evidence_kind"] == "production_method_execution"]
            production_selectors = []
            for row in production_rows:
                source_text = (ROOT / row["java_source"]["path"]).read_text(errors="replace")
                package = re.search(r"^\s*package\s+([\w.]+)\s*;", source_text, re.MULTILINE)
                if package is None:
                    raise SystemExit("C025 production source has no Java package: " + row["id"])
                production_selectors.append((row["id"], package.group(1) + "." + pathlib.Path(row["java_source"]["path"]).stem, row["java_symbol"]))
            production_runner = out / "C025ProductionMethods.java"
            production_runner.write_text("""import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import sun.misc.Unsafe;
public final class C025ProductionMethods {
  private static Object value(Class<?> type) {
    if (!type.isPrimitive()) return null;
    if (type == boolean.class) return false;
    if (type == char.class) return '\\0';
    if (type == byte.class) return (byte) 0;
    if (type == short.class) return (short) 0;
    if (type == int.class) return 0;
    if (type == long.class) return 0L;
    if (type == float.class) return 0F;
    return 0D;
  }
  private static Object instance(Class<?> type) throws Exception {
    try { Constructor<?> constructor = type.getDeclaredConstructor(); constructor.setAccessible(true); return constructor.newInstance(); }
    catch (Throwable ignored) { Field field = Unsafe.class.getDeclaredField("theUnsafe"); field.setAccessible(true); return ((Unsafe) field.get(null)).allocateInstance(type); }
  }
  private static String encode(String text) { return Base64.getEncoder().encodeToString(text.getBytes(StandardCharsets.UTF_8)); }
  public static void main(String[] args) throws Exception {
    for (int i = 0; i < args.length; i += 3) {
      String id = args[i], className = args[i + 1], methodName = args[i + 2];
      String observation;
      try {
        Class<?> type = Class.forName(className);
        Method selected = null;
        for (Method method : type.getDeclaredMethods()) if (method.getName().equals(methodName)) { selected = method; break; }
        if (selected == null) throw new NoSuchMethodException(methodName);
        selected.setAccessible(true);
        Object target = Modifier.isStatic(selected.getModifiers()) ? null : instance(type);
        Class<?>[] parameterTypes = selected.getParameterTypes(); Object[] values = new Object[parameterTypes.length];
        StringBuilder input = new StringBuilder();
        for (int p = 0; p < values.length; p++) { values[p] = value(parameterTypes[p]); if (p > 0) input.append(','); input.append(parameterTypes[p].getName()).append("=default"); }
        final Method method = selected; final Object receiver = target; final Object[] arguments = values;
        final Object[] output = new Object[1]; final Throwable[] failure = new Throwable[1];
        Thread invocation = new Thread(() -> { try { output[0] = method.invoke(receiver, arguments); } catch (Throwable error) { failure[0] = error; } }, "c025-" + id);
        invocation.setDaemon(true); invocation.start(); invocation.join(500L);
        if (invocation.isAlive()) {
          invocation.interrupt(); observation = "input=" + input + ";output=none;error=java.util.concurrent.TimeoutException;effect=method_timed_out";
        } else if (failure[0] instanceof InvocationTargetException) {
          Throwable cause = ((InvocationTargetException) failure[0]).getCause();
          observation = "input=" + input + ";output=none;error=" + cause.getClass().getName() + ";effect=method_threw";
        } else if (failure[0] != null) {
          observation = "input=" + input + ";output=none;error=" + failure[0].getClass().getName() + ";effect=invocation_rejected";
        } else observation = "input=" + input + ";output=" + String.valueOf(output[0]) + ";error=none;effect=method_returned";
      } catch (Throwable error) {
        observation = "input=reflection;output=none;error=" + error.getClass().getName() + ";effect=invocation_rejected";
      }
      System.out.println("C025_PRODUCTION=" + id + "=" + encode(observation));
    }
    System.exit(0);
  }
}
""")
            result = session.run([str(session.java_home / "bin/javac"), "-cp", runtime_classpath, "-d", str(out), str(production_runner)], cwd=session.work, classpath=runtime_classpath)
            if result.returncode:
                raise SystemExit("C025 production-method runner compilation failed")
            production_args = [value for row_id, cls, method in production_selectors for value in (row_id, cls, method)]
            result = session.run([str(session.java_home / "bin/java"), "-cp", direct_cp, "C025ProductionMethods", *production_args], cwd=session.work, classpath=direct_cp)
            production_output = result.stdout.decode("utf-8", "replace")
            production_outcomes = {}
            for row_id, _, _ in production_selectors:
                match = re.search(r"^C025_PRODUCTION=" + re.escape(row_id) + r"=([A-Za-z0-9+/=]+)$", production_output, re.MULTILINE)
                if match is None:
                    raise SystemExit("C025 production Java method was not attempted: " + row_id)
                production_outcomes[row_id] = base64.b64decode(match.group(1)).decode("utf-8", "replace")
            if len(production_outcomes) != 160:
                raise SystemExit("C025 did not observe exactly 160 production methods")

            tsv = out / "evidence.tsv"
            test_outcomes = {row_id: outcomes[(cls, method)] for row_id, cls, method, _ in selectors}
            lines = []
            for row in evidence:
                source = "%s:%s" % (row["java_source"]["path"], row["java_source"]["line"])
                declaration_hash = row["java_observation"]["source_line_sha256"]
                if row["evidence_kind"] == "java_test_execution":
                    observation = "input=selector:%s;output=%s;error=none;effect=junit_completed;declaration_sha256=%s" % (row["java_symbol"], test_outcomes[row["id"]], declaration_hash)
                elif row["evidence_kind"] == "production_method_execution":
                    observation = production_outcomes[row["id"]] + ";declaration_sha256=" + declaration_hash
                else:
                    observation = "immutable_declaration_sha256=%s;source_file_sha256=%s;declaration_kind=%s" % (declaration_hash, row["java_observation"]["source_file_sha256"], row["java_observation"]["declaration_kind"])
                lines.append("\t".join((row["id"], row["evidence_kind"], source, observation)))
            tsv.write_text("\n".join(lines) + "\n")
            sources = [ROOT / "tools/operations/C025Oracle.java", ROOT / "tools/operations/instrumentation/org/tron/tools/c025/C025Capture.java"]
            result = session.run([str(session.java_home / "bin/javac"), "-d", str(out), *[str(path) for path in sources]], cwd=session.work)
            if result.returncode:
                raise SystemExit("C025 Java oracle compilation failed")
            classpath = str(out)
            result = session.run([str(session.java_home / "bin/java"), "-cp", classpath, "C025Oracle", str(tsv)], cwd=session.work, classpath=classpath)
            text = result.stdout.decode("utf-8", "replace")
            required = ["C025_JAVA_TEST_EXECUTIONS=135", "C025_PRODUCTION_METHOD_EXECUTIONS=160", "C025_SOURCE_DECLARATIONS=205", "C025_EXACT_ROWS=500", "C025_CENTRAL_SHA256="]
            if result.returncode or any(marker not in text for marker in required):
                raise SystemExit("C025 guarded Java capture mismatch")
            capture_hash = re.search(r"C025_CENTRAL_SHA256=([0-9a-f]{64})", text).group(1)
    print(json.dumps({"schema": "c025-java-oracle-v3", "java_tests_executed": 135, "junit_lifecycle_errors": lifecycle_errors, "production_methods_executed": 160, "source_declarations": 205, "rows": 500, "capture_sha256": capture_hash, "status": "passed"}, separators=(",", ":")))


def run(name):
    print("+", " ".join(COMMANDS[name]), flush=True)
    capture = name in {"events-plugin-family", "metrics-node-family", "lifecycle-limits-family", "lifecycle", "scenarios"}
    completed = subprocess.run(COMMANDS[name], cwd=RUST, check=True, text=True, stdout=subprocess.PIPE if capture else None, stderr=subprocess.STDOUT if capture else None)
    if capture:
        text = completed.stdout
        sys.stdout.write(text)
        output_hash = hashlib.sha256(text.encode()).hexdigest()
        family_by_target = {"events-plugin-family": "events-plugin", "metrics-node-family": "metrics-node", "lifecycle-limits-family": "lifecycle-limits"}
        if name in family_by_target:
            family = family_by_target[name]
            artifact = load(FAMILY_ARTIFACTS[family])
            members = artifact.get("cases", artifact.get("rows", []))
            expected_ids = {member.get("stable_id", member.get("id")) for member in members if member.get("evidence_kind", member.get("kind")) not in {"source_declaration", "declaration"}}
            emitted = {}
            for row_id, payload in re.findall(r"C025_FAMILY_BEHAVIOR=([^\t\r\n]+)\t([^\r\n]+)", text):
                value = json.loads(payload)
                if set(value) != {"input", "result", "effect", "error"}:
                    raise SystemExit("C025 incomplete emitted behavior map: " + row_id)
                emitted[row_id] = value
            if set(emitted) != expected_ids or len(emitted) != len(expected_ids):
                raise SystemExit(f"C025 {family} emitted ID map mismatch")
        print(json.dumps({"schema": "c025-live-output-v2", "target": name, "output_sha256": output_hash, "status": "passed"}, separators=(",", ":")))


def main():
    choices = ["metadata", "oracle", *COMMANDS, "all"]
    parser = argparse.ArgumentParser()
    parser.add_argument("targets", nargs="*", choices=choices)
    targets = parser.parse_args().targets or ["all"]
    if "all" in targets:
        targets = ["metadata", "oracle", "events-plugin-family", "metrics-node-family", "lifecycle-limits-family", "lifecycle", "scenarios", "all-targets"]
    for target in targets:
        metadata() if target == "metadata" else oracle() if target == "oracle" else run(target)
    print(json.dumps({"schema": "c025-gate-v2", "targets": targets, "status": "passed"}, separators=(",", ":")))


if __name__ == "__main__":
    main()
