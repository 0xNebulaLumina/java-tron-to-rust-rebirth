#!/usr/bin/env python3
import argparse, hashlib, importlib.util, json, os, pathlib, re, subprocess, sys, tempfile, xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[2]
RUST = ROOT / "rust-tron"
ORACLES = ROOT / "docs/oracles"
INVENTORY = ORACLES / "c022-rpc-inventory.v1.json"
OWNERSHIP = ORACLES / "c022-ownership-reconciliation.v1.json"
TRACKER = ROOT / "docs/PORTING_TRACKER.json"
MANIFEST = ORACLES / "manifest.v1.json"
DESCRIPTOR = RUST / "crates/tron-protocol/descriptors/protocol.v1.pb"
COMMANDS = {
    "wallet-mutation": ["cargo", "test", "-p", "tron-apis", "--test", "c022_wallet_mutation", "--locked"],
    "wallet-query": ["cargo", "test", "-p", "tron-apis", "--test", "c022_wallet_query", "--locked"],
    "cursors": ["cargo", "test", "-p", "tron-apis", "--test", "c022_cursors", "--locked"],
    "server": ["cargo", "test", "-p", "tron-apis", "--test", "c022_server", "--locked"],
    "limits": ["cargo", "test", "-p", "tron-apis", "--test", "c022_limits", "--locked"],
    "extension": ["cargo", "test", "-p", "tron-apis", "--test", "c022_extension_e2e", "--locked"],
    "scenarios": ["cargo", "test", "-p", "tron-apis", "--test", "c022_scenarios", "--locked", "--", "--test-threads=1"],
    "all-targets": ["cargo", "check", "-p", "tron-apis", "--all-targets", "--locked"],
}

def load(path): return json.loads(path.read_text())
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def varint(data, offset):
    value = shift = 0
    while True:
        byte = data[offset]; offset += 1; value |= (byte & 127) << shift
        if byte < 128: return value, offset
        shift += 7

def fields(data):
    offset = 0
    while offset < len(data):
        key, offset = varint(data, offset); number, wire = key >> 3, key & 7
        if wire == 0: value, offset = varint(data, offset)
        elif wire == 1: value, offset = data[offset:offset+8], offset + 8
        elif wire == 2:
            size, offset = varint(data, offset); value, offset = data[offset:offset+size], offset + size
        elif wire == 5: value, offset = data[offset:offset+4], offset + 4
        else: raise SystemExit("unsupported descriptor wire type")
        yield number, wire, value

def descriptor_inventory():
    services = []
    for number, _, file_bytes in fields(DESCRIPTOR.read_bytes()):
        if number != 1: continue
        file_fields = list(fields(file_bytes))
        package = next((v.decode() for n, _, v in file_fields if n == 2), "")
        for n, _, service_bytes in file_fields:
            if n != 6: continue
            service_fields = list(fields(service_bytes)); name = next(v.decode() for n, _, v in service_fields if n == 1)
            methods = []
            for mn, _, method_bytes in service_fields:
                if mn == 2:
                    method_fields = list(fields(method_bytes)); methods.append(next(v.decode() for n, _, v in method_fields if n == 1))
            services.append((package, name, methods))
    return services
def descriptor_method_types():
    methods = {}
    for number, _, file_bytes in fields(DESCRIPTOR.read_bytes()):
        if number != 1: continue
        file_fields = list(fields(file_bytes))
        package = next((v.decode() for n, _, v in file_fields if n == 2), "")
        for n, _, service_bytes in file_fields:
            if n != 6: continue
            service_fields = list(fields(service_bytes))
            service = next(v.decode() for n, _, v in service_fields if n == 1)
            for mn, _, method_bytes in service_fields:
                if mn != 2: continue
                method_fields = list(fields(method_bytes))
                values = {n: v.decode() for n, _, v in method_fields if n in (1, 2, 3)}
                methods[f"/{package}.{service}/{values[1]}"] = (values[2], values[3])
    return methods

def annotated_java_tests(ownership, disposition="executed"):
    rows = [row for row in ownership.get("rows", [])
            if row.get("kind") == "java_test" and row.get("disposition") == disposition]
    paths = sorted({row["source"]["path"] for row in rows})
    discovered = []
    for relative in paths:
        lines = (ROOT / relative).read_text().splitlines()
        for index, line in enumerate(lines):
            if "@Test" not in line:
                continue
            for declaration in range(index + 1, min(index + 12, len(lines))):
                match = re.search(r"\bpublic\s+(?:void|[\w<>, ?]+)\s+(\w+)\s*\(", lines[declaration])
                if match:
                    discovered.append({"path": relative, "line": declaration + 1, "symbol": match.group(1)})
                    break
    expected = [{"path": row["source"]["path"], "line": row["source"]["line"], "symbol": row["symbol"]}
                for row in rows]
    discovered_keys = {(row["path"], row["line"], row["symbol"]) for row in discovered}
    expected_keys = {(row["path"], row["line"], row["symbol"]) for row in expected}
    if not expected_keys.issubset(discovered_keys):
        raise SystemExit("C022 Java annotation/source path/line/symbol reconciliation drift")
    return rows

def validate_seams(ownership):
    c022_rows = ownership.get("rows", [])
    c021_ids = {row["id"] for row in load(ORACLES / "c021-ownership-reconciliation.v1.json").get("rows", [])
                if row.get("disposition") == "seam_exclusion"}
    claimed_c021 = {row["id"] for row in c022_rows if row.get("kind") == "c021_grpc_client_seam"}
    if claimed_c021 != c021_ids:
        raise SystemExit("C022/C021 exact gRPC seam identity drift")
    c006_ids = {row["id"] for row in load(ORACLES / "c006-shielded-replacement-ledger.v1.json").get("rows", [])
                if isinstance(row.get("replacement"), dict) and row["replacement"].get("owner_chunk", "").startswith("C022.")}
    claimed_c006 = {row["id"] for row in c022_rows if row.get("kind") == "c006_shielded_seam"}
    if claimed_c006 != c006_ids:
        raise SystemExit("C022/C006 exact shielded identity drift")

def gradle_test_results(tree, expected_rows):
    expected = {(pathlib.Path(row["source"]["path"]).stem, row["symbol"]) for row in expected_rows}
    actual = []
    for report in tree.glob("framework/build/test-results/test/TEST-*.xml"):
        suite = ET.parse(report).getroot()
        for case in suite.findall("testcase"):
            failure = case.find("failure")
            error = case.find("error")
            actual.append({
                "class": case.get("classname", "").rsplit(".", 1)[-1],
                "request": case.get("name", ""),
                "status": "failed" if failure is not None or error is not None else ("skipped" if case.find("skipped") is not None else "passed"),
                "result": ((failure.text if failure is not None else None) or (error.text if error is not None else None) or ""),
            })
    observed = {(row["class"], row["request"].split("[")[0]) for row in actual}
    unexpected = observed - expected
    if unexpected:
        raise SystemExit("C022 guarded Java emitted unowned test IDs: " + repr(sorted(unexpected)))
    if any(row["status"] == "failed" for row in actual):
        raise SystemExit("C022 guarded Java result capture contains failures")
    for class_name, request in sorted(expected - observed):
        actual.append({"class": class_name, "request": request, "status": "source_only", "result": "not emitted by JUnit"})
    return actual

def metadata():
    inventory = load(INVENTORY); services = descriptor_inventory()
    service_counts = {name: len(methods) for _, name, methods in services}
    descriptor_method_count = sum(service_counts.values())
    if inventory.get("descriptor_sha256") != sha(DESCRIPTOR): raise SystemExit("C022 inventory descriptor drift")
    if inventory.get("service_count") != len(services) or inventory.get("method_count") != descriptor_method_count: raise SystemExit("C022 inventory count drift")
    paths = [f"/{package}.{service}/{method}" for package, service, methods in services for method in methods]
    rows = inventory.get("methods", [])
    if [row.get("path") for row in rows] != paths or inventory.get("unmapped") != []:
        raise SystemExit("C022 inventory mapping drift")
    descriptor_types = descriptor_method_types()
    if any((row.get("input_type"), row.get("output_type")) != descriptor_types[row["path"]] for row in rows):
        raise SystemExit("C022 RPC input/output descriptor type drift")
    forbidden = re.compile(r"(?:generic|fallback|default|todo|stub)", re.I)
    handlers = [row.get("rust_handler", "") for row in rows]
    if any(not handler or forbidden.search(handler) for handler in handlers):
        raise SystemExit("C022 generic RPC handler/fallback rejected")
    rust_rpc = (RUST / "crates/tron-apis/src/rpc_services.rs").read_text()
    missing_handlers = [handler for handler in handlers if not re.search(r"\basync\s+fn\s+" + re.escape(handler.rsplit("::", 1)[-1]) + r"\b", rust_rpc)]
    if missing_handlers:
        raise SystemExit("C022 RPC mapping lacks executable Rust cases: " + repr(missing_handlers[:8]))
    unimplemented = [row["path"] for row in rows if row.get("java_disposition") == "unimplemented"]
    expected_unimplemented = ["/protocol.Wallet/BuyStorage","/protocol.Wallet/BuyStorageBytes","/protocol.Wallet/SellStorage","/protocol.WalletExtension/GetTransactionsFromThis","/protocol.WalletExtension/GetTransactionsFromThis2","/protocol.WalletExtension/GetTransactionsToThis","/protocol.WalletExtension/GetTransactionsToThis2","/protocol.TronZksnark/CheckZksnarkProof"]
    if unimplemented != expected_unimplemented: raise SystemExit("C022 exact Java UNIMPLEMENTED set drift")
    ownership = load(OWNERSHIP)
    java_rows = annotated_java_tests(ownership)
    validate_seams(ownership)
    rows_by_kind = {}
    for row in ownership.get("rows", []):
        key = "future_http_seams" if row.get("disposition") == "future_http_seam" else ({"java_test":"java_tests","c021_grpc_client_seam":"c021_grpc_client_seams","c006_shielded_seam":"c006_shielded_cases"}.get(row.get("kind")))
        if key: rows_by_kind[key] = rows_by_kind.get(key, 0) + 1
    rows_by_kind["total"] = len(ownership.get("rows", []))
    if ownership.get("canonical_counts") != rows_by_kind or ownership.get("unmapped") != []: raise SystemExit("C022 ownership reconciliation drift")
    if len({row["id"] for row in ownership["rows"]}) != len(ownership["rows"]): raise SystemExit("C022 ownership identity collision")
    manifest = load(MANIFEST)
    for key, path in (("c022_rpc_inventory", INVENTORY),("c022_ownership_reconciliation",OWNERSHIP),("c022_server_limits",ORACLES/"c022-server-limits.v1.json"),("c022_wallet_query",ORACLES/"c022-wallet-query.v1.json")):
        if manifest.get(key) != {"path":path.name,"sha256":sha(path)}: raise SystemExit("central manifest drift: " + key)
    chunk = next(row for row in load(TRACKER)["chunks"] if row["id"] == "C022")
    if chunk.get("status") != "done" or chunk.get("owner") is not None or chunk.get("resume") is not None or chunk["gate"].get("status") != "passed" or chunk["gate"].get("last_failure") is not None or any(item.get("status") != "done" for item in chunk["items"]): raise SystemExit("C022 tracker closure drift")
    if chunk.get("review") != {"state":"approved","round":1,"findings":[]}: raise SystemExit("C022 review approval drift")
    if inventory.get("service_count") != 7 or descriptor_method_count != 204 or len(rows) - len(unimplemented) != 196 or len(unimplemented) != 8 or len(java_rows) != 260 or rows_by_kind != {"java_tests":260,"future_http_seams":2,"c021_grpc_client_seams":22,"c006_shielded_cases":22,"total":306}: raise SystemExit("C022 closure count drift")
    if ownership.get("review") != {"state":"approved","findings":[]}: raise SystemExit("C022 ownership review approval drift")
    print(json.dumps({"schema":"c022-metadata-v1","services":len(services),"methods":descriptor_method_count,"implemented":descriptor_method_count-len(unimplemented),"java_unimplemented":len(unimplemented),"java_tests":len(java_rows),"ownership":rows_by_kind,"status":"passed"},separators=(",",":")))
def java_oracle(run_tests):
    ownership = load(OWNERSHIP)
    java_rows = annotated_java_tests(ownership)
    sys.path.insert(0, str(ROOT / "tools/reference-runner"))
    from java_reference_guard import install_java_reference_guard
    with install_java_reference_guard(ROOT) as session:
        with tempfile.TemporaryDirectory(prefix="c022-java-", dir=session.work) as raw:
            out = pathlib.Path(raw); init = out / "classpath.gradle"
            init.write_text("allprojects { p -> if (p.path == ':framework') { p.afterEvaluate { p.tasks.register('c022RuntimeClasspath') { doLast { println 'C022_CLASSPATH=' + p.sourceSets.test.runtimeClasspath.asPath } } } } }\n")
            built = session.gradle(["-I",str(init),":framework:testClasses",":actuator:jar",":consensus:jar",":chainbase:jar",":crypto:jar",":common:jar",":protocol:jar",":platform:jar"])
            if built.returncode: raise SystemExit("C022 Java classpath build failed:\n" + built.stderr.decode("utf-8","replace"))
            queried = session.gradle(["-I",str(init),":framework:c022RuntimeClasspath"])
            matches = [line.split("=",1)[1] for line in queried.stdout.decode().splitlines() if line.startswith("C022_CLASSPATH=")]
            if queried.returncode or len(matches) != 1: raise SystemExit("C022 Java classpath query failed")
            cp = matches[0]; source = ROOT / "tools/api/C022Oracle.java"
            result = session.run([str(session.java_home/"bin/javac"),"-cp",cp,"-d",str(out),str(source)],cwd=session.work,classpath=cp)
            if result.returncode: raise SystemExit("C022 Java oracle compilation failed")
            oracle_cp = str(out) + os.pathsep + cp
            before = session.guard(phase="immediately before C022 descriptor capture",classpath=oracle_cp)
            result = session.run([str(session.java_home/"bin/java"),"-cp",oracle_cp,"C022Oracle"],cwd=session.work,classpath=oracle_cp)
            spec = importlib.util.spec_from_file_location("c022_capture",ROOT/"tools/api/instrumentation/c022_capture.py"); module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
            capture = module.parse(result.stdout.decode("utf-8","replace"))
            descriptor_methods = sum(len(methods) for _, _, methods in descriptor_inventory())
            if result.returncode or capture.get("services") != len(descriptor_inventory()) or capture.get("methods") != descriptor_methods: raise SystemExit("C022 authenticated Java descriptor capture mismatch")
            if len(capture.get("inventory","").split(",")) != descriptor_methods: raise SystemExit("C022 Java method inventory drift")
            test_results = []
            if run_tests:
                classes = sorted({row["source"]["path"].split("/java/",1)[1][:-5].replace("/", ".") for row in java_rows})
                args = [":framework:test"] + sum((["--tests", name] for name in classes), [])
                tests = session.gradle(args)
                if tests.returncode: raise SystemExit("C022 exact guarded pinned Java test suite failed:\n" + tests.stderr.decode("utf-8","replace"))
                test_results = gradle_test_results(session.tree, java_rows)
            after = session.guard(phase="immediately after C022 Java captures",classpath=oracle_cp)
            if before != after: raise SystemExit("Java reference identity changed across C022 capture")
            print(json.dumps({"schema":"c022-java-oracle-v1","services":capture["services"],"methods":descriptor_methods,"java_tests":len(java_rows) if run_tests else 0,"results":test_results,"status":"passed"},separators=(",",":")))

def run(target):
    print("+", " ".join(COMMANDS[target]), flush=True); subprocess.run(COMMANDS[target], cwd=RUST, check=True)

def main():
    choices = ["metadata","oracle","java-tests",*COMMANDS,"all"]
    parser = argparse.ArgumentParser(); parser.add_argument("targets",nargs="*",choices=choices); targets = parser.parse_args().targets or ["all"]
    if "all" in targets: targets = ["metadata","oracle","java-tests","wallet-mutation","wallet-query","cursors","server","limits","extension","scenarios","all-targets"]
    for target in targets:
        if target == "metadata": metadata()
        elif target == "oracle": java_oracle(False)
        elif target == "java-tests": java_oracle(True)
        else: run(target)
    print(json.dumps({"schema":"c022-gate-v1","targets":targets,"status":"passed"},separators=(",",":")))
if __name__ == "__main__": main()
