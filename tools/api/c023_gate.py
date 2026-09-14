#!/usr/bin/env python3
import argparse, hashlib, json, os, pathlib, re, subprocess, sys, tempfile, xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[2]
RUST = ROOT / "rust-tron"
ORACLES = ROOT / "docs/oracles"
ROUTES = ORACLES / "c023-routes.v1.json"
RECON = ORACLES / "c023-ownership-reconciliation.v1.json"
SCENARIOS = ORACLES / "c023-scenarios.v1.json"
TRACKER = ROOT / "docs/PORTING_TRACKER.json"
MANIFEST = ORACLES / "manifest.v1.json"
JAVA_TEST_OWNERSHIP = ORACLES / "java-test-ownership.v1.json"
COMMANDS = {
    "routes": ["cargo","test","-p","tron-apis","--test","c023_routes","--locked"],
    "json": ["cargo","test","-p","tron-apis","--test","c023_json","--locked"],
    "controls": ["cargo","test","-p","tron-apis","--test","c023_http_controls","--locked"],
    "custom": ["cargo","test","-p","tron-apis","--test","c023_custom","--locked"],
    "scenarios": ["cargo","test","-p","tron-apis","--test","c023_scenarios","--locked","--","--test-threads=1"],
    "all-targets": ["cargo","check","-p","tron-apis","--all-targets","--locked"],
}

def load(path): return json.loads(path.read_text())
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def java_method_body(path, line):
    lines = path.read_text().splitlines()
    depth = 0; begun = False; body = []
    for text in lines[line - 1:]:
        body.append(text.rstrip())
        depth += text.count("{") - text.count("}")
        begun = begun or "{" in text
        if begun and depth <= 0: break
    return "\n".join(body)


def java_rows(reconciliation):
    rows = [row for row in reconciliation.get("rows", []) if row.get("kind") == "java_test"]
    if len(rows) != 333: raise SystemExit("C023 exact 333 Java test rows drift")
    ledger_rows = load(JAVA_TEST_OWNERSHIP).get("rows", [])
    stable_ids = {
        (entry.get("source", {}).get("path"), entry.get("source", {}).get("line"), entry.get("case")): entry.get("id")
        for entry in ledger_rows
        if entry.get("kind") == "java_test_case"
    }
    expected = []
    seen_stable_ids = set()
    for row in rows:
        source = ROOT / row["source"]["path"]
        if row.get("source_sha256") != sha(source): raise SystemExit("C023 Java authenticated source hash drift: " + row["id"])
        lines = source.read_text().splitlines()
        line = row["source"]["line"]
        if not (1 <= line <= len(lines)) or not re.search(r"\b" + re.escape(row["symbol"]) + r"\s*\(", lines[line - 1]):
            raise SystemExit("C023 Java source path/line/symbol drift: " + row["id"])
        identity = (row["source"]["path"], line, row["symbol"])
        if stable_ids.get(identity) != row.get("stable_id") or not re.fullmatch(r"TCASE-[0-9A-F]{16}", row.get("stable_id", "")):
            raise SystemExit("C023 exact stable-ID/source identity drift: " + row["id"])
        seen_stable_ids.add(row["stable_id"])
        expected.append((row["source"]["path"].split("/java/", 1)[1][:-5].replace("/", "."), row["symbol"], row["id"]))
    if len(seen_stable_ids) != 333 or len(set((name, symbol) for name, symbol, _ in expected)) != 333: raise SystemExit("C023 Java test identity collision")
    return rows, expected

def rust_cases_exist(rows):
    files = {path.stem: path.read_text() for path in (RUST / "crates/tron-apis/tests").glob("c023_*.rs")}
    forbidden = re.compile(r"(?:generic|fallback|default|todo|stub)", re.I)
    for row in rows:
        case = row.get("rust_case")
        if case:
            if forbidden.search(case): raise SystemExit("C023 generic Rust evidence rejected: " + row["id"])
            file_name, symbol = case.split("::", 1)
            if file_name not in files or not re.search(r"\b(?:async\s+)?fn\s+" + re.escape(symbol) + r"\b", files[file_name]):
                raise SystemExit("C023 nonexistent concrete Rust case: " + row["id"])
        elif not (row.get("terminal_state") == "deferred" and row.get("deferral", {}).get("reason") and row.get("deferral", {}).get("owner")):
            raise SystemExit("C023 row lacks concrete Rust case or exact deferral: " + row["id"])

def metadata():
    inventory = load(ROUTES); rows = inventory.get("routes", [])
    if inventory.get("counts") != {"FULL":123,"SOLIDITY":45,"PBFT":47,"TOTAL":215} or len(rows) != 215: raise SystemExit("C023 exact 215-route inventory drift")
    identities = [(r["surface"], r["path"]) for r in rows]
    if len(set(identities)) != 215: raise SystemExit("C023 duplicate production identity")
    required = ("methods","rpc_api","rpc_method","request_type","response_type","cursor","success_status","error_status","handler_mode")
    if any(any(k not in r for k in required) or not r["methods"] for r in rows): raise SystemExit("C023 incomplete route contract")
    if any(r["cursor"] not in ("HEAD","SOLIDITY","PBFT") for r in rows): raise SystemExit("C023 cursor mapping drift")
    custom = {r["path"] for r in rows if r["handler_mode"] == "custom"}
    if custom != {"/wallet/validateaddress","/wallet/broadcasthex"}: raise SystemExit("C023 exact custom-route set drift")
    source = (RUST / "crates/tron-apis/src/http_rpc.rs").read_text()
    dispatch = set(re.findall(r'\("([^"]+)",\s*"([^"]+)"\)\s*=>', source))
    missing = sorted({(r["rpc_api"],r["rpc_method"]) for r in rows if r["handler_mode"] == "descriptor"} - dispatch)
    if missing: raise SystemExit("C023 unmapped executable dispatch: " + repr(missing))
    reconciliation = load(RECON); all_rows = reconciliation.get("rows", []); counts = reconciliation.get("canonical_counts", {})
    if reconciliation.get("unmapped") != [] or counts != {"production_routes":215,"java_tests":333,"total":548} or len(all_rows) != 548: raise SystemExit("C023 exact 548-row reconciliation drift")
    if len({r["id"] for r in all_rows}) != 548 or any(not r.get("result_key") for r in all_rows): raise SystemExit("C023 exact row result-map identity drift")
    prod = [r for r in all_rows if r["kind"] == "production_route"]
    if {(r["surface"],r["path"]) for r in prod} != set(identities): raise SystemExit("C023 row-specific production reconciliation drift")
    if any(r.get("source_sha256") != sha(ROUTES) or r.get("terminal_state") != "observed" for r in prod): raise SystemExit("C023 production source hash/terminal evidence drift")
    jrows, _ = java_rows(reconciliation); rust_cases_exist(all_rows)
    scenario = load(SCENARIOS); scenarios = scenario.get("scenarios", []); proofs = scenario.get("row_proofs", [])
    if len(scenarios) != 18 or len({r.get("id") for r in scenarios}) != 18 or any(not r.get("rust_case") or r.get("terminal_state") != "observed" for r in scenarios): raise SystemExit("C023 exact 18-scenario identity/terminal coverage drift")
    rust_cases_exist(scenarios)
    if len(proofs) != 333 or scenario.get("row_proof_count") != 333 or len({p.get("stable_id") for p in proofs}) != 333: raise SystemExit("C023 exact 333 row-proof identity drift")
    proof_by_id = {p["stable_id"]: p for p in proofs}
    rust_source = (RUST / "crates/tron-apis/tests/c023_scenarios.rs").read_text()
    behavior_contracts = {}
    semantic_fingerprints = {}
    forbidden_default_inputs = {"", "{}"}
    for row in jrows:
        stable_id = row["stable_id"]
        behavior = row.get("behavior")
        source = row["source"]
        exact_key = f"{stable_id}|{source['path']}:{source['line']}::{row['symbol']}"
        if not isinstance(behavior, dict) or behavior.get("key") != exact_key:
            raise SystemExit("C023 exact stable-ID/source behavior mapping drift: " + stable_id)
        source_class = pathlib.Path(source["path"]).stem
        expected_assertion_prefix = f"{source_class}#{row['symbol']}:"
        if not isinstance(behavior.get("assertion"), str) or not behavior["assertion"].startswith(expected_assertion_prefix):
            raise SystemExit("C023 behavior assertion is not bound to its source method: " + stable_id)
        observation = row.get("java_observation")
        if not isinstance(observation, dict) or set(observation) != {"slice","source_method_sha256","assertions","assertion_count","digest"}:
            raise SystemExit("C023 exact Java observation missing: " + stable_id)
        if observation["assertion_count"] != len(observation["assertions"]) or not re.fullmatch(r"[0-9a-f]{64}", observation["source_method_sha256"]):
            raise SystemExit("C023 malformed Java source assertion observation: " + stable_id)
        observation_payload = {key:value for key,value in observation.items() if key != "digest"}
        observation_digest = hashlib.sha256(json.dumps(observation_payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if observation["digest"] != observation_digest:
            raise SystemExit("C023 Java observation digest drift: " + stable_id)
        guarded_method = java_method_body(ROOT / source["path"], source["line"])
        guarded_body = re.sub(r"\s+", " ", guarded_method).strip()
        guarded_assertions = [text.strip() for text in guarded_method.splitlines() if re.search(r"\b(assert|verify|expect|fail\s*\()", text, re.I)]
        if observation["source_method_sha256"] != hashlib.sha256(guarded_body.encode()).hexdigest() or observation["assertions"] != guarded_assertions:
            raise SystemExit("C023 guarded Java source assertions drift: " + stable_id)
        observation_fields = {"behavior_slice","observation_digest","expected_observables","operation"}
        if behavior.get("behavior_slice") != observation["slice"] or behavior.get("observation_digest") != observation["digest"] or behavior.get("expected_observables") != (observation["assertions"] or [behavior.get("assertion")]) or behavior.get("operation") != row["symbol"]:
            raise SystemExit("C023 Rust behavior is not bound to the guarded Java operation/observation: " + stable_id)
        if behavior.get("kind") == "json-unit":
            required_behavior_fields = {"key","kind","route","method","surface","input","proof_function","parser_result","assertion"} | observation_fields
            if set(behavior) != required_behavior_fields or behavior["route"] != "" or behavior["method"] != "UNIT" or behavior["surface"] != "PARSER" or behavior["proof_function"] != "c023_json::production_parser_case":
                raise SystemExit("C023 parser-unit row substituted an HTTP proof: " + stable_id)
            if behavior["parser_result"] not in {"parse_success","parse_exception","constraints_depth20_tokens100000"}:
                raise SystemExit("C023 invalid exact parser result: " + stable_id)
            contract = (behavior["kind"], behavior["proof_function"], behavior["input"], behavior["parser_result"], behavior["operation"], behavior["behavior_slice"], tuple(behavior["expected_observables"]))
        else:
            required_behavior_fields = {"key","kind","route","method","surface","input","expected_status","assertion"} | observation_fields
            if set(behavior) != required_behavior_fields or behavior["method"] not in ("GET","POST") or behavior["surface"] not in ("FULL","SOLIDITY","PBFT"):
                raise SystemExit("C023 invalid exact HTTP behavior contract: " + stable_id)
            if behavior["expected_status"] == [200, 400]:
                raise SystemExit("C023 broad success/error status substitution rejected: " + stable_id)
            contract = (behavior["kind"], behavior["route"], behavior["method"], behavior["surface"], behavior["input"], tuple(behavior["expected_status"]), behavior["operation"], behavior["behavior_slice"], tuple(behavior["expected_observables"]))
        if behavior["input"] in forbidden_default_inputs:
            raise SystemExit("C023 empty/default behavior input rejected: " + stable_id)
        if stable_id in behavior_contracts:
            raise SystemExit("C023 duplicate exact behavior contract: " + stable_id)
        behavior_contracts[stable_id] = contract
        normalized = json.dumps(contract, sort_keys=True, separators=(",", ":"))
        fingerprint = hashlib.sha256(normalized.encode()).hexdigest()
        prior = semantic_fingerprints.get(fingerprint)
        if prior and proof_by_id[prior]["java_observation"]["digest"] != observation["digest"]:
            raise SystemExit("C023 normalized Rust behavior duplicates non-identical Java observations: " + prior + " and " + stable_id)
        semantic_fingerprints[fingerprint] = stable_id
        case = row["symbol"].lower()
        exact_parser_cases = {
            "TCASE-B2E6737D25EE29F2": ('{a:1}', "parse_success"),
            "TCASE-472B63ACF325D391": ('{a:1, a:2 }', "parse_success"),
            "TCASE-8E83BB067871C5CE": ("{'a':'1'}", "parse_success"),
            "TCASE-F356A8E31D690479": ("{'a':+1,b:-2,c:.3,d:-.4,e:+.5,f:+6.,h:007}", "parse_success"),
            "TCASE-AF621E9BF2958287": ("{'a':'line1\n\tline2'}", "parse_success"),
            "TCASE-7B1E77B5A4C86C9B": ('{/* comment */"a":1}', "parse_success"),
            "TCASE-B953AD91CF184781": ('{"zzz":{"a":1,"b":[true,false,null,{"c":"d"}],"e":{"f":2}},"address":"61646472657373"}', "parse_success"),
            "TCASE-1A877C8B6766B4C7": ("@nested-object:10", "parse_success"),
            "TCASE-94015C0E2E3EEF18": ('{"genesisBlockId":{"hash":"00","number":1,},"address":"61646472657373",}', "parse_success"),
            "TCASE-A037C952A7B966C2": ("@unknown-nested-object:21", "parse_exception"),
            "TCASE-66361C13405383AA": ("@nested-array:21", "parse_exception"),
            "TCASE-0FCD6FE6295B449F": ("@nested-object:100000", "parse_exception"),
            "TCASE-FC15342AA62E8EA9": ("@nested-array:100000", "parse_exception"),
            "TCASE-01E495A39E52F3DF": ('{"c023_case":"TCASE-01E495A39E52F3DF","java_class":"JsonTest","java_behavior":"testJsonMapperHasConfiguredConstraints"}', "constraints_depth20_tokens100000"),
            "TCASE-EB9B652B5EAAF9CF": ("@jackson-object:120", "parse_exception"),
            "TCASE-E8678FD65A4DEC5A": ("@token-array:100500", "parse_exception"),
        }
        if stable_id in exact_parser_cases and (behavior["input"], behavior["parser_result"]) != exact_parser_cases[stable_id]:
            raise SystemExit("C023 exact production-parser case/input/result drift: " + stable_id)
        if stable_id in exact_parser_cases and behavior["kind"] != "json-unit":
            raise SystemExit("C023 parser exception replaced by HTTP route status: " + stable_id)
        if source["path"].endswith("/JsonFormatTest.java") or source["path"].endswith("/org/tron/json/JsonTest.java"):
            if behavior["kind"] != "json-unit": raise SystemExit("C023 Java parser unit row crossed into HTTP semantics: " + stable_id)
        if stable_id == "TCASE-B7272FC2B9889A84" and (behavior["kind"], behavior["route"], behavior["method"], behavior["expected_status"]) != ("route", "/wallet/getnowblock", "POST", [200]):
            raise SystemExit("C023 GetNowBlock POST must ignore its body and remain HTTP 200")
        exact_size_cases = {
            "TCASE-45C2C387CA68BA44": ("@bytes:a:10", [200]),
            "TCASE-F034B0A72B5741F0": ("@bytes:a:1025", [413]),
            "TCASE-218B7D40722AEEBC": ("@raw-malformed-content-length", [400]),
            "TCASE-650059671FFDB730": (behavior["input"], [414]),
            "TCASE-2022C773FC2BCD8F": ("@bytes:b:1024", [200]),
            "TCASE-E4458B80C97935F1": ("@two-services:d:612", [200, 413]),
            "TCASE-C61B1B219D2C3745": ("@utf8-cjk:342", [413]),
            "TCASE-E7220679BA1C61AF": ("@chunked:a:256", [200]),
            "TCASE-29C39693D1258F87": ("@chunked:a:2048", [200]),
            "TCASE-F3B5EB8DE6DFBAEE": ("@zero-limit:empty-and-x", [200, 413]),
        }
        if stable_id in exact_size_cases and (behavior["input"], behavior["expected_status"]) != exact_size_cases[stable_id]:
            raise SystemExit("C023 exact SizeLimitHandler transport/result drift: " + stable_id)
        if behavior["kind"] == "route":
            class_name = pathlib.Path(source["path"]).stem.removesuffix("Test").removesuffix("Servlet").lower()
            route_name = re.sub(r"[^a-z0-9]", "", behavior["route"].rsplit("/", 1)[-1].lower())
            class_name = re.sub(r"[^a-z0-9]", "", class_name)
            aliases = {"broadcast":"broadcasttransaction", "getmemofeeprices":"getmemofee", "http":"getnowblock", "transfer":"createtransaction", "gettransactionbyidsolidity":"gettransactionbyid", "getbandwidthpricesonpbft":"getbandwidthprices", "getbandwidthpricesonsolidity":"getbandwidthprices", "getenergypricesonpbft":"getenergyprices", "getenergypricesonsolidity":"getenergyprices"}
            expected_route = aliases.get(class_name, class_name)
            if class_name == "scanshieldedtrc20notes": expected_route += "byivk" if "ivk" in case else "byovk"
            if route_name != expected_route:
                raise SystemExit("C023 route row does not call its own route: " + stable_id)
        if proof_by_id[stable_id].get("behavior") != behavior:
            raise SystemExit("C023 scenario/reconciliation behavior mapping drift: " + stable_id)
    if len(behavior_contracts) != 333 or "selector_index" in rust_source or "execute_row_behavior(stable_id, family" in rust_source:
        raise SystemExit("C023 hash/generic Java-row behavior dispatch rejected")
    executable_families = {
        "c023_scenarios::exact_equivalence_manifest_reaches_terminal_http_states",
        "c023_http_controls::body_connection_and_rate_limits_release_permits",
        "c023_scenarios::all_215_inventory_rows_execute_through_real_localhost_http",
        "c023_json::descriptor_codec_matches_visible_byte_rules_and_int64_scope",
        "c023_custom::validate_address_matches_java_formats_and_messages",
    }
    if "async fn execute_row_behavior" not in rust_source or "execute_row_behavior(stable_id, row)" not in rust_source or "#[tokio::test" not in rust_source:
        raise SystemExit("C023 row proofs are not executable behavior tests")
    for row in jrows:
        stable_id = row["stable_id"]; proof = proof_by_id.get(stable_id); symbol = "c023_" + stable_id.lower().replace("-", "_")
        family = row.get("rust_case") or "c023_scenarios::exact_equivalence_manifest_reaches_terminal_http_states"
        expected = f"{stable_id}|{row['source']['path']}:{row['source']['line']}::{row['symbol']}|terminal={row['terminal_state']}|result={row['result_key']}|family={family}"
        command = f"cargo test -p tron-apis --test c023_scenarios --locked -- {symbol} --exact"
        behavior = row["java_behavior"]
        required = {"stable_id":stable_id,"source_identity":{"path":row["source"]["path"],"line":row["source"]["line"],"case":row["symbol"]},"fixture_selector":stable_id,"expected_result":expected,"java_behavior":behavior,"rust_symbol":f"c023_scenarios::{symbol}","rust_test":f"c023_scenarios::{symbol}","rust_family_test":family,"command":command,"terminal_state":row["terminal_state"],"result_key":row["result_key"],"proof_kind":"executable_behavior","behavior_selector":stable_id,"behavior_family":family,"behavior":row["behavior"],"java_observation":row["java_observation"]}
        if family not in executable_families: raise SystemExit("C023 row proof lacks executable family: " + stable_id)
        if proof != required or any(row.get(key) != value for key, value in required.items() if key not in {"stable_id", "terminal_state", "result_key"}): raise SystemExit("C023 row-specific executable proof contract drift: " + stable_id)
        if not re.search(r"\bc023_row_proof!\(" + re.escape(symbol) + r"\s*,\s*\"" + re.escape(stable_id) + r"\"", rust_source): raise SystemExit("C023 missing exact executable Rust row selector: " + stable_id)
    if "rust_live" in scenario or "rust_live_http" in scenario: raise SystemExit("C023 boolean live evidence rejected")
    manifest = load(MANIFEST)
    for key, path in (("c023_routes",ROUTES),("c023_scenarios",SCENARIOS),("c023_ownership_reconciliation",RECON)):
        if manifest.get(key) != {"path":path.name,"sha256":sha(path)}: raise SystemExit("central manifest drift: " + key)
    chunk = next(row for row in load(TRACKER)["chunks"] if row["id"] == "C023")
    if chunk.get("status") != "done" or chunk.get("owner") is not None or chunk.get("resume") is not None or chunk["gate"].get("status") != "passed" or chunk["gate"].get("last_failure") is not None or any(item.get("status") != "done" for item in chunk["items"]): raise SystemExit("C023 tracker closure drift")
    if reconciliation.get("review") != {"state":"approved","findings":[]}: raise SystemExit("C023 reconciliation approval drift")
    print(json.dumps({"schema":"c023-metadata-v2","routes":215,"custom":2,"descriptor":213,"java_tests":len(jrows),"evidence_rows":548,"scenarios":len(scenarios),"unmapped":0,"status":"passed"},separators=(",",":")))

def gradle_results(tree, expected):
    wanted = {(name, symbol): row_id for name, symbol, row_id in expected}; observed = {}
    for report in tree.glob("framework/build/test-results/test/TEST-*.xml"):
        suite = ET.parse(report).getroot()
        for case in suite.findall("testcase"):
            key = (case.get("classname", ""), case.get("name", "").split("[")[0])
            if key not in wanted: continue
            failure, error, skipped = case.find("failure"), case.find("error"), case.find("skipped")
            status = "failed" if failure is not None or error is not None else ("skipped" if skipped is not None else "passed")
            detail = ((failure.text if failure is not None else None) or (error.text if error is not None else None) or "")
            result = {"id":wanted[key],"request":f"{key[0]}#{key[1]}","status":status,"body":detail,"headers":{},"source":"authenticated-java-tron"}
            previous = observed.get(key)
            if previous is None or {"passed":0,"skipped":1,"failed":2}[status] > {"passed":0,"skipped":1,"failed":2}[previous["status"]]: observed[key] = result
    missing = set(wanted) - set(observed)
    if missing: raise SystemExit("C023 guarded Java omitted exact methods: " + repr(sorted(missing)[:8]))
    return [observed[(name, symbol)] for name, symbol, _ in expected]

def java_oracle(run_tests):
    reconciliation = load(RECON); _, expected = java_rows(reconciliation)
    sys.path.insert(0, str(ROOT / "tools/reference-runner")); from java_reference_guard import install_java_reference_guard
    with install_java_reference_guard(ROOT) as session:
        with tempfile.TemporaryDirectory(prefix="c023-java-", dir=session.work) as raw:
            out = pathlib.Path(raw); source = ROOT / "tools/api/C023Oracle.java"
            compiled = session.run([str(session.java_home/"bin/javac"),"-d",str(out),str(source)],cwd=session.work)
            if compiled.returncode: raise SystemExit("C023 Java oracle compilation failed")
            before = session.guard(phase="immediately before C023 authenticated capture",classpath=str(out))
            result = session.run([str(session.java_home/"bin/java"),"-cp",str(out),"C023Oracle"],cwd=session.work,classpath=str(out))
            text = result.stdout.decode("utf-8","replace"); scenario_names = [r["java_equivalence_class"] for r in load(SCENARIOS)["scenarios"] if r["java_equivalence_class"] != "all-routes" and r["java_equivalence_class"] != "process-error"]
            count = int(re.search(r"C023_CLASSES=(\d+)",text).group(1)); names = re.search(r"C023_INVENTORY=(.+)",text).group(1).strip().split(",")
            if result.returncode or count != 16 or len(set(names)) != 16 or set(names) != set(scenario_names) or "C023_BASE64_ADDRESS=true" not in text: raise SystemExit("C023 guarded Java equivalence capture mismatch")
            results = []
            if run_tests:
                args = [":framework:test"] + sum((["--tests", f"{name}.{symbol}"] for name, symbol, _ in expected), [])
                tests = session.gradle(args)
                # A guarded Java failure is evidence, not a reason to discard the exact result map.
                results = gradle_results(session.tree, expected)
            after = session.guard(phase="immediately after C023 authenticated capture",classpath=str(out))
            if before != after: raise SystemExit("C023 Java identity changed")
    print(json.dumps({"schema":"c023-java-oracle-v2","classes":16,"java_tests":len(results),"results":results,"status":"passed"},separators=(",",":")))

def run(target):
    print("+", " ".join(COMMANDS[target]), flush=True); subprocess.run(COMMANDS[target], cwd=RUST, check=True)

def main():
    choices=["metadata","oracle","java-tests",*COMMANDS,"all"]
    parser=argparse.ArgumentParser(); parser.add_argument("targets",nargs="*",choices=choices); targets=parser.parse_args().targets or ["all"]
    if "all" in targets: targets=["metadata","oracle","java-tests","routes","json","controls","custom","scenarios","all-targets"]
    for target in targets:
        if target=="metadata": metadata()
        elif target=="oracle": java_oracle(False)
        elif target=="java-tests": java_oracle(True)
        else: run(target)
    print(json.dumps({"schema":"c023-gate-v2","targets":targets,"status":"passed"},separators=(",",":")))
if __name__ == "__main__": main()
