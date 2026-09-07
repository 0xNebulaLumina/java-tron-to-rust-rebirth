#!/usr/bin/env python3
import argparse, hashlib, json, os, pathlib, re, subprocess, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
RUST = ROOT / "rust-tron"
ORACLES = ROOT / "docs/oracles"
EXPOSURE = ORACLES / "c026-solidity-exposure.v1.json"
REPLICA = ORACLES / "c026-solidity-replica.v1.json"
ROUTES = ORACLES / "c023-routes.v1.json"
RECON = ORACLES / "c026-ownership-reconciliation.v1.json"
MANIFEST = ORACLES / "manifest.v1.json"
TRACKER = ROOT / "docs/PORTING_TRACKER.json"
JAVA_PROTO = pathlib.Path("protocol/src/main/protos/api/api.proto")
JAVA_RPC = pathlib.Path("framework/src/main/java/org/tron/core/services/RpcApiService.java")
JAVA_HTTP = pathlib.Path("framework/src/main/java/org/tron/core/services/http/solidity/SolidityNodeHttpApiService.java")
COMMANDS = {
    "exposure": ["cargo", "test", "-p", "tron-apis", "--test", "c026_exposure", "--locked"],
    "scenarios": ["cargo", "test", "-p", "tron-apis", "--test", "c026_scenarios", "--locked", "--", "--test-threads=1"],
    "replica": ["cargo", "test", "-p", "tron-node", "--test", "c026_replica", "--locked"],
    "config": ["cargo", "test", "-p", "tron-config", "--test", "c026_solidity", "--locked"],
    "all-targets": ["cargo", "check", "-p", "tron-apis", "-p", "tron-node", "-p", "tron-config", "--all-targets", "--locked"],
}

def load(path): return json.loads(path.read_text())
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def capture_value(text, key):
    matches = [line.split("=", 1)[1] for line in text.splitlines() if line.startswith(key + "=")]
    if len(matches) != 1: raise SystemExit("C026 guarded Java capture missing/duplicate " + key)
    return matches[0]

def registered(name, path):
    entry = load(MANIFEST).get(name)
    if entry != {"path": path.name, "sha256": sha(path)}:
        raise SystemExit("C026 oracle manifest drift: " + name)

def proto_services(proto):
    text = proto.read_text()
    result = {}
    for match in re.finditer(r"(?m)^service\s+(\w+)\s*\{", text):
        name, cursor, depth = match.group(1), match.end(), 1
        end = cursor
        while depth:
            if text[end] == "{": depth += 1
            elif text[end] == "}": depth -= 1
            end += 1
        body = text[cursor:end - 1]
        result[name] = [(row.group(1), row.group(2).strip(), row.group(3).strip()) for row in re.finditer(r"(?m)^\s*rpc\s+(\w+)\s*\(([^)]+)\)\s*returns\s*\(([^)]+)\)", body)]
    return result

SOLIDITY_TEST_PATH = "java-tron/framework/src/test/java/org/tron/program/SolidityNodeTest.java"
SOLIDITY_TEST_SHA256 = "b62fab97c14ae9e2d8359f0620e378cc904c065f3895e8c780282ccd3d824d67"
EXPECTED_SOLIDITY_TESTS = {
    "TCASE-2A5C9AA3AA6EA9F8": ("testSolidityGrpcCall", 82, "C026.04", "covered", "tron-apis::c026_scenarios::standalone_live_grpc_services_and_forbidden_families_are_observed", "live_grpc"),
    "TCASE-ECC75FD437461ADA": ("testSolidityNodeHttpApiService", 111, "C026.04", "covered", "tron-apis::c026_scenarios::all_45_solidity_routes_execute_on_live_isolated_http", "live_http"),
    "TCASE-4FB5B48C32F41CBF": ("testExecutorsInitializedOnStartup", 125, "C025.08", "excluded", "tron-node::c025_cases_lifecycle_limits", "c025_exact_exclusion"),
    "TCASE-88A0D8FDBE4E44F0": ("testOnApplicationEventSetsFlagFalse", 142, "C025.08", "excluded", "tron-node::c025_cases_lifecycle_limits", "c025_exact_exclusion"),
    "TCASE-6A17A3F0489100CD": ("testSolidityConditionMatchesWhenSolidityFlagSet", 154, "C025.08", "excluded", "tron-node::c025_cases_lifecycle_limits", "c025_exact_exclusion"),
    "TCASE-EBD0B48CD2BC4233": ("testResolveCompatibilityIssueWhenSolidityLagsHead", 167, "C026.03", "covered", "tron-node::c026_replica::startup_reconciles_stale_marker_to_committed_head_before_fetching_next_height", "replica_startup_reconciliation"),
    "TCASE-EBE8CD81B908660A": ("testShutdownCallsDatabaseClientShutdown", 193, "C026.03", "covered", "tron-node::c026_replica::service_shutdown_joins_publication_before_closing_database_client", "replica_shutdown"),
    "TCASE-B98268F7AD12945A": ("testSleep", 226, "C026.02", "covered", "tron-node::c026_replica::startup_reconciles_stale_marker_to_committed_head_before_fetching_next_height", "replica_restart"),
    "TCASE-BF84229BC644C593": ("testGetBlockByNum", 253, "C026.02", "covered", "tron-node::c026_replica::retries_same_height_then_applies_exact_sequence_and_persists", "replica_retry"),
    "TCASE-D6924C75B79C8610": ("testGetBlockByNumWhenClosed", 293, "C026.03", "covered", "tron-node::c026_replica::startup_reconciles_stale_marker_to_committed_head_before_fetching_next_height", "replica_restart"),
    "TCASE-7AB4A24CB6974B48": ("testGetBlockByNumNoErrorOnExceptionDuringShutdown", 340, "C026.03", "covered", "tron-node::c026_replica::source_fetch_error_during_shutdown_still_closes_database_source", "replica_shutdown"),
    "TCASE-F04F02E5141D1305": ("testGetLastSolidityBlockNum", 382, "C026.02", "covered", "tron-node::c026_replica::retries_same_height_then_applies_exact_sequence_and_persists", "replica_retry"),
    "TCASE-2C4199CA57939EB1": ("testGetLastSolidityBlockNumWhenClosed", 413, "C026.03", "covered", "tron-node::c026_replica::durable_solidity_cursor_remains_readable_after_database_source_closes", "replica_shutdown"),
    "TCASE-2B6B086198EF7F45": ("testLoopProcessBlock", 451, "C026.02", "covered", "tron-node::c026_replica::startup_reconciles_stale_marker_to_committed_head_before_fetching_next_height", "replica_restart"),
    "TCASE-015D2E1CB6D2173E": ("testGetBlockProcessesOneBlock", 504, "C026.03", "covered", "tron-node::c026_replica::returned_height_mismatch_retries_without_apply_or_cursor_advance", "replica_mismatch"),
    "TCASE-92120864D65D2229": ("testGetBlockShutdownPaths", 557, "C026.03", "covered", "tron-node::c026_replica::service_shutdown_joins_publication_before_closing_database_client", "replica_shutdown"),
    "TCASE-E8E51BCEAD8A629B": ("testProcessSolidityBlockProcessesQueuedBlock", 634, "C026.03", "covered", "tron-node::c026_replica::startup_reconciles_stale_marker_to_committed_head_before_fetching_next_height", "replica_restart"),
    "TCASE-C7B71DDE0A291F8E": ("testProcessSolidityBlockHandlesInterrupt", 672, "C026.03", "covered", "tron-node::c026_replica::interrupt_cancels_inflight_replica_read_and_closes_database_source", "replica_shutdown"),
}
REPLICA_PROOFS = {
    "durable_solidity_cursor_remains_readable_after_database_source_closes",
    "fatal_replica_before_readiness_start_never_becomes_healthy_ready_or_ingress_enabled",
    "production_start_fatal_after_graph_readiness_unwinds_every_started_resource_exactly_once",
    "production_start_preserves_fatal_when_later_service_times_out",
    "stop_controller_fatal_latch_preserves_nonfatal_queue_and_every_fatal_cause",
    "production_operator_before_fatal_cannot_report_successful_shutdown",
    "production_interrupt_before_fatal_cannot_report_successful_shutdown",
    "production_fatal_and_graph_shutdown_error_are_structurally_aggregated",
    "production_nonfatal_shutdown_remains_successful",
    "production_factory_hooks_share_the_nodes_exact_status_and_stop_state",
    "production_factory_validates_mode_config_before_factory_side_effects",
    "public_production_entrypoint_prevalidates_canonical_config_before_consuming_dependencies",
    "production_start_atomically_drains_every_concurrent_fatal_in_order",
    "interrupt_cancels_inflight_replica_read_and_closes_database_source",
    "replica_worker_failure_revokes_readiness_and_requests_fatal_stop",
    "retries_same_height_then_applies_exact_sequence_and_persists",
    "replica_worker_and_database_shutdown_failures_preserve_both_exact_causes",
    "returned_height_mismatch_retries_without_apply_or_cursor_advance",
    "service_shutdown_joins_publication_before_closing_database_client",
    "source_fetch_error_during_shutdown_still_closes_database_source",
    "timed_out_replica_stop_remains_owned_and_retry_joins_source_shutdown",
    "startup_reconciles_stale_marker_to_committed_head_before_fetching_next_height",
}
REQUIRED_TESTS = {
    RUST / "crates/tron-apis/tests/c026_scenarios.rs": {
        "standalone_live_grpc_services_and_forbidden_families_are_observed",
        "all_45_solidity_routes_execute_on_live_isolated_http",
        "forbidden_transport_ports_are_absent_and_default_live_ports_are_pinned",
    },
    RUST / "crates/tron-apis/tests/c026_exposure.rs": {
        "standalone_solidity_grpc_service_matrix_is_exact",
        "standalone_solidity_grpc_method_matrix_is_exact",
        "standalone_solidity_http_routes_are_exact_and_executable",
        "standalone_solidity_ports_and_absences_are_exact",
    },
    RUST / "crates/tron-config/tests/c026_solidity.rs": {
        "solidity_requires_nonblank_valid_trust_node_before_services",
        "full_and_keystore_modes_do_not_require_trust_node",
    },
    RUST / "crates/tron-node/tests/c026_replica.rs": REPLICA_PROOFS,
}

TEST_ATTRIBUTE = re.compile(r"(?m)^\s*#\[(?:tokio::)?test(?:\([^\]]*\))?\]\s*\n\s*(?:async\s+)?fn\s+(\w+)\b")

def attributed_tests(text):
    return set(TEST_ATTRIBUTE.findall(text))

def verify_test_discovery_mutation():
    fixture = "#[test]\nfn sync_proof() {}\n#[tokio::test]\nasync fn async_proof() {}\n"
    if attributed_tests(fixture) != {"sync_proof", "async_proof"}:
        raise SystemExit("C026 test-attribute discovery fixture failed")
    mutated = fixture.replace("#[tokio::test]\n", "")
    if "async_proof" in attributed_tests(mutated):
        raise SystemExit("C026 de-attributed proof mutation was not rejected")

OBSERVATIONS = {
    "live_grpc": ["required-service-call", "forbidden-family-rejection"],
    "live_http": ["all-45-routes-execute", "solidity-cursor"],
    "c025_exact_exclusion": {
        "TCASE-4FB5B48C32F41CBF": ["executor-initialization", "application-lifecycle"],
        "TCASE-88A0D8FDBE4E44F0": ["application-close-flag", "application-lifecycle"],
        "TCASE-6A17A3F0489100CD": ["solidity-condition-selection", "application-lifecycle"],
    },
    "replica_startup_reconciliation": {
        "TCASE-EBD0B48CD2BC4233": ["startup-marker-3", "committed-head-10", "reconciled-marker-10", "first-trust-node-fetch-11"],
    },
    "replica_restart": {
        "TCASE-B98268F7AD12945A": ["cancellation-visible", "startup-reconciliation-before-fetch"],
        "TCASE-D6924C75B79C8610": ["closed-source-cancellation", "no-publication-after-cancel"],
        "TCASE-2B6B086198EF7F45": ["loop-cancellation", "restart-advances-from-local-head"],
        "TCASE-E8E51BCEAD8A629B": ["queued-block-apply", "publication-cancellation"],
    },
    "replica_shutdown": {
        "TCASE-EBE8CD81B908660A": ["joined-publication", "database-client-close", "no-fatal-stop"],
        "TCASE-7AB4A24CB6974B48": ["shutdown-fetch-error-tolerated", "database-client-close"],
        "TCASE-2C4199CA57939EB1": ["closed-cursor-read", "joined-publication"],
        "TCASE-92120864D65D2229": ["shutdown-paths", "joined-publication", "database-client-close"],
        "TCASE-C7B71DDE0A291F8E": ["interrupt-cancellation", "joined-publication", "database-client-close"],
    },
    "replica_retry": {
        "TCASE-BF84229BC644C593": ["exact-height-fetch", "sequential-apply", "cursor-persist"],
        "TCASE-F04F02E5141D1305": ["dynamic-solidity-height", "cursor-persist"],
    },
    "replica_mismatch": ["returned-height-validation", "no-apply", "no-cursor-advance", "retry"],
}

def metadata(java_tree):
    manifest = load(EXPOSURE); rows = manifest.get("rows", [])
    expected_counts = {"grpc_services": 6, "grpc_methods": 203, "http_routes": 45, "ports": 8, "total": 262}
    if manifest.get("schema") != "c026-solidity-exposure-v1" or manifest.get("version") != 1 or manifest.get("counts") != expected_counts or len(rows) != 262:
        raise SystemExit("C026 versioned exposure manifest/count drift")
    if len({row.get("id") for row in rows}) != len(rows): raise SystemExit("C026 duplicate/missing exposure row ID")
    for source in manifest.get("sources", []):
        relative = pathlib.Path(source["path"])
        path = (java_tree / pathlib.Path(*relative.parts[1:])) if relative.parts and relative.parts[0] == "java-tron" else ROOT / relative
        if not path.is_file() or sha(path) != source["sha256"]: raise SystemExit("C026 authenticated source drift: " + source["path"])
    services = proto_services(java_tree / JAVA_PROTO)
    if {name: len(methods) for name, methods in services.items()} != {"Wallet":147,"WalletSolidity":47,"WalletExtension":4,"Database":4,"Monitor":1,"Network":0}:
        raise SystemExit("C026 descriptor service/method drift")
    service_rows = {row["service"]: row for row in rows if row["kind"] == "grpc_service"}
    expected_state = {"Database":"required","WalletSolidity":"required","WalletExtension":"optional","Monitor":"optional","Wallet":"forbidden","Network":"not_applicable"}
    if {name: row["exposure"] for name, row in service_rows.items()} != expected_state: raise SystemExit("C026 general service exposure drift")
    method_rows = {(row["service"],row["method"],row["request"],row["response"]):row for row in rows if row["kind"] == "grpc_method"}
    expected_methods = {(service,*method) for service, methods in services.items() for method in methods}
    if set(method_rows) != expected_methods or any(row["exposure"] != expected_state[row["service"]] for row in method_rows.values()):
        raise SystemExit("C026 every general method row must be classified")
    rpc = (java_tree / JAVA_RPC).read_text()
    for needle in ("serverBuilder.addService(databaseApi)", "serverBuilder.addService(walletSolidityApi)", "isWalletExtensionApi()", "serverBuilder.addService(new WalletExtensionApi())", "isNodeMetricsEnable()", "serverBuilder.addService(monitorApi)"):
        if needle not in rpc: raise SystemExit("C026 Java gRPC composition drift: " + needle)
    routes = [row for row in load(ROUTES)["routes"] if row["surface"] == "SOLIDITY"]
    route_rows = {(row["path"],tuple(row["methods"]),row["rpc_api"],row["rpc_method"]):row for row in rows if row["kind"] == "http_route"}
    expected_routes = {(row["path"],tuple(row["methods"]),row["rpc_api"],row["rpc_method"]) for row in routes}
    if len(routes) != 45 or set(route_rows) != expected_routes or any(row["port"] != 8091 or row["cursor"] != "SOLIDITY" or row["exposure"] != "required" for row in route_rows.values()):
        raise SystemExit("C026 exact 45 standalone Solidity HTTP route/cursor drift")
    http = (java_tree / JAVA_HTTP).read_text()
    if "getSolidityHttpPort()" not in http or "!isFullNode()" not in http: raise SystemExit("C026 standalone HTTP mode/port drift")
    ports = {row["name"]:(row["port"],row["exposure"]) for row in rows if row["kind"] == "port"}
    expected_ports = {"GRPC":(50051,"required"),"HTTP":(8091,"required"),"SOLIDITY_GRPC_SECONDARY":(50061,"forbidden"),"FULL_HTTP":(8090,"forbidden"),"PBFT_HTTP":(8092,"forbidden"),"PBFT_GRPC":(50071,"forbidden"),"P2P":(18888,"forbidden"),"JSON_RPC":(8545,"forbidden")}
    if ports != expected_ports: raise SystemExit("C026 exact port/absence drift")
    if not REPLICA.is_file(): raise SystemExit("C026 replica oracle missing")
    for name, path in {
        "c026_solidity_exposure": EXPOSURE,
        "c026_solidity_replica": REPLICA,
        "c026_ownership_reconciliation": RECON,
    }.items(): registered(name, path)
    replica = load(REPLICA)
    if replica.get("schemaVersion") != 1 or replica.get("chunk") != "C026.01-C026.03" or len(replica.get("vectors", [])) < 5:
        raise SystemExit("C026 replica oracle drift")
    reconciliation = load(RECON)
    expected_recon = {"solidity_node_java_tests":18,"covered":15,"excluded":3,"seams":4,"unmapped":0}
    if reconciliation.get("schema") != "c026-ownership-reconciliation-v1" or reconciliation.get("version") != 1 or reconciliation.get("canonical_counts") != expected_recon:
        raise SystemExit("C026 reconciliation count/schema drift")
    reconciliation_rows = reconciliation.get("rows", [])
    if len(reconciliation_rows) != 18 or len({row.get("id") for row in reconciliation_rows}) != 18:
        raise SystemExit("C026 exact SolidityNode Java test reconciliation drift")
    actual_ids = {row.get("id") for row in reconciliation_rows}
    if actual_ids != set(EXPECTED_SOLIDITY_TESTS):
        raise SystemExit(f"C026 closed Java ID set drift missing={sorted(set(EXPECTED_SOLIDITY_TESTS)-actual_ids)!r} extra={sorted(actual_ids-set(EXPECTED_SOLIDITY_TESTS))!r}")
    c025_evidence = {row.get("id"): row for row in load(ORACLES / "c025-row-evidence.v1.json").get("rows", [])}
    for row in reconciliation_rows:
        case, line, owner, status, dispatch, category = EXPECTED_SOLIDITY_TESTS[row["id"]]
        identity = (row.get("java_case"), row.get("source", {}).get("line"), row.get("owning_item"), row.get("status"), row.get("rust_dispatch"), row.get("proof", {}).get("category"))
        if identity != (case, line, owner, status, dispatch, category):
            raise SystemExit("C026 exact ownership/proof routing drift: " + row["id"])
        if row.get("kind") != "java_test" or row.get("source") != {"line": line, "path": SOLIDITY_TEST_PATH} or row.get("source_sha256") != SOLIDITY_TEST_SHA256:
            raise SystemExit("C026 authenticated Java source identity drift: " + row["id"])
        proof = row.get("proof", {})
        if not isinstance(proof.get("observes"), list) or not proof["observes"] or len(proof["observes"]) != len(set(proof["observes"])):
            raise SystemExit("C026 concrete observation contract missing/duplicate: " + row["id"])
        category_contract = OBSERVATIONS[category]
        expected_observations = category_contract[row["id"]] if isinstance(category_contract, dict) else category_contract
        if proof["observes"] != expected_observations:
            raise SystemExit("C026 observation contract/category drift: " + row["id"])
        if status == "covered":
            if proof.get("rust_symbol") != dispatch or set(proof) != {"category", "observes", "rust_symbol"}:
                raise SystemExit("C026 covered row lacks its exact Rust proof: " + row["id"])
        else:
            evidence = c025_evidence.get(row["id"], {})
            if proof != {"category": "c025_exact_exclusion", "observes": proof["observes"], "artifact": "c025-row-evidence.v1.json", "evidence_row_id": row["id"], "rust_case": "solidity_replica_retries_fetches_processes_and_shuts_down_client"}:
                raise SystemExit("C026 exclusion is not an exact C025 evidence reference: " + row["id"])
            if evidence.get("java_symbol") != case or evidence.get("java_source") != {"line": line, "path": SOLIDITY_TEST_PATH} or evidence.get("rust_dispatch") != dispatch or evidence.get("rust_case") != proof["rust_case"] or evidence.get("evidence_kind") != "java_test_execution":
                raise SystemExit("C026 excluded row C025 proof drift: " + row["id"])
    if sum(row["status"] == "covered" for row in reconciliation_rows) != 15 or sum(row["status"] == "excluded" for row in reconciliation_rows) != 3:
        raise SystemExit("C026 Java test coverage/exclusion drift")
    expected_seams = [
        ("C026-SEAM-C021-DATABASE-CLIENT", "C021", "c021-ownership-reconciliation.v1.json", 22, "excluded"),
        ("C026-SEAM-C022-GRPC", "C022", "c022-ownership-reconciliation.v1.json", 203, "covered"),
        ("C026-SEAM-C023-HTTP", "C023", "c023-ownership-reconciliation.v1.json", 45, "covered"),
        ("C026-SEAM-C025-LIFECYCLE", "C025", "c025-ownership-reconciliation.v1.json", 3, "excluded"),
    ]
    seams = reconciliation.get("seams", [])
    if [(row.get("id"), row.get("source_chunk"), row.get("source_artifact"), row.get("count"), row.get("classification")) for row in seams] != expected_seams:
        raise SystemExit("C026 exact cross-chunk seam drift")
    for row in seams:
        source = ORACLES / row["source_artifact"]
        if not source.is_file() or row.get("source_sha256") != sha(source) or not row.get("c026_case"):
            raise SystemExit("C026 cross-chunk seam source/case drift: " + row.get("id", "missing"))
    verify_test_discovery_mutation()
    for test, names in REQUIRED_TESTS.items():
        if not test.is_file(): raise SystemExit("C026 required executable proof missing: " + str(test))
        discovered = attributed_tests(test.read_text())
        if not names <= discovered: raise SystemExit("C026 attributed executable proof missing: " + ",".join(sorted(names-discovered)))
    expected_replica_proof = next((proof for proof in replica.get("rustProofs", []) if proof.get("command") == "cargo test -p tron-node --test c026_replica --locked"), None)
    if expected_replica_proof != {"command": "cargo test -p tron-node --test c026_replica --locked", "cases": 22, "names": sorted(REPLICA_PROOFS)}:
        raise SystemExit("C026 replica rustProofs must authenticate all twenty-two exact test names")
    for test, names in REQUIRED_TESTS.items():
        package = test.parts[-3]
        target = test.stem
        listed = subprocess.run(["cargo", "test", "-p", package, "--test", target, "--locked", "--", "--list"], cwd=RUST, check=True, capture_output=True, text=True).stdout
        runnable = {line.rsplit(": test", 1)[0] for line in listed.splitlines() if line.endswith(": test")}
        if not names <= runnable: raise SystemExit("C026 cargo test does not include required proof: " + ",".join(sorted(names-runnable)))
    replica_dispatches = {"tron-node::c026_replica::" + name for name in REPLICA_PROOFS}
    covered_replica = {row["rust_dispatch"] for row in reconciliation_rows if row["status"] == "covered" and row["rust_dispatch"].startswith("tron-node::c026_replica::")}
    integration_dispatches = {row.get("rust_dispatch") for row in reconciliation.get("integration_cases", [])}
    if len(REPLICA_PROOFS) != 22 or not covered_replica <= replica_dispatches or not replica_dispatches <= integration_dispatches:
        raise SystemExit("C026 all twenty-two exact replica proofs must be canonical and routed")
    covered_symbols = {row["rust_dispatch"] for row in reconciliation_rows if row["status"] == "covered"}
    canonical_symbols = {dispatch for names in REQUIRED_TESTS.values() for dispatch in names}
    if any(symbol.rsplit("::", 1)[-1] not in canonical_symbols for symbol in covered_symbols):
        raise SystemExit("C026 covered row proof is outside canonical REQUIRED_TESTS")
    print(json.dumps({"schema":"c026-metadata-v1",**expected_counts,**expected_recon,"required_services":2,"optional_services":2,"forbidden_or_na_services":2,"status":"passed"},separators=(",",":")))

def oracle(session):
    with tempfile.TemporaryDirectory(prefix="c026-java-", dir=session.work) as raw:
        out = pathlib.Path(raw); init = out / "classpath.gradle"
        init.write_text("allprojects { p -> if (p.path == ':framework') { p.afterEvaluate { p.tasks.register('c026RuntimeClasspath') { doLast { println 'C026_CLASSPATH=' + p.sourceSets.test.runtimeClasspath.asPath } } } } }\n")
        built = session.gradle(["-I",str(init),":framework:testClasses",":actuator:jar",":consensus:jar",":chainbase:jar",":crypto:jar",":common:jar",":protocol:jar",":platform:jar"])
        if built.returncode: raise SystemExit("C026 Java runtime build failed:\n" + built.stderr.decode("utf-8","replace"))
        queried = session.gradle(["-I",str(init),":framework:c026RuntimeClasspath"])
        matches = [line.split("=",1)[1] for line in queried.stdout.decode().splitlines() if line.startswith("C026_CLASSPATH=")]
        if queried.returncode or len(matches) != 1: raise SystemExit("C026 Java classpath query failed")
        cp = matches[0]; source = ROOT / "tools/node/C026Oracle.java"
        result = session.run([str(session.java_home/"bin/javac"),"-cp",cp,"-d",str(out),str(source)],cwd=session.work,classpath=cp)
        if result.returncode: raise SystemExit("C026 Java oracle compilation failed:\n" + result.stderr.decode("utf-8","replace"))
        oracle_cp = str(out) + os.pathsep + cp
        before = session.guard(phase="immediately before C026 authenticated capture",classpath=oracle_cp)
        result = session.run([str(session.java_home/"bin/java"),"-cp",oracle_cp,"C026Oracle"],cwd=session.work,classpath=oracle_cp)
        text = result.stdout.decode("utf-8","replace")
        if result.returncode:
            raise SystemExit("C026 guarded Java capture failed:\n" + text + "\n" + result.stderr.decode("utf-8","replace"))
        service_inventory = capture_value(text, "C026_INVENTORY").split(",")
        method_inventory = capture_value(text, "C026_METHOD_INVENTORY").split(",")
        test_inventory = capture_value(text, "C026_TEST_INVENTORY").split(",")
        config_inventory = capture_value(text, "C026_CONFIG")
        digest = capture_value(text, "C026_CANONICAL_SHA256")
        exposure = load(EXPOSURE); rows = exposure["rows"]
        expected_services = sorted(f"protocol.{row['service']}:{sum(method['kind'] == 'grpc_method' and method['service'] == row['service'] for method in rows)}" for row in rows if row["kind"] == "grpc_service")
        expected_methods = sorted(f"protocol.{row['service']}/{row['method']}" for row in rows if row["kind"] == "grpc_method")
        expected_tests = sorted(row["java_case"] for row in load(RECON)["rows"])
        if service_inventory != expected_services or method_inventory != expected_methods or test_inventory != expected_tests:
            raise SystemExit("C026 guarded Java inventory does not exactly match registered exposure/reconciliation")
        invariants = exposure["invariants"]
        expected_config = f"127.0.0.1:50051:{invariants['grpc_base_port']}:{invariants['http_port']}:false"
        if config_inventory != expected_config:
            raise SystemExit("C026 guarded Java runtime config drift: " + config_inventory)
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise SystemExit("C026 guarded Java canonical digest missing")
        after = session.guard(phase="immediately after C026 authenticated capture",classpath=oracle_cp)
        if before != after: raise SystemExit("C026 Java identity changed")
    print(json.dumps({"schema":"c026-java-oracle-v1","services":6,"methods":203,"java_tests":18,"status":"passed"},separators=(",",":")))

def run(target):
    print("+", " ".join(COMMANDS[target]), flush=True); subprocess.run(COMMANDS[target], cwd=RUST, check=True)

def main():
    choices=["metadata","oracle",*COMMANDS,"all"]
    parser=argparse.ArgumentParser(); parser.add_argument("targets",nargs="*",choices=choices); targets=parser.parse_args().targets or ["all"]
    if "all" in targets: targets=["metadata","oracle","exposure","scenarios","replica","config","all-targets"]
    needs_java = "metadata" in targets or "oracle" in targets
    session = None
    if needs_java:
        sys.path.insert(0, str(ROOT / "tools/reference-runner")); from java_reference_guard import install_java_reference_guard
        session = install_java_reference_guard(ROOT)
    try:
        for target in targets:
            if target == "metadata": metadata(session.tree)
            elif target == "oracle": oracle(session)
            else: run(target)
    finally:
        if session is not None: session.close()
    print(json.dumps({"schema":"c026-gate-v1","targets":targets,"status":"passed"},separators=(",",":")))
if __name__ == "__main__": main()
