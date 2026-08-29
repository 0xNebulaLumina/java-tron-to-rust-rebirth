#!/usr/bin/env python3
"""Generate revision-bound production and Java test ownership inventories.

Ownership is selected from the reviewed, ordered domain inventory below.  There is
no default owner: a new Java module/path must be classified before regeneration.
"""
from pathlib import Path
import hashlib
import json
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
JAVA = ROOT / "java-tron"
OUT = ROOT / "docs/oracles"
TRACKER = ROOT / "docs/PORTING_TRACKER.json"
REV = "df50ce9676b94de0b10a605076adfd8728811384"
EXCLUDED = {".git", ".gradle", "__pycache__", "build", "out", "target", "node_modules"}

# Reviewed mappings for framework paths.  These are deliberately finite package
# and file families: framework is not itself an ownership domain.
FRAMEWORK_DOMAINS = [
    ("build_release", r"^java-tron/framework/(?:build\.gradle|config/|src/lombok\.config$)", "C028.08", "C028.V"),
    ("configuration", r"^java-tron/framework/src/(?:main|test)/resources/(?:config(?!-shield)[^/]*\.conf|logback[^/]*\.xml)$", "C003.08", "C003.V"),
    ("shielded", r"^java-tron/framework/src/(?:main|test)/resources/(?:params/|json/(?:merkle_|.*sapling)|.*shield)", "C006.06", "C006.V"),
    ("tvm", r"^java-tron/framework/src/test/resources/precompiles/", "C015.06", "C015.V"),
    ("application_lifecycle", r"^java-tron/framework/src/(?:main|test)/java/org/tron/common/application/", "C025.08", "C025.V"),
    ("pbft", r"^java-tron/framework/src/(?:main|test)/java/org/tron/common/backup/", "C018.06", "C018.V"),
    ("p2p", r"^java-tron/framework/src/(?:main|test)/java/org/tron/common/client/", "C021.09", "C021.V"),
    ("events_metrics", r"^java-tron/framework/src/(?:main|test)/java/org/tron/common/(?:logsfilter|prometheus|log)/", "C025.08", "C025.V"),
    ("transaction_pipeline", r"^java-tron/framework/src/(?:main|test)/java/org/tron/common/runtime/", "C016.06", "C016.V"),
    ("shielded", r"^java-tron/framework/src/(?:main|test)/java/org/tron/common/zksnark/", "C006.06", "C006.V"),
    ("configuration", r"^java-tron/framework/src/test/java/org/tron/common/(?:command|config|cron)/", "C003.08", "C003.V"),
    ("storage", r"^java-tron/framework/src/test/java/org/tron/common/storage/", "C008.11", "C008.V"),
    ("crypto", r"^java-tron/framework/src/test/java/org/tron/common/(?:crypto|utils)/", "C004.06", "C004.V"),
    ("http_api", r"^java-tron/framework/src/test/java/org/tron/common/jetty/", "C023.06", "C023.V"),
    ("common_primitives", r"^java-tron/framework/src/test/java/org/tron/common/(?:cache/|(?:BaseMethodTest|BaseTest|ClassLevelAppContextFixture|ComparatorTest|EntityTest|MultiLayoutPatternTest|ParameterTest|TestConstants)\.java$)", "C002.07", "C002.V"),
    ("common_primitives", r"^java-tron/framework/src/test/java/org/tron/core/(?:exception|utils)/", "C002.07", "C002.V"),
    ("grpc_api", r"^java-tron/framework/src/(?:main|test)/java/org/tron/core/(?:Wallet(?:Mock)?(?:Test)?\.java$|services/(?:NodeInfoService|RpcApiService|WalletOnCursor|filter/LiteFnQueryGrpcInterceptor|filter/RpcApiAccessInterceptor|interfaceOn(?:PBFT|Solidity)/(?!http/)|ratelimiter/(?!PrometheusInterceptor)|(?:RpcApiServices|WalletApi)Test))", "C022.02", "C022.V"),
    ("consensus", r"^java-tron/framework/src/(?:main|test)/java/org/tron/core/(?:consensus/|witness/|services/(?:WitnessProductBlockService|DelegationService|ProposalService))", "C017.07", "C017.V"),
    ("pbft", r"^java-tron/framework/src/(?:main|test)/java/org/tron/core/pbft/", "C018.06", "C018.V"),
    ("events_metrics", r"^java-tron/framework/src/(?:main|test)/java/org/tron/core/(?:event/|metrics/|services/event/|services/ratelimiter/PrometheusInterceptor)", "C025.08", "C025.V"),
    ("json_rpc", r"^java-tron/framework/src/(?:main|test)/java/org/tron/core/(?:jsonrpc/|services/(?:jsonrpc/|interfaceJsonRpcOn))", "C024.08", "C024.V"),
    ("http_api", r"^java-tron/framework/src/(?:main|test)/java/(?:org/springframework/http/|org/tron/json/|org/tron/core/services/(?:http/|filter/(?!LiteFnQueryGrpcInterceptor|RpcApiAccessInterceptor)|interfaceOn(?:PBFT|Solidity)/http/))", "C023.06", "C023.V"),
    ("p2p", r"^java-tron/framework/src/(?:main|test)/java/org/tron/core/net/", "C021.09", "C021.V"),
    ("configuration", r"^java-tron/framework/src/(?:main|test)/java/org/tron/core/config/", "C003.08", "C003.V"),
    ("tvm", r"^java-tron/framework/src/test/java/org/tron/core/(?:vm|tire)/", "C015.06", "C015.V"),
    ("transaction_pipeline", r"^java-tron/framework/src/test/java/org/tron/core/(?:actuator/|(?:BandwidthProcessor|EnergyProcessor|TxInput|TxOutput).*)", "C016.06", "C016.V"),
    ("shielded", r"^java-tron/framework/src/(?:main|test)/java/org/tron/core/(?:zen/|zksnark/|Shield.*)", "C006.06", "C006.V"),
    ("storage", r"^java-tron/framework/src/(?:main|test)/java/org/tron/core/(?:capsule/|db2?/)", "C008.11", "C008.V"),
    ("state_genesis", r"^java-tron/framework/src/main/java/org/tron/core/trie/", "C010.06", "C010.V"),
    ("block_pipeline", r"^java-tron/framework/src/(?:main|test)/java/org/tron/core/(?:services/(?:stop/|ComputeRewardTest)|(?:BlockUtil|ForkController|CoreException).*)", "C019.07", "C019.V"),
    ("application_lifecycle", r"^java-tron/framework/src/(?:main|test)/java/org/tron/program/", "C025.08", "C025.V"),
    ("crypto", r"^java-tron/framework/src/test/java/org/tron/keystore/", "C004.06", "C004.V"),
]

# Reviewed mappings outside framework.  Patterns remain module/registry based.
DOMAINS = [
    ("protocol", r"^java-tron/protocol/", "C001.07", "C001.V"),
    ("crypto", r"^java-tron/(?:crypto|common/src/main/java/org/tron/common/(?:crypto|utils/(?:Base58|ByteArray|Sha256Hash)))/", "C004.06", "C004.V"),
    ("shielded", r"^java-tron/common/src/(?:main|test)/.*(?:zksnark|shield|librustzcash|libsodium|sapling)", "C006.06", "C006.V"),
    ("storage", r"^java-tron/chainbase/src/(?:main|test)/java/org/tron/core/(?:db|store|capsule)/", "C008.11", "C008.V"),
    ("chainbase", r"^java-tron/chainbase/(?!src/(?:main|test)/java/org/tron/core/(?:db|store|capsule)/)", "C009.06", "C009.V"),
    ("actuators", r"^java-tron/actuator/", "C016.06", "C016.V"),
    ("consensus", r"^java-tron/consensus/", "C017.07", "C017.V"),
    ("plugins_toolkit", r"^java-tron/plugins/", "C027.06", "C027.V"),
    ("configuration", r"^java-tron/(?:config/|common/src/(?:main|test)/(?:resources|java/org/tron/common/parameter)/)", "C003.08", "C003.V"),
    ("common_primitives", r"^java-tron/common/(?!src/(?:main|test)/(?:resources|java/org/tron/common/(?:parameter|crypto|utils/(?:Base58|ByteArray|Sha256Hash)))/)(?!src/(?:main|test)/.*(?:zksnark|shield|librustzcash|libsodium|sapling))", "C002.07", "C002.V"),
    ("platform_native", r"^java-tron/platform/", "C006.06", "C006.V"),
    ("build_release", r"^java-tron/(?:\.github/|docker/|gradle/|errorprone/|example/|docs/|(?:build\.gradle|settings\.gradle|gradle\.properties|gradlew|gradlew\.bat|start\.sh|start\.sh\.simple|install_dependencies\.sh|gen\.sh|ver\.sh|jitpack\.yml|lombok\.config|sonar-project\.properties|\.codeclimate\.yml|\.dockerignore|LICENSE|NOTICE|README\.md|SECURITY\.md|CONTRIBUTING\.md|METRICS_CHANGELOG\.md|quickstart\.md|shell\.md|Tron protobuf protocol document\.md)$)", "C028.08", "C028.V"),
]
EXPECTED_DOMAIN_OWNERSHIP = {
    "actuators": ("C016.06", "C016.V"),
    "application_lifecycle": ("C025.08", "C025.V"),
    "block_pipeline": ("C019.07", "C019.V"),
    "build_release": ("C028.08", "C028.V"),
    "chainbase": ("C009.06", "C009.V"),
    "common_primitives": ("C002.07", "C002.V"),
    "configuration": ("C003.08", "C003.V"),
    "consensus": ("C017.07", "C017.V"),
    "crypto": ("C004.06", "C004.V"),
    "events_metrics": ("C025.08", "C025.V"),
    "grpc_api": ("C022.02", "C022.V"),
    "http_api": ("C023.06", "C023.V"),
    "json_rpc": ("C024.08", "C024.V"),
    "p2p": ("C021.09", "C021.V"),
    "pbft": ("C018.06", "C018.V"),
    "platform_native": ("C006.06", "C006.V"),
    "plugins_toolkit": ("C027.06", "C027.V"),
    "protocol": ("C001.07", "C001.V"),
    "shielded": ("C006.06", "C006.V"),
    "state_genesis": ("C010.06", "C010.V"),
    "storage": ("C008.11", "C008.V"),
    "transaction_pipeline": ("C016.06", "C016.V"),
    "tvm": ("C015.06", "C015.V"),
}
COMPILED_FRAMEWORK_DOMAINS = [(name, re.compile(pattern), item, gate) for name, pattern, item, gate in FRAMEWORK_DOMAINS]
COMPILED_DOMAINS = [(name, re.compile(pattern), item, gate) for name, pattern, item, gate in DOMAINS]


def stable(prefix, *parts):
    value = REV + "\0" + "\0".join(map(str, parts))
    return prefix + "-" + hashlib.sha256(value.encode()).hexdigest()[:16].upper()


def classify(path):
    inventory = COMPILED_FRAMEWORK_DOMAINS if path.startswith("java-tron/framework/") else COMPILED_DOMAINS
    matches = [(name, item, gate) for name, pattern, item, gate in inventory if pattern.search(path)]
    if not matches:
        raise ValueError(f"unclassified source path: {path}")
    if len(matches) != 1:
        raise ValueError(f"ambiguous source path: {path}: {matches}")
    return matches[0]


def tracker_ids():
    data = json.loads(TRACKER.read_text())
    found = set()
    def visit(value):
        if isinstance(value, dict):
            if isinstance(value.get("id"), str):
                found.add(value["id"])
            for child in value.values(): visit(child)
        elif isinstance(value, list):
            for child in value: visit(child)
    visit(data)
    return found


def validate_domains():
    ids = tracker_ids()
    errors = []
    seen = {}
    for name, _, item, gate in FRAMEWORK_DOMAINS + DOMAINS:
        expected = EXPECTED_DOMAIN_OWNERSHIP.get(name)
        if expected != (item, gate):
            errors.append(f"domain {name}: expected owner/gate {expected}, found {(item, gate)}")
        previous = seen.setdefault(name, (item, gate))
        if previous != (item, gate):
            errors.append(f"domain {name}: conflicting owner/gate mappings {previous} and {(item, gate)}")
        if item not in ids: errors.append(f"domain {name}: missing owning item {item}")
        if gate not in ids: errors.append(f"domain {name}: missing gate {gate}")
        if item.split(".", 1)[0] != gate.split(".", 1)[0]:
            errors.append(f"domain {name}: owner {item} and gate {gate} cross chunks")
    if errors:
        raise ValueError("\n".join(errors))


def files(test=False):
    tracked = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=JAVA,
        check=True,
        capture_output=True,
    ).stdout.split(b"\0")
    for encoded in sorted(path for path in tracked if path):
        relative_to_java = Path(encoded.decode("utf-8"))
        if any(part in EXCLUDED for part in relative_to_java.parts):
            continue
        path = JAVA / relative_to_java
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT).as_posix()
        low = rel.lower()
        is_test = "/src/test/" in low or "/src/integrationtest/" in low or bool(re.search(r"(?:test|tests)\.java$", low))
        if is_test == test:
            yield path, rel


def base_row(prefix, rel, line, sha, kind, identity):
    domain, item, gate = classify(rel)
    return {"id": stable(prefix, rel, kind, identity, line), "kind": kind,
            "source": {"path": rel, "line": line, "sha256": sha},
            "domain": domain, "owning_item": item, "acceptance_gate": gate}


def production_rows():
    rows = []
    source_ext = {".java", ".proto", ".kt", ".groovy"}
    resource_ext = {".conf", ".properties", ".xml", ".json", ".csv", ".txt", ".sh", ".bat", ".yml", ".yaml", ".gradle", ".md"}
    for path, rel in files(False):
        if path.suffix.lower() not in source_ext | resource_ext and path.name not in {"Dockerfile", "LICENSE", "NOTICE", "gradlew"}:
            continue
        raw = path.read_bytes(); sha = hashlib.sha256(raw).hexdigest(); text = raw.decode("utf-8", errors="replace")
        kind = "source_file" if path.suffix.lower() in source_ext else "resource_or_script"
        row = base_row("PROD", rel, 1, sha, kind, rel)
        row.update({"symbol": rel, "category": "module" if kind == "source_file" else "resource/script", "acceptance_case_ids": [], "disposition": "port_or_review", "dependencies": [], "adoptions": []})
        rows.append(row)
        patterns = []
        if path.suffix == ".java":
            patterns = [("package", r"^\s*package\s+([\w.]+)\s*;"), ("class", r"\b(?:class|interface|enum|record)\s+(\w+)"), ("api_method", r"\b(?:public|protected)\s+(?:static\s+)?[\w<>, ?\[\].]+\s+(\w+)\s*\([^;{}]*\)\s*(?:\{|;)")]
        elif path.suffix == ".proto":
            patterns = [("proto_package", r"^\s*package\s+([\w.]+)\s*;"), ("message", r"^\s*message\s+(\w+)"), ("enum", r"^\s*enum\s+(\w+)"), ("service", r"^\s*service\s+(\w+)"), ("rpc", r"^\s*rpc\s+(\w+)")]
        for line_no, line in enumerate(text.splitlines(), 1):
            for declaration_kind, pattern in patterns:
                for match in re.finditer(pattern, line):
                    symbol = match.group(1).strip()
                    declaration = base_row("PROD", rel, line_no, sha, declaration_kind, symbol)
                    declaration.update({"symbol": symbol, "category": declaration_kind, "acceptance_case_ids": [], "disposition": "port_or_review", "dependencies": [], "adoptions": []})
                    rows.append(declaration)
    return rows


TEST_ANNOTATION = re.compile(r"@(?:org\.junit[\w.]*\.)?(Test|ParameterizedTest|RepeatedTest|TestFactory|TestTemplate)\b")
METHOD = re.compile(r"\b(?:public|protected|private)?\s*(?:static\s+)?(?:void|[\w<>, ?\[\].]+)\s+(\w+)\s*\([^;{}]*\)")
JUNIT3 = re.compile(r"\bpublic\s+void\s+(test\w+)\s*\(\s*\)")


def static_expansions(annotations):
    expansions = []
    for annotation in annotations:
        m = re.search(r"@ValueSource\s*\(\s*\w+\s*=\s*\{?([^})]+)", annotation)
        if m:
            expansions.extend(("value", x.strip()) for x in m.group(1).split(",") if x.strip())
        m = re.search(r"@CsvSource\s*\(\s*(?:value\s*=\s*)?\{?(.+?)\}?\s*\)$", annotation)
        if m:
            expansions.extend(("csv", x) for x in re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(1)))
        m = re.search(r"@RepeatedTest\s*\(\s*(\d+)", annotation)
        if m:
            expansions.extend(("repetition", str(i)) for i in range(1, int(m.group(1)) + 1))
    return expansions


def test_rows():
    rows = []
    inherited_candidates = {}
    parsed = []
    for path, rel in files(True):
        raw = path.read_bytes(); sha = hashlib.sha256(raw).hexdigest(); text = raw.decode("utf-8", errors="replace"); lines = text.splitlines()
        parsed.append((path, rel, sha, lines))
        class_match = re.search(r"\bclass\s+(\w+)(?:\s+extends\s+(\w+))?", text)
        if class_match:
            inherited_candidates[class_match.group(1)] = (rel, class_match.group(2))
    declared_by_class = {}
    for path, rel, sha, lines in parsed:
        if path.suffix != ".java":
            row = base_row("TRES", rel, 1, sha, "test_resource", rel)
            row.update({"case": rel, "annotations": [], "parameter_sources": [], "expansion": {"status": "not_applicable", "identity": None}, "nested": False, "inherited": False, "generated": False, "ignored": False, "ignore_reason": None, "assumption_gated": False, "disposition": "provisional", "rust_case_ids": []})
            rows.append(row); continue
        text = "\n".join(lines)
        cm = re.search(r"\bclass\s+(\w+)(?:\s+extends\s+(\w+))?", text)
        class_name = cm.group(1) if cm else rel
        class_parameterized = bool(re.search(r"@RunWith\s*\(\s*(?:Parameterized|Enclosed)\.class", text))
        pending = []; class_ignored = False; methods = []
        for line_no, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("@"): pending.append(stripped)
            if ("@Ignore" in stripped or "@Disabled" in stripped) and re.search(r"\bclass\b", " ".join(pending) + " " + stripped): class_ignored = True
            annotated = METHOD.search(line) if any(TEST_ANNOTATION.search(a) for a in pending) else None
            junit3 = JUNIT3.search(line)
            match = annotated or junit3
            if match:
                name = match.group(1); annotations = pending.copy() if annotated else ["JUnit3:test* convention"]
                if class_parameterized and annotated:
                    annotations.append("JUnit4:class-level parameter expansion")
                params = [a for a in annotations if re.search(r"(?:ValueSource|CsvSource|MethodSource|EnumSource|ArgumentsSource|Parameters|DataProvider|RepeatedTest|class-level parameter)", a)]
                expansions = static_expansions(annotations)
                dynamic = (class_parameterized or any(re.search(r"(?:MethodSource|EnumSource|ArgumentsSource|Parameters|DataProvider|TestFactory|TestTemplate|ParameterizedTest)", a) for a in annotations)) and not expansions
                identities = expansions or [("unresolved_dynamic" if dynamic else "single", name)]
                for expansion_kind, expansion_value in identities:
                    row = base_row("TCASE", rel, line_no, sha, "java_test_case", f"{name}:{expansion_kind}:{expansion_value}")
                    ignored = class_ignored or any("Ignore" in a or "Disabled" in a for a in annotations)
                    row.update({"case": name, "annotations": annotations, "parameter_sources": params,
                                "expansion": {"status": "bounded_unresolved" if dynamic else "enumerated", "kind": expansion_kind, "identity": expansion_value},
                                "nested": any("@Nested" in x for x in lines[:line_no]), "inherited": False,
                                "generated": any(re.search(r"(?:TestFactory|ParameterizedTest|RepeatedTest)", a) for a in annotations),
                                "ignored": ignored, "ignore_reason": next((a for a in annotations if "Ignore" in a or "Disabled" in a), None),
                                "assumption_gated": any("Assum" in x for x in lines[line_no - 1:min(len(lines), line_no + 40)]),
                                "disposition": "provisional", "rust_case_ids": []})
                    rows.append(row)
                methods.append((name, line_no, annotations))
                pending = []
            elif stripped and not stripped.startswith("@") and not stripped.startswith("//") and not METHOD.search(line):
                pending = []
        declared_by_class[class_name] = (rel, sha, methods)
    # Exact inherited rows are emitted for concrete test subclasses whose parent is
    # another discovered test class.  Their IDs bind both declaration and inheritor.
    for child, (child_rel, parent) in inherited_candidates.items():
        if not parent or parent not in declared_by_class: continue
        parent_rel, parent_sha, methods = declared_by_class[parent]
        _, item, gate = classify(child_rel)
        for name, line_no, annotations in methods:
            rows.append({"id": stable("TCASE", child_rel, parent_rel, name, "inherited"), "kind": "java_test_case",
                         "source": {"path": parent_rel, "line": line_no, "sha256": parent_sha}, "domain": classify(child_rel)[0],
                         "case": f"{child}.{name}", "annotations": annotations, "parameter_sources": [],
                         "expansion": {"status": "enumerated", "kind": "inherited", "identity": child},
                         "nested": False, "inherited": True, "generated": False, "ignored": False, "ignore_reason": None,
                         "assumption_gated": False, "owning_item": item, "acceptance_gate": gate, "disposition": "provisional", "rust_case_ids": []})
    return rows


def emit():
    validate_domains()
    prods = sorted(production_rows(), key=lambda r: (r["source"]["path"], r["source"]["line"], r["id"]))
    tests = sorted(test_rows(), key=lambda r: (r["source"]["path"], r["source"]["line"], r["id"]))
    inventory_hash = hashlib.sha256(json.dumps(FRAMEWORK_DOMAINS + DOMAINS, separators=(",", ":")).encode()).hexdigest()
    common = {"schema_version": 1, "java_source_revision": REV,
              "generator": {"path": "tools/reference-runner/generate-ledgers.py", "version": 3,
                            "sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
              "regeneration": {"command": ["python3", "tools/reference-runner/generate-ledgers.py"],
                               "domain_inventory_sha256": inventory_hash,
                               "tracker_input": "docs/PORTING_TRACKER.json",
                               "unknown_policy": "fail", "ordering": "source path, line, stable id"}}
    prod = {**common, "ledger": "production-ownership", "coverage": "reviewed Java module/registry domains; every included file and discovered declaration; unknown paths fail", "row_count": len(prods), "rows": prods}
    test = {**common, "ledger": "java-test-ownership", "coverage": "annotated JUnit 4/5, JUnit3 test* methods, statically enumerable parameter/repetition cases, inherited cases and exact bounded-unresolved dynamic expansion rows, plus test resources", "row_count": len(tests), "rows": tests}
    (OUT / "production-ownership.v1.json").write_text(json.dumps(prod, indent=2, sort_keys=True) + "\n")
    (OUT / "java-test-ownership.v1.json").write_text(json.dumps(test, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"production_rows": len(prods), "test_rows": len(tests), "domain_inventory_sha256": inventory_hash}))


if __name__ == "__main__":
    emit()
