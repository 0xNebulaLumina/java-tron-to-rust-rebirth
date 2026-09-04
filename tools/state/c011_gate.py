#!/usr/bin/env python3
"""Generate and verify pinned C011 fork-graph and activation evidence."""
import argparse, hashlib, json, re, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ORACLES = ROOT / "docs/oracles"
TRACKER = ROOT / "docs/PORTING_TRACKER.json"
TEST = ROOT / "rust-tron/crates/tron-state/tests/khaos_contract.rs"
OWNERSHIP = ORACLES / "java-test-ownership.v1.json"
INVENTORY = ORACLES / "c011-source-inventory.v1.json"
FIXTURES = ORACLES / "c011-fixtures.v1.json"
RECONCILIATION = ORACLES / "c011-java-test-reconciliation.v1.json"
KHAOS_CONTRACT = ORACLES / "c011-khaos-contract.v1.json"
FORK_CONTRACT = ORACLES / "c011-fork-contract.v1.json"
MANIFEST = ORACLES / "manifest.v1.json"
EXPECTED_COMMANDS = [
    {"name": "C011 pinned Java inventory, fixtures, ownership and dispatch gate", "cwd": ".", "argv": ["python3", "tools/state/c011_gate.py"], "timeout_seconds": 300},
    {"name": "C011 fork graph and activation contracts", "cwd": "rust-tron", "argv": ["cargo", "test", "-p", "tron-state", "--test", "khaos_contract", "--locked"], "timeout_seconds": 300},
    {"name": "C011 tron-state module contracts", "cwd": "rust-tron", "argv": ["cargo", "test", "-p", "tron-state", "--lib", "--locked"], "timeout_seconds": 300},
    {"name": "C011 exact workspace target check", "cwd": "rust-tron", "argv": ["cargo", "check", "-p", "tron-state", "--all-targets", "--locked"], "timeout_seconds": 300},
]
SOURCES = [
    "java-tron/chainbase/src/main/java/org/tron/core/db/KhaosDatabase.java",
    "java-tron/chainbase/src/main/java/org/tron/common/utils/ForkController.java",
    "java-tron/framework/src/test/java/org/tron/core/db/KhaosDatabaseTest.java",
    "java-tron/framework/src/test/java/org/tron/core/ForkControllerTest.java",
]
CASES = [
    ("khaos:linked", "linked parent resolves; child enters linked store", "linked=true,unlinked=false"),
    ("khaos:orphan", "missing nonzero parent after head exists", "insert-unlinked-before-UnLinkedBlock"),
    ("khaos:replacement", "same id inserted twice", "hash-index=replacement,height-list=append"),
    ("khaos:duplicate", "duplicate id removal", "all matching ids removed from indexed value height only"),
    ("khaos:eviction", "head=3,maxCapacity=2", "evict the complete height-0 bucket while preserving height-1 siblings"),
    ("khaos:head", "equal-height candidate", "retain existing head; strictly greater wins"),
    ("khaos:remove", "remove linked root/head candidates", "reselect first insertion at maximum retained height; mutation precedes null-head error"),
    ("khaos:pop", "pop linked child", "head=weak-parent; stores unchanged"),
    ("khaos:weak-parent", "remove parent ownership and head reference", "child parent upgrade fails"),
    ("khaos:modern-branch", "two retained tips", "argument-oriented tip-to-common-exclusive paths"),
    ("khaos:deprecated-branch", "initial tip absent", "two empty paths; missing traversed parent still errors"),
    ("khaos:resource-limits", "duplicate, orphan, byte, and future-height pressure", "bounded independently by insertion count and accounted bytes"),
    ("khaos:parent-retention", "linked child fits alone but parent plus child exceeds resource limit", "reject ResourceLimit before graph, head, or accounting mutation; exact resolved parent Rc remains indexed"),
    ("khaos:pinned-parent-sibling", "same-height pinned parent and older sibling under entry pressure", "skip only the exact parent Rc; evict the sibling entry and admit the child at the strict bound"),
    ("khaos:interleaved-resource-order", "resource victims inserted at heights 5,1,4 before height 6", "evict the oldest insertion rather than the lowest-height bucket"),
    ("khaos:cycle-defense", "replaced IDs form malformed or cyclic parent chains", "typed malformed-chain or cycle error within retained-step bound"),
    ("khaos:deep-payload-limits", "oversized linked and orphan payloads exceed byte budgets", "reject before linked/head or orphan-store mutation"),
    ("khaos:deprecated-cycle-defense", "deprecated branch traverses malformed and cyclic parent chains", "typed malformed-chain or cycle error within retained-step bound"),
    ("khaos:unsupported-is-not-empty", "inherited isNotEmpty call", "typed UnsupportedOperation"),
    ("activation:old-version", "stats=[1,1,1] then [1,2,1]", "pass=true then false; raw length"),
    ("activation:energy-height", "version=5 at height 4727890", "before=false,at=true"),
    ("activation:maintenance-rounding", "hardForkTime=100,interval=10", "activation boundary uses Java maintenance rounding"),
    ("activation:new-version-quorum", "rate=80,raw lengths 5 and 3", "required=ceil(rate*rawLength/100)"),
    ("activation:old-v6-no-time", "version=6 with hardForkTime=Long.MAX_VALUE", "old all-one stats pass without time or quorum"),
    ("activation:reset", "passing and failing raw arrays", "retain passing raw length; failing becomes active-length zeros"),
    ("activation:upgrade", "candidate vote reaches quorum only after recording", "candidate is published on the following update because pass precedes current vote"),
    ("activation:new-v17-path", "version=17 at hardForkTime=100,rate=80", "new path requires rounded time and quorum"),
    ("activation:downgrade", "future version is before its activation boundary", "later non-passing slot is cleared before candidate pass/vote handling"),
    ("activation:duplicate-witness", "active roster contains duplicate address", "Java indexOf selects and updates only the first matching index"),
    ("activation:resize-order", "active=5,candidate passing stored length=1,older arrays length=5", "pass uses stored candidate; local resize supplies upgrade slot size; older arrays remain length 5"),
]
TEST_ROWS = {
    "TCASE-DC962C8486AEB077": ("testStartBlock", "C011.01", "C009.V", ["khaos:linked"]),
    "TCASE-4FC0EDF1C0D78E1B": ("testPushGetBlock", "C011.01", "C009.V", ["khaos:orphan", "khaos:remove"]),
    "TCASE-3502FD0040F2328C": ("checkWeakReference", "C011.01", "C009.V", ["khaos:weak-parent"]),
    "TCASE-F8C35B5DF3CB7207": ("testGetBranch", "C011.02", "C009.V", ["khaos:modern-branch"]),
    "TCASE-C70C87BC73F43547": ("testIsNotEmpty", "C011.01", "C009.V", ["khaos:unsupported-is-not-empty"]),
    "TCASE-478556449FDDE99F": ("testPass", "C011.03", "C019.V", ["activation:old-version", "activation:energy-height", "activation:maintenance-rounding", "activation:new-version-quorum"]),
    "TCASE-359D8D71081CED91": ("testReset", "C011.03", "C019.V", ["activation:reset"]),
    "TCASE-373DA15C1459A3A0": ("testUpdate", "C011.03", "C019.V", ["activation:upgrade", "activation:downgrade", "activation:duplicate-witness", "activation:resize-order"]),
}

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def dump(value): return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
def revision(): return subprocess.check_output(["git", "-C", str(ROOT / "java-tron"), "rev-parse", "HEAD"], text=True).strip()
def inventory():
    return {"schema_version": 1, "chunk": "C011", "java_revision": revision(), "sources": [{"path": p, "sha256": sha(ROOT / p)} for p in SOURCES]}
def dispatch():
    text = TEST.read_text()
    marker = "const C011_CASE_TABLE: &[(&str, fn())] = &["
    if marker not in text: raise ValueError("missing C011_CASE_TABLE executable dispatcher")
    table = text.split(marker, 1)[1].split("];", 1)[0]
    rows = re.findall(r'^\s*\("([a-z0-9:-]+)",\s*([a-zA-Z0-9_]+)\),\s*$', table, re.MULTILINE)
    if [row[0] for row in rows] != [row[0] for row in CASES]: raise ValueError("C011_CASE_TABLE order/content mismatch")
    if len({row[0] for row in rows}) != len(rows): raise ValueError("duplicate C011 case ID")
    for _, symbol in rows:
        if not re.search(rf"fn\s+{re.escape(symbol)}\s*\(", text): raise ValueError(f"missing Rust handler {symbol}")
    return dict(rows)
def fixtures():
    handlers = dispatch()
    return {"schema_version": 1, "chunk": "C011", "java_revision": revision(), "rows": [{"id": i, "input": inp, "expected": out, "rust_symbol": f"rust-tron/crates/tron-state/tests/khaos_contract.rs::{handlers[i]}", "command_index": 1} for i, inp, out in CASES]}
def reconciliation():
    handlers = dispatch(); ledger = json.loads(OWNERSHIP.read_text()); by_id = {r["id"]: r for r in ledger["rows"]}
    rows = []
    for stable_id, (case, item, previous_gate, rust_case_ids) in TEST_ROWS.items():
        row = by_id.get(stable_id)
        if row is None: raise ValueError(f"missing ownership row {stable_id}")
        actual = row["case"]["name"] if isinstance(row.get("case"), dict) else row.get("case")
        if actual != case: raise ValueError(f"ownership metadata drift {stable_id}")
        symbols = [handlers[case_id] for case_id in rust_case_ids]
        fixture = rust_case_ids[0]
        rows.append({"stable_id": stable_id, "java_source": row["source"]["path"], "java_line": row["source"]["line"], "java_case": case, "previous_gate": previous_gate, "owner": "C011", "owning_item": item, "acceptance_gate": "C011.V", "fixture_id": fixture, "rust_case_ids": rust_case_ids, "rust_symbol": f"rust-tron/crates/tron-state/tests/khaos_contract.rs::{symbols[0]}"})
    return {"schema_version": 1, "chunk": "C011", "rows": rows}
def contract(schema, prefix, source_paths, fixture_document):
    rows = [row for row in fixture_document["rows"] if row["id"].startswith(prefix)]
    expected_ids = [case_id for case_id, _, _ in CASES if case_id.startswith(prefix)]
    if [row["id"] for row in rows] != expected_ids:
        raise ValueError(f"{schema} fixture coverage drift")
    return {
        "schema": schema,
        "schema_version": 1,
        "chunk": "C011",
        "java_revision": revision(),
        "sources": [{"path": path, "sha256": sha(ROOT / path)} for path in source_paths],
        "fixture_source": {
            "path": FIXTURES.relative_to(ROOT).as_posix(),
            "rows_sha256": hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        },
        "case_table": TEST.relative_to(ROOT).as_posix() + "::C011_CASE_TABLE",
        "case_count": len(rows),
        "cases": rows,
    }

def manifest(contracts):
    value = json.loads(MANIFEST.read_text())
    value["c011_khaos_contract"] = {
        "path": KHAOS_CONTRACT.name,
        "sha256": hashlib.sha256(dump(contracts[KHAOS_CONTRACT])).hexdigest(),
    }
    value["c011_fork_contract"] = {
        "path": FORK_CONTRACT.name,
        "sha256": hashlib.sha256(dump(contracts[FORK_CONTRACT])).hexdigest(),
    }
    return value
def verify_tracker(errors):
    tracker = json.loads(TRACKER.read_text()); chunk = next(c for c in tracker["chunks"] if c["id"] == "C011")
    if chunk["status"] != "active" or chunk["gate"]["status"] != "not_run": errors.append("C011 must remain active with gate not_run")
    if chunk["gate"]["commands"] != EXPECTED_COMMANDS: errors.append("C011 gate commands drift")
    if any(i["status"] != "done" for i in chunk["items"]): errors.append("all C011 implementation items must be done")
def verify_ownership(errors):
    ledger = json.loads(OWNERSHIP.read_text()); by_id = {r["id"]: r for r in ledger["rows"]}
    for stable_id, (_, item, _, rust_case_ids) in TEST_ROWS.items():
        row = by_id[stable_id]
        if (row.get("acceptance_gate"), row.get("owning_item"), row.get("rust_case_ids")) != ("C011.V", item, rust_case_ids):
            errors.append(f"C011 ownership not reassigned exactly: {stable_id}")
def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--write", action="store_true"); args = parser.parse_args()
    fixture_document = fixtures()
    contracts = {
        KHAOS_CONTRACT: contract("c011-khaos-contract.v1", "khaos:", SOURCES[0::2], fixture_document),
        FORK_CONTRACT: contract("c011-fork-contract.v1", "activation:", SOURCES[1::2], fixture_document),
    }
    artifacts = {INVENTORY: inventory(), FIXTURES: fixture_document, RECONCILIATION: reconciliation(), **contracts}
    expected_manifest = manifest(contracts)
    if args.write:
        for path, value in artifacts.items(): path.write_bytes(dump(value))
        MANIFEST.write_bytes(dump(expected_manifest))
    errors = []
    for path, value in artifacts.items():
        if not path.exists() or path.read_bytes() != dump(value): errors.append(f"stale generated artifact: {path.relative_to(ROOT)}")
    if not MANIFEST.exists() or MANIFEST.read_bytes() != dump(expected_manifest):
        errors.append(f"stale generated artifact registration: {MANIFEST.relative_to(ROOT)}")
    verify_tracker(errors); verify_ownership(errors)
    if errors:
        for error in errors: print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"C011 gate metadata OK: {len(CASES)} fixtures, {len(TEST_ROWS)} reconciled Java tests, {len(SOURCES)} pinned sources, 2 authenticated contracts")
    return 0
if __name__ == "__main__": raise SystemExit(main())
