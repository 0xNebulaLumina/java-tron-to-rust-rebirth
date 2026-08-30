#!/usr/bin/env python3
"""Generate and verify pinned-Java C009 evidence, lifecycle contracts, and Rust dispatch."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ORACLES = ROOT / "docs/oracles"
REVISION = "4a21592f95e37908b21bc3f611c6e7a1a67f09f3"
OWNERSHIP = ORACLES / "java-test-ownership.v1.json"
INVENTORY = ORACLES / "c009-revoking-source-inventory.v1.json"
FIXTURES = ORACLES / "c009-revoking-fixtures.v1.json"
RECONCILIATION = ORACLES / "c009-java-test-reconciliation.v1.json"
PRODUCTION = ORACLES / "production-ownership.v1.json"
PRODUCTION_RECONCILIATION = ORACLES / "c009-production-reconciliation.v1.json"
TRACKER = ROOT / "docs/PORTING_TRACKER.json"
POLICY = ROOT / "docs/architecture/security-threat-policy.md"
LIFECYCLE = ORACLES / "c009-state-lifecycle.v1.json"
LIFECYCLE_PAYLOAD_SHA256 = "6379b5e35b6958fc1c25d25a776313bb3cbc04fe171cd761a45554dcd0785ed1"
POLICY_MARKERS = (
    "capture the same immutable logical HEAD: the durable root plus every",
    "committed, non-abandoned overlay, while excluding all active speculative overlays",
    "Direct `DurableStore` reads are intentionally different and expose only the physical durable",
)
LIFECYCLE_ISOLATION = {
    "manager_read_view": "immutable durable root plus every committed non-abandoned overlay (logical HEAD); excludes active speculative overlays",
    "manager_session_view": "same immutable logical HEAD as manager_read_view; committed overlays remain visible before physical flush and active speculative overlays are excluded",
    "durable_store_read": "public physical durable-root read capability; excludes every overlay regardless of commit state",
    "durable_store_mutation": "rejected while any ordinary or pending session is active; checkpoint and flush root writes remain manager-locked",
    "session_parent_capability": "manager constructors create roots only at active depth zero; nested layers require the live top Session or PendingSession parent capability",
}
TEST = "rust-tron/crates/tron-state/tests/revoking_contract.rs"
EXPECTED_COMMANDS = [
    {"name": "C009 pinned Java and production reconciliation gate", "cwd": ".", "argv": ["python3", "tools/state/c009_gate.py"], "timeout_seconds": 300},
    {"name": "C009 complete revoking contract", "cwd": "rust-tron", "argv": ["cargo", "test", "-p", "tron-state", "--test", "revoking_contract", "--locked"], "timeout_seconds": 300},
    {"name": "C009 state workspace check", "cwd": "rust-tron", "argv": ["cargo", "check", "-p", "tron-state", "--all-targets", "--locked"], "timeout_seconds": 300},
]
REQUIRED_TEST_SYMBOLS = {
    "direct_java_snapshot_cases_dispatch_by_case_id",
    "exhaustive_45_store_transition_matrix_restores_root_after_revoke",
    "nested_commit_merge_pop_destroy_and_disabled_session_matrix",
    "committed_child_composes_with_parent_finalization_by_identity",
    "manager_view_exposes_committed_child_without_active_speculation",
    "checkpoint_publication_recovery_relink_retreat_and_limits",
    "checkpoint_publication_serializes_commits_and_competing_persists",
    "checkpoint_restart_history_and_retreat_publication_are_atomic",
    "pending_child_merge_reset_commit_close_and_drop_are_atomic",
    "failed_pending_commit_can_close_and_release_reservation",
    "cloned_manager_cannot_join_or_interfere_with_pending_stack",
    "durable_mutation_is_rejected_under_ordinary_session_and_revoke_preserves_root",
    "typed_cursor_fallback_clamp_offset_and_speculative_isolation",
    "cross_store_flush_and_view_capture_never_tear",
    "lifecycle_shutdown_flushes_committed_and_aggregates_disposition_errors",
}
DIRECT_CASES = {
    "RevokingDbWithCacheNewValueTest",
    "SnapshotImplTest",
    "SnapshotManagerTest",
    "SnapshotRootTest",
    "CheckpointV2Test",
}
BACKEND = {
    "CheckOrInitEngineTest", "DbDataSourceImplTest", "LevelDbDataSourceImplTest",
    "RocksDbDataSourceImplTest", "DBIteratorTest", "ChainbaseTest", "TxCacheDBInitTest",
    "TxCacheDBTest", "ByteArrayWrapperTest", "SerializedTest",
}
API_WORDS = ("Trigger", "Filter", "Logs")
FORK_WORDS = ("Fork", "fork", "ReOrg", "ReApply", "Branch", "branch", "SignVerified")
PENDING_WORDS = ("Pending", "Transaction", "transaction", "RePush", "processTransaction")
PROOFS = {
    stem: "direct_java_snapshot_cases_dispatch_by_case_id"
    for stem in DIRECT_CASES | {"TronDatabaseTest", "CheckPointV2StoreTest"}
}
PRODUCTION_PATH_OWNERS = {
    "java-tron/chainbase/README.md": ("C029.03", "C029.V"),
    "java-tron/chainbase/build.gradle": ("C029.03", "C029.V"),
    "org/tron/common/bloom/": ("C024.05", "C024.V"),
    "org/tron/common/error/": ("C007.07", "C007.V"),
    "org/tron/common/overlay/message/": ("C021.01", "C021.V"),
    "org/tron/common/runtime/CallCreate.java": ("C014.02", "C014.V"),
    "org/tron/common/runtime/InternalTransaction.java": ("C014.02", "C014.V"),
    "org/tron/common/runtime/ProgramResult.java": ("C016.05", "C016.V"),
    "org/tron/common/runtime/Runtime.java": ("C016.04", "C016.V"),
    "org/tron/common/storage/metric/": ("C025.05", "C025.V"),
    "org/tron/common/storage/": ("C007.01", "C007.V"),
    "org/tron/common/utils/Commons.java": ("C004.04", "C004.V"),
    "org/tron/common/utils/Fork": ("C011.03", "C011.V"),
    "org/tron/common/utils/LocalWitnesses.java": ("C003.05", "C003.V"),
    "org/tron/common/zksnark/": ("C006.04", "C006.V"),
    "org/tron/core/actuator/": ("C012.05", "C012.V"),
    "org/tron/core/config/args/": ("C003.02", "C003.V"),
    "org/tron/core/db2/common/ConcurrentHashDB.java": ("C007.01", "C007.V"),
    "org/tron/core/db2/common/DB.java": ("C007.01", "C007.V"),
    "org/tron/core/db2/common/HashDB.java": ("C007.01", "C007.V"),
    "org/tron/core/db2/common/Instance.java": ("C007.01", "C007.V"),
    "org/tron/core/db2/common/LevelDB.java": ("C007.01", "C007.V"),
    "org/tron/core/db2/common/RocksDB.java": ("C007.01", "C007.V"),
    "org/tron/core/db2/common/TxCacheDB.java": ("C016.06", "C016.V"),
    "org/tron/core/db2/common/Key.java": ("C002.02", "C002.V"),
    "org/tron/core/db2/common/WrappedByteArray.java": ("C002.02", "C002.V"),
    "org/tron/core/db2/core/ITronChainBase.java": ("C008.11", "C008.V"),
    "org/tron/core/net/message/": ("C021.01", "C021.V"),
    "org/tron/core/service/": ("C017.04", "C017.V"),
}

RETAINED_PRODUCTION_FILES = {
    "Value.java", "Flusher.java", "IRevokingDB.java", "AbstractSnapshot.java",
    "Snapshot.java", "SnapshotImpl.java", "SnapshotManager.java", "SnapshotRoot.java",
}

RUST_PRODUCTION_SOURCES = {
    "Value.java": "rust-tron/crates/tron-state/src/session.rs::OverlayValue",
    "Flusher.java": "rust-tron/crates/tron-state/src/checkpoint.rs::CheckpointStack::flush_bounded",
    "IRevokingDB.java": "rust-tron/crates/tron-state/src/session.rs::SessionManager",
    "AbstractSnapshot.java": "rust-tron/crates/tron-state/src/session.rs::ReadView",
    "Snapshot.java": "rust-tron/crates/tron-state/src/session.rs::ReadView",
    "SnapshotImpl.java": "rust-tron/crates/tron-state/src/session.rs::OverlayStore",
    "SnapshotRoot.java": "rust-tron/crates/tron-state/src/store.rs::StateStore",
}

def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def dump(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()

def ledger_rows() -> list[dict]:
    ledger = json.loads(OWNERSHIP.read_text())
    return [row for row in ledger["rows"] if row.get("acceptance_gate") == "C009.V"]

def c009_production_rows(ledger: dict) -> list[dict]:
    if PRODUCTION_RECONCILIATION.is_file():
        ids = {row["stable_id"] for row in json.loads(PRODUCTION_RECONCILIATION.read_text())["rows"]}
        return [row for row in ledger["rows"] if row["id"] in ids]
    return [row for row in ledger["rows"] if row.get("acceptance_gate") == "C009.V" or row.get("owning_item") == "C009.06"]

def retained_production(row: dict) -> bool:
    path = row["source"]["path"]
    stem = Path(path).name
    if stem in RETAINED_PRODUCTION_FILES:
        return True
    if stem == "Chainbase.java":
        return row["symbol"] in {"Cursor", "setCursor", "getCursor", "getHead", "setHead"}
    if stem == "ChainBaseManager.java":
        return row["symbol"] in {"getHeadBlockId", "getHeadBlockNum", "getHeadBlockTimeStamp", "getSolidBlockId"}
    return False

def retained_rust_symbol(row: dict) -> str:
    stem, symbol = Path(row["source"]["path"]).name, row["symbol"]
    if stem == "SnapshotManager.java":
        target = {
            "buildSession": "SessionManager::build_session_enabled", "setCursor": "SessionManager::record_checkpoint",
            "add": "SessionManager::build_session_enabled", "merge": "Session::merge", "revoke": "Session::revoke",
            "commit": "Session::commit", "pop": "SessionManager::pop", "fastPop": "SessionManager::pop",
            "enable": "SessionManager::enable", "disable": "SessionManager::disable", "size": "SessionManager::depth",
            "shutdown": "SessionManager::shutdown_aggregated", "updateSolidity": "SessionManager::record_checkpoint",
            "flush": "CheckpointStack::flush_bounded", "createCheckpoint": "CheckpointStack::persist",
            "getCheckpointList": "SessionManager::committed_checkpoints", "check": "CheckpointStack::recover",
            "Session": "Session", "destroy": "Session::close", "close": "Session::close",
        }.get(symbol, "SessionManager")
        source = "checkpoint.rs" if target.startswith("CheckpointStack") else "session.rs"
        return f"rust-tron/crates/tron-state/src/{source}::{target}"
    if stem == "Chainbase.java" or stem == "ChainBaseManager.java":
        return "rust-tron/crates/tron-state/src/cursor.rs::CursorSet"
    return RUST_PRODUCTION_SOURCES[stem]

def reassigned_production_owner(row: dict) -> tuple[str, str]:
    path, symbol = row["source"]["path"], row["symbol"]
    if path.endswith("StorageUtils.java"):
        return (("C014.05", "C014.V") if symbol == "getEnergyLimitHardFork" else ("C007.01", "C007.V"))
    if path.endswith("WalletUtil.java"):
        if symbol in {"generateContractAddress", "generateContractAddress2"}: return "C004.06", "C004.V"
        if symbol == "isConstant": return "C016.04", "C016.V"
        if symbol == "getSelector": return "C014.02", "C014.V"
        return "C002.02", "C002.V"
    if path.endswith("ChainBaseManager.java"):
        if symbol == "initGenesis": return "C010.01", "C010.V"
        if symbol in {"getWitnesses", "addWitness", "getHeadSlot", "getNextBlockSlotTime"}: return "C017.01", "C017.V"
        if symbol == "shutdown": return "C025.07", "C025.V"
        if symbol == "isLiteNode": return "C003.02", "C003.V"
        return "C019.01", "C019.V"
    if path.endswith("Chainbase.java"):
        if symbol in {"close", "reset"}: return "C007.01", "C007.V"
        return "C008.11", "C008.V"
    for marker, target in PRODUCTION_PATH_OWNERS.items():
        if marker == path or marker in path:
            return target
    raise ValueError(f"unclassified C009 production row: {row['id']} {path}::{symbol}")

def production_reconciliation(ledger: dict) -> dict:
    result = []
    for row in c009_production_rows(ledger):
        base = {"stable_id": row["id"], "java_source": row["source"]["path"], "java_line": row["source"]["line"], "java_symbol": row["symbol"]}
        if retained_production(row):
            result.append(base | {"disposition": "rust", "owner": "C009", "owning_item": "C009.06", "acceptance_gate": "C009.V", "rust_symbol": retained_rust_symbol(row)})
        else:
            item, gate = reassigned_production_owner(row)
            result.append(base | {"disposition": "reassigned", "owner": item.split(".", 1)[0], "owning_item": item, "acceptance_gate": gate})
    return {"schema_version": 1, "java_revision": REVISION, "source_row_count": len(result), "rows": result}
def is_direct(row: dict) -> bool:
    stem = Path(row["source"]["path"]).stem
    if stem in DIRECT_CASES:
        return True
    return (stem == "TronDatabaseTest" and row["case"] == "TestGetFromRoot") or (stem == "CheckPointV2StoreTest" and row["case"] == "testStubMethods")

def owner(row: dict) -> tuple[str, str]:
    stem, case = Path(row["source"]["path"]).stem, row["case"]
    if stem in BACKEND or stem in {"TronDatabaseTest", "CheckPointV2StoreTest"}:
        return "C007", "Physical backend, engine selection, iterator/resource lifecycle, and root-store plumbing belong to C007."
    if stem == "KhaosDatabaseTest" or any(word in case for word in FORK_WORDS):
        return "C019", "Fork graph, branch switching, replay, and signature-cache invalidation belong to C019."
    if any(word in case for word in API_WORDS):
        return "C024", "Filter, trigger, and externally observed API/event routing belong to C024."
    if stem in {"ManagerTest", "ManagerMockTest"} and any(word in case for word in PENDING_WORDS):
        return "C016", "Admission, transaction processing, pending capacity, and requeue behavior belong to C016."
    return "C029", "This manager, VM-history, utility, or cross-cutting regression case is outside the C009 revoking primitive and remains explicit C029 closure work."

def documents() -> dict[Path, dict]:
    rows = ledger_rows()
    source_paths = sorted({row["source"]["path"] for row in rows})
    inventory = {
        "schema_version": 1,
        "java_revision": REVISION,
        "sources": [{"path": path, "sha256": sha(ROOT / path), "case_count": sum(row["source"]["path"] == path for row in rows)} for path in source_paths],
        "source_count": len(source_paths),
        "case_count": len(rows),
    }
    reconciliation = []
    for row in rows:
        base = {"stable_id": row["id"], "java_source": row["source"]["path"], "java_line": row["source"]["line"], "java_case": row["case"]}
        if is_direct(row):
            stem = Path(row["source"]["path"]).stem
            case_id = f"snapshot::{row['id']}"
            reconciliation.append(base | {"disposition": "rust", "owner": "C009", "rust_symbol": f"{TEST}::{PROOFS[stem]}", "rust_case_id": case_id, "dispatch_kind": "parameterized_case"})
        else:
            target, rationale = owner(row)
            reconciliation.append(base | {"disposition": "reassigned", "owner": target, "rationale": rationale})
    stores = [match.group(1) for match in re.finditer(r"Self::([A-Za-z0-9]+)", (ROOT / "rust-tron/crates/tron-state/src/store.rs").read_text().split("pub const ALL", 1)[1].split("];", 1)[0])]
    transitions = ["root_put", "outer_put", "child_put", "child_merge", "outer_revoke", "root_restored"]
    direct_case_ids = [row["rust_case_id"] for row in reconciliation if row["disposition"] == "rust"]
    test_text = (ROOT / TEST).read_text()
    test_symbols = re.findall(r"#\[test\]\s*fn\s+([a-zA-Z0-9_]+)\s*\(", test_text)
    fixtures = {
        "schema_version": 1,
        "java_revision": REVISION,
        "test_symbols": test_symbols,
        "java_snapshot_cases": [{"case_id": case_id, "proof": f"{TEST}::direct_java_snapshot_cases_dispatch_by_case_id"} for case_id in direct_case_ids],
        "transition_matrix": [{"store": store, "case_id": f"store::{store}", "transitions": transitions, "proof": f"{TEST}::exhaustive_45_store_transition_matrix_restores_root_after_revoke"} for store in stores],
        "checkpoint_cases": [
            *[{"case_id": f"checkpoint::{phase}", "phase": phase, "proof": f"{TEST}::checkpoint_publication_recovery_relink_retreat_and_limits"} for phase in ["BeforeStage", "AfterStage", "BeforePublish", "AfterPublish"]],
            {"case_id": "checkpoint::publication-linearization", "proof": f"{TEST}::checkpoint_publication_serializes_commits_and_competing_persists"},
            {"case_id": "checkpoint::restart-history", "proof": f"{TEST}::checkpoint_restart_history_and_retreat_publication_are_atomic"},
            {"case_id": "checkpoint::failed-retreat-publication", "proof": f"{TEST}::checkpoint_restart_history_and_retreat_publication_are_atomic"},
            {"case_id": "checkpoint::successful-retreat-publication", "proof": f"{TEST}::checkpoint_restart_history_and_retreat_publication_are_atomic"},
            {"case_id": "checkpoint::envelope-exact-max-bytes", "proof": f"{TEST}::checkpoint_publication_recovery_relink_retreat_and_limits"},
            {"case_id": "checkpoint::envelope-one-over-max-bytes", "proof": f"{TEST}::checkpoint_publication_recovery_relink_retreat_and_limits"},
            {"case_id": "checkpoint::internal-metadata-isolation", "proof": f"{TEST}::checkpoint_publication_recovery_relink_retreat_and_limits"},
            {"case_id": "checkpoint::constant-state-bounded-publication", "proof": f"{TEST}::checkpoint_publication_recovery_relink_retreat_and_limits"},
        ],
        "cursor_cases": [
            *[{"case_id": case_id, "proof": f"{TEST}::typed_cursor_fallback_clamp_offset_and_speculative_isolation"}
              for case_id in ["cursor::typed-offset", "cursor::negative-offset-error", "cursor::missing-pbft-fallback", "cursor::durable-read-isolation", "cursor::immutable-checkpoint-history", "cursor::identity-ancestry-validation"]],
            {"case_id": "cursor::fresh-manager-restart", "proof": f"{TEST}::checkpoint_restart_history_and_retreat_publication_are_atomic"},
            {"case_id": "cursor::retreat-removes-heads", "proof": f"{TEST}::checkpoint_restart_history_and_retreat_publication_are_atomic"},
        ],
        "pending_cases": [
            {"case_id": "pending::child-merge-reset-commit-close-drop", "proof": f"{TEST}::pending_child_merge_reset_commit_close_and_drop_are_atomic"},
            {"case_id": "pending::failed-commit-close-reservation", "proof": f"{TEST}::failed_pending_commit_can_close_and_release_reservation"},
        ],
        "transition_cases": [
            {"case_id": "session::commit-merge-pop-destroy-disabled", "proof": f"{TEST}::nested_commit_merge_pop_destroy_and_disabled_session_matrix"},
            {"case_id": "session::committed-child-parent-finalization", "proof": f"{TEST}::committed_child_composes_with_parent_finalization_by_identity"},
        ],
        "isolation_cases": [
            {"case_id": "isolation::cross-store-flush-view-race", "proof": f"{TEST}::cross_store_flush_and_view_capture_never_tear"},
            {"case_id": "isolation::manager-clone-parent-capability", "proof": f"{TEST}::cloned_manager_cannot_join_or_interfere_with_pending_stack"},
            {"case_id": "isolation::pending-child-capability", "proof": f"{TEST}::cloned_manager_cannot_join_or_interfere_with_pending_stack"},
            {"case_id": "isolation::durable-mutation-active-rejection", "proof": f"{TEST}::durable_mutation_is_rejected_under_ordinary_session_and_revoke_preserves_root"},
            {"case_id": "isolation::revoke-preserves-durable-root", "proof": f"{TEST}::durable_mutation_is_rejected_under_ordinary_session_and_revoke_preserves_root"},
            {"case_id": "shutdown::flush-and-error-aggregation", "proof": f"{TEST}::lifecycle_shutdown_flushes_committed_and_aggregates_disposition_errors"},
        ],
    }
    production = json.loads(PRODUCTION.read_text())
    return {
        INVENTORY: inventory,
        RECONCILIATION: {"schema_version": 1, "java_revision": REVISION, "rows": reconciliation},
        PRODUCTION_RECONCILIATION: production_reconciliation(production),
        FIXTURES: fixtures,
    }

def verify(errors: list[str], expected: dict[Path, dict]) -> None:
    actual_revision = subprocess.check_output(["git", "-C", str(ROOT / "java-tron"), "rev-parse", "HEAD"], text=True).strip()
    if actual_revision != REVISION:
        errors.append(f"java-tron revision drift: {actual_revision}")
    if not POLICY.is_file():
        errors.append("missing C009 security policy")
    else:
        policy_text = POLICY.read_text()
        if any(marker not in policy_text for marker in POLICY_MARKERS):
            errors.append("C009 security policy read-view markers drift")
    if not LIFECYCLE.is_file():
        errors.append("missing C009 state-lifecycle oracle")
    else:
        if sha(LIFECYCLE) != LIFECYCLE_PAYLOAD_SHA256:
            errors.append("C009 state-lifecycle payload digest drift")
        try:
            lifecycle = json.loads(LIFECYCLE.read_text())
        except json.JSONDecodeError as error:
            errors.append(f"invalid C009 state-lifecycle oracle: {error}")
        else:
            isolation = lifecycle.get("isolation", {})
            if any(isolation.get(key) != value for key, value in LIFECYCLE_ISOLATION.items()):
                errors.append("C009 state-lifecycle read-view markers drift")
    fixtures = expected[FIXTURES]
    if len(fixtures["transition_matrix"]) != 45 or len({row["store"] for row in fixtures["transition_matrix"]}) != 45:
        errors.append("transition matrix must exhaust exactly 45 logical stores")
    reconciliation = expected[RECONCILIATION]["rows"]
    ledger_ids = {row["id"] for row in ledger_rows()}
    if len(reconciliation) != 155 or {row["stable_id"] for row in reconciliation} != ledger_ids:
        errors.append("C009 reconciliation must match exactly 155 stable Java-test rows")
    direct = [row for row in reconciliation if row["disposition"] == "rust"]
    direct_ids = [row.get("rust_case_id") for row in direct]
    if len(direct) != 23 or any(row["owner"] != "C009" or row.get("dispatch_kind") != "parameterized_case" for row in direct):
        errors.append("exactly 23 snapshot cases must have concrete parameterized C009 dispatch")
    reassigned = [row for row in reconciliation if row["disposition"] == "reassigned"]
    if {row["owner"] for row in reassigned} != {"C007", "C016", "C019", "C024", "C029"}:
        errors.append("provisional backend/manager/fork/API rows must be reassigned only and completely to C007/C016/C019/C024/C029")
    test = (ROOT / TEST).read_text()
    dispatched_ids = re.findall(r'JavaSnapshotCase\s*\{\s*case_id:\s*"([^"]+)"', test)
    fixture_ids = [row["case_id"] for row in fixtures["java_snapshot_cases"]]
    if len(dispatched_ids) != 23 or len(set(dispatched_ids)) != 23 or set(dispatched_ids) != set(direct_ids) or fixture_ids != direct_ids:
        errors.append("all 23 reconciliation case IDs must be uniquely dispatched by the parameterized Rust case table")
    actual_test_symbols = re.findall(r"#\[test\]\s*fn\s+([a-zA-Z0-9_]+)\s*\(", test)
    if fixtures["test_symbols"] != actual_test_symbols or len(actual_test_symbols) != len(set(actual_test_symbols)):
        errors.append("revoking-contract test inventory must exactly match every executable #[test] symbol")
    if set(actual_test_symbols) != REQUIRED_TEST_SYMBOLS:
        errors.append(f"revoking-contract target must expose exactly the canonical C009 test symbols: {sorted(REQUIRED_TEST_SYMBOLS)}")
    fixture_symbols = {case["proof"].rsplit("::", 1)[-1] for group in ("transition_matrix", "checkpoint_cases", "cursor_cases", "pending_cases", "transition_cases", "isolation_cases") for case in fixtures[group]}
    if not fixture_symbols.issubset(set(actual_test_symbols)):
        errors.append("every C009 fixture proof must dispatch to an executable Rust test")
    production = expected[PRODUCTION_RECONCILIATION]
    production_rows = c009_production_rows(json.loads(PRODUCTION.read_text()))
    if production["source_row_count"] != 604 or len(production["rows"]) != 604 or len({row["stable_id"] for row in production["rows"]}) != 604:
        errors.append("C009 production reconciliation must contain exactly 604 unique stable IDs")
    if {row["stable_id"] for row in production["rows"]} != {row["id"] for row in production_rows}:
        errors.append("C009 production reconciliation IDs must exactly match the original C009.V/C009.06 set")
    retained = [row for row in production["rows"] if row["disposition"] == "rust"]
    if not retained or any(row.get("owner") != "C009" or not row.get("rust_symbol") for row in retained):
        errors.append("retained C009 production rows must be exact session/snapshot/cursor rows with Rust symbols")
    for row in retained:
        source, symbol = row["rust_symbol"].split("::", 1)
        source_text = (ROOT / source).read_text()
        leaf = symbol.rsplit("::", 1)[-1]
        if not re.search(rf"\b{re.escape(leaf)}\b", source_text):
            errors.append(f"missing retained production Rust symbol for {row['stable_id']}: {row['rust_symbol']}")
    desired = {row["stable_id"]: (row["owning_item"], row["acceptance_gate"]) for row in production["rows"]}
    if any((row.get("owning_item"), row.get("acceptance_gate")) != desired[row["id"]] for row in production_rows):
        errors.append("production ownership ledger does not match the exact C009 reconciliation")

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    try:
        expected = documents()
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        print(f"C009 oracle failed: {error}", file=sys.stderr)
        return 1
    if args.write:
        production = json.loads(PRODUCTION.read_text())
        desired = {row["stable_id"]: row for row in expected[PRODUCTION_RECONCILIATION]["rows"]}
        for row in production["rows"]:
            if row["id"] in desired:
                row["owning_item"] = desired[row["id"]]["owning_item"]
                row["acceptance_gate"] = desired[row["id"]]["acceptance_gate"]
        PRODUCTION.write_bytes(dump(production))
        for path, value in expected.items():
            path.write_bytes(dump(value))
        return 0
    errors: list[str] = []
    for path, value in expected.items():
        if not path.is_file() or path.read_bytes() != dump(value):
            errors.append(f"generated oracle drift: {path.relative_to(ROOT)}; run with --write")
    tracker = json.loads(TRACKER.read_text())
    c009 = next((chunk for chunk in tracker.get("chunks", []) if chunk.get("id") == "C009"), None)
    statuses = {item.get("status") for item in c009.get("items", [])} if c009 else set()
    if not c009 or c009.get("status") != "active" or statuses != {"doing"} or c009.get("gate", {}).get("status") != "not_run" or c009.get("gate", {}).get("commands") != EXPECTED_COMMANDS:
        errors.append("C009 tracker must be active with all items doing, canonical commands, and gate not_run")
    verify(errors, expected)
    if errors:
        print("C009 gate failed:", *errors, sep="\n- ", file=sys.stderr)
        return 1
    print(f"C009 gate passed: 45 stores, 155 Java cases, 23 direct case-ID dispatches, 604 exact production rows, {len(REQUIRED_TEST_SYMBOLS)} executable Rust tests")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
