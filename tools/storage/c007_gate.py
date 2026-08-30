#!/usr/bin/env python3
"""C007 storage inventory, format-vector, reconciliation and platform gate."""
from __future__ import annotations

import json
import platform
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ORACLES = ROOT / "docs/oracles"
TRACKER = ROOT / "docs/PORTING_TRACKER.json"
TEST_ROOT = ROOT / "rust-tron/crates/tron-storage/tests"
REVISION = "4a21592f95e37908b21bc3f611c6e7a1a67f09f3"
EXPECTED_COMMANDS = [
    {"name":"C007 inventory, vectors and matrix gate","cwd":".","argv":["python3","tools/storage/c007_gate.py"],"timeout_seconds":300},
    {"name":"C007 backend, ordering, batch and reopen","cwd":"rust-tron","argv":["cargo","test","-p","tron-storage","--test","backend_contract","--test","market_order","--locked"],"timeout_seconds":300},
    {"name":"C007 manifest, reject, migration, rollback, resume, snapshot and resync","cwd":"rust-tron","argv":["cargo","test","-p","tron-storage","--test","format_contract","--locked"],"timeout_seconds":300},
    {"name":"C007 crash, corrupt, lock, permission and disk-full categories","cwd":"rust-tron","argv":["cargo","test","-p","tron-storage","--test","failure_contract","--locked"],"timeout_seconds":300},
    {"name":"C007 pure-Rust storage all-targets check","cwd":"rust-tron","argv":["cargo","check","-p","tron-storage","--all-targets","--locked"],"timeout_seconds":300}
]
FILES = {
    "inventory": ORACLES / "c007-storage-source-inventory.v1.json",
    "vectors": ORACLES / "c007-rustlog-format-vectors.v1.json",
    "reconciliation": ORACLES / "c007-storage-reconciliation.v1.json",
    "matrix": ORACLES / "c007-storage-matrix.v1.json",
}
PRODUCTION_LEDGER = ORACLES / "production-ownership.v1.json"
JAVA_TEST_LEDGER = ORACLES / "java-test-ownership.v1.json"


def test_command_name(path: str) -> str | None:
    test_name = Path(path).stem
    for command in EXPECTED_COMMANDS:
        argv = command["argv"]
        if "--test" in argv and test_name in argv:
            return command["name"]
    return None
def rust_enum_variants(source: str, enum_name: str) -> list[str]:
    match = re.search(rf"\benum\s+{re.escape(enum_name)}\s*\{{", source)
    if not match:
        return []
    depth = 1
    index = match.end()
    body_start = index
    while index < len(source) and depth:
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
        index += 1
    body = source[body_start:index - 1]
    variants: list[str] = []
    depth = 0
    token_start = 0
    for offset, character in enumerate(body + ","):
        if character in "({[":
            depth += 1
        elif character in ")} ]".replace(" ", ""):
            depth -= 1
        elif character == "," and depth == 0:
            token = body[token_start:offset].strip()
            name = re.match(r"([A-Za-z][A-Za-z0-9_]*)", token)
            if name:
                variants.append(name.group(1))
            token_start = offset + 1
    return variants

def rust_function_body(source: str, function_name: str) -> str:
    match = re.search(rf"\bfn\s+{re.escape(function_name)}\s*\([^)]*\)[^{{]*\{{", source)
    if not match:
        return ""
    depth = 1
    index = match.end()
    body_start = index
    while index < len(source) and depth:
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
        index += 1
    return source[body_start:index - 1] if depth == 0 else ""


def durable_phases_used_by(source: str, function_name: str) -> list[str]:
    enum_variants = rust_enum_variants(source, "DurablePhase")
    body = rust_function_body(source, function_name)
    used = set(re.findall(r"\bDurablePhase::([A-Za-z][A-Za-z0-9_]*)", body))
    return [variant for variant in enum_variants if variant in used]


def load(path: Path, errors: list[str]) -> dict:
    try:
        value = json.loads(path.read_text())
    except Exception as error:
        errors.append(f"{path.relative_to(ROOT)}: {error}")
        return {}
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        errors.append(f"{path.relative_to(ROOT)} must be a schema_version 1 object")
    return value


def main() -> int:
    errors: list[str] = []
    docs = {name: load(path, errors) for name, path in FILES.items()}
    tracker = json.loads(TRACKER.read_text())
    c007 = next((row for row in tracker.get("chunks", []) if row.get("id") == "C007"), None)
    if not c007 or c007.get("gate", {}).get("commands") != EXPECTED_COMMANDS:
        errors.append("C007 tracker commands must match the canonical stored gate exactly")
    pre_run_item_statuses = {
        "C007.01": "doing",
        **{f"C007.{index:02d}": "todo" for index in range(2, 8)},
    }
    post_closure_item_statuses = {f"C007.{index:02d}": "done" for index in range(1, 8)}
    item_statuses = {item.get("id"): item.get("status") for item in c007.get("items", [])} if c007 else {}
    chunk_status = c007.get("status") if c007 else None
    gate_status = c007.get("gate", {}).get("status") if c007 else None
    review_state = c007.get("review", {}).get("state") if c007 else None
    pre_run_state = (
        chunk_status == "active"
        and item_statuses == pre_run_item_statuses
        and gate_status == "not_run"
        and review_state == "not_started"
    )
    post_closure_state = (
        chunk_status == "done"
        and item_statuses == post_closure_item_statuses
        and gate_status == "passed"
        and review_state == "approved"
        and c007.get("resume") is None
    ) if c007 else False
    if not (pre_run_state or post_closure_state):
        errors.append(
            "C007 tracker state must be either the complete pre-run state "
            "(active, C007.01 doing, C007.02-.07 todo, gate not_run, review not_started) "
            "or the complete post-closure state "
            "(done, all items done, gate passed, review approved, resume null)"
        )

    inventory = docs["inventory"]
    if inventory.get("java_revision") != REVISION:
        errors.append("C007 Java revision drift")
    try:
        revision = subprocess.check_output(["git", "-C", str(ROOT / "java-tron"), "rev-parse", "HEAD"], text=True).strip()
        if revision != REVISION: errors.append(f"java-tron gitlink drift: {revision}")
    except Exception as error:
        errors.append(f"cannot authenticate java-tron revision: {error}")
    production = json.loads(PRODUCTION_LEDGER.read_text())
    production_rows = production.get("rows", [])
    for row in inventory.get("sources", []):
        source_path = row.get("path", "")
        path = ROOT / source_path
        canonical = [entry for entry in production_rows if entry.get("kind") == "source_file" and entry.get("source", {}).get("path") == source_path]
        if not path.is_file() or len(canonical) != 1 or not row.get("c007_contract"):
            errors.append(f"missing, ambiguous or incomplete C007 Java source row: {source_path}")
            continue
        owner, gate = canonical[0].get("owning_item"), canonical[0].get("acceptance_gate")
        if (row.get("canonical_owner"), row.get("canonical_gate")) != (owner, gate):
            errors.append(f"C007 Java source ownership conflicts with canonical ledger: {source_path}")
    expected_sources = {
        "java-tron/chainbase/src/main/java/org/tron/core/db/common/DbSourceInter.java",
        "java-tron/chainbase/src/main/java/org/tron/common/storage/leveldb/LevelDbDataSourceImpl.java",
        "java-tron/chainbase/src/main/java/org/tron/common/storage/rocksdb/RocksDbDataSourceImpl.java",
        "java-tron/chainbase/src/main/java/org/tron/common/utils/StorageUtils.java",
        "java-tron/platform/src/main/java/common/org/tron/common/utils/MarketOrderPriceComparatorForLevelDB.java",
        "java-tron/platform/src/main/java/x86/org/tron/common/utils/MarketOrderPriceComparatorForRocksDB.java",
        "java-tron/platform/src/main/java/arm/org/tron/common/utils/MarketOrderPriceComparatorForRocksDB.java",
    }
    inventory_sources = [row.get("path") for row in inventory.get("sources", [])]
    if set(inventory_sources) != expected_sources or len(inventory_sources) != len(expected_sources):
        errors.append("C007 Java source inventory is incomplete or contains duplicate sources")
    expected_markers = {"engine.properties", "CURRENT", "LOG", "LOG.old", "LOCK", "MANIFEST-", "OPTIONS-", ".sst", ".ldb", "IDENTITY"}
    markers = {row.get("name") or row.get("prefix") or row.get("suffix") for row in inventory.get("java_markers", [])}
    if markers != expected_markers: errors.append("Java marker inventory must exactly match the read-only classifier")

    vectors = docs["vectors"]
    expected_hex = {"empty-wal":"524c4f4757414c31", "put-a-1":"010000000001000000610100000031", "delete-a":"01000000010100000061", "empty-snapshot-file":"524c4f47534e503104000000000000001cdf442100000000"}
    vector_rows = vectors.get("vectors", [])
    vector_ids = [row.get("id") for row in vector_rows]
    actual_hex = {row.get("id"): row.get("hex") for row in vector_rows if "hex" in row}
    expected_vector_ids = [*expected_hex, "too-many-snapshot-entries", "write-commit-points"]
    if actual_hex != expected_hex or vector_ids != expected_vector_ids or len(vector_ids) != len(set(vector_ids)):
        errors.append("rustlog-v1 canonical byte and corruption vectors must be exact and duplicate-free")
    corruption_rows = [row for row in vector_rows if row.get("kind") == "corruption"]
    corruption_variants = [row.get("variant") for row in corruption_rows]
    if corruption_variants != ["TooManySnapshotEntries"] or len(corruption_variants) != len(set(corruption_variants)):
        errors.append("rustlog-v1 corruption vectors must uniquely enumerate the added corruption contract")
    for row in corruption_rows:
        proof = row.get("proof", {})
        proof_file, symbol = proof.get("file", ""), proof.get("symbol", "")
        path = ROOT / proof_file
        text = path.read_text() if path.is_file() else ""
        body = rust_function_body(text, symbol)
        if test_command_name(proof_file) is None or not body or f"Corruption::{row.get('variant')}" not in body:
            errors.append(f"corruption vector lacks an executable variant-specific proof: {row.get('id')}")
    if vectors.get("checksum") != "CRC-32/ISO-HDLC over the frame payload or snapshot body": errors.append("rustlog checksum contract drifted")
    write_contract = next((row for row in vector_rows if row.get("id") == "write-commit-points"), {})
    expected_write_phases = ["Append", "Flush", "Sync", "Truncate", "RollbackSync", "Metadata", "Compaction"]
    if (
        write_contract.get("kind") != "write_failure_contract"
        or write_contract.get("phases") != expected_write_phases
        or write_contract.get("pre_commit_error") != "Io"
        or write_contract.get("rollback_error") != "Poisoned"
        or write_contract.get("post_commit_error_channel") != "maintenance_error"
    ):
        errors.append("rustlog-v1 write commit-point vector must map every phase and error channel exactly")
    expected_write_proofs = {
        ("rust-tron/crates/tron-storage/tests/failure_contract.rs", "write_commit_points_are_atomic_across_reopen"),
        ("rust-tron/crates/tron-storage/tests/failure_contract.rs", "rollback_failures_poison_reject_operations_and_retain_lock"),
        ("rust-tron/crates/tron-storage/tests/failure_contract.rs", "post_commit_metadata_and_compaction_failures_are_maintenance_errors"),
        ("rust-tron/crates/tron-storage/tests/backend_contract.rs", "default_write_policy_defers_sync_but_consuming_close_is_durable"),
    }
    actual_write_proofs = {(proof.get("file"), proof.get("symbol")) for proof in write_contract.get("proofs", [])}
    if actual_write_proofs != expected_write_proofs or len(write_contract.get("proofs", [])) != len(expected_write_proofs):
        errors.append("rustlog-v1 write commit-point vector must have exact duplicate-free executable proofs")
    for proof_file, symbol in actual_write_proofs:
        path = ROOT / proof_file
        text = path.read_text() if path.is_file() else ""
        if test_command_name(proof_file) is None or not rust_function_body(text, symbol):
            errors.append(f"write commit-point vector lacks executable proof: {proof_file}::{symbol}")
    snapshot_bound = "Snapshot encoding and decoding enforce the same max_snapshot_entries bound; over-limit encoding fails before a temporary snapshot file is created."
    if snapshot_bound not in vectors.get("invariants", []): errors.append("rustlog snapshot entry bound contract drifted")
    storage_source = (ROOT / "rust-tron/crates/tron-storage/src/lib.rs").read_text()
    encode_snapshot_body = rust_function_body(storage_source, "encode_snapshot")
    decode_snapshot_body = rust_function_body(storage_source, "decode_snapshot")
    if "options.max_snapshot_entries" not in encode_snapshot_body or "options.max_snapshot_entries" not in decode_snapshot_body:
        errors.append("C007 snapshot encode/decode entry bounds must remain consistent")

    reconciliation = docs["reconciliation"]
    java_test_rows = [row for row in json.loads(JAVA_TEST_LEDGER.read_text()).get("rows", []) if row.get("acceptance_gate") == "C007.V"]
    java_test_ids = [row.get("id") for row in java_test_rows]
    if reconciliation.get("status") != "reconciled_to_canonical_ledgers":
        errors.append("C007 Java reconciliation must be final and ledger-backed")
    if reconciliation.get("java_test_ledger_rows") != len(java_test_rows) or reconciliation.get("java_test_ledger_row_ids") != java_test_ids:
        errors.append("C007 Java test reconciliation disagrees with the canonical Java-test ledger")
    for proof in reconciliation.get("rust_proofs", []):
        path = ROOT / proof.get("file", "")
        text = path.read_text() if path.is_file() else ""
        for symbol in proof.get("symbols", []):
            if not re.search(rf"\bfn\s+{re.escape(symbol)}\s*\(", text): errors.append(f"missing Rust proof symbol: {symbol}")

    matrix = docs["matrix"]
    rows = {row.get("id"): row for row in matrix.get("rows", [])}
    x64, arm64 = rows.get("P-LINUX-X64", {}), rows.get("P-LINUX-ARM64", {})
    expected_platform_commands = {command["name"] for command in EXPECTED_COMMANDS if command["name"] != "C007 inventory, vectors and matrix gate"}
    if (x64.get("enabled"), x64.get("state"), x64.get("os"), x64.get("architecture"), x64.get("target"), x64.get("runtime"), x64.get("ffi")) != (True, "qualification", "linux", "x86_64", "x86_64-unknown-linux-gnu", "pure-rust", "none"):
        errors.append("Linux x86_64 must be the explicit sole enabled pure-Rust C007 qualification row")
    if set(x64.get("commands", [])) != expected_platform_commands:
        errors.append("enabled Linux x86_64 row must run every canonical C007 proof command")
    if arm64.get("enabled") is not False or arm64.get("state") != "future" or arm64.get("evidence") or arm64.get("commands"):
        errors.append("Linux aarch64 must remain an unproved future row")
    required_scenarios = {"backend","writable_rejection","initialization_locking","initialization_classification","initialization_recovery","ordering","filesystem_security","batch_atomicity","reopen","durable_close","write_commit_points","checkpoint","crash","corrupt","lock","permission","diskfull","migration","rollback","resume","snapshot","resource_bounds","resync"}
    scenarios = matrix.get("scenarios", [])
    scenario_ids = [row.get("id") for row in scenarios]
    missing_scenarios = required_scenarios - set(scenario_ids)
    unexpected_scenarios = set(scenario_ids) - required_scenarios
    duplicate_scenarios = {scenario_id for scenario_id in scenario_ids if scenario_ids.count(scenario_id) > 1}
    if missing_scenarios:
        errors.append(f"C007 scenario matrix is missing scenarios: {', '.join(sorted(missing_scenarios))}")
    if unexpected_scenarios:
        errors.append(f"C007 scenario matrix contains unexpected scenarios: {', '.join(sorted(unexpected_scenarios))}")
    if duplicate_scenarios:
        errors.append(f"C007 scenario matrix contains duplicate scenarios: {', '.join(sorted(duplicate_scenarios))}")
    for scenario in scenarios:
        proofs = scenario.get("proofs")
        if not isinstance(proofs, list) or not proofs:
            errors.append(f"C007 scenario has no executable proofs: {scenario.get('id')}")
            continue
        scenario_identities: set[tuple[str, str]] = set()
        for proof in proofs:
            proof_file, symbol = proof.get("file", ""), proof.get("symbol", "")
            identity = (proof_file, symbol)
            path = ROOT / proof_file
            text = path.read_text() if path.is_file() else ""
            command_name = test_command_name(proof_file)
            if identity in scenario_identities:
                errors.append(f"duplicate scenario proof: {scenario.get('id')}::{proof_file}::{symbol}")
            scenario_identities.add(identity)
            if not symbol or not re.search(rf"\bfn\s+{re.escape(symbol)}\s*\(", text):
                errors.append(f"missing scenario proof symbol: {proof_file}::{symbol}")
            if command_name not in x64.get("commands", []):
                errors.append(f"enabled platform does not run scenario proof: {proof_file}::{symbol}")
    corrupt = next((scenario for scenario in scenarios if scenario.get("id") == "corrupt"), {})
    corrupt_identities = [(proof.get("file"), proof.get("symbol")) for proof in corrupt.get("proofs", [])]
    for row in corruption_rows:
        proof = row.get("proof", {})
        identity = (proof.get("file"), proof.get("symbol"))
        if corrupt_identities.count(identity) != 1:
            errors.append(f"corruption vector proof must appear exactly once in the corrupt scenario: {row.get('id')}")
    crash = next((scenario for scenario in scenarios if scenario.get("id") == "crash"), {})
    crash_symbols = {proof.get("symbol") for proof in crash.get("proofs", [])}
    if "checkpoint_crash_child_terminates_at_publication_stage" not in crash_symbols:
        errors.append("C007 crash scenario must execute the checkpoint child-termination proof symbol")
    initialization = next((scenario for scenario in scenarios if scenario.get("id") == "initialization_locking"), {})
    expected_initialization_proofs = {
        ("rust-tron/crates/tron-storage/tests/backend_contract.rs", "concurrent_fresh_initialization_has_one_locked_loser_and_complete_generation"),
        ("rust-tron/crates/tron-storage/tests/failure_contract.rs", "active_initialization_journal_is_untouched_by_second_opener"),
        ("rust-tron/crates/tron-storage/tests/format_contract.rs", "inspect_to_open_path_and_nonempty_swaps_fail_without_mutation"),
    }
    actual_initialization_proofs = {(proof.get("file"), proof.get("symbol")) for proof in initialization.get("proofs", [])}
    if actual_initialization_proofs != expected_initialization_proofs or len(initialization.get("proofs", [])) != len(expected_initialization_proofs):
        errors.append("C007 initialization-locking scenario must execute every canonical proof exactly once")
    initialization_classification = next((scenario for scenario in scenarios if scenario.get("id") == "initialization_classification"), {})
    expected_initialization_classification_proofs = {
        ("rust-tron/crates/tron-storage/tests/backend_contract.rs", "writable_open_rejects_every_format_class_without_writes"),
        ("rust-tron/crates/tron-storage/tests/format_contract.rs", "initialization_classification_precedence_and_malformed_trees_are_no_write"),
    }
    actual_initialization_classification_proofs = {(proof.get("file"), proof.get("symbol")) for proof in initialization_classification.get("proofs", [])}
    if actual_initialization_classification_proofs != expected_initialization_classification_proofs or len(initialization_classification.get("proofs", [])) != len(expected_initialization_classification_proofs):
        errors.append("C007 initialization-classification scenario must execute every canonical proof exactly once")
    initialization_recovery = next((scenario for scenario in scenarios if scenario.get("id") == "initialization_recovery"), {})
    expected_initialization_recovery_proofs = {
        ("rust-tron/crates/tron-storage/tests/format_contract.rs", "legitimate_abrupt_initialization_phases_recover_deterministically"),
    }
    actual_initialization_recovery_proofs = {(proof.get("file"), proof.get("symbol")) for proof in initialization_recovery.get("proofs", [])}
    if actual_initialization_recovery_proofs != expected_initialization_recovery_proofs or len(initialization_recovery.get("proofs", [])) != len(expected_initialization_recovery_proofs):
        errors.append("C007 initialization-recovery scenario must execute every canonical proof exactly once")
    format_source = (ROOT / "rust-tron/crates/tron-storage/src/format.rs").read_text()
    storage_source = (ROOT / "rust-tron/crates/tron-storage/src/lib.rs").read_text()
    migration_phases = matrix.get("migration_phases")
    if migration_phases != rust_enum_variants(format_source, "DurablePhase") or migration_phases != durable_phases_used_by(format_source, "migrate_generation"):
        errors.append("C007 migration phase matrix must exactly enumerate DurablePhase and every phase used by migrate_generation")
    bounded_read_body = rust_function_body(format_source, "read_capped")
    snapshot_open_body = rust_function_body(format_source, "open")
    if not all(token in bounded_read_body for token in ("checked_add(1)", "file.take(limit as u64)", "with_capacity(limit.min(8192))", "try_reserve(read)", "value.len()>max")):
        errors.append("C007 untrusted reads must use a max+1 capped fallible read with small fixed initial capacity")
    if not all(token in snapshot_open_body for token in ("max_source_bytes", "metadata.len() > max_source_bytes as u64", "StableError::SourceTooLarge", "read_capped(&mut file, max_source_bytes")):
        errors.append("C007 snapshot source open must enforce the explicit import-policy byte bound before and during capture")
    import_body = rust_function_body(format_source, "import_snapshot_with_faults")
    if "SnapshotSource::open(snapshot,max_source_bytes)?" not in import_body or import_body.find("SnapshotSource::open") > import_body.find("verifier.verify"):
        errors.append("C007 snapshot import must reject source bounds before verifier or materializer invocation")
    storage_error_categories = matrix.get("storage_error_categories")
    storage_error_variants = rust_enum_variants(storage_source, "StorageError")
    if storage_error_categories != storage_error_variants or len(storage_error_categories or []) != len(set(storage_error_categories or [])):
        errors.append("C007 storage error matrix must exactly enumerate StorageError without duplicates")
    corruption_categories = matrix.get("corruption_categories")
    corruption_enum_variants = rust_enum_variants(storage_source, "Corruption")
    if corruption_categories != corruption_enum_variants or len(corruption_categories or []) != len(set(corruption_categories or [])):
        errors.append("C007 corruption matrix must exactly enumerate Corruption without duplicates")
    write_phases = matrix.get("write_phases")
    write_phase_variants = rust_enum_variants(storage_source, "WritePhase")
    if write_phases != write_phase_variants or write_phases != expected_write_phases or len(write_phases or []) != len(set(write_phases or [])):
        errors.append("C007 write phase matrix must exactly enumerate WritePhase in commit order without duplicates")
    write_scenario = next((scenario for scenario in scenarios if scenario.get("id") == "write_commit_points"), {})
    write_scenario_proofs = {(proof.get("file"), proof.get("symbol")) for proof in write_scenario.get("proofs", [])}
    if write_scenario_proofs != expected_write_proofs or len(write_scenario.get("proofs", [])) != len(expected_write_proofs):
        errors.append("C007 write commit-point scenario must execute every canonical proof exactly once")
    failure_contract = (TEST_ROOT / "failure_contract.rs").read_text()
    atomic_body = rust_function_body(failure_contract, "write_commit_points_are_atomic_across_reopen")
    error_mapping_body = rust_function_body(failure_contract, "assert_injected_io")
    poison_body = rust_function_body(failure_contract, "rollback_failures_poison_reject_operations_and_retain_lock")
    maintenance_body = rust_function_body(failure_contract, "post_commit_metadata_and_compaction_failures_are_maintenance_errors")
    if not all(token in atomic_body for token in ("WritePhase::Append", "WritePhase::Flush", "WritePhase::Sync", "reopened.get")) or "StorageError::Io" not in error_mapping_body:
        errors.append("C007 pre-commit write proof must map append/flush/sync I/O errors and verify reopen absence")
    if not all(token in poison_body for token in ("WritePhase::Truncate", "WritePhase::RollbackSync", "StorageError::Poisoned", "StorageError::Locked", "reopened.get")):
        errors.append("C007 rollback proof must cover poison, operation rejection, retained lock, and reopen absence")
    if not all(token in maintenance_body for token in ("WritePhase::Metadata", "WritePhase::Compaction", "take_maintenance_error", "reopened.get")):
        errors.append("C007 post-commit proof must separate metadata/compaction maintenance errors and verify reopen presence")
    if any(variant not in corruption_enum_variants for variant in corruption_variants):
        errors.append("rustlog-v1 corruption vector names a variant outside the Corruption enum")
    required_close_symbols = (
        "pub fn close(&self, store: RustLog) -> Result<()>",
        "pub fn close(self) -> Result<()>",
        "pub fn close_with_faults(mut self, faults: &dyn ShutdownFaultInjector) -> Result<()>",
        "fn sync_for_shutdown(&mut self, faults: &dyn ShutdownFaultInjector) -> Result<()>",
    )
    if any(symbol not in storage_source for symbol in required_close_symbols):
        errors.append("C007 durable consuming close API or shutdown sync path is missing")
    shutdown_body = rust_function_body(storage_source, "sync_for_shutdown")
    if not all(symbol in shutdown_body for symbol in ("wal.flush()", "wal.sync_data()", "snapshot.sync_data()", "directory.sync()")):
        errors.append("C007 shutdown must flush and sync WAL, optional snapshot, and generation directory")
    lifecycle = (ROOT / "docs/architecture/runtime-dependency-lifecycle.md").read_text()
    if "composition root must invoke the consuming, fallible storage close path" not in lifecycle:
        errors.append("C007 composition lifecycle must require fallible consuming close")
    source = "\n".join(path.read_text() for path in sorted((ROOT / "rust-tron/crates/tron-storage/src").glob("*.rs")))
    cargo = (ROOT / "rust-tron/crates/tron-storage/Cargo.toml").read_text()
    unsafe_code = re.search(r"(?:^|[;{}]\s*)unsafe\s*(?:\{|extern\b|fn\b|impl\b|trait\b)", source, re.MULTILINE)
    if unsafe_code or re.search(r"extern\s+\"C\"", source) or any(name in cargo for name in ("rocksdb", "leveldb", "libc")):
        errors.append("C007 enabled backend must remain pure Rust with no unsafe/FFI/native backend dependency")
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
        errors.append("this C007 qualification command is enabled only on native Linux x86_64")
    if errors:
        print("C007 gate failed:", file=sys.stderr)
        for error in errors: print(f"- {error}", file=sys.stderr)
        return 1
    print("C007 inventory/vectors/reconciliation/matrix gate passed for native pure-Rust Linux x86_64")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
