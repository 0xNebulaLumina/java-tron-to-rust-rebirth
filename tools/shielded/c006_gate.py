#!/usr/bin/env python3
"""C006 source/native/parameter provenance, replacement-ledger and dispatch gate."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROVENANCE = ROOT / "docs/oracles/c006-shielded-provenance.v1.json"
LEDGER = ROOT / "docs/oracles/c006-shielded-replacement-ledger.v1.json"
OWNERSHIP = ROOT / "docs/oracles/java-test-ownership.v1.json"
VECTORS = ROOT / "docs/oracles/c006-shielded-oracle-vectors.v1.json"
TRACKER = ROOT / "docs/PORTING_TRACKER.json"
TEST_ROOT = ROOT / "rust-tron/crates/tron-shielded/tests"
PACKAGE_ROOT = ROOT / "rust-tron/crates/tron-shielded"
LICENSE_PATH = PACKAGE_ROOT / "LICENSE-LGPL-3.0"
UPSTREAM_LICENSE_PATH = ROOT / "java-tron/LICENSE"
LICENSE_ENTRY = "LICENSE-LGPL-3.0"
LICENSE_SHA256 = "98d91346fc3f8eb94f8d0c0716faad059fc228a5d64b8aef3173aaab3efd495f"
PACKAGE_METADATA = {".cargo_vcs_info.json", "Cargo.lock", "Cargo.toml", "Cargo.toml.orig"}
LGPL_FIXTURE_NAMES = {
    "merkle_commitments_sapling.json",
    "merkle_path_sapling.json",
    "merkle_roots_empty_sapling.json",
    "merkle_roots_sapling.json",
}
SAPLING_PARAMETER_NAMES = {"sapling-spend.params", "sapling-output.params"}
REVISION = "4a21592f95e37908b21bc3f611c6e7a1a67f09f3"
EXPECTED_COMMANDS = [
    {"name":"C006 provenance and replacement gate","cwd":".","argv":["python3","tools/shielded/c006_gate.py"],"timeout_seconds":300},
    {"name":"C006 parameters and Merkle fixtures","cwd":"rust-tron","argv":["cargo","test","-p","tron-shielded","--test","merkle_fixtures","--locked"],"timeout_seconds":300},
    {"name":"C006 sodium, keys, notes and encryption","cwd":"rust-tron","argv":["cargo","test","-p","tron-shielded","--test","note_compat","--locked"],"timeout_seconds":300},
    {"name":"C006 proofs, contexts, failures and concurrency","cwd":"rust-tron","argv":["cargo","test","-p","tron-shielded","--test","context_contract","--locked"],"timeout_seconds":600},
    {"name":"C006 local TronZksnark gRPC boundary","cwd":"rust-tron","argv":["cargo","test","-p","tron-shielded","--test","zksnark_grpc_boundary","--locked"],"timeout_seconds":300},
    {"name":"Rust workspace all-targets check","cwd":"rust-tron","argv":["cargo","check","--workspace","--all-targets","--locked"],"timeout_seconds":600},
]

def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def load(path: Path, errors: list[str]) -> dict:
    try:
        value = json.loads(path.read_text())
    except Exception as error:
        errors.append(f"{path.relative_to(ROOT)}: {error}")
        return {}
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        errors.append(f"{path.relative_to(ROOT)} must be schema_version 1")
    return value

def packaged_files(errors: list[str]) -> list[str]:
    try:
        result = subprocess.run(
            ["cargo", "package", "--list", "--allow-dirty"],
            cwd=PACKAGE_ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        detail = error.stderr.strip() if isinstance(error, subprocess.CalledProcessError) and error.stderr else str(error)
        errors.append(f"cannot list tron-shielded Cargo package: {detail}")
        return []
    return [line.strip().replace("\\", "/") for line in result.stdout.splitlines() if line.strip()]

def main() -> int:
    errors: list[str] = []
    provenance = load(PROVENANCE, errors)
    ledger = load(LEDGER, errors)
    vectors = load(VECTORS, errors)
    tracker = json.loads(TRACKER.read_text())
    c006 = next((row for row in tracker.get("chunks", []) if row.get("id") == "C006"), None)
    if not c006 or c006.get("gate", {}).get("commands") != EXPECTED_COMMANDS:
        errors.append("C006 tracker commands must match the canonical stored gate exactly")
    pre_run_item_statuses = {
        "C006.01": "doing",
        "C006.02": "todo",
        "C006.03": "todo",
        "C006.04": "todo",
        "C006.05": "todo",
        "C006.06": "todo",
    }
    post_closure_item_statuses = {f"C006.{index:02d}": "done" for index in range(1, 7)}
    item_statuses = {item.get("id"): item.get("status") for item in c006.get("items", [])} if c006 else {}
    chunk_status = c006.get("status") if c006 else None
    gate_status = c006.get("gate", {}).get("status") if c006 else None
    review_state = c006.get("review", {}).get("state") if c006 else None
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
    )
    if not (pre_run_state or post_closure_state):
        errors.append(
            "C006 tracker state must be either the complete pre-run state "
            "(active, C006.01 doing, C006.02-.06 todo, gate not_run, review not_started) "
            "or the complete post-closure state (done, all items done, gate passed, review approved)"
        )
    if provenance.get("java_revision") != REVISION:
        errors.append("Java revision drift")
    try:
        actual = subprocess.check_output(["git", "-C", str(ROOT / "java-tron"), "rev-parse", "HEAD"], text=True).strip()
        if actual != REVISION:
            errors.append(f"java-tron gitlink drift: {actual}")
    except Exception as error:
        errors.append(f"cannot authenticate java-tron revision: {error}")
    for row in provenance.get("sources", []) + provenance.get("fixtures", []):
        path = ROOT / row.get("path", "")
        if not path.is_file() or digest(path) != row.get("sha256"):
            errors.append(f"missing or drifted source/fixture: {row.get('path')}")
    for row in provenance.get("parameters", []):
        path = ROOT / row.get("path", "")
        if not path.is_file() or path.stat().st_size != row.get("bytes") or digest(path) != row.get("sha256"):
            errors.append(f"missing or drifted parameter: {row.get('path')}")
        elif hashlib.blake2b(path.read_bytes()).hexdigest() != row.get("blake2b512"):
            errors.append(f"parameter BLAKE2b-512 drift: {row.get('path')}")
    package_entries = packaged_files(errors)
    forbidden_content = {
        row.get("sha256")
        for row in provenance.get("sources", []) + provenance.get("fixtures", []) + provenance.get("parameters", [])
        if row.get("sha256")
    }
    java_copied_names = {
        Path(row.get("path", "")).name for row in provenance.get("sources", []) if row.get("path")
    }
    java_copied_names.update(
        Path(row.get("source", {}).get("path", "")).name
        for row in ledger.get("rows", [])
        if str(row.get("id", "")).startswith("TRES-") and row.get("source", {}).get("path")
    )
    for entry in package_entries:
        parts = Path(entry).parts
        name = Path(entry).name
        if entry not in PACKAGE_METADATA and entry != LICENSE_ENTRY and not entry.startswith("src/"):
            errors.append(f"tron-shielded package contains non-production path: {entry}")
        if "tests" in parts or "fixtures" in parts:
            errors.append(f"tron-shielded package contains tests/fixtures: {entry}")
        if name in LGPL_FIXTURE_NAMES:
            errors.append(f"tron-shielded package contains LGPL fixture name: {entry}")
        if name in SAPLING_PARAMETER_NAMES:
            errors.append(f"tron-shielded package contains Sapling parameter name: {entry}")
        if name in java_copied_names or name.endswith(".java"):
            errors.append(f"tron-shielded package contains copied Java resource name: {entry}")
        source = PACKAGE_ROOT / entry
        if source.is_file() and digest(source) in forbidden_content:
            errors.append(f"tron-shielded package contains copied Java resource or Sapling parameter content: {entry}")
    package_license = provenance.get("package_license", {})
    if package_entries.count(LICENSE_ENTRY) != 1:
        errors.append("tron-shielded package must contain exactly LICENSE-LGPL-3.0")
    if not LICENSE_PATH.is_file() or digest(LICENSE_PATH) != LICENSE_SHA256:
        errors.append("tron-shielded LGPL-3.0 license file is missing or drifted")
    elif not UPSTREAM_LICENSE_PATH.is_file() or LICENSE_PATH.read_bytes() != UPSTREAM_LICENSE_PATH.read_bytes():
        errors.append("tron-shielded LGPL-3.0 license must exactly match pinned java-tron LICENSE")
    expected_license_provenance = {
        "path": "rust-tron/crates/tron-shielded/LICENSE-LGPL-3.0",
        "source_path": "java-tron/LICENSE",
        "source_repository": "https://github.com/tronprotocol/java-tron.git",
        "source_revision": REVISION,
        "source_url": f"https://github.com/tronprotocol/java-tron/blob/{REVISION}/LICENSE",
        "license": "LGPL-3.0-only",
        "copy_method": "verbatim",
        "bytes": 7810,
        "sha256": LICENSE_SHA256,
        "distribution": "required in every tron-shielded Cargo package",
    }
    if package_license != expected_license_provenance:
        errors.append("tron-shielded package license provenance must match the authenticated pinned license")
    production_dependencies = {row.get("crate"): row for row in provenance.get("production_dependencies", [])}
    promoted_dependencies = {
        "tron-protocol": ("0.0.0", "LGPL-3.0-only", "workspace path ../tron-protocol"),
        "prost": ("0.13.5", "Apache-2.0", "crates.io"),
        "tokio": ("1.53.1", "MIT", "crates.io"),
        "tonic": ("0.12.3", "MIT", "crates.io"),
    }
    for crate, (version, license_name, source_name) in promoted_dependencies.items():
        row = production_dependencies.get(crate, {})
        if (row.get("version"), row.get("license"), row.get("source")) != (version, license_name, source_name):
            errors.append(f"promoted production dependency inventory drift: {crate}")
    cargo_manifest = (PACKAGE_ROOT / "Cargo.toml").read_text()
    for marker in ('tron-protocol = { path = "../tron-protocol" }', "prost.workspace = true", 'tokio = { version = "=1.53.1", features = ["sync", "time"] }', "tonic.workspace = true"):
        if marker not in cargo_manifest:
            errors.append(f"missing promoted production dependency declaration: {marker}")
    methods = provenance.get("methods", [])
    if provenance.get("method_count") != 39 or len(methods) != 39:
        errors.append("method inventory must contain exactly 39 methods")
    if len({(row.get("class"), row.get("method")) for row in methods}) != 39:
        errors.append("method inventory contains duplicates")
    rows = ledger.get("rows", [])
    ownership = json.loads(OWNERSHIP.read_text())
    owned_rows = [row for row in ownership.get("rows", []) if row.get("acceptance_gate") == "C006.V"]
    java_rows = [row for row in rows if str(row.get("id", "")).startswith(("TCASE-", "TRES-"))]
    case_rows = [row for row in rows if str(row.get("id", "")).startswith("TCASE-")]
    resource_rows = [row for row in rows if str(row.get("id", "")).startswith("TRES-")]
    rust_rows = [row for row in rows if str(row.get("id", "")).startswith("C006-RUST-")]
    ignored = [row for row in case_rows if row.get("ignored")]
    if ledger.get("active_count") != 157 or len(case_rows) != 157:
        errors.append("replacement ledger must contain structured accounting for exactly 157 Java test cases")
    if ledger.get("ignored_count") != 16 or len(ignored) != 16:
        errors.append("replacement ledger must preserve exactly 16 consciously replaced ignored cases")
    if len(owned_rows) != 162 or len(java_rows) != 162 or len(resource_rows) != 5 or len(rust_rows) != 11:
        errors.append("replacement ledger must reconcile 157 Java cases, 5 Java resources, and 11 Rust proof rows")
    owned_by_id = {row.get("id"): row for row in owned_rows}
    ledger_by_id = {row.get("id"): row for row in java_rows}
    if len(owned_by_id) != 162 or set(ledger_by_id) != set(owned_by_id):
        errors.append("replacement ledger Java IDs must exactly match java-test-ownership C006.V")
    for row_id, row in ledger_by_id.items():
        owned = owned_by_id.get(row_id, {})
        if any(row.get(field) != owned.get(field) for field in ("case", "ignored")) or row.get("source") != owned.get("source"):
            errors.append(f"replacement ledger ownership drift for {row_id}")
    generic = re.compile(r"covered by|fixture family|gate dispatch|generic|placeholder|todo|tbd", re.IGNORECASE)
    required_mapping_fields = {"owner_chunk", "rust_test_file", "rust_test_symbol", "dispatch", "covered_contract"}
    allowed_owners = {"C006.01", "C006.02", "C006.03", "C006.04", "C006.05", "C006.06", "C015.04", "C016.02", "C022.01B", "C022.02", "C029.02"}
    builder_rows = [row for row in ignored if row.get("source", {}).get("path", "").endswith("ShieldedTRC20BuilderTest.java")]
    expected_owner_counts = {"C022.01B": 7, "C016.02": 6, "C015.04": 1}
    actual_owner_counts = {
        owner: sum(row.get("replacement", {}).get("owner_chunk") == owner for row in builder_rows)
        for owner in expected_owner_counts
    }
    if len(builder_rows) != 14 or actual_owner_counts != expected_owner_counts:
        errors.append("14 ignored TRC20 builder rows must map 7/6/1 to C022.01B/C016.02/C015.04")
    if any(("WithoutAsk" in row.get("case", "")) != (row.get("replacement", {}).get("owner_chunk") == "C016.02") for row in builder_rows):
        errors.append("TRC20 builders without ask must belong to C016.02 ownerless shielded validation")
    trigger_rows = [row for row in builder_rows if row.get("case") == "getTriggerInputForForMint"]
    if len(trigger_rows) != 1 or trigger_rows[0].get("replacement", {}).get("owner_chunk") != "C015.04":
        errors.append("TRC20 trigger-input execution boundary must belong to C015.04")
    grpc_rows = [row for row in ignored if row.get("case") == "checkZksnark"]
    concurrent_rows = [row for row in ignored if row.get("case") == "calBenchmarkSpendConcurrent"]
    if len(grpc_rows) != 1 or grpc_rows[0].get("replacement", {}).get("owner_chunk") != "C006.06" or grpc_rows[0].get("replacement", {}).get("rust_test_symbol") != "check_zksnark_proof_preserves_the_local_grpc_boundary":
        errors.append("ignored external ZK case must dispatch to the named C006.06 local gRPC boundary test")
    if len(concurrent_rows) != 1 or concurrent_rows[0].get("replacement", {}).get("owner_chunk") != "C006.05" or concurrent_rows[0].get("replacement", {}).get("rust_test_symbol") != "bounded_concurrent_contexts_replace_ignored_benchmark":
        errors.append("ignored concurrent benchmark must dispatch to the named bounded C006.05 test")
    for row in case_rows:
        mapping = row.get("replacement")
        if not isinstance(mapping, dict) or set(mapping) != required_mapping_fields:
            errors.append(f"Java row {row.get('id')} must use exactly the five structured replacement mapping fields")
            continue
        owner = mapping.get("owner_chunk")
        test_file = mapping.get("rust_test_file")
        test_symbol = mapping.get("rust_test_symbol")
        dispatch = mapping.get("dispatch")
        contract = mapping.get("covered_contract")
        text_fields = (owner, test_file, test_symbol, contract)
        if owner not in allowed_owners or any(not isinstance(value, str) or not value.strip() or generic.search(value) for value in text_fields):
            errors.append(f"Java row {row.get('id')} has a missing, generic, or invalid replacement field")
            continue
        if not isinstance(dispatch, list) or not dispatch or any(not isinstance(value, str) or not value for value in dispatch):
            errors.append(f"Java row {row.get('id')} has a missing or string-only dispatch")
            continue
        if owner.startswith("C006."):
            path = ROOT / test_file
            if TEST_ROOT not in path.parents or not path.is_file() or not re.search(rf"\bfn\s+{re.escape(test_symbol)}\s*\(", path.read_text()):
                errors.append(f"Java row {row.get('id')} references missing local C006 Rust test {test_file}::{test_symbol}")
                continue
            expected_dispatch = ["cargo", "test", "-p", "tron-shielded", "--test", path.stem, test_symbol, "--", "--exact"]
        else:
            expected_dispatch = ["pending-owner-gate", owner, test_symbol]
            if test_file != f"owner-gate:{owner}":
                errors.append(f"Java row {row.get('id')} must identify its reassigned owner gate instead of a C006 Rust file")
        if dispatch != expected_dispatch:
            errors.append(f"Java row {row.get('id')} has a non-canonical replacement dispatch")
    payload = json.dumps(vectors.get("vectors", []), sort_keys=True, separators=(",", ":")).encode()
    if hashlib.sha256(payload).hexdigest() != vectors.get("vectors_sha256"):
        errors.append("oracle vector payload digest drift")
    blake2_rows = [row for row in vectors.get("vectors", []) if row.get("id") == "C006.NATIVE.BLAKE2B.NULL_KEY_NULL_SALT"]
    if len(blake2_rows) != 1:
        errors.append("oracle vectors must contain exactly one fixed null-key/null-salt BLAKE2b row")
    else:
        row = blake2_rows[0]
        independent = {
            "stateful_prf_expand_64": hashlib.blake2b(bytes(range(32)) + b"\x02", digest_size=64, person=b"Ztron_ExpandSeed").hexdigest(),
            "stateful_default_diversifier_11": hashlib.blake2b(bytes(range(32)) + b"\x03\x00", digest_size=64, person=b"Ztron_ExpandSeed").digest()[:11].hex(),
            "one_shot_sapling_kdf_32": hashlib.blake2b(bytes(range(64)), digest_size=32, person=b"Ztron_SaplingKDF").hexdigest(),
            "one_shot_ock_32": hashlib.blake2b(bytes(range(128)), digest_size=32, person=b"Ztron_Derive_ock").hexdigest(),
        }
        expected_shape = {
            "basis": "independent_python_hashlib_blake2b",
            "stateful_prf_expand_input_bytes": 33,
            "stateful_prf_expand_personal": "Ztron_ExpandSeed",
            "stateful_prf_expand_digest_bytes": 64,
            "stateful_default_diversifier_input_bytes": 34,
            "stateful_default_diversifier_digest_bytes": 64,
            "stateful_default_diversifier_final_bytes": 11,
            "one_shot_sapling_kdf_input_bytes": 64,
            "one_shot_sapling_kdf_personal": "Ztron_SaplingKDF",
            "one_shot_sapling_kdf_digest_bytes": 32,
            "one_shot_ock_input_bytes": 128,
            "one_shot_ock_personal": "Ztron_Derive_ock",
            "one_shot_ock_digest_bytes": 32,
        }
        if any(row.get(field) != value for field, value in {**expected_shape, **independent}.items()):
            errors.append("fixed BLAKE2b row must match the independently computed Java note-derivation shapes and digests")
    binding_rows = [
        row for row in vectors.get("vectors", [])
        if row.get("id") == "C006.JAVA.BINDING_SIG.EMPTY_CONTEXT_NONZERO_BALANCE"
    ]
    expected_binding_row = {
        "basis": "java_source_exact_regression",
        "source": "java-tron/framework/src/test/java/org/tron/core/zksnark/LibrustzcashTest.java::testZcashParam",
        "value_balance": 1,
        "sighash": "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f",
        "test": "context_contract.rs::exact_java_empty_context_nonzero_binding_balance_fails_without_output_mutation",
    }
    if len(binding_rows) != 1 or any(
        binding_rows[0].get(field) != value for field, value in expected_binding_row.items()
    ):
        errors.append("binding signature oracle must preserve Java's exact empty-context nonzero-balance regression")
    snapshot_rows = [
        row for row in vectors.get("vectors", [])
        if row.get("id") == "C006.BEHAVIOR.PARAMETER_SNAPSHOT_TOCTOU"
    ]
    expected_snapshot_row = {
        "basis": "rust_behavioral_regression",
        "test": "context_contract.rs::authenticated_parameter_snapshot_survives_in_place_mutation",
        "contract": "each exact-bounded parameter file is read once into owned immutable bytes while BLAKE2b-512 and size are checked; parsing uses only that authenticated snapshot, survives later in-place mutation or truncation of the source, and rejects a same-size pre-snapshot mutation by digest",
    }
    if len(snapshot_rows) != 1 or any(
        snapshot_rows[0].get(field) != value for field, value in expected_snapshot_row.items()
    ):
        errors.append("parameter snapshot oracle must close in-place mutation TOCTOU")
    combined = "\n".join(path.read_text() for path in TEST_ROOT.glob("*.rs"))
    markers = [
        "java_merkle_roots_and_paths_match", "all_java_empty_roots_match", "pre_zip212_note_round_trips",
        "wrong_incoming_or_outgoing_key", "raw_validation_rejects_before_output_mutation",
        "context_bound_is_explicit_and_nonzero", "actual_spend_output_proofs_verify_and_finalize",
        "exact_java_empty_context_nonzero_binding_balance_fails_without_output_mutation",
        "authenticated_parameter_snapshot_survives_in_place_mutation",
        "check_zksnark_proof_preserves_the_local_grpc_boundary",
        "check_zksnark_proof_reports_an_unavailable_endpoint",
        "client_rejects_non_loopback_endpoints",
        "client_rejects_oversize_requests_before_transport",
        "client_applies_one_inflight_backpressure",
        "attacker_controlled_sodium_lengths_fail_without_proportional_allocation_or_panic",
        "fixed_blake2b_null_key_null_salt_note_derivation_vectors",
        "same_handle_queued_before_free_obeys_retirement_barrier",
        "retiring_context_keeps_its_capacity_reserved_until_quiesced",
    ]
    for marker in markers:
        if marker not in combined:
            errors.append(f"missing Rust dispatch marker {marker}")
    parameter_source = (PACKAGE_ROOT / "src/parameters.rs").read_text()
    parameter_snapshot_markers = (
        "fn authenticated_bytes(",
        "vec![0_u8; expected_len].into_boxed_slice()",
        "hasher.update(&bytes[offset..offset + read])",
        "SpendParameters::read(Cursor::new(spend), false)",
        "OutputParameters::read(Cursor::new(output), false)",
    )
    for marker in parameter_snapshot_markers:
        if marker not in parameter_source:
            errors.append(f"missing immutable authenticated parameter snapshot marker {marker}")
    for forbidden in ("BufReader", "SeekFrom", ".seek("):
        if forbidden in parameter_source:
            errors.append(f"parameter parsing must not seek or reread writable files: {forbidden}")
    sodium_source = (PACKAGE_ROOT / "src/sodium.rs").read_text()
    allocation_markers = (
        "LIBSODIUM_AEAD_MESSAGE_BYTES_MAX",
        "MAX_SODIUM_MESSAGE_BYTES",
        "MAX_SODIUM_AAD_BYTES",
        "MAX_SODIUM_CIPHERTEXT_BYTES",
        "MAX_SODIUM_OUTPUT_BYTES",
        "checked_add(AEAD_TAG_BYTES)",
        "AeadResult::failure()",
    )
    for marker in allocation_markers:
        if marker not in sodium_source:
            errors.append(f"missing attacker-controlled allocation bound marker {marker}")
    blake2_markers = (
        "normalized_blake2b_salt",
        "if !matches!(input.len(), 33 | 34)",
        "out_len != 32",
        "Blake2bMac::<U32>::new_with_salt_and_personal",
    )
    for marker in blake2_markers:
        if marker not in sodium_source:
            errors.append(f"missing BLAKE2 compatibility/resource marker {marker}")
    if "vec![0; output_capacity]" in sodium_source:
        errors.append("AEAD failure still allocates attacker-controlled output capacity")
    params_source = (PACKAGE_ROOT / "src/params.rs").read_text()
    if "exact(&vec![0u8;self.out_len],32)" in params_source or "self.out_len != 32" not in params_source:
        errors.append("Black2b out_len validation must compare directly without allocating")
    zksnark_source = (PACKAGE_ROOT / "src/zksnark_client.rs").read_text()
    grpc_security_markers = (
        "DEFAULT_ZKSNARK_ENDPOINT",
        "127.0.0.1:60051",
        "MAX_ZKSNARK_REQUEST_BYTES",
        "connect_timeout(ZKSNARK_CONNECT_TIMEOUT)",
        "timeout(ZKSNARK_REQUEST_TIMEOUT",
        "Semaphore::new(1)",
        "try_acquire_owned()",
        "std::net::Ipv4Addr::LOCALHOST",
        "std::net::Ipv6Addr::LOCALHOST",
        "ZksnarkClientError::Unavailable",
        "ZksnarkClientError::Failed",
    )
    for marker in grpc_security_markers:
        if marker not in zksnark_source:
            errors.append(f"missing production TronZksnark security marker {marker}")
    contextual_sources = "\n".join(
        (PACKAGE_ROOT / relative).read_text() for relative in ("src/context.rs", "src/raw.rs")
    )
    cap_markers = (
        "MAX_SHIELDED_SPENDS",
        "MAX_SHIELDED_OUTPUTS",
        "shielded transaction spend limit exceeded",
        "shielded transaction output limit exceeded",
        "shielded transaction spend or output limit exceeded",
    )
    for marker in cap_markers:
        if marker in contextual_sources:
            errors.append(f"invented contextual spend/output cap marker remains: {marker}")
    context_source = (PACKAGE_ROOT / "src/context.rs").read_text()
    for forbidden in ("VerifiedItem", "fn replay", "verified: Vec"):
        if forbidden in context_source:
            errors.append(f"verification replay or proof retention remains: {forbidden}")
    retirement_markers = (
        "struct AdmissionState",
        "retired: bool",
        "active: usize",
        "struct AdmissionGuard",
        "struct ContextTableState",
        "reserved_slots: usize",
        "struct ReservedSlotGuard",
        "fn admit(self: &Arc<Self>)",
        "state.reserved_slots >= self.max_contexts",
        "state.reserved_slots += 1",
        "admission.retired = true",
        "while admission.active != 0",
        "entry.quiesced.wait(admission)",
        "drop(reserved_slot)",
    )
    for marker in retirement_markers:
        if marker not in context_source:
            errors.append(f"missing context retirement barrier marker: {marker}")
    preverify_spend = context_source.find("let mut preverification = SaplingVerificationContext::new()")
    commit_spend = context_source.find("self.inner.check_spend", preverify_spend)
    preverify_output = context_source.find("let mut preverification = SaplingVerificationContext::new()", preverify_spend + 1)
    commit_output = context_source.find("self.inner.check_output", preverify_output)
    if min(preverify_spend, commit_spend, preverify_output, commit_output) < 0 or not (
        preverify_spend < commit_spend < preverify_output < commit_output
    ):
        errors.append("spend and output verification must preverify before committing to the live context")
    if "preverification_count" not in context_source or "assert_eq!(incremental.preverification_count(), 5)" not in combined:
        errors.append("missing constant-incremental proof-call instrumentation contract")
    binding_markers = (
        "commitments: CommitmentSum",
        "self.commitments += &value_commitment",
        "self.commitments -= &value_commitment",
        "self.commitments.into_bvk(value_balance)",
        "redjubjub::VerificationKey::from(&bsk) != expected_bvk",
    )
    for marker in binding_markers:
        if marker not in context_source:
            errors.append(f"missing native binding value-balance consistency marker: {marker}")
    inventory = (ROOT / "rust-tron/crates/tron-shielded/src/inventory.rs").read_text()
    if "JLIBRUSTZCASH_METHODS:[JLibrustzcashMethod;31]" not in inventory or "JLIBSODIUM_METHODS:[JLibsodiumMethod;8]" not in inventory:
        errors.append("Rust inventory must enforce the 31+8 method split")
    if errors:
        for error in errors:
            print(f"C006 gate: {error}", file=sys.stderr)
        return 1
    print("C006 gate passed: package boundary, 39 methods, 157 Java case mappings (16 ignored), authenticated params/fixtures, local gRPC boundary")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
