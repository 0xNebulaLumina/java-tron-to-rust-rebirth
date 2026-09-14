#!/usr/bin/env python3
"""Terminal zero-gap Java-suite reconciliation gate for C029."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import shutil
import shlex
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
import pwd
import tomllib
import time

from typing import Any
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "reference-runner"))
from java_reference_guard import JavaReferenceError, verify_java_reference

ROOT = Path(__file__).resolve().parents[2]
ORACLES = ROOT / "docs/oracles"
LEDGER = ORACLES / "java-test-ownership.v1.json"
ARTIFACT = ORACLES / "c029-java-surface-reconciliation.v1.json"
C016_OWNERSHIP = ORACLES / "c016-ownership-reconciliation.v1.json"
MANIFEST = ORACLES / "manifest.v1.json"
C008_COVERAGE = ORACLES / "c008-state-coverage.v1.json"
C009_RECONCILIATION = ORACLES / "c009-java-test-reconciliation.v1.json"
C023_OWNERSHIP = ORACLES / "c023-ownership-reconciliation.v1.json"
PINNED_TEST_INVENTORIES = {
    C008_COVERAGE: (189, "0db78910ec46d6d66e718c915b3188833e8942d097d6de7a3478f0ea5cfe580b", "f62bfce68df6ba34b83f0014d8896b040dd9be2bd7fa08baae08e8091d69cf7a"),
    C009_RECONCILIATION: (155, "07be6fef6ca4b312b4373b2a460bfa3e923888accff366e04644d3f1b758c8f6", "4f95dc0cd8305c08241f3ba0adac1d0865b0e2e2db09866ba12f10e476ca60bc"),
}
TRACKER = ROOT / "docs/PORTING_TRACKER.json"
PIN = "4a21592f95e37908b21bc3f611c6e7a1a67f09f3"
ARTIFACT_KEY = "c029_java_surface_reconciliation"
GATE_KEY = "c029_gate_source"
ID_RE = re.compile(r"^(?:TCASE|TRESOURCE)-[0-9A-F]{16}$")
PROOF_ID_RE = re.compile(r"^C029-PROOF-[0-9A-Z][0-9A-Z._-]*$")
ITEMS = {f"C029.{number:02d}" for number in range(1, 7)}
SEMANTIC_DOMAINS = {"protocol", "crypto", "chainbase", "consensus"}
PINNED_RUST_TOOLCHAIN = {
    "channel": "1.85.1",
    "host": "x86_64-unknown-linux-gnu",
    "profile": "minimal",
    "components": ("cargo", "clippy", "rust-docs", "rustfmt"),
    "targets": ("aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-unknown-linux-gnu"),
    "installed_components": (
        "clippy-preview-x86_64-unknown-linux-gnu", "cargo-x86_64-unknown-linux-gnu",
        "rust-docs-x86_64-unknown-linux-gnu", "rust-std-aarch64-apple-darwin",
        "rust-std-aarch64-unknown-linux-gnu", "rust-std-x86_64-unknown-linux-gnu",
        "rustc-x86_64-unknown-linux-gnu", "rustfmt-preview-x86_64-unknown-linux-gnu",
        "rust-std-x86_64-apple-darwin",
    ),
    "manifest_files": (
        "components", "manifest-cargo-x86_64-unknown-linux-gnu",
        "manifest-clippy-preview-x86_64-unknown-linux-gnu",
        "manifest-rust-docs-x86_64-unknown-linux-gnu",
        "manifest-rust-std-aarch64-apple-darwin",
        "manifest-rust-std-aarch64-unknown-linux-gnu",
        "manifest-rust-std-x86_64-apple-darwin",
        "manifest-rust-std-x86_64-unknown-linux-gnu",
        "manifest-rustc-x86_64-unknown-linux-gnu",
        "manifest-rustfmt-preview-x86_64-unknown-linux-gnu",
        "multirust-channel-manifest.toml", "multirust-config.toml", "rust-installer-version",
    ),
    "channel_manifest_sha256": "7e97a1235ea88353e5b930cd19308477d1fcb854e1c69bd4f1a5140e087e54d2",
    "config_manifest_sha256": "2ef02fd1c74593cb7bbd30682fd1019fab6e16c3a6b98b0ce453b323aa149f50",
    "components_sha256": "b681eda7dd3a3d83dc7a2144788a974c62ab3b883e3cbee3a9191dc7aedf1ca7",
    "tree_sha256": "1ffe6c8e2e9704b5c60978de8e1c1a555aa2e9f9e927b196bfb7a41d565ae3b0",
    "entry_count": 46889,
    "file_count": 45598,
    "directory_count": 1291,
    "total_file_bytes": 1583329647,
    "cargo_sha256": "87e9ff02f95ea17d877e7c4eeb0f365f50fe3827f5afec132131ff3b8031a57e",
    "rustc_sha256": "f8d033fd72e878ec60493788c8bffec2e6c154dcab6f0cb4c145af8ada26a7ed",
}
C016_EXECUTABLE_ROWS = 37
C016_NON_APPLICABLE_ROWS = 8
C023_JAVA_CONTRACTS = 333
C023_EXECUTABLE_ROWS = 294
C023_NON_APPLICABLE_ROWS = 39
CLASSIFICATION_POLICY = {
    "algorithm": "c029-tracker-semantics-v1",
    "observable_mismatch_markers": (
        "protobuf-java", "captured java error bytes", "canonical persisted fork state",
        "non-vm actuator execution", "surface-specific dispatch", "java-compatible 404",
        "solidity json-rpc surface",
    ),
    "resolution_markers": (
        "reproduces protobuf-java", "exact byte comparison", "every requested fork",
        "exact captured java error bytes", "classifies execution before vm policy",
        "surface-specific", "return 404 with byte-identical trees", "without writes",
        "removed unsupported solidity json-rpc",
    ),
    "non_compatibility_markers": (
        "final review", "independent review", "security review", "provenance reviewer",
        "attacker-controlled", "crash", "tamper", "toctou", "command injection",
        "trust boundary", "signature", "signing", "authenticated", "schema validation",
    ),
}
ROW_BOUND_DEFECT_STABLE_IDS = {
    "C013-R3-001": ("TCASE-E6F1B8CAC044DEB5",),
    "C027-R6-01": ("TCASE-0A0889ADBE9E8BD3", "TCASE-E1CE182966F2CAE4"),
}

GENERIC = re.compile(r"\b(?:generic|same as java|equivalent|covered|ported|parity|works|n/?a|not applicable)\b", re.I)


def is_vm_source(path: str) -> bool:
    """Recognize every explicit VM path/class family in the pinned ledger."""
    lowered = path.lower()
    basename = Path(lowered).name
    return (
        "/runtime/vm/" in lowered
        or "/actuator/vm/" in lowered
        or "/core/vm/repository/" in lowered
        or basename.startswith("vmactuator")
        or basename.startswith("vmconfig")
        or basename.startswith("historyblockhashvm")
    )




class GateError(RuntimeError):
    pass


def fail(condition: bool, message: str) -> None:
    if not condition:
        raise GateError(message)


def load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise GateError(f"{path.relative_to(ROOT)}: cannot load JSON: {error}") from error
    fail(isinstance(value, dict), f"{path.relative_to(ROOT)}: top level must be an object")
    return value


def validate_vm_ledger(rows: list[dict[str, Any]]) -> None:
    explicit_non_runtime = {
        row["id"] for row in rows
        if is_vm_source(row["source"]["path"]) and "/runtime/vm/" not in row["source"]["path"].lower()
    }
    fail(len(explicit_non_runtime) == 44, f"pinned ledger explicit non-runtime VM set drift: expected 44, found {len(explicit_non_runtime)}")


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_path(path: Path) -> str:
    return sha256_bytes(path.read_bytes())
def validate_pinned_owner_inventories() -> None:
    """Keep C008/C009 row identity and ownership-transition inputs review-pinned."""
    for path, (row_count, identity_digest, transition_digest) in PINNED_TEST_INVENTORIES.items():
        inventory = load(path).get("pinned_test_inventory")
        fail(isinstance(inventory, dict), f"{path.relative_to(ROOT)}: pinned_test_inventory object required")
        fail(inventory == {
            "ordered_identity_sha256": identity_digest,
            "ordered_ownership_transitions_sha256": transition_digest,
            "row_count": row_count,
        }, f"{path.relative_to(ROOT)}: pinned test inventory digest/count drift")




def exact_keys(value: dict[str, Any], required: set[str], where: str) -> None:
    missing = required - value.keys()
    extra = value.keys() - required
    fail(not missing, f"{where}: missing fields {sorted(missing)}")
    fail(not extra, f"{where}: unknown fields {sorted(extra)}")


def strings(values: Any, where: str, *, nonempty: bool = True) -> list[str]:
    fail(isinstance(values, list), f"{where}: must be an array")
    fail(not nonempty or bool(values), f"{where}: must not be empty")
    fail(all(isinstance(value, str) and value for value in values), f"{where}: entries must be non-empty strings")
    return values


def ledger_projection(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{"id": row["id"], "source": row["source"], "case": row["case"], "kind": row["kind"]} for row in rows]


def source_treatment(source: dict[str, Any]) -> dict[str, str]:
    """Derive C029 special handling solely from generated source classifications."""
    path = source["source"]["path"].lower()
    basename = Path(path).name.lower()
    classified = {
        "ignored": bool(source.get("ignored")),
        "shielded": any(token in path for token in ("shield", "zksnark", "sapling", "/zen/note/", "burncipher")),
        "vm": is_vm_source(path),
        "benchmark": "benchmark" in basename,
        "resource": source["kind"] == "test_resource",
        "assumption_gated": bool(source.get("assumption_gated")),
        "bounded_dynamic": source.get("expansion", {}).get("status") == "bounded_unresolved",
    }
    active_value = {
        "ignored": "covered",
        "shielded": "covered",
        "vm": "covered",
        "benchmark": "covered",
        "resource": "resource",
        "assumption_gated": "assumption_gated",
        "bounded_dynamic": "bounded_dynamic",
    }
    return {field: active_value[field] if active else "not_applicable" for field, active in classified.items()}


def historical_findings() -> dict[str, dict[str, Any]]:
    tracker = load(TRACKER)
    result: dict[str, dict[str, Any]] = {}
    for chunk in tracker.get("chunks", []):
        chunk_id = chunk.get("id")
        if not isinstance(chunk_id, str) or not re.fullmatch(r"C\d{3}", chunk_id) or not (1 <= int(chunk_id[1:]) <= 28):
            continue
        for finding in chunk.get("review", {}).get("findings", []):
            finding_id = finding.get("id")
            fail(isinstance(finding_id, str) and finding_id, f"{chunk_id}: tracker review finding lacks an ID")
            fail(finding_id not in result, f"tracker: duplicate historical finding {finding_id}")
            result[finding_id] = finding
    return result


def classification_policy_projection() -> dict[str, Any]:
    return {
        "algorithm": CLASSIFICATION_POLICY["algorithm"],
        "observable_mismatch_markers": list(CLASSIFICATION_POLICY["observable_mismatch_markers"]),
        "resolution_markers": list(CLASSIFICATION_POLICY["resolution_markers"]),
        "non_compatibility_markers": list(CLASSIFICATION_POLICY["non_compatibility_markers"]),
    }


def classify_tracker_finding(finding: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Classify tracker prose, never finding IDs, using authenticated summary/resolution text."""
    summary = finding.get("summary")
    resolution = finding.get("resolution")
    fail(isinstance(summary, str) and summary, "tracker finding: non-empty summary required")
    fail(isinstance(resolution, str) and resolution, "tracker finding: non-empty resolution required")
    summary_lower = summary.lower()
    resolution_lower = resolution.lower()
    mismatch = [marker for marker in CLASSIFICATION_POLICY["observable_mismatch_markers"] if marker in summary_lower]
    remediation = [marker for marker in CLASSIFICATION_POLICY["resolution_markers"] if marker in resolution_lower]
    excluded = [marker for marker in CLASSIFICATION_POLICY["non_compatibility_markers"] if marker in summary_lower]
    classification = "compatibility_defect" if mismatch and remediation and not excluded else "non_compatibility"
    evidence = {
        "tracker_summary": summary,
        "tracker_summary_sha256": sha256_bytes(summary.encode()),
        "tracker_resolution": resolution,
        "tracker_resolution_sha256": sha256_bytes(resolution.encode()),
        "observable_mismatch_markers": mismatch,
        "resolution_markers": remediation,
        "non_compatibility_markers": excluded,
        "derived_classification": classification,
    }
    return classification, evidence

def source_asserts(path: str, tokens: tuple[str, ...], finding_id: str) -> None:
    source = (ROOT / path).read_text(encoding="utf-8")
    fail(all(token in source for token in tokens), f"{finding_id}: defect-specific source assertions are absent from {path}")


def validate_external_defect(defect: dict[str, Any]) -> bool:
    finding_id = defect["finding_id"]
    contracts: dict[str, dict[str, Any]] = {
        "C001-R1-001": {
            "behavior_claim_ids": ["constructed protobuf map bytes preserve protobuf-java insertion order for every descriptor map field"],
            "fixture_ids": ["docs/oracles/protocol-fixtures.v1.json#map_order_vectors"],
            "rust_test_ids": ["rust-tron/crates/tron-protocol/tests/protocol_surface.rs::ordered_map_encoder_matches_java_in_both_insertion_orders_for_every_map_field"],
            "command_ids": ["C029-PROOF-557EF645060BB6BE"],
            "result_links": ["C029-PROOF-557EF645060BB6BE|recurrence:all 15 descriptor map fields match protobuf-java forward and reverse insertion bytes"],
        },
        "C014-R2-001": {
            "behavior_claim_ids": ["C014-E2E-027 canonical_fork_state_loader"],
            "fixture_ids": ["docs/oracles/c014-execution-oracle.v1.json#C014-E2E-027"],
            "rust_test_ids": ["rust-tron/crates/tron-tvm/tests/c014_runtime.rs::production_rules_load_uses_persisted_version_35_fork_state", "rust-tron/crates/tron-tvm/tests/c014_runtime.rs::production_rules_load_rejects_malformed_fork_state_and_preserves_precedence_flags"],
            "command_ids": ["C029-PROOF-6440FA156F92136A", "C029-PROOF-891ED00195920695"],
            "result_links": ["C029-PROOF-6440FA156F92136A|recurrence:version 35 uses exact persisted raw-stat bytes and denominator without current-version shortcut", "C029-PROOF-891ED00195920695|recurrence:malformed active-witness schedule cannot replace canonical fork-state precedence"],
        },
        "C016-R1-001": {
            "behavior_claim_ids": ["non-VM actuators bypass VM-only fee-limit, dynamic-energy, planning, and settlement policy while preserving energy state"],
            "fixture_ids": ["rust-tron/crates/tron-execution/tests/c016_pipeline.rs#non_vm_actuators_ignore_vm_energy_policy_and_preserve_energy_state"],
            "rust_test_ids": ["rust-tron/crates/tron-execution/tests/c016_pipeline.rs::non_vm_actuators_ignore_vm_energy_policy_and_preserve_energy_state"],
            "command_ids": ["C029-PROOF-A20BCDCB8DF8CF2D"],
            "result_links": ["C029-PROOF-A20BCDCB8DF8CF2D|recurrence:non-VM transfer, account-create, and asset-transfer actuators execute without VM energy dynamics or settlement and preserve account and block energy state"],
        },
        "C023-R1-001": {
            "behavior_claim_ids": ["Full, Solidity, and PBFT duplicate HTTP route registrations remain distinct by surface and path"],
            "fixture_ids": ["rust-tron/crates/tron-apis/src/http_routes.rs#HTTP_ROUTES"],
            "rust_test_ids": ["rust-tron/crates/tron-apis/tests/c023_routes.rs::servlet_inventory_is_exact_and_excludes_commented_registrations"],
            "command_ids": ["C029-PROOF-F39D03B730B4A1CD"],
            "result_links": ["C029-PROOF-F39D03B730B4A1CD|recurrence:HTTP_ROUTES preserves exact Full=123 Solidity=45 PBFT=47 surface-qualified registrations"],
        },
        "C028-R3-004": {
            "behavior_claim_ids": ["the packaged Solidity deployment does not advertise the unsupported Solidity JSON-RPC endpoint"],
            "fixture_ids": ["rust-tron/packaging/config/solidity.deployment.json", "rust-tron/packaging/config/solidity.conf", "rust-tron/packaging/container/compose.yaml"],
            "rust_test_ids": ["rust-tron/crates/tron-node/tests/c028_deployment.rs::packaged_surfaces_match_runtime_and_solidity_json_rpc_is_forbidden"],
            "command_ids": ["C029-PROOF-139ED6EC1DA514C9"],
            "result_links": ["C029-PROOF-139ED6EC1DA514C9|recurrence:packaged Solidity surfaces exclude JSON-RPC port 8555 from config and Compose"],
        },
    }
    contract = contracts.get(finding_id)
    if contract is None:
        return False
    fail(defect["affected_stable_ids"] == [], f"{finding_id}: external defect must not substitute unrelated ledger rows")
    fail(all(defect[field] == value for field, value in contract.items()), f"{finding_id}: exact defect-specific evidence contract mismatch")
    if finding_id == "C001-R1-001":
        vectors = load(ROOT / "docs/oracles/protocol-fixtures.v1.json").get("java_map_serialization", {}).get("rows")
        fail(isinstance(vectors, list) and len(vectors) == 15 and all(set(row) >= {"field", "forward_hex", "reverse_hex"} and row["forward_hex"] != row["reverse_hex"] for row in vectors), "C001-R1-001: exact 15-field forward/reverse map fixture is absent")
        source_asserts("rust-tron/crates/tron-protocol/tests/protocol_surface.rs", ("fn ordered_map_encoder_matches_java_in_both_insertion_orders_for_every_map_field", "assert_eq!(rows.len(), 15)", "assert_eq!(rust_forward, java_forward", "assert_eq!(rust_reverse, java_reverse"), finding_id)
    elif finding_id == "C014-R2-001":
        fixture = next(row for row in load(ROOT / "docs/oracles/c014-execution-oracle.v1.json")["vectors"] if row.get("id") == "C014-E2E-027")
        fail(fixture.get("family") == "canonical_fork_state_loader", "C014-R2-001: canonical fork-state fixture binding mismatch")
        source_asserts("rust-tron/crates/tron-tvm/tests/c014_runtime.rs", ("production_rules_load_uses_persisted_version_35_fork_state", "vec![1;19]", "vec![1;18]", "vec![1;27]", "VERSION_NUMBER", "ACTIVE_WITNESSES_KEY", "malformed.push(2)", "production_rules_load_rejects_malformed_fork_state_and_preserves_precedence_flags"), finding_id)
    elif finding_id == "C016-R1-001":
        source_asserts("rust-tron/crates/tron-execution/tests/c016_pipeline.rs", ("fn non_vm_actuators_ignore_vm_energy_policy_and_preserve_energy_state", "for case in [\"transfer\", \"account\", \"asset\"]", "sign_with_fee(contract, &key, i64::MAX)", "remove_vm_energy_dynamics(&manager)", "assert_no_energy_billing(&manager, &owner, &output)"), finding_id)
    elif finding_id == "C023-R1-001":
        source_asserts("rust-tron/crates/tron-apis/src/http_routes.rs", ("HTTP_ROUTES", "HttpSurface::Full", "HttpSurface::Solidity", "HttpSurface::Pbft"), finding_id)
        source_asserts("rust-tron/crates/tron-apis/tests/c023_routes.rs", ("servlet_inventory_is_exact_and_excludes_commented_registrations", "HttpSurface::Full", "HttpSurface::Solidity", "HttpSurface::Pbft", "123", "45", "47"), finding_id)
    else:
        source_asserts("rust-tron/crates/tron-node/tests/c028_deployment.rs", ("packaged_surfaces_match_runtime_and_solidity_json_rpc_is_forbidden", "[\"admin\",\"grpc\",\"http\",\"prometheus\",\"zeromq\"]", "contains(\"8555\")", "contains(\"jsonrpc\")", "contains(\"8555:8555\")"), finding_id)
        fail(all((ROOT / path).is_file() for path in contract["fixture_ids"]), "C028-R3-004: packaged Solidity evidence file is absent")
    return True


def string_tokens(value: Any) -> set[str]:
    if isinstance(value, str) and value:
        return {value}
    if isinstance(value, dict):
        return {token for item in value.values() for token in string_tokens(item)}
    if isinstance(value, list):
        return {token for item in value for token in string_tokens(item)}
    return set()


def validate_historical_findings(document: dict[str, Any], ledger_ids: set[str], command_ids: set[str]) -> None:
    findings = document["review_findings"]
    defects = document["compatibility_defects"]
    policy = classification_policy_projection()
    fail(document["classification_policy"] == {**policy, "sha256": sha256_bytes(canonical(policy))}, "artifact.classification_policy: pinned semantic algorithm drift")
    fail(isinstance(findings, list) and findings, "artifact.review_findings: exhaustive non-empty classification array required")
    fail(isinstance(defects, list), "artifact.compatibility_defects: must be an array")
    tracker_findings = historical_findings()
    by_id: dict[str, dict[str, Any]] = {}
    derived_defects: set[str] = set()
    for index, finding in enumerate(findings):
        where = f"review_findings[{index}]"
        fail(isinstance(finding, dict), f"{where}: object required")
        exact_keys(finding, {"finding_id", "source_refs", "classification", "rationale", "classification_evidence"}, where)
        finding_id = finding["finding_id"]
        fail(isinstance(finding_id, str) and finding_id and finding_id not in by_id, f"{where}.finding_id: non-empty unique ID required")
        tracker_finding = tracker_findings.get(finding_id)
        fail(tracker_finding is not None, f"{finding_id}: orphan historical classification")
        refs = strings(finding["source_refs"], f"{finding_id}.source_refs")
        fail(refs == [f"docs/PORTING_TRACKER.json#{finding_id}"], f"{finding_id}.source_refs: exact tracker reference required")
        derived, evidence = classify_tracker_finding(tracker_finding)
        fail(finding["classification"] == derived and finding["classification_evidence"] == evidence, f"{finding_id}: classification or authenticated semantic evidence differs from tracker derivation")
        rationale = finding["rationale"]
        fail(isinstance(rationale, str) and len(rationale.split()) >= 5 and not GENERIC.search(rationale), f"{finding_id}.rationale: concrete source-bound rationale required")
        if derived == "compatibility_defect":
            derived_defects.add(finding_id)
        by_id[finding_id] = finding
    expected = set(tracker_findings)
    fail(set(by_id) == expected, f"artifact.review_findings: historical finding join mismatch; missing={sorted(expected-set(by_id))}, orphan={sorted(set(by_id)-expected)}")
    classified_defects = {finding_id for finding_id, finding in by_id.items() if finding["classification"] == "compatibility_defect"}
    fail(classified_defects == derived_defects, "artifact.review_findings: labels must equal independently derived tracker semantics")
    fail(document["accounting"]["compatibility_defects"] == len(classified_defects), "artifact.accounting.compatibility_defects: must equal the independently derived classified-defect count")
    rows_by_id = {row["stable_id"]: row for row in document["rows"]}
    defect_by_finding: dict[str, dict[str, Any]] = {}
    for index, defect in enumerate(defects):
        where = f"compatibility_defects[{index}]"
        fail(isinstance(defect, dict), f"{where}: object required")
        required = {"finding_id", "source_refs", "rationale", "affected_stable_ids", "behavior_claim_ids", "fixture_ids", "rust_test_ids", "command_ids", "result_links"}
        fail(required <= defect.keys(), f"{where}: missing {sorted(required - defect.keys())}")
        finding_id = defect["finding_id"]
        fail(finding_id in classified_defects and finding_id not in defect_by_finding, f"{where}.finding_id: unique compatibility-defect classification required")
        tracker_finding = tracker_findings[finding_id]
        exact_ref = f"docs/PORTING_TRACKER.json#{finding_id}"
        fail(defect["source_refs"] == [exact_ref] and by_id[finding_id]["source_refs"] == [exact_ref], f"{finding_id}.source_refs: exact tracker finding reference required")
        rationale_words = set(re.findall(r"[a-z0-9]+", defect["rationale"].lower()))
        for field in ("summary", "resolution"):
            tracker_words = {word for word in re.findall(r"[a-z0-9]+", str(tracker_finding.get(field, "")).lower()) if len(word) >= 5}
            fail(len(rationale_words & tracker_words) >= 2, f"{finding_id}.rationale: not semantically grounded in tracker {field}")
        stable_ids = set(strings(defect["affected_stable_ids"], f"{finding_id}.affected_stable_ids", nonempty=False))
        external = validate_external_defect(defect)
        if external:
            fail(not stable_ids, f"{finding_id}: external defect must not bind ledger rows")
        else:
            fail(stable_ids == set(ROW_BOUND_DEFECT_STABLE_IDS.get(finding_id, ())), f"{finding_id}.affected_stable_ids: exact row-bound stable-ID join required")
        fail(stable_ids <= ledger_ids, f"{finding_id}.affected_stable_ids: unknown IDs {sorted(stable_ids-ledger_ids)}")
        for field in ("source_refs", "behavior_claim_ids", "fixture_ids", "rust_test_ids", "command_ids", "result_links"):
            strings(defect[field], f"{finding_id}.{field}", nonempty=field != "command_ids" or bool(stable_ids))
        fail(set(defect["command_ids"]) <= command_ids, f"{finding_id}.command_ids: unknown proof command")
        if external:
            fail(len(defect["result_links"]) == len(defect["command_ids"]), f"{finding_id}: each recurrence command needs one exclusive result")
            fail({link.split("|", 1)[0] for link in defect["result_links"]} == set(defect["command_ids"]) and all("|recurrence:" in link for link in defect["result_links"]), f"{finding_id}: result links must point exclusively to its recurrence proofs")
        if not external:
            fail(stable_ids, f"{finding_id}: row-bound defect must name affected stable IDs")
            affected_rows = [rows_by_id[stable_id] for stable_id in stable_ids]
            row_fixtures = {link for row in affected_rows for link in row["fixture_links"]}
            row_tests = {proof["target"] for row in affected_rows for proof in row["rust_proofs"]}
            row_claims = {token for row in affected_rows for claim in row["behavior_claims"] for token in string_tokens(claim)}
            row_results = {token for row in affected_rows for token in string_tokens(row["observable_result"])}
            row_commands = {row["proof_command_id"] for row in affected_rows if row["proof_command_id"] is not None}
            fail(set(defect["fixture_ids"]) <= row_fixtures, f"{finding_id}.fixture_ids: must resolve through its exact affected rows")
            fail(set(defect["rust_test_ids"]) <= row_tests, f"{finding_id}.rust_test_ids: must resolve through its exact affected rows")
            fail(set(defect["behavior_claim_ids"]) <= row_claims, f"{finding_id}.behavior_claim_ids: must resolve through its exact affected rows")
            fail(set(defect["result_links"]) <= row_results, f"{finding_id}.result_links: must resolve through its exact affected rows")
            fail(set(defect["command_ids"]) == row_commands <= command_ids, f"{finding_id}.command_ids: exact affected-row command join required")
            fail(all(finding_id in row["defect_refs"] for row in affected_rows), f"{finding_id}: every affected row must carry the defect reference")
        fail(isinstance(defect["rationale"], str) and len(defect["rationale"].split()) >= 5, f"{finding_id}.rationale: concrete defect rationale required")
        defect_by_finding[finding_id] = defect
    fail(set(defect_by_finding) == classified_defects, f"artifact.compatibility_defects: exact classified-defect join required; missing={sorted(classified_defects-set(defect_by_finding))}, orphan={sorted(set(defect_by_finding)-classified_defects)}")




def source_identity(row: dict[str, Any]) -> dict[str, Any]:
    return {"id": row["id"], "path": row["source"]["path"], "line": row["source"]["line"], "case": row["case"], "kind": row["kind"]}

def artifact_rows(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Return explicit row collections from supported versioned owning artifacts."""
    rows: list[dict[str, Any]] = []
    row_keys = (
        "rows", "cases", "entries", "mappings", "case_results", "reconciliations", "scenarios",
        "java_replacements", "inventory_rows", "java_test_reconciliation", "state_cases",
        "additional_stable_id_proofs", "source_equivalences", "case_table", "production_rows",
        "java_test_rows", "exclusions", "excluded_rows", "c011_excluded_rows", "direct_results",
        "command_results", "architecture_results", "integration_cases", "seams",
    )
    for key in row_keys:
        value = document.get(key)
        if isinstance(value, list):
            rows.extend(candidate for candidate in value if isinstance(candidate, dict))
    return rows


def candidate_ids(candidate: dict[str, Any]) -> set[str]:
    keys = ("stable_id", "id", "case_id", "rust_case_id", "rust_case", "rust_test", "rust_symbol", "rust_dispatch", "rust_target", "scenario_id", "variant_id", "executable_id", "behavior_id", "fixture_selector", "result_selector")
    return {candidate[key] for key in keys if isinstance(candidate.get(key), str) and candidate[key]}


def candidate_source(candidate: dict[str, Any]) -> tuple[str | None, int | None, str | None]:
    source_identity = candidate.get("source_identity")
    source = source_identity if isinstance(source_identity, dict) else candidate.get("source")
    path = source.get("path") if isinstance(source, dict) else None
    line = source.get("line") if isinstance(source, dict) else None
    case = source.get("case") if isinstance(source, dict) else None
    path = path or candidate.get("java_source") or candidate.get("javaSource")
    line = line if line is not None else candidate.get("java_line", candidate.get("line"))
    case = case or candidate.get("java_case") or candidate.get("java_symbol") or candidate.get("symbol") or candidate.get("case")
    return path, line, case


def linked_json_row(row: dict[str, Any], link: str) -> tuple[Path, dict[str, Any], str] | None:
    path_text, separator, selector = link.partition("#")
    if not separator or not selector or not path_text.endswith(".json"):
        return None
    path = ROOT / path_text
    fail(path.is_file(), f"{row['stable_id']}.fixture_links: linked artifact is missing: {path_text}")
    token = selector.rstrip("/").rsplit("/", 1)[-1]
    document = load(path)
    candidates = artifact_rows(document)
    stable = [candidate for candidate in candidates if candidate.get("stable_id") == row["stable_id"] or candidate.get("id") == row["stable_id"]]
    if stable:
        selected = [candidate for candidate in stable if token in candidate_ids(candidate)]
        matches = selected if selected else stable
    else:
        source = row["source_identity"]
        # Older owning artifacts predate stable IDs. Their only admissible join is
        # the complete Java path+line+case identity; the selector then pins that
        # exact row's versioned ID rather than receiving path-family credit.
        matches = [candidate for candidate in candidates if candidate_source(candidate) == (source["path"], source["line"], source["case"]) and token in candidate_ids(candidate)]
    if len(matches) > 1:
        return None
    if not matches:
        return None
    candidate = matches[0]
    if not stable and token not in candidate_ids(candidate) and token != row["stable_id"]:
        return None
    return path, candidate, token


def first_string(candidate: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = candidate.get(key)
        if isinstance(value, str) and value:
            return value
    return None

def referenced_c021_rust_test(candidate: dict[str, Any]) -> str | None:
    """Resolve a C021 family's authoritative executable target without stale row aliases."""
    artifact = candidate.get("artifact")
    family = candidate.get("family")
    if not isinstance(artifact, str) or not artifact.startswith("c021-cases-") or not artifact.endswith(".v1.json"):
        return None
    path = ORACLES / artifact
    if not path.is_file():
        return None
    document = load(path)
    if document.get("source_ledger") != "docs/oracles/c021-ownership-reconciliation.v1.json" or document.get("family") != family:
        return None
    rust_test = document.get("rust_test")
    return rust_test if isinstance(rust_test, str) and rust_test else None


def authoritative_fields(candidate: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
    rust_keys = ("rust_test", "rustTest", "rust_symbol", "rustCase", "rust_case", "rust_dispatch", "rust_target", "rust_test_symbol", "rust_api")
    expected_keys = ("expected_result", "canonical_expected_result", "java_expected_result", "rust_expected", "expected", "result_selector", "expected_digest", "java_expected_digest", "observation_digest", "observation_sha256", "observable_result", "row_result")
    selector_keys = ("fixture_selector", "case_selector", "case_id", "rust_case_id", "scenario_id", "variant_id", "executable_id", "behavior_id", "id", "stable_id", "selector")
    def scalar(container: dict[str, Any], keys: tuple[str, ...]) -> str | None:
        value = first_string(container, keys)
        if value is not None:
            return value
        for key in keys:
            structured = container.get(key)
            if isinstance(structured, (dict, list)) and structured:
                return json.dumps(structured, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return None
    rust_test = referenced_c021_rust_test(candidate) or first_string(candidate, rust_keys)
    expected = scalar(candidate, expected_keys)
    selector = scalar(candidate, selector_keys)
    for nested_key in ("result", "dispatcher_evidence", "rust_invocation", "proof", "evidence", "executable_proof", "replacement", "reassignment"):
        nested = candidate.get(nested_key)
        if not isinstance(nested, dict):
            continue
        rust_test = rust_test or first_string(nested, rust_keys)
        if expected is None and nested_key == "rust_invocation":
            expected_fields = {key: value for key, value in nested.items() if key.startswith("expected_")}
            if expected_fields:
                expected = json.dumps(expected_fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        expected = expected or scalar(nested, expected_keys + ("digest", "sha256"))
        if expected is None and nested_key == "result" and nested:
            expected = json.dumps(nested, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        selector = selector or scalar(nested, selector_keys)
    if expected is None and isinstance(candidate.get("observation_digests"), list) and candidate["observation_digests"]:
        expected = json.dumps(candidate["observation_digests"], separators=(",", ":"))
    if expected is None and isinstance(candidate.get("java_observation"), (dict, list)) and candidate["java_observation"]:
        expected = json.dumps(candidate["java_observation"], sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if expected is None:
        expected = first_string(candidate, ("equivalence",))
    return selector, expected, rust_test


def rust_target_parts(target: str, *, require_source: bool = False) -> tuple[Path | None, str]:
    source_text, separator, identifier = target.partition("::")
    if separator and source_text.endswith(".rs"):
        source = Path(source_text)
        fail(source.parts[:2] == ("rust-tron", "crates"), f"unsupported Rust proof target layout: {target!r}")
    else:
        source = None
        identifier = target
    fail(bool(identifier) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*(?:::[A-Za-z_][A-Za-z0-9_]*)*", identifier) is not None, f"invalid Rust proof identifier: {identifier!r}")
    fail(not require_source or source is not None, f"Rust executable proof target lacks an exact source path: {target!r}")
    return source, identifier


def same_rust_symbol(authoritative: str, target: str) -> bool:
    _, identifier = rust_target_parts(target)
    return authoritative == identifier or authoritative.rsplit("::", 1)[-1] == identifier.rsplit("::", 1)[-1]


def authoritative_row_evidence(candidate: dict[str, Any], target: str) -> tuple[bool, bool]:
    """Validate exact enriched target, behavior, and result evidence."""
    targets = {value for key in ("rust_case", "rust_case_id", "rust_test", "rust_symbol", "rust_dispatch", "rust_target", "rust_api") if isinstance((value := candidate.get(key)), str) and value}
    referenced_target = referenced_c021_rust_test(candidate)
    if referenced_target is not None:
        targets.add(referenced_target)
    claim = any(candidate.get(key) for key in ("java_behavior", "java_observation", "observation", "behavior_slices", "behavior_claims"))
    result = any(candidate.get(key) is not None for key in ("expected_result", "observable_result", "result_selector", "row_result", "observation_digest", "java_observation", "observation"))
    for nested_key in ("dispatcher_evidence", "rust_invocation", "proof", "evidence", "result"):
        nested = candidate.get(nested_key)
        if not isinstance(nested, dict):
            continue
        targets.update(value for key in ("rust_case", "rust_test", "rust_symbol", "rust_dispatch", "rust_target", "rust_api") if isinstance((value := nested.get(key)), str) and value)
        claim = claim or any(nested.get(key) for key in ("java_behavior", "java_observation", "observation", "behavior_slices", "behavior_claims"))
        result = result or any(nested.get(key) is not None for key in ("expected_result", "observable_result", "result_selector", "row_result", "observation_digest", "digest", "sha256"))
    fail(any(same_rust_symbol(value, target) for value in targets), f"authoritative target mismatch: {target!r} not in {sorted(targets)}")
    return bool(claim), bool(result)


def authoritative_proof(row: dict[str, Any], proof: dict[str, Any]) -> tuple[str, str, str] | None:
    """Return (fixture selector, expected result/digest, Rust test) from an owning artifact."""
    source = row["source_identity"]
    exact_link = f"{proof['artifact']}#{proof['selector']}"
    fail(exact_link in row["fixture_links"], f"{row['stable_id']}: proof does not name an exact linked artifact selector")
    linked = linked_json_row(row, exact_link)
    fail(linked is not None, f"{row['stable_id']}: exact proof artifact selector is unresolved")
    path, candidate, link_selector = linked
    case_id, expected, rust_test = authoritative_fields(candidate)
    if not all((rust_test, expected, case_id)):
        return None
    ids = candidate_ids(candidate)
    stable_ids = {candidate.get("stable_id"), candidate.get("id")} - {None}
    if row["stable_id"] not in stable_ids:
        fail(candidate_source(candidate) == (source["path"], source["line"], source["case"]), f"{row['stable_id']}: exact source path+line+case mismatch in {path.relative_to(ROOT)}")
    fail(link_selector in ids or link_selector == row["stable_id"], f"{row['stable_id']}: fixture link does not select the authoritative versioned row in {path.relative_to(ROOT)}")
    fail(proof["selector"] == case_id or proof["selector"] in ids, f"{row['stable_id']}: proof selector does not match authoritative {path.relative_to(ROOT)} row")
    fail(row.get("observable_result") == expected, f"{row['stable_id']}: observable result/digest does not match authoritative {path.relative_to(ROOT)} row")
    fail(same_rust_symbol(rust_test, proof["target"]), f"{row['stable_id']}: mapped Rust proof symbol does not match authoritative {path.relative_to(ROOT)} row ({rust_test})")
    return case_id, expected, rust_test


def repository_snapshot(root: Path) -> dict[str, str]:
    """Hash tracked and untracked, nonignored files without changing the worktree."""
    done = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    fail(done.returncode == 0, f"clean-state baseline: git ls-files failed: {done.stderr.decode(errors='replace').strip()}")
    result: dict[str, str] = {}
    for raw in done.stdout.split(b"\0"):
        if not raw:
            continue
        relative = os.fsdecode(raw)
        path = root / relative
        if path.is_symlink():
            result[relative] = "link:" + os.readlink(path)
        elif path.is_file():
            result[relative] = "file:" + sha256_path(path)
        else:
            result[relative] = "missing"
    return result

def tree_snapshot(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_dir():
            continue
        relative = path.relative_to(root).as_posix()
        result[relative] = "link:" + os.readlink(path) if path.is_symlink() else "file:" + sha256_path(path)
    return result


def copy_current_tree(destination: Path, baseline: dict[str, str]) -> None:
    """Materialize exactly the byte identities captured by repository_snapshot."""
    for relative, identity in baseline.items():
        source = ROOT / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if identity.startswith("link:"):
            fail(source.is_symlink() and "link:" + os.readlink(source) == identity, f"source changed during snapshot materialization: {relative}")
            target.symlink_to(os.readlink(source))
            fail("link:" + os.readlink(target) == identity, f"copied symlink differs from snapshot: {relative}")
        elif identity == "missing":
            # Gitlink/submodule entries are materialized separately from the authenticated pin.
            continue
        else:
            fail(source.is_file() and "file:" + sha256_path(source) == identity, f"source changed before snapshot materialization: {relative}")
            shutil.copyfile(source, target)
            fail("file:" + sha256_path(source) == identity, f"source changed during snapshot materialization: {relative}")
            fail("file:" + sha256_path(target) == identity, f"copied file differs from snapshot: {relative}")


def validate_mapped_source_snapshot(tree: Path, document: dict[str, Any], baseline: dict[str, str]) -> None:
    """Bind every executable proof source to identical current-tree and disposable bytes."""
    mapped_sources: set[Path] = set()
    for row in document["rows"]:
        for proof in row["rust_proofs"]:
            source, _ = rust_target_parts(resolve_c025_family_target(ROOT, row, proof), require_source=True)
            assert source is not None
            mapped_sources.add(source)
    fail(mapped_sources, "mapped Rust proof source inventory is empty")
    for relative in sorted(mapped_sources):
        key = relative.as_posix()
        expected = baseline.get(key)
        fail(isinstance(expected, str) and expected.startswith("file:"), f"mapped Rust proof source is absent from captured repository snapshot: {key}")
        current = ROOT / relative
        copied = tree / relative
        fail(current.is_file() and copied.is_file(), f"mapped Rust proof source is incomplete: {key}")
        fail("file:" + sha256_path(current) == expected, f"mapped Rust proof source changed after snapshot capture: {key}")
        fail("file:" + sha256_path(copied) == expected, f"disposable mapped Rust proof source differs from current snapshot: {key}")

def materialize_java_reference(destination: Path) -> None:
    """Clone the authenticated pin without sharing a writable worktree or build debris."""
    try:
        revision = verify_java_reference(ROOT, phase="before disposable Java materialization")
    except JavaReferenceError as error:
        raise GateError(str(error)) from error
    source = ROOT / "java-tron"
    parent = destination.parent
    initialized = subprocess.run(
        ["git", "-C", str(parent), "init", "--quiet"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
    )
    fail(initialized.returncode == 0, f"disposable guard repository init failed: {initialized.stderr.strip()}")
    indexed = subprocess.run(
        ["git", "-C", str(parent), "update-index", "--add", "--cacheinfo", f"160000,{revision},java-tron"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
    )
    fail(indexed.returncode == 0, f"disposable Java gitlink creation failed: {indexed.stderr.strip()}")
    tree = subprocess.run(
        ["git", "-C", str(parent), "write-tree"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
    )
    fail(tree.returncode == 0, f"disposable guard tree creation failed: {tree.stderr.strip()}")
    commit_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(parent), "TMPDIR": str(parent), "LANG": "C", "LC_ALL": "C", "TZ": "UTC", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_AUTHOR_NAME": "C029 Gate", "GIT_AUTHOR_EMAIL": "c029@invalid", "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+00:00", "GIT_COMMITTER_NAME": "C029 Gate", "GIT_COMMITTER_EMAIL": "c029@invalid", "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+00:00"}
    commit = subprocess.run(
        ["git", "-C", str(parent), "commit-tree", tree.stdout.strip(), "-m", "pinned Java reference"],
        env=commit_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
    )
    fail(commit.returncode == 0, f"disposable guard commit creation failed: {commit.stderr.strip()}")
    installed = subprocess.run(
        ["git", "-C", str(parent), "update-ref", "HEAD", commit.stdout.strip()],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
    )
    fail(installed.returncode == 0, f"disposable guard HEAD creation failed: {installed.stderr.strip()}")
    done = subprocess.run(
        ["git", "clone", "--shared", "--no-checkout", "--quiet", str(source), str(destination)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
    )
    fail(done.returncode == 0, f"disposable Java clone failed: {done.stderr.strip()}")
    done = subprocess.run(
        ["git", "-C", str(destination), "checkout", "--detach", "--quiet", revision],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
    )
    fail(done.returncode == 0, f"disposable Java checkout failed: {done.stderr.strip()}")
    head = subprocess.run(
        ["git", "-C", str(destination), "rev-parse", "HEAD"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
    )
    status = subprocess.run(
        ["git", "-C", str(destination), "status", "--porcelain=v1", "--untracked-files=all"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
    )
    fail(head.returncode == 0 and head.stdout.strip() == revision, "disposable Java clone has the wrong git identity")
    fail(status.returncode == 0 and not status.stdout.strip(), "disposable Java clone is not pristine")
    for path in sorted(destination.rglob("*"), reverse=True):
        if not path.is_symlink():
            path.chmod(path.stat().st_mode & ~0o222)
    destination.chmod(destination.stat().st_mode & ~0o222)


def make_tree_writable(root: Path) -> None:
    """Permit deterministic cleanup of intentionally read-only disposable sources."""
    if not root.exists():
        return
    for path in root.rglob("*"):
        if not path.is_symlink():
            path.chmod(path.stat().st_mode | 0o700)
    root.chmod(root.stat().st_mode | 0o700)



def validate_source_envelope(
    document: dict[str, Any],
    ledger: dict[str, Any],
    *,
    allow_ledger_file_digest_drift: bool = False,
) -> None:
    exact_keys(document, {"schema", "schema_version", "chunk", "java_source_revision", "source_ledger", "gate_source", "classification_policy", "accounting", "proof_commands", "compatibility_defects", "review_findings", "rows", "unsupported_by_owning_artifact_repair"}, "artifact")
    fail(document["schema"] == "c029-java-surface-reconciliation", "artifact.schema: expected c029-java-surface-reconciliation")
    fail(document["schema_version"] == 1, "artifact.schema_version: expected 1")
    fail(document["chunk"] == "C029", "artifact.chunk: expected C029")
    fail(document["java_source_revision"] == PIN == ledger.get("java_source_revision"), "artifact.java_source_revision: pinned revision mismatch")
    envelope = document["source_ledger"]
    exact_keys(envelope, {"path", "sha256", "row_count", "ordering", "ordered_identity_sha256", "identity_projection"}, "artifact.source_ledger")
    projection = ledger_projection(ledger["rows"])
    expected = {"path": "docs/oracles/java-test-ownership.v1.json", "sha256": sha256_path(LEDGER), "row_count": len(ledger["rows"]), "ordering": ledger["regeneration"]["ordering"], "ordered_identity_sha256": sha256_bytes(canonical(projection)), "identity_projection": projection}
    if allow_ledger_file_digest_drift:
        fail(envelope | {"sha256": expected["sha256"]} == expected, "artifact.source_ledger: regenerated source/count/order/identity drift; only ledger file digest refresh is permitted")
    else:
        fail(envelope == expected, "artifact.source_ledger: exact regenerated source/count/order/identity envelope mismatch")
    gate = document["gate_source"]
    exact_keys(gate, {"path", "sha256"}, "artifact.gate_source")
    fail(gate["path"] == "tools/regression/c029_gate.py", "artifact.gate_source.path: wrong gate")
    # A self-digest is refreshed by --write and authenticated by the central manifest in --check.
    fail(re.fullmatch(r"[0-9a-f]{64}", gate["sha256"] or "") is not None, "artifact.gate_source.sha256: invalid digest")


def validate_command(command: dict[str, Any], index: int) -> None:
    where = f"proof_commands[{index}]"
    exact_keys(command, {"id", "cwd", "argv", "timeout_seconds", "environment", "result_contract", "owning_item"}, where)
    fail(isinstance(command["id"], str) and PROOF_ID_RE.fullmatch(command["id"]), f"{where}.id: invalid stable proof ID")
    fail(isinstance(command["cwd"], str) and command["cwd"] in {".", "rust-tron"}, f"{command['id']}.cwd: must be . or rust-tron")
    argv = strings(command["argv"], f"{command['id']}.argv")
    fail(argv[0] not in {"sh", "bash", "zsh"} and "-c" not in argv[:2], f"{command['id']}.argv: shell indirection is forbidden")
    fail(argv[:2] == ["cargo", "test"] and "--offline" in argv and "--locked" in argv, f"{command['id']}.argv: exact offline locked cargo test required")
    fail("--" in argv, f"{command['id']}.argv: libtest argument separator required")
    libtest = argv[argv.index("--") + 1:]
    selectors = [value for value in libtest if not value.startswith("-")]
    fail(len(selectors) == 1 and "--exact" in libtest, f"{command['id']}.argv: exactly one explicit proof symbol plus --exact required")
    fail(isinstance(command["timeout_seconds"], int) and 1 <= command["timeout_seconds"] <= 1800, f"{command['id']}.timeout_seconds: must be 1..1800")
    environment = command["environment"]
    fail(isinstance(environment, dict) and environment, f"{command['id']}.environment: closed deterministic environment required")
    required_env = {"HOME", "TMPDIR", "LANG", "LC_ALL", "TZ", "RUST_TEST_THREADS", "CARGO_NET_OFFLINE"}
    fail(set(environment) == required_env, f"{command['id']}.environment: expected closed allowlist {sorted(required_env)}")
    fail(all(isinstance(k, str) and isinstance(v, str) for k, v in environment.items()), f"{command['id']}.environment: string map required")
    fail(environment["TZ"] == "UTC" and environment["RUST_TEST_THREADS"] == "1", f"{command['id']}.environment: UTC and one test thread required")
    contract = command["result_contract"]
    exact_keys(contract, {"expected_exit", "minimum_executed_tests", "forbid_ignored", "forbid_skipped", "observable_projection"}, f"{command['id']}.result_contract")
    fail(contract["expected_exit"] == 0, f"{command['id']}.result_contract.expected_exit: must be zero")
    fail(isinstance(contract["minimum_executed_tests"], int) and contract["minimum_executed_tests"] > 0, f"{command['id']}.result_contract.minimum_executed_tests: zero-test credit forbidden")
    fail(contract["forbid_ignored"] is True and contract["forbid_skipped"] is True, f"{command['id']}.result_contract: ignored/skipped credit forbidden")
    strings(contract["observable_projection"], f"{command['id']}.result_contract.observable_projection")
    fail(command["owning_item"] == "C029.06", f"{command['id']}.owning_item: expected C029.06")


def validate_artifact(
    document: dict[str, Any],
    ledger: dict[str, Any],
    *,
    check_files: bool = True,
    allow_ledger_file_digest_drift: bool = False,
) -> dict[str, Any]:
    validate_source_envelope(document, ledger, allow_ledger_file_digest_drift=allow_ledger_file_digest_drift)
    commands = document["proof_commands"]
    fail(isinstance(commands, list), "artifact.proof_commands: must be an array")
    for index, command in enumerate(commands):
        validate_command(command, index)
    command_ids = [command["id"] for command in commands]
    fail(len(command_ids) == len(set(command_ids)), "artifact.proof_commands: duplicate proof command ID")
    by_command = {command["id"]: command for command in commands}
    validate_vm_ledger(ledger["rows"])

    rows = document["rows"]
    fail(isinstance(rows, list) and len(rows) == len(ledger["rows"]) == 3443, "artifact.rows: exact 3443-row ledger coverage required")
    source_ids = [row["id"] for row in ledger["rows"]]
    fail([row.get("stable_id") for row in rows] == source_ids, "artifact.rows: exact ledger stable-ID order mismatch")
    counts = {"mapped": 0, "unmapped": 0, "generic": 0, "applicable": 0, "non_applicable": 0, "ignored": 0, "resources": 0, "assumption_gated": 0, "bounded_dynamic": 0, "semantic_rehomes": 0, "compatibility_defects": len(document["compatibility_defects"]), "review_findings": len(document["review_findings"])}
    unmapped_by_owner: dict[str, list[dict[str, Any]]] = {}
    c016_non_applicable = {
        candidate["stable_id"]: candidate
        for candidate in load(C016_OWNERSHIP).get("non_applicable_java_test_rows", [])
    }
    for index, (row, source) in enumerate(zip(rows, ledger["rows"], strict=True)):
        sid = source["id"]; where = f"rows[{index}]({sid})"
        exact_keys(row, {"stable_id", "source_identity", "behavior_claims", "applicability", "owning_item", "fixture_links", "rust_proofs", "proof_command_id", "observable_result", "behavior_slices", "semantic_rehome", "treatment", "determinism_isolation", "defect_refs"}, where)
        fail(row["source_identity"] == source_identity(source), f"{sid}.source_identity: ledger source/case/kind drift")
        applicability = row["applicability"]
        exact_keys(applicability, {"type", "rationale"}, f"{sid}.applicability")
        disposition = applicability["type"]
        fail(disposition in {"covered", "non_applicable", "unmapped"}, f"{sid}.applicability.type: invalid enriched disposition")
        fail(isinstance(applicability["rationale"], str) and len(applicability["rationale"].split()) >= 5, f"{sid}.applicability.rationale: concrete rationale required")
        claims = row["behavior_claims"]
        fail(isinstance(claims, list), f"{sid}.behavior_claims: must be an array")
        fail(all(isinstance(claim, (str, dict)) and bool(claim) for claim in claims), f"{sid}.behavior_claims: non-empty strings or structured claims required")
        fixtures = strings(row["fixture_links"], f"{sid}.fixture_links")
        proofs = row["rust_proofs"]
        fail(isinstance(proofs, list), f"{sid}.rust_proofs: must be an array")
        authoritative_claim = authoritative_result = False
        if disposition == "covered":
            fail(proofs and row["observable_result"] is not None, f"{sid}: covered row requires proofs and observable result")
            counts["mapped"] += 1; counts["applicable"] += 1; counts["semantic_rehomes"] += 1
        elif disposition == "non_applicable":
            c016_exclusion = c016_non_applicable.get(sid)
            if c016_exclusion is None:
                fail(claims and row["observable_result"] is not None, f"{sid}: non-applicable row requires retained authoritative evidence")
            else:
                constraint = c016_exclusion.get("constraint")
                fail(c016_exclusion.get("decision") == "not_applicable" and claims == [constraint] and applicability["rationale"] == constraint, f"{sid}: C016 non-applicable evidence differs from authoritative owner decision")
                fail(not proofs and row["proof_command_id"] is None and row["observable_result"] is None, f"{sid}: C016 non-applicable row must not receive executable credit")
            counts["mapped"] += 1; counts["non_applicable"] += 1; counts["semantic_rehomes"] += 1
        else:
            fail(not claims and not proofs and row["proof_command_id"] is None and row["observable_result"] is None, f"{sid}: unmapped row must not claim executable credit")
            counts["unmapped"] += 1
            owner = next((link.partition("#")[0] for link in fixtures if link.partition("#")[0] != "docs/oracles/java-test-ownership.v1.json"), None)
            owner = owner or f"docs/oracles/{row['owning_item'].split('.')[0].lower()}-ownership-reconciliation.v1.json"
            unmapped_by_owner.setdefault(owner, []).append({"stable_id": sid, "source_identity": row["source_identity"], "missing_field": "row-specific executable evidence is absent: requires fixture/case selector, observable expected result or digest, Rust test symbol, and canonical command"})
        fail(row["proof_command_id"] is None or row["proof_command_id"] in by_command, f"{sid}.proof_command_id: dangling command")
        for proof_index, proof in enumerate(proofs):
            exact_keys(proof, {"artifact", "selector", "target"}, f"{sid}.rust_proofs[{proof_index}]")
            fail(all(isinstance(proof[field], str) and proof[field] for field in ("artifact", "selector", "target")), f"{sid}.rust_proofs[{proof_index}]: concrete artifact, selector, and target required")
            link = f"{proof['artifact']}#{proof['selector']}"
            fail(link in fixtures, f"{sid}.rust_proofs[{proof_index}]: proof artifact selector must be an exact fixture link")
            linked = linked_json_row(row, link)
            fail(linked is not None, f"{sid}.rust_proofs[{proof_index}]: authoritative row selector is unresolved")
            if disposition == "covered":
                claim_evidence, result_evidence = authoritative_row_evidence(linked[1], proof["target"])
                authoritative_claim = authoritative_claim or claim_evidence
                authoritative_result = authoritative_result or result_evidence
        if disposition == "covered":
            fail(bool(claims) or authoritative_claim, f"{sid}: covered row lacks exact behavior claim evidence")
            fail(authoritative_result, f"{sid}: covered row lacks exact authoritative result evidence")
        fail(isinstance(row["behavior_slices"], list), f"{sid}.behavior_slices: must be an array")
        rehome = row["semantic_rehome"]
        exact_keys(rehome, {"domain", "crate", "final_owner", "final_gate", "rationale"}, f"{sid}.semantic_rehome")
        fail(rehome["final_owner"] == row["owning_item"] and isinstance(rehome["final_gate"], str), f"{sid}.semantic_rehome: final owner/gate mismatch")
        treatment = row["treatment"]
        exact_keys(treatment, {"ignored", "shielded", "vm", "benchmark", "resource", "assumption_gated", "bounded_dynamic"}, f"{sid}.treatment")
        expected_treatment = source_treatment(source)
        fail(treatment == expected_treatment, f"{sid}.treatment: source-derived mismatch; expected {expected_treatment}")
        for field, value in expected_treatment.items():
            active = value != "not_applicable"
            if field in {"ignored", "resource", "assumption_gated", "bounded_dynamic"}:
                counts[field + ("s" if field == "resource" else "")] += int(active)
        contract = row["determinism_isolation"]
        exact_keys(contract, {"fresh_temp", "virtual_or_injected_time", "ephemeral_listeners", "fixed_seed", "immutable_inputs", "repeat_runs", "projection"}, f"{sid}.determinism_isolation")
        fail(isinstance(contract["projection"], list) and isinstance(contract["repeat_runs"], int), f"{sid}.determinism_isolation: invalid projection contract")
        strings(row["defect_refs"], f"{sid}.defect_refs", nonempty=False)
    referenced_command_ids = {row["proof_command_id"] for row in rows if row["proof_command_id"] is not None}
    referenced_command_ids.update(command_id for defect in document["compatibility_defects"] for command_id in defect.get("command_ids", []))
    fail(set(command_ids) == referenced_command_ids, f"artifact.proof_commands: exact row/defect referenced set required; orphan={sorted(set(command_ids) - referenced_command_ids)}, missing={sorted(referenced_command_ids - set(command_ids))}")

    unsupported = document["unsupported_by_owning_artifact_repair"]
    fail(isinstance(unsupported, dict), "artifact.unsupported_by_owning_artifact_repair: grouped object required")
    fail(unsupported == unmapped_by_owner, "artifact.unsupported_by_owning_artifact_repair: exact grouped unmapped-row repair inventory mismatch")
    fail(document["accounting"] == counts, f"artifact.accounting: exact recomputation mismatch; expected {counts}")
    fail(counts["mapped"] + counts["unmapped"] == 3443 and counts["generic"] == 0, "artifact.accounting: all rows must be exact-mapped or explicit unsupported gaps")
    validate_historical_findings(document, set(source_ids), set(command_ids))
    return by_command


def verify_manifest(document: dict[str, Any]) -> None:
    manifest = load(MANIFEST)
    expected = {ARTIFACT_KEY: (ARTIFACT, "c029-java-surface-reconciliation.v1.json"), GATE_KEY: (Path(__file__), "tools/regression/c029_gate.py")}
    for key, (path, relative) in expected.items():
        entry = manifest.get(key)
        fail(isinstance(entry, dict), f"manifest.{key}: missing registered digest entry")
        fail(entry == {"path": relative, "sha256": sha256_path(path)}, f"manifest.{key}: path/digest mismatch")
    fail(document["gate_source"]["sha256"] == sha256_path(Path(__file__)), "artifact.gate_source.sha256: current gate source digest mismatch")


def parse_test_result(output: str) -> tuple[int, int, int]:
    passed = sum(int(value) for value in re.findall(r"test result: ok\. (\d+) passed", output))
    ignored = sum(int(value) for value in re.findall(r"(?:;|,) (\d+) ignored", output))
    skipped = len(re.findall(r"\bSKIP(?:PED)?\b", output, re.I))
    return passed, ignored, skipped




def require_disk(path: Path, minimum: int, purpose: str) -> None:
    available = shutil.disk_usage(path).free
    fail(
        available >= minimum,
        f"insufficient free space for {purpose}: {available // (1024**2)} MiB available, "
        f"need at least {minimum // (1024**2)} MiB; remove stale build artifacts or set TMPDIR to a roomier filesystem",
    )


def is_exact_c016_generated_test(relative: Path, source_text: str, symbol: str, stable_id: str) -> bool:
    """Recognize only C016's reviewed per-stable-ID test macro invocation."""
    if relative.parent.name != "tests" or not relative.name.startswith("c016_"):
        return False
    expected_symbol = f"c016_tcase_{stable_id.removeprefix('TCASE-').lower()}"
    if symbol != expected_symbol or ID_RE.fullmatch(stable_id) is None:
        return False
    invocation = re.compile(
        rf"(?m)^\s*c016_behavior_case!\(\s*{re.escape(symbol)}\s*,\s*{re.escape(json.dumps(stable_id))}\s*,"
    )
    return invocation.search(source_text) is not None

def is_exact_c023_generated_test(relative: Path, source_text: str, symbol: str, row: dict[str, Any]) -> bool:
    """Recognize only C023 row proofs whose macro literals match the exact row behavior contract."""
    if relative != Path("rust-tron/crates/tron-apis/tests/c023_scenarios.rs"):
        return False
    stable_id = row["stable_id"]
    expected_symbol = f"c023_tcase_{stable_id.removeprefix('TCASE-').lower()}"
    expected = row.get("observable_result")
    if symbol != expected_symbol or ID_RE.fullmatch(stable_id) is None or not isinstance(expected, str) or "|family=" not in expected:
        return False
    family = expected.rsplit("|family=", 1)[1]
    invocation = re.compile(
        rf"(?m)^\s*c023_row_proof!\(\s*{re.escape(symbol)}\s*,\s*{re.escape(json.dumps(stable_id))}\s*,\s*{re.escape(json.dumps(expected))}\s*,\s*{re.escape(json.dumps(family))}\s*\);"
    )
    return invocation.search(source_text) is not None


def resolve_c025_family_target(tree: Path, row: dict[str, Any], proof: dict[str, Any]) -> str:
    """Pair C025 dispatch/case shorthands with their exact authoritative test source."""
    target = proof["target"]
    if not row["owning_item"].startswith("C025."):
        return target
    linked = linked_json_row(row, f"{proof['artifact']}#{proof['selector']}")
    if linked is None:
        return target
    path, candidate, _ = linked
    family = load(path)
    dispatch = candidate.get("rust_dispatch", family.get("test_target"))
    case = candidate.get("rust_case")
    if not isinstance(case, str):
        for paired_proof in row["rust_proofs"]:
            paired = linked_json_row(row, f"{paired_proof['artifact']}#{paired_proof['selector']}")
            if paired is None:
                continue
            paired_dispatch = paired[1].get("rust_dispatch", load(paired[0]).get("test_target"))
            paired_case = paired[1].get("rust_case")
            if paired_dispatch == dispatch and isinstance(paired_case, str):
                candidate = paired[1]
                case = paired_case
                break
    if not isinstance(dispatch, str) or re.fullmatch(r"[a-z0-9-]+::c025_cases_[A-Za-z0-9_]+", dispatch) is None or not isinstance(case, str):
        return target
    resolved = canonical_rust_target(path, {**candidate, "rust_dispatch": dispatch})
    fail(resolved is not None and resolved not in {dispatch, case}, f"{row['stable_id']}: C025 family metadata lacks an exact Rust test source and symbol")
    fail(target in {dispatch, case, resolved}, f"{row['stable_id']}: C025 proof target is unrelated to its authoritative dispatch, paired case, and exact source target")
    source, symbol = rust_target_parts(resolved, require_source=True)
    assert source is not None
    fail(symbol == case, f"{row['stable_id']}: resolved C025 symbol differs from authoritative paired case")
    fail((tree / source).is_file(), f"{row['stable_id']}: resolved C025 Rust test source is missing: {source}")
    package, test_target = dispatch.split("::", 1)
    fail(source == Path(f"rust-tron/crates/{package}/tests/{test_target}.rs"), f"{row['stable_id']}: resolved C025 source differs from authoritative package/test target")
    argv = canonical_proof_argv({**candidate, "rust_dispatch": dispatch}, resolved)
    fail(argv is not None and "-p" in argv and argv[argv.index("-p") + 1] == package, f"{row['stable_id']}: C025 canonical command package mismatch")
    fail("--test" in argv and argv[argv.index("--test") + 1] == test_target, f"{row['stable_id']}: C025 canonical command test-target mismatch")
    fail(argv[argv.index("--") + 1] == symbol, f"{row['stable_id']}: C025 canonical command symbol mismatch")
    return resolved


def referenced_targets(tree: Path, document: dict[str, Any]) -> dict[tuple[str, str, str], set[str]]:
    plans: dict[tuple[str, str, str], set[str]] = {}
    for row in document["rows"]:
        for proof in row["rust_proofs"]:
            resolved_target = resolve_c025_family_target(tree, row, proof)
            relative, identifier = rust_target_parts(resolved_target, require_source=True)
            assert relative is not None
            crate = tree / "rust-tron" / relative.parts[1] / relative.parts[2]
            manifest = crate / "Cargo.toml"
            fail(manifest.is_file(), f"Rust proof crate manifest missing: {manifest.relative_to(tree)}")
            manifest_data = tomllib.loads(manifest.read_text(encoding="utf-8"))
            package = manifest_data["package"]["name"]
            inside = Path(*relative.parts[3:])
            symbol = identifier.rsplit("::", 1)[-1]
            source_text = (tree / relative).read_text(encoding="utf-8")
            test_definition = re.compile(rf"#\[(?:[A-Za-z_][\w:]*::)?test(?:\([^]]*\))?\]\s*(?:#\[[^]]+\]\s*)*(?:async\s+)?fn\s+{re.escape(symbol)}\b")
            direct_test = test_definition.search(source_text) is not None
            generated_c016_test = is_exact_c016_generated_test(relative, source_text, symbol, row["stable_id"])
            generated_c023_test = is_exact_c023_generated_test(relative, source_text, symbol, row)
            fail(direct_test or generated_c016_test or generated_c023_test, f"Rust proof symbol is not a test in its mapped source: {relative}::{symbol}")
            if inside.parts[0] == "src":
                selector, target_name = "lib", manifest_data.get("lib", {}).get("name", package.replace("-", "_"))
            else:
                fail(len(inside.parts) == 2 and inside.parts[0] == "tests", f"proof source is not a lib or integration target: {relative}")
                selector, target_name = "test", inside.stem
            plans.setdefault((package, selector, target_name), set()).add(identifier)
    for defect in document["compatibility_defects"]:
        if defect["affected_stable_ids"]:
            continue
        for target_text in defect["rust_test_ids"]:
            relative, identifier = rust_target_parts(target_text, require_source=True)
            assert relative is not None
            crate = tree / "rust-tron" / relative.parts[1] / relative.parts[2]
            manifest = crate / "Cargo.toml"
            fail(manifest.is_file(), f"external defect proof crate manifest missing: {manifest.relative_to(tree)}")
            manifest_data = tomllib.loads(manifest.read_text(encoding="utf-8"))
            package = manifest_data["package"]["name"]
            inside = Path(*relative.parts[3:])
            symbol = identifier.rsplit("::", 1)[-1]
            source_text = (tree / relative).read_text(encoding="utf-8")
            test_definition = re.compile(rf"#\[(?:[A-Za-z_][\w:]*::)?test(?:\([^]]*\))?\]\s*(?:#\[[^]]+\]\s*)*(?:async\s+)?fn\s+{re.escape(symbol)}\b")
            fail(test_definition.search(source_text) is not None, f"external defect Rust proof symbol is not a direct test: {relative}::{symbol}")
            if inside.parts[0] == "src":
                selector, target_name = "lib", manifest_data.get("lib", {}).get("name", package.replace("-", "_"))
            else:
                fail(len(inside.parts) == 2 and inside.parts[0] == "tests", f"external defect proof source is not a lib or integration target: {relative}")
                selector, target_name = "test", inside.stem
            plans.setdefault((package, selector, target_name), set()).add(identifier)
    fail(plans, "Rust proof target inventory is empty")
    return plans


def existing_target_names(target: Path) -> set[str]:
    deps = target / "debug" / "deps"
    if not deps.is_dir():
        return set()
    names: set[str] = set()
    for candidate in deps.iterdir():
        if candidate.is_file() and os.access(candidate, os.X_OK):
            names.add(candidate.name.split("-", 1)[0])
    return names


def toolchain_inventory(root: Path) -> dict[str, Any]:
    """Digest every toolchain path and file byte under an exact, symlink-free tree."""
    entries: list[list[Any]] = []
    file_count = directory_count = total_file_bytes = 0
    for path in sorted(root.rglob("*"), key=lambda candidate: candidate.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        fail(not path.is_symlink(), f"pinned Rust toolchain contains a symlink: {relative}")
        if path.is_dir():
            entries.append([relative, "d", 0, ""])
            directory_count += 1
        else:
            fail(path.is_file(), f"pinned Rust toolchain contains a non-file entry: {relative}")
            size = path.stat().st_size
            entries.append([relative, "f", size, sha256_path(path)])
            file_count += 1
            total_file_bytes += size
    return {
        "tree_sha256": sha256_bytes(json.dumps(entries, separators=(",", ":"), ensure_ascii=True).encode()),
        "entry_count": len(entries), "file_count": file_count,
        "directory_count": directory_count, "total_file_bytes": total_file_bytes,
    }


def cache_state(roots: list[Path]) -> dict[str, tuple[int, int, int]]:
    state: dict[str, tuple[int, int, int]] = {}
    for root in roots:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            stat = path.lstat()
            state[str(path)] = (stat.st_mode, stat.st_size, stat.st_mtime_ns)
    return state
def authenticate_unpacked_crate(path: Path, checksum: str, filename: str) -> None:
    """Validate Cargo's unpacked registry checksum manifest and every listed file."""
    manifest_path = path / ".cargo-checksum.json"
    fail(manifest_path.is_file(), f"authenticated Cargo source lacks .cargo-checksum.json: {path}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise GateError(f"{manifest_path}: invalid checksum manifest: {error}") from error
    fail(isinstance(manifest, dict) and manifest.get("package") == checksum and isinstance(manifest.get("files"), dict), f"Cargo source package checksum mismatch for {filename}")
    expected = manifest["files"]
    actual: dict[str, str] = {}
    for candidate in sorted(path.rglob("*")):
        fail(not candidate.is_symlink(), f"authenticated Cargo source contains a symlink: {candidate}")
        if candidate.is_file() and candidate != manifest_path:
            relative = candidate.relative_to(path).as_posix()
            actual[relative] = sha256_path(candidate)
    fail(all(isinstance(name, str) and isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) for name, digest in expected.items()), f"Cargo source file checksum map is invalid for {filename}")
    fail(actual == expected, f"Cargo source contents/checksums mismatch for {filename}")


def make_read_only(path: Path) -> None:
    """Remove write permission from copied authenticated cache material."""
    for candidate in [path, *sorted(path.rglob("*"))]:
        candidate.chmod(candidate.stat().st_mode & ~0o222)




def resolve_rust_tools(scratch: Path, guard: dict[str, Any]) -> dict[str, Any]:
    """Authenticate the repository-pinned toolchain/cache and copy them into private homes."""
    policy_home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()
    source_cargo_home = (policy_home / ".cargo").resolve()
    source_rustup_home = (policy_home / ".rustup").resolve()
    fail(source_cargo_home.is_dir(), f"repository-policy Cargo cache is unavailable: {source_cargo_home}")
    fail(source_rustup_home.is_dir(), f"repository-policy Rust toolchain cache is unavailable: {source_rustup_home}")
    config = tomllib.loads((ROOT / "rust-tron" / "rust-toolchain.toml").read_text(encoding="utf-8"))
    expected_config = {"toolchain": {"channel": PINNED_RUST_TOOLCHAIN["channel"], "profile": PINNED_RUST_TOOLCHAIN["profile"], "components": list(PINNED_RUST_TOOLCHAIN["components"]), "targets": list(PINNED_RUST_TOOLCHAIN["targets"])}}
    fail(config == expected_config, "rust-tron toolchain differs from the repository-trusted C029 contract")
    channel = PINNED_RUST_TOOLCHAIN["channel"]
    source_toolchain = source_rustup_home / "toolchains" / f"{channel}-{PINNED_RUST_TOOLCHAIN['host']}"
    fail(source_toolchain.is_dir(), f"repository-trusted Rust toolchain is unavailable: {source_toolchain}")
    rustlib = source_toolchain / "lib" / "rustlib"
    manifest_names = tuple(sorted(path.name for path in rustlib.iterdir() if path.is_file() and (path.name.startswith("manifest-") or path.name in {"components", "multirust-channel-manifest.toml", "multirust-config.toml", "rust-installer-version"})))
    fail(manifest_names == tuple(sorted(PINNED_RUST_TOOLCHAIN["manifest_files"])), "pinned Rust toolchain manifest inventory mismatch")
    installed_components = tuple(line for line in (rustlib / "components").read_text(encoding="utf-8").splitlines() if line)
    fail(installed_components == PINNED_RUST_TOOLCHAIN["installed_components"], "pinned Rust installed-component inventory mismatch")
    for filename, key in (("multirust-channel-manifest.toml", "channel_manifest_sha256"), ("multirust-config.toml", "config_manifest_sha256"), ("components", "components_sha256")):
        fail(sha256_path(rustlib / filename) == PINNED_RUST_TOOLCHAIN[key], f"pinned Rust {filename} digest mismatch")
    source_inventory = toolchain_inventory(source_toolchain)
    expected_inventory = {key: PINNED_RUST_TOOLCHAIN[key] for key in ("tree_sha256", "entry_count", "file_count", "directory_count", "total_file_bytes")}
    fail(source_inventory == expected_inventory, "repository-trusted Rust toolchain tree inventory/digest mismatch")
    guard.update({"source_toolchain": source_toolchain, "source_inventory": source_inventory})
    guarded_roots = [source_toolchain, *[source_cargo_home / name for name in ("registry", "git") if (source_cargo_home / name).exists()]]
    guard.update({"guarded_roots": guarded_roots, "cache_state": cache_state(guarded_roots)})
    lock = tomllib.loads((ROOT / "rust-tron" / "Cargo.lock").read_text(encoding="utf-8"))
    cargo_home = scratch / "cargo-home"; rustup_home = scratch / "rustup-home"
    cargo_home.mkdir(); (rustup_home / "toolchains").mkdir(parents=True)
    source_registry = source_cargo_home / "registry"; private_registry = cargo_home / "registry"
    private_registry.mkdir()
    source_index = source_registry / "index"
    crate_inputs: dict[Path, str] = {}
    if source_index.exists():
        shutil.copytree(source_index, private_registry / "index", symlinks=False); make_read_only(private_registry / "index")
        for index_file in sorted((private_registry / "index").rglob("*")):
            if index_file.is_file(): crate_inputs[index_file] = sha256_path(index_file)
    shared_cargo_inputs: dict[Path, str] = {}
    for package in lock.get("package", []):
        source = package.get("source", ""); checksum = package.get("checksum")
        if not source.startswith("registry+"):
            fail(not source.startswith("git+"), f"Cargo.lock git input is not supported by the authenticated offline cache: {source}"); continue
        fail(isinstance(checksum, str) and re.fullmatch(r"[0-9a-f]{64}", checksum), f"Cargo.lock lacks a registry checksum for {package.get('name')}")
        stem = f"{package['name']}-{package['version']}"; filename = f"{stem}.crate"
        archives = sorted((source_registry / "cache").glob(f"*/{filename}"))
        fail(len(archives) <= 1, f"authenticated Cargo cache has ambiguous {filename} archives: {len(archives)}")
        if archives:
            fail(sha256_path(archives[0]) == checksum, f"Cargo cache checksum mismatch for {filename}")
            shared_cargo_inputs[archives[0]] = checksum
            destination = private_registry / "cache" / archives[0].parent.name / filename
            destination.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(archives[0], destination); make_read_only(destination); crate_inputs[destination] = checksum
            continue
        sources = sorted(path for path in (source_registry / "src").glob(f"*/{stem}") if path.is_dir())
        fail(len(sources) == 1, f"authenticated Cargo cache requires exactly one {filename} archive or unpacked {stem} source tree, found {len(sources)} sources")
        authenticate_unpacked_crate(sources[0], checksum, filename)
        for source_file in sorted(sources[0].rglob("*")):
            if source_file.is_file(): shared_cargo_inputs[source_file] = sha256_path(source_file)
        destination = private_registry / "src" / sources[0].parent.name / stem
        destination.parent.mkdir(parents=True, exist_ok=True); shutil.copytree(sources[0], destination, symlinks=False); make_read_only(destination)
        for copied_file in sorted(destination.rglob("*")):
            if copied_file.is_file(): crate_inputs[copied_file] = sha256_path(copied_file)
    private_toolchain = rustup_home / "toolchains" / source_toolchain.name
    copied = subprocess.run(["/usr/bin/cp", "--archive", "--reflink=auto", str(source_toolchain), str(private_toolchain)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    fail(copied.returncode == 0, f"private Rust toolchain materialization failed: {copied.stderr.strip()}")
    fail(toolchain_inventory(private_toolchain) == expected_inventory, "private Rust toolchain copy differs from trusted inventory")
    make_read_only(private_toolchain)
    cargo = private_toolchain / "bin" / "cargo"; rustc = private_toolchain / "bin" / "rustc"
    fail(sha256_path(cargo) == PINNED_RUST_TOOLCHAIN["cargo_sha256"], "repository-trusted cargo digest mismatch")
    fail(sha256_path(rustc) == PINNED_RUST_TOOLCHAIN["rustc_sha256"], "repository-trusted rustc digest mismatch")
    auth_env = {"PATH": os.pathsep.join((str(cargo.parent), "/usr/bin", "/bin")), "HOME": str(scratch), "CARGO_HOME": str(cargo_home), "RUSTUP_HOME": str(rustup_home), "RUSTUP_TOOLCHAIN": channel, "RUSTUP_AUTO_INSTALL": "0", "CARGO_NET_OFFLINE": "true", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
    rustc_version = subprocess.run([str(rustc), "--version"], env=auth_env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    cargo_version = subprocess.run([str(cargo), "--version"], env=auth_env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    fail(rustc_version.returncode == 0 and rustc_version.stdout.startswith(f"rustc {channel} "), f"pinned rustc authentication failed: {rustc_version.stderr.strip() or rustc_version.stdout.strip()}")
    fail(cargo_version.returncode == 0 and cargo_version.stdout.startswith(f"cargo {channel} "), f"pinned cargo authentication failed: {cargo_version.stderr.strip() or cargo_version.stdout.strip()}")
    guard.update({"cargo": cargo, "rustc": rustc, "cargo_home": cargo_home, "rustup_home": rustup_home, "channel": channel, "private_toolchain": private_toolchain, "crate_inputs": crate_inputs, "shared_cargo_inputs": shared_cargo_inputs})
    return guard


def verify_rust_inputs_unchanged(tools: dict[str, Any]) -> None:
    if "source_toolchain" in tools:
        fail(toolchain_inventory(tools["source_toolchain"]) == tools["source_inventory"], "shared authenticated Rust toolchain changed during gate execution")
    if "private_toolchain" in tools:
        fail(toolchain_inventory(tools["private_toolchain"])["tree_sha256"] == tools["source_inventory"]["tree_sha256"], "private authenticated Rust toolchain changed during gate execution")
    if "crate_inputs" in tools:
        fail(all(path.is_file() and sha256_path(path) == digest for path, digest in tools["crate_inputs"].items()), "authenticated Cargo cache changed during gate execution")
    if "shared_cargo_inputs" in tools:
        fail(all(path.is_file() and sha256_path(path) == digest for path, digest in tools["shared_cargo_inputs"].items()), "shared authenticated Cargo input changed during gate execution")
    if "guarded_roots" in tools:
        fail(cache_state(tools["guarded_roots"]) == tools["cache_state"], "shared Rust toolchain/Cargo cache metadata changed during gate execution")


def compilation_budget(target: Path, plans: dict[tuple[str, str, str], set[str]]) -> tuple[int, int]:
    existing = existing_target_names(target)
    missing = sum(target_name.replace("-", "_") not in existing for _, _, target_name in plans)
    return missing, 256 * 1024**2 + missing * 128 * 1024**2


def build_referenced_tests(tree: Path, scratch: Path, target: Path, plans: dict[tuple[str, str, str], set[str]], tools: dict[str, Any]) -> dict[Path, tuple[tuple[str, str, str], set[str]]]:
    fail(target.is_dir() and not any(target.iterdir()), f"private CARGO_TARGET_DIR must be unique and empty before compilation: {target}")

    build_home = scratch / "build-home"; build_tmp = scratch / "build-tmp"
    build_home.mkdir(); build_tmp.mkdir()
    cargo = tools["cargo"]; rustc = tools["rustc"]
    cargo_home = tools["cargo_home"]; rustup_home = tools["rustup_home"]; channel = tools["channel"]
    tool_path = os.pathsep.join((str(cargo.parent), "/usr/bin", "/bin"))
    base_env = {"PATH": tool_path, "HOME": str(build_home), "TMPDIR": str(build_tmp), "CARGO_HOME": str(cargo_home), "RUSTUP_HOME": str(rustup_home), "RUSTUP_TOOLCHAIN": channel, "RUSTUP_AUTO_INSTALL": "0", "RUSTC": str(rustc), "RUSTC_WRAPPER": "", "RUSTC_WORKSPACE_WRAPPER": "", "CARGO_BUILD_RUSTC_WRAPPER": "", "CARGO_NET_OFFLINE": "true", "CARGO_TARGET_DIR": str(target), "CARGO_INCREMENTAL": "0", "CARGO_BUILD_JOBS": "2", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
    executables: dict[Path, tuple[tuple[str, str, str], set[str]]] = {}
    for package, selector, target_name in sorted(plans):
        manifests = []
        for manifest in sorted((tree / "rust-tron" / "crates").glob("*/Cargo.toml")):
            if tomllib.loads(manifest.read_text(encoding="utf-8"))["package"]["name"] == package:
                manifests.append(manifest)
        fail(len(manifests) == 1, f"Rust package {package} resolves to {len(manifests)} manifests")
        crate = manifests[0].parent
        source_path = crate / ("src/lib.rs" if selector == "lib" else f"tests/{target_name}.rs")
        fail(source_path.is_file(), f"Rust exact target source is missing: {source_path.relative_to(tree)}")
        source_digest = sha256_path(source_path)
        source_relative = source_path.relative_to(tree)
        worktree_source = ROOT / source_relative
        fail(worktree_source.is_file() and sha256_path(worktree_source) == source_digest, f"current worktree source differs from disposable build source: {source_relative}")
        env = base_env
        build_started_ns = time.time_ns()
        argv = [cargo, "test", "--no-run", "--locked", "--offline", "-p", package]
        argv.extend(("--lib",) if selector == "lib" else ("--test", target_name))
        argv.append("--message-format=json-render-diagnostics")
        try:
            done = subprocess.run(argv, cwd=tree / "rust-tron", env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=1800)
        except subprocess.TimeoutExpired as error:
            captured = error.stdout or ""
            if isinstance(captured, bytes):
                captured = captured.decode(errors="replace")
            raise GateError(f"Rust referenced-target build timed out for {package} {selector} {target_name} after {error.timeout}s; Cargo output tail:\n{captured[-16000:]}") from error
        fail(done.returncode == 0, f"Rust referenced-target build failed for {package} {selector} {target_name} (exit {done.returncode}); Cargo output tail:\n{done.stdout[-16000:]}")
        selected: dict[Path, bool] = {}
        for line in done.stdout.splitlines():
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            executable = message.get("executable")
            cargo_target = message.get("target", {})
            expected_kind = "lib" if selector == "lib" else "test"
            if message.get("reason") == "compiler-artifact" and executable and cargo_target.get("name") == target_name and expected_kind in cargo_target.get("kind", []):
                selected[Path(executable)] = message.get("fresh") is False
        fail(len(selected) == 1, f"Rust exact target {package} {selector} {target_name} produced {len(selected)} executables")
        executable = next(iter(selected))
        fail(selected[executable], f"Rust exact target was reused instead of compiled from this invocation: {executable}")
        fail(executable.stat().st_mtime_ns >= build_started_ns, f"Rust exact target predates this build invocation: {executable}")
        fail(executable.is_relative_to(target), f"Rust executable escaped private CARGO_TARGET_DIR: {executable}")
        dep_info = executable.with_suffix(".d")
        fail(dep_info.is_file(), f"Rust exact target lacks compiler dep-info: {dep_info}")
        dep_text = dep_info.read_text(encoding="utf-8", errors="replace")
        expected_source = source_path.relative_to(tree / "rust-tron").as_posix()
        fail(expected_source in dep_text, f"Rust exact target dep-info does not bind current mapped source {expected_source}: {dep_info}")
        fail(sha256_path(source_path) == source_digest, f"Rust exact target disposable source changed during compilation: {expected_source}")
        fail(sha256_path(worktree_source) == source_digest, f"Rust exact target worktree source changed during compilation: {source_relative}")
        fail(executable not in executables, f"Rust executable collision for exact targets: {executable}")
        executables[executable] = ((package, selector, target_name), set(plans[(package, selector, target_name)]))
    fail(executables, "Rust referenced-target build produced no current-tree libtest executables")
    return dict(sorted(executables.items()))


def discover_rust_tests(executables: dict[Path, tuple[tuple[str, str, str], set[str]]], env: dict[str, str], cwd: Path) -> dict[Path, set[str]]:
    discovered: dict[Path, set[str]] = {}
    for executable in executables:
        done = subprocess.run([str(executable), "--list"], cwd=cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
        output = done.stdout + "\n" + done.stderr
        fail(done.returncode == 0, f"Rust test discovery failed for {executable.name} (exit {done.returncode}):\nstdout:\n{done.stdout[-2000:]}\nstderr:\n{done.stderr[-2000:]}")
        discovered[executable] = set(re.findall(r"^([^\s].*?): test$", output, re.M))
    fail(any(discovered.values()), "Rust test discovery returned zero compiled tests")
    return discovered


def validate_table_dispatcher(tree: Path, target: str, entries: list[tuple[str, str, str, dict[str, Any]]], ledger_ids: set[str], mapped_target_ids: dict[str, set[str]]) -> bool:
    """Recognize and validate a shared test proving a complete authoritative row table."""
    stable_ids = [entry[0] for entry in entries]
    selectors = [entry[1] for entry in entries]
    results = [entry[2] for entry in entries]
    if len(set(stable_ids)) != len(entries) or len(set(zip(stable_ids, selectors, results, strict=True))) != len(entries):
        return False
    by_artifact: dict[str, set[tuple[str, str, str]]] = {}
    for stable_id, selector, result, proof in entries:
        by_artifact.setdefault(proof["artifact"], set()).add((stable_id, selector, result))
    for artifact, selected in by_artifact.items():
        path = ROOT / artifact
        fail(path.name.endswith(".json") and ".v" in path.name, f"{target}: table dispatcher artifact is not versioned")
        authoritative: set[tuple[str, str, str]] = set()
        for candidate in artifact_rows(load(path)):
            candidate_id = candidate.get("stable_id", candidate.get("id"))
            if candidate_id not in ledger_ids or candidate_id not in mapped_target_ids.get(target, set()):
                continue
            try:
                candidate_target = canonical_rust_target(path, candidate)
                candidate_selector, candidate_result, _ = authoritative_fields(candidate)
            except GateError:
                continue
            if candidate_target == target and candidate_selector and candidate_result:
                authoritative.add((candidate_id, candidate_selector, candidate_result))
        if selected != authoritative:
            return False
    return True


def run_proofs(tree: Path, scratch: Path, target: Path, plans: dict[tuple[str, str, str], set[str]], commands: dict[str, Any], document: dict[str, Any], tools: dict[str, Any]) -> None:
    executables = build_referenced_tests(tree, scratch, target, plans, tools)
    discovery_home = scratch / "discovery-home"; discovery_tmp = scratch / "discovery-tmp"
    discovery_home.mkdir(); discovery_tmp.mkdir()
    runtime_cwd = tree / "rust-tron"
    cargo = tools["cargo"]; rustc = tools["rustc"]
    cargo_home = tools["cargo_home"]; rustup_home = tools["rustup_home"]; channel = tools["channel"]
    tool_path = os.pathsep.join((str(cargo.parent), "/usr/bin", "/bin"))
    rustc_env = {"PATH": tool_path, "HOME": str(discovery_home), "TMPDIR": str(discovery_tmp), "CARGO_HOME": str(cargo_home), "RUSTUP_HOME": str(rustup_home), "RUSTUP_TOOLCHAIN": channel, "LANG": "C", "LC_ALL": "C", "TZ": "UTC", "RUSTUP_AUTO_INSTALL": "0", "CARGO_NET_OFFLINE": "true"}
    rust_lib = subprocess.run([rustc, "--print", "target-libdir"], cwd=runtime_cwd, env=rustc_env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    fail(rust_lib.returncode == 0, f"rustc target library discovery failed (exit {rust_lib.returncode}): {rust_lib.stderr[-2000:]}")
    rust_libdir = Path(rust_lib.stdout.strip())
    fail(rust_libdir.is_dir(), f"rustc target library directory is unavailable: {rust_libdir}")
    library_dirs = [target / "debug" / "deps", target / "debug", rust_libdir]
    base_env = {"PATH": tool_path, "HOME": str(discovery_home), "TMPDIR": str(discovery_tmp), "CARGO_HOME": str(cargo_home), "RUSTUP_HOME": str(rustup_home), "RUSTUP_TOOLCHAIN": channel, "LANG": "C", "LC_ALL": "C", "TZ": "UTC", "RUST_TEST_THREADS": "1", "RUSTUP_AUTO_INSTALL": "0", "CARGO_NET_OFFLINE": "true", "CARGO_TARGET_DIR": str(target), "C029_REPO_ROOT": str(tree), "C029_FIXTURE_ROOT": str(tree / "docs" / "oracles"), "C029_JAVA_REFERENCE_ROOT": str(tree / "java-tron"), "LD_LIBRARY_PATH": os.pathsep.join(str(path) for path in library_dirs), "DYLD_FALLBACK_LIBRARY_PATH": os.pathsep.join(str(path) for path in library_dirs)}
    discovered = discover_rust_tests(executables, base_env, runtime_cwd)
    selected: dict[Path, list[str]] = {}
    for executable, (_, family_symbols) in executables.items():
        names = discovered[executable]
        exact_names: list[str] = []
        for family_symbol in sorted(family_symbols):
            matches = sorted(name for name in names if name == family_symbol or name.endswith("::" + family_symbol))
            fail(len(matches) == 1, f"Rust compiled-test inventory resolves explicit mapped family symbol {family_symbol!r} to {len(matches)} tests in {executable.name}: {matches}")
            exact_names.append(matches[0])
        selected[executable] = exact_names
    proof_targets: dict[str, tuple[str, str, str, str]] = {}
    for row in document["rows"]:
        for proof in row["rust_proofs"]:
            target_text = proof["target"]
            if target_text in proof_targets:
                continue
            source, identifier = rust_target_parts(target_text, require_source=True)
            assert source is not None
            proof_manifest = tree / "rust-tron" / "crates" / source.parts[2] / "Cargo.toml"
            proof_package = tomllib.loads(proof_manifest.read_text(encoding="utf-8"))["package"]["name"]
            inside = source.parts[3:]
            proof_selector = "lib" if inside[0] == "src" else "test"
            proof_target = proof_package.replace("-", "_") if proof_selector == "lib" else Path(*inside).stem
            proof_targets[target_text] = (proof_package, proof_selector, proof_target, identifier)
    executions: dict[tuple[Path, str, str], tuple[dict[str, Any], list[tuple[str, str, str, dict[str, Any]]]]] = {}
    for executable, test_names in selected.items():
        package, selector, target_name = executables[executable][0]
        for test_name in test_names:
            matches = [family for family in executables[executable][1] if test_name == family or test_name.endswith("::" + family)]
            fail(len(matches) == 1, f"discovered test {test_name!r} does not identify exactly one mapped family symbol")
            family_symbol = matches[0]
            for row in document["rows"]:
                command_id = row["proof_command_id"]
                if command_id is None:
                    continue
                matching_proofs = [proof for proof in row["rust_proofs"] if proof_targets[proof["target"]] == (package, selector, target_name, family_symbol)]
                if not matching_proofs:
                    continue
                command = commands[command_id]
                command_filter = [value for value in command["argv"][command["argv"].index("--") + 1:] if not value.startswith("-")]
                fail(command_filter == [family_symbol], f"{command_id}: canonical command does not select only {family_symbol!r}")
                key = (executable, test_name, command_id)
                execution = executions.setdefault(key, (command, []))
                for proof in matching_proofs:
                    authority = authoritative_proof(row, proof)
                    fail(authority is not None, f"{row['stable_id']}: exact executable proof lacks authoritative row selector/result")
                    execution[1].append((row["stable_id"], authority[0], authority[1], proof))
    for defect in document["compatibility_defects"]:
        for target_text in defect["rust_test_ids"]:
            if target_text in proof_targets:
                continue
            source, identifier = rust_target_parts(target_text, require_source=True)
            assert source is not None
            proof_manifest = tree / "rust-tron" / "crates" / source.parts[2] / "Cargo.toml"
            proof_package = tomllib.loads(proof_manifest.read_text(encoding="utf-8"))["package"]["name"]
            inside = source.parts[3:]
            proof_selector = "lib" if inside[0] == "src" else "test"
            proof_target = proof_package.replace("-", "_") if proof_selector == "lib" else Path(*inside).stem
            proof_targets[target_text] = (proof_package, proof_selector, proof_target, identifier)
    external_execution_keys: set[tuple[Path, str, str]] = set()
    for defect in document["compatibility_defects"]:
        if defect["affected_stable_ids"]:
            continue
        links_by_command = {link.split("|", 1)[0]: link for link in defect["result_links"]}
        for command_id in defect["command_ids"]:
            command = commands[command_id]
            command_symbol = next(value for value in command["argv"][command["argv"].index("--") + 1:] if not value.startswith("-"))
            matching_targets = [candidate for candidate in defect["rust_test_ids"] if proof_targets[candidate][3] == command_symbol or proof_targets[candidate][3].endswith("::" + command_symbol)]
            fail(len(matching_targets) == 1, f"{command_id}: external defect command resolves to {len(matching_targets)} Rust targets")
            target_text = matching_targets[0]
            expected_argv = canonical_proof_argv({}, target_text)
            fail(expected_argv is not None and command["argv"] == expected_argv, f"{command_id}: external defect command does not exactly select {target_text}")
            package, selector, target_name, identifier = proof_targets[target_text]
            matching_executables = [executable for executable, (identity, _) in executables.items() if identity == (package, selector, target_name)]
            fail(len(matching_executables) == 1, f"{command_id}: external defect target resolves to {len(matching_executables)} executables")
            executable = matching_executables[0]
            matching_names = sorted(name for name in discovered[executable] if name == identifier or name.endswith("::" + identifier))
            fail(len(matching_names) == 1, f"{command_id}: external defect symbol {identifier!r} resolves to {len(matching_names)} compiled tests")
            key = (executable, matching_names[0], command_id)
            executions[key] = (command, [(defect["finding_id"], defect["source_refs"][0], links_by_command[command_id], {"target": target_text})])
            external_execution_keys.add(key)
    expected_external_commands = {
        command_id
        for defect in document["compatibility_defects"]
        if not defect["affected_stable_ids"]
        for command_id in defect["command_ids"]
    }
    actual_external_commands = {key[2] for key in external_execution_keys}
    fail(actual_external_commands == expected_external_commands, f"external defect execution linkage mismatch: missing={sorted(expected_external_commands-actual_external_commands)} orphan={sorted(actual_external_commands-expected_external_commands)}")
    fail(executions, "proof execution inventory is empty")
    ledger_ids = {row["id"] for row in load(LEDGER)["rows"]}
    proof_modes: dict[tuple[Path, str, str], str] = {}
    mapped_target_ids: dict[str, set[str]] = {}
    for row in document["rows"]:
        if row["proof_command_id"] is None:
            continue
        for proof in row["rust_proofs"]:
            mapped_target_ids.setdefault(proof["target"], set()).add(row["stable_id"])
    for key, (_, entries) in executions.items():
        if key in external_execution_keys:
            proof_modes[key] = "external"
            continue
        target_text = entries[0][3]["target"]
        exact_union = validate_table_dispatcher(tree, target_text, entries, ledger_ids, mapped_target_ids)
        proof_modes[key] = "direct" if len(entries) == 1 and exact_union else "table" if len(entries) > 1 and exact_union else "per_id"
        if len(entries) > 1 and proof_modes[key] == "per_id":
            source, _ = rust_target_parts(target_text, require_source=True)
            assert source is not None
            source_text = (tree / source).read_text(encoding="utf-8")
            emitter_contract = "C029_CASE_SELECTOR" in source_text and "C029_EXPECTED_RESULT" in source_text and ("println!(" in source_text or "print!(" in source_text)
            fail(emitter_contract, f"{target_text}: multi-row symbol is neither an exact authoritative table nor a verified per-ID emitter")
    observations = []
    for run in range(2):
        outputs = []
        totals: dict[str, list[int]] = {command_id: [0, 0, 0] for command_id in commands}
        for execution_key, (command, entries) in sorted(executions.items(), key=lambda item: tuple(str(value) for value in item[0])):
            executable, test_name, command_id = execution_key
            proof_mode = proof_modes[execution_key]
            entry_batches = [entries] if proof_mode == "table" else [[entry] for entry in entries]
            for entry_batch in entry_batches:
                stable_id, case_selector, expected_result, _ = entry_batch[0]
                run_root = scratch / "runs" / command_id / str(run) / (proof_mode if proof_mode != "per_id" else stable_id)
                home = run_root / "home"; tmp = run_root / "tmp"
                home.mkdir(parents=True); tmp.mkdir()
                env = dict(base_env)
                env.update({key: value for key, value in command["environment"].items() if not (isinstance(value, str) and value.startswith("${"))})
                env.update({"HOME": str(home), "TMPDIR": str(tmp), "C029_CASE_SELECTOR": case_selector, "C029_EXPECTED_RESULT": expected_result})
                runtime_cwd = tree / command["cwd"]
                argv = [str(executable), test_name, "--exact", "--nocapture", "--test-threads=1"]
                done = subprocess.run(argv, cwd=runtime_cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=command["timeout_seconds"])
                output = done.stdout + "\n" + done.stderr
                passed, ignored, skipped = parse_test_result(output)
                fail(done.returncode == command["result_contract"]["expected_exit"], f"{command_id}: run {run+1} exact test {test_name!r} exit {done.returncode}\nstdout:\n{done.stdout[-4000:]}\nstderr:\n{done.stderr[-4000:]}")
                fail(passed + ignored + skipped == 1, f"{command_id}: exact test selected {passed + ignored + skipped} tests; expected exactly 1")
                if proof_mode == "per_id":
                    fail(stable_id in output and expected_result in output, f"{command_id}: exact test {test_name!r} did not emit mapped result for {stable_id}")
                for index, value in enumerate((passed, ignored, skipped)):
                    totals[command_id][index] += value
                outputs.append(output)
        for command_id, command in commands.items():
            passed, ignored, skipped = totals[command_id]
            contract = command["result_contract"]
            fail(passed >= contract["minimum_executed_tests"], f"{command_id}: run {run+1} executed {passed} tests")
            fail(not contract["forbid_ignored"] or ignored == 0, f"{command_id}: ignored-test credit ({ignored})")
            fail(not contract["forbid_skipped"] or skipped == 0, f"{command_id}: skipped-test credit ({skipped})")
        normalized = re.sub(r"finished in [0-9.]+s", "finished in ${TIME}", re.sub(re.escape(str(scratch / "runs")), "${RUNS}", "\n".join(outputs)))
        observations.append(sha256_bytes(normalized.encode()))
    fail(observations[0] == observations[1], "deterministic double-run projection mismatch")


def mutation_self_checks(document: dict[str, Any], ledger: dict[str, Any]) -> None:
    mutations = []
    def add(label: str, mutate) -> None:
        changed = copy.deepcopy(document); mutate(changed); mutations.append((label, changed))
    add("stable ID substitution", lambda value: value["rows"][0].__setitem__("stable_id", value["rows"][1]["stable_id"]))
    add("source identity drift", lambda value: value["rows"][0]["source_identity"].__setitem__("line", -1))
    add("mapped accounting", lambda value: value["accounting"].__setitem__("mapped", value["accounting"]["mapped"] + 1))
    add("generic accounting", lambda value: value["accounting"].__setitem__("generic", 1))
    add("dangling proof command", lambda value: value["rows"][0].__setitem__("proof_command_id", "C029-PROOF-MISSING"))
    non_defect_index = next(index for index, finding in enumerate(document["review_findings"]) if finding["classification"] == "non_compatibility")
    def relabel_with_evidence(value: dict[str, Any]) -> None:
        finding = value["review_findings"][non_defect_index]
        finding["classification"] = "compatibility_defect"
        finding["classification_evidence"]["derived_classification"] = "compatibility_defect"
    add("classification label and recorded derivation", relabel_with_evidence)
    external_defects = [defect for defect in document["compatibility_defects"] if not defect["affected_stable_ids"]]
    if len(external_defects) >= 2:
        first_id = external_defects[0]["finding_id"]
        second_link = external_defects[1]["result_links"][0]
        add("cross-defect recurrence result substitution", lambda value: next(defect for defect in value["compatibility_defects"] if defect["finding_id"] == first_id)["result_links"].__setitem__(0, second_link))
    if document["unsupported_by_owning_artifact_repair"]:
        add("unsupported inventory removal", lambda value: next(iter(value["unsupported_by_owning_artifact_repair"].values())).pop())
    covered_index = next(index for index, row in enumerate(document["rows"]) if row["applicability"]["type"] == "covered")
    add("covered proof removal", lambda value: value["rows"][covered_index].__setitem__("rust_proofs", []))
    for label, mutated in mutations:
        try:
            validate_artifact(mutated, ledger, check_files=False)
        except (GateError, StopIteration):
            continue
        raise GateError(f"mutation self-check accepted bypass: {label}")


OWNER_TEST_CRATES = {
    "c017": "tron-consensus", "c018": "tron-consensus", "c019": "tron-execution",
    "c021": "tron-network", "c022": "tron-apis", "c023": "tron-apis", "c024": "tron-apis",
    "c025": "tron-node", "c026": "tron-node", "c027": "tron-node",
}

def canonical_rust_target(path: Path, candidate: dict[str, Any]) -> str | None:
    """Return only an exact executable Rust test target from an authoritative row."""
    values: list[str] = []
    referenced_target = referenced_c021_rust_test(candidate)
    if referenced_target is not None:
        values.append(referenced_target)
    containers = (candidate, *(candidate.get(key) for key in ("dispatcher_evidence", "rust_invocation", "proof", "evidence", "executable_proof", "replacement", "reassignment")))
    for container in containers:
        if isinstance(container, dict):
            values.extend(value for key in ("rust_symbol", "rust_test", "rust_target", "rust_case", "rust_test_symbol") if isinstance((value := container.get(key)), str) and value)
    for value in values:
        source, _ = rust_target_parts(value)
        if source is not None:
            return value
    dispatch = first_string(candidate, ("rust_dispatch",))
    case = first_string(candidate, ("rust_case", "rust_test"))
    module_test = next((value for value in values if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*::[A-Za-z_][A-Za-z0-9_]*", value)), None)
    prefix = path.name.split("-", 1)[0]
    owner_crate = OWNER_TEST_CRATES.get(prefix)
    if owner_crate and module_test:
        test_target, test_name = module_test.split("::", 1)
        return f"rust-tron/crates/{owner_crate}/tests/{test_target}.rs::{test_name}"
    target_name = first_string(candidate, ("rust_target",))
    test_name = first_string(candidate, ("rust_test",))
    prefix = path.name.split("-", 1)[0]
    crate = OWNER_TEST_CRATES.get(prefix)
    if crate and target_name and test_name and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", target_name) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", test_name):
        return f"rust-tron/crates/{crate}/tests/{target_name}.rs::{test_name}"
    if dispatch and case and re.fullmatch(r"[a-z0-9-]+::[A-Za-z_][A-Za-z0-9_]*", dispatch):
        crate, test_target = dispatch.split("::", 1)
        return f"rust-tron/crates/{crate}/tests/{test_target}.rs::{case.rsplit('::', 1)[-1]}"
    if path.name == "c023-ownership-reconciliation.v1.json":
        value = next((value for value in values if value.startswith("c023_scenarios::")), None)
        if value:
            return f"rust-tron/crates/tron-apis/tests/c023_scenarios.rs::{value.split('::', 1)[1]}"
    return None


def canonical_proof_argv(candidate: dict[str, Any], target: str) -> list[str] | None:
    command: Any = candidate.get("canonical_command", candidate.get("command"))
    for nested_key in ("rust_invocation", "executable_proof", "replacement", "reassignment"):
        nested = candidate.get(nested_key)
        if command is None and isinstance(nested, dict):
            command = nested.get("canonical_command", nested.get("command", nested.get("argv", nested.get("dispatch"))))
    source, identifier = rust_target_parts(target, require_source=True)
    assert source is not None
    crate = source.parts[2]
    inside = source.parts[3:]
    if len(inside) == 2 and inside[0] == "tests":
        selector = ("--test", Path(inside[1]).stem)
    elif inside and inside[0] == "src":
        selector = ("--lib", None)
    else:
        return None
    if command is not None:
        if isinstance(command, str):
            provenance = shlex.split(command)
        elif isinstance(command, list) and all(isinstance(value, str) for value in command):
            provenance = list(command)
        else:
            return None
        if any(token in {";", "||", "|"} for token in provenance):
            return None
        segments: list[list[str]] = [[]]
        for token in provenance:
            if token == "&&":
                if not segments[-1]:
                    return None
                segments.append([])
            else:
                segments[-1].append(token)
        if not segments[-1]:
            return None
        matching: list[list[str]] = []
        for segment in segments:
            base = segment[:segment.index("--")] if "--" in segment else segment
            if len(base) < 2 or Path(base[0]).name != "cargo" or base[1] != "test":
                return None
            packages = [base[index + 1] for index, value in enumerate(base[:-1]) if value in {"-p", "--package"}]
            if selector[0] == "--test":
                targets = [base[index + 1] for index, value in enumerate(base[:-1]) if value == "--test"]
                matches_target = targets == [selector[1]] and "--lib" not in base
            else:
                matches_target = "--lib" in base and "--test" not in base
            if packages == [crate] and matches_target:
                matching.append(segment)
        if len(matching) != 1:
            return None
    argv = ["cargo", "test", "--offline", "--locked", "-p", crate]
    argv.append(selector[0])
    if selector[1] is not None:
        argv.append(selector[1])
    argv.extend(("--", identifier, "--exact", "--test-threads=1"))
    return argv


def validate_c016_synthesis(refreshed: dict[str, Any], commands_by_argv: dict[tuple[str, ...], dict[str, Any]]) -> None:
    """Require all executable and explicitly non-applicable C016 Java rows to retain exact evidence."""
    owner = load(C016_OWNERSHIP)
    owner_rows = owner.get("java_test_rows")
    owner_ids = owner.get("java_test_ids")
    excluded = owner.get("non_applicable_java_test_rows")
    fail(isinstance(owner_rows, list) and len(owner_rows) == C016_EXECUTABLE_ROWS, f"C016 owner artifact: exact {C016_EXECUTABLE_ROWS} executable java_test_rows required")
    fail(isinstance(owner_ids, list) and len(owner_ids) == C016_EXECUTABLE_ROWS, f"C016 owner artifact: exact {C016_EXECUTABLE_ROWS} executable java_test_ids required")
    fail(isinstance(excluded, list) and len(excluded) == owner.get("non_applicable_java_test_row_count") == C016_NON_APPLICABLE_ROWS, f"C016 owner artifact: exact {C016_NON_APPLICABLE_ROWS} non-applicable Java rows required")

    fail([candidate.get("stable_id") for candidate in owner_rows] == owner_ids, "C016 owner artifact: Java row stable-ID order mismatch")
    refreshed_by_id = {row["stable_id"]: row for row in refreshed["rows"]}
    excluded_ids: set[str] = set()
    for candidate in excluded:
        stable_id = candidate.get("stable_id")
        fail(isinstance(stable_id, str) and stable_id not in excluded_ids and stable_id not in owner_ids, "C016 owner artifact: non-applicable stable IDs must be unique and disjoint")
        excluded_ids.add(stable_id)
        row = refreshed_by_id.get(stable_id)
        constraint = candidate.get("constraint")
        fail(row is not None and candidate.get("decision") == "not_applicable", f"{stable_id}: invalid C016 non-applicable evidence")
        fail(isinstance(constraint, str) and len(constraint.split()) >= 8, f"{stable_id}: concrete C016 non-applicable constraint required")
        fail(row["applicability"] == {"type": "non_applicable", "rationale": constraint}, f"{stable_id}: synthesized C016 non-applicable decision differs from owner")
        fail(row["behavior_claims"] == [constraint] and row["rust_proofs"] == [] and row["proof_command_id"] is None and row["observable_result"] is None, f"{stable_id}: non-applicable C016 row received execution credit")
    for candidate in owner_rows:
        stable_id = candidate["stable_id"]
        row = refreshed_by_id.get(stable_id)
        symbol = f"c016_tcase_{stable_id.removeprefix('TCASE-').lower()}"
        target = candidate.get("rust_symbol")
        fail(isinstance(target, str), f"{stable_id}: C016 Rust symbol is absent")
        if candidate.get("target_family") != "consensus":
            expected_target = f"rust-tron/crates/tron-execution/tests/{candidate['target_family'].join(('c016_', '.rs'))}::{symbol}"
            fail(target == expected_target, f"{stable_id}: C016 Rust symbol is not the exact c016_tcase target")
        else:
            symbol = rust_target_parts(target, require_source=True)[1]
        argv = canonical_proof_argv(candidate, target)
        fail(argv is not None, f"{stable_id}: C016 canonical command does not select exactly {symbol}")
        command = commands_by_argv.get(tuple(argv))
        if candidate.get("target_family") == "consensus":
            fail(row["proof_command_id"] is not None, f"{stable_id}: C016 consensus rehome lacks an executable proof command")
        else:
            fail(command is not None, f"{stable_id}: C016 canonical command is absent from proof execution plan")
        expected = candidate.get("expected_result")
        selector = candidate.get("fixture_selector")
        result_digest = candidate.get("expected_result_sha256", candidate.get("result_digest"))
        dispatcher = candidate.get("dispatcher_evidence")
        fail(isinstance(expected, str) and expected.startswith(f"{stable_id}|observable:") and not expected.endswith("|behavior-ok"), f"{stable_id}: C016 authoritative observable result is missing or generic")
        fail(isinstance(selector, str) and selector.startswith(f"{stable_id}:") and selector.removeprefix(f"{stable_id}:") == expected.removeprefix(f"{stable_id}|observable:"), f"{stable_id}: C016 authoritative fixture selector/result mismatch")
        fail(isinstance(result_digest, str) and re.fullmatch(r"[0-9a-f]{64}", result_digest) is not None and result_digest == sha256_bytes(expected.encode()), f"{stable_id}: C016 authoritative result digest mismatch")
        fail(isinstance(dispatcher, dict) and dispatcher.get("observable_result") == expected and dispatcher.get("selector") == selector and dispatcher.get("expected_result_sha256") == result_digest and dispatcher.get("rust_symbol") == target, f"{stable_id}: C016 dispatcher evidence differs from authoritative result/selector/digest/target")
        fail(row["applicability"]["type"] == "covered", f"{stable_id}: C016 executable row is not covered")
        fail(row["observable_result"] == expected, f"{stable_id}: synthesized observable result differs from C016 owner")
        if candidate.get("target_family") == "consensus":
            fail(len(row["rust_proofs"]) == 1 and row["rust_proofs"][0]["target"] == target, f"{stable_id}: synthesized C016 consensus proof is not exact")
        else:
            fail(row["proof_command_id"] == command["id"], f"{stable_id}: synthesized proof command differs from C016 owner")
            fail(row["rust_proofs"] == [{"artifact": "docs/oracles/c016-ownership-reconciliation.v1.json", "selector": selector, "target": target}], f"{stable_id}: synthesized C016 proof is not exact")
    deadline_ids = {
        "TCASE-278A08C04434DD3C",
        "TCASE-5EE7BE8B2946C5A4",
        "TCASE-E2B2E810B8609151",
    }
    fail(deadline_ids <= set(owner_ids), "C016 owner artifact: production deadline Java contracts are absent")
    source_asserts(
        "rust-tron/crates/tron-execution/src/runtime.rs",
        ("trigger_is_constant_abi(envelope, session, self.config)", "Self::execution_deadline(", "self.config.constant_call_timeout", "retry"),
        "C016-production-deadline",
    )
    source_asserts(
        "rust-tron/crates/tron-execution/src/pipeline.rs",
        ("constant_call_timeout", "RuntimeConfig", "execution_config"),
        "C016-production-deadline",
    )

def c023_non_applicable_result(candidate: dict[str, Any]) -> dict[str, str]:
    applicability = candidate["applicability"]
    observation = candidate["java_observation"]
    return {
        "terminal_state": "non_applicable",
        "source_method_sha256": observation["source_method_sha256"],
        "reason": applicability["reason"],
        "java_surface": applicability["java_surface"],
        "rust_surface": applicability["rust_surface"],
    }


def validate_c023_synthesis(refreshed: dict[str, Any], commands_by_argv: dict[tuple[str, ...], dict[str, Any]]) -> None:
    """Require 294 executable and 39 source-reviewed non-applicable C023 Java rows."""
    owner = load(C023_OWNERSHIP)
    fail(owner.get("canonical_counts") == {"production_routes": 215, "java_tests": C023_JAVA_CONTRACTS, "total": 548}, "C023 owner artifact: canonical counts drift")
    candidates = [candidate for candidate in owner.get("rows", []) if candidate.get("kind") == "java_test"]
    fail(len(candidates) == C023_JAVA_CONTRACTS, f"C023 owner artifact: exact {C023_JAVA_CONTRACTS} Java contracts required")
    executable = [candidate for candidate in candidates if candidate.get("disposition") == "executed"]
    non_applicable = [candidate for candidate in candidates if candidate.get("disposition") == "reviewed_non_applicable"]
    fail(len(executable) == C023_EXECUTABLE_ROWS and len(non_applicable) == C023_NON_APPLICABLE_ROWS, f"C023 owner artifact: expected {C023_EXECUTABLE_ROWS} executable and {C023_NON_APPLICABLE_ROWS} reviewed-non-applicable Java rows")
    stable_ids = [candidate.get("stable_id") for candidate in candidates]
    fail(all(isinstance(stable_id, str) and ID_RE.fullmatch(stable_id) for stable_id in stable_ids) and len(set(stable_ids)) == C023_JAVA_CONTRACTS, "C023 owner artifact: Java stable IDs must be exact and unique")
    behavior_keys = [candidate.get("behavior", {}).get("key") for candidate in executable]
    fail(all(isinstance(key, str) and key for key in behavior_keys) and len(set(behavior_keys)) == C023_EXECUTABLE_ROWS, "C023 owner artifact: executable source-specific behavior keys must be exact and unique")
    refreshed_by_id = {row["stable_id"]: row for row in refreshed["rows"]}
    for candidate in non_applicable:
        stable_id = candidate["stable_id"]
        row = refreshed_by_id.get(stable_id)
        applicability = candidate.get("applicability")
        fail(row is not None and candidate.get("terminal_state") == "non_applicable" and candidate.get("proof_kind") == "non_applicable_source_review", f"{stable_id}: invalid C023 reviewed-non-applicable evidence")
        fail(isinstance(applicability, dict) and applicability.get("state") == "reviewed_non_applicable", f"{stable_id}: C023 source-review applicability is absent")
        reason = applicability.get("reason")
        fail(isinstance(reason, str) and len(reason.split()) >= 12, f"{stable_id}: concrete C023 source-review rationale required")
        fail(all(isinstance(applicability.get(field), str) and applicability[field] for field in ("java_surface", "rust_surface")), f"{stable_id}: C023 Java/Rust surface rationale is incomplete")
        observation = candidate.get("java_observation")
        fail(isinstance(observation, dict) and re.fullmatch(r"[0-9a-f]{64}", observation.get("source_method_sha256", "")) is not None, f"{stable_id}: C023 source-method digest is absent")
        result = c023_non_applicable_result(candidate)
        fail(row["behavior_claims"] == [reason] and row["rust_proofs"] == [] and row["proof_command_id"] is None and row["observable_result"] == result, f"{stable_id}: C023 reviewed-non-applicable row must retain exact source-review evidence without execution credit")
        fail(row["applicability"] == {"type": "non_applicable", "rationale": reason}, f"{stable_id}: synthesized C023 non-applicable rationale differs from source review")
        owner_link = f"docs/oracles/c023-ownership-reconciliation.v1.json#{stable_id}"
        fail(owner_link in row["fixture_links"] and all(link == owner_link or link.partition("#")[0] == "docs/oracles/java-test-ownership.v1.json" for link in row["fixture_links"]), f"{stable_id}: C023 non-applicable fixtures must retain only ledger identity and source-review evidence")
    for candidate in executable:
        stable_id = candidate["stable_id"]
        row = refreshed_by_id.get(stable_id)
        fail(row is not None, f"{stable_id}: C023 authoritative Java contract is absent from C029 reconciliation")
        selector = candidate.get("fixture_selector")
        expected = candidate.get("expected_result")
        target = canonical_rust_target(C023_OWNERSHIP, candidate)
        argv = canonical_proof_argv(candidate, target) if target else None
        fail(isinstance(selector, str) and selector == candidate.get("behavior_selector") == stable_id, f"{stable_id}: C023 exact behavior selector mismatch")
        fail(isinstance(expected, str) and expected.startswith(f"{stable_id}|") and f"|family={candidate.get('behavior_family')}" in expected, f"{stable_id}: C023 exact expected-result contract mismatch")
        fail(target is not None and argv is not None, f"{stable_id}: C023 exact executable target/command is incomplete")
        command = commands_by_argv.get(tuple(argv))
        fail(command is not None, f"{stable_id}: C023 canonical command is absent from proof execution plan")
        fail(row["applicability"]["type"] == "covered" and row["observable_result"] == expected, f"{stable_id}: synthesized C023 result differs from owner")
        fail(row["proof_command_id"] == command["id"], f"{stable_id}: synthesized C023 proof command differs from owner")
        fail(row["rust_proofs"] == [{"artifact": "docs/oracles/c023-ownership-reconciliation.v1.json", "selector": selector, "target": target}], f"{stable_id}: synthesized C023 proof is not exact")



def normalize_c025_proofs(rows: list[dict[str, Any]]) -> int:
    """Collapse every C025 proof equivalent to one exact source-qualified target."""
    normalized_count = 0
    for row in rows:
        if not row["owning_item"].startswith("C025.") or not row["rust_proofs"]:
            continue
        normalized: list[dict[str, Any]] = []
        targets: set[str] = set()
        for proof in row["rust_proofs"]:
            target = resolve_c025_family_target(ROOT, row, proof)
            source, _ = rust_target_parts(target, require_source=True)
            assert source is not None
            normalized_proof = {**proof, "target": target}
            normalized_count += int(normalized_proof != proof or target in targets)
            if target not in targets:
                normalized.append(normalized_proof)
                targets.add(target)
        row["rust_proofs"] = normalized
    bare = [proof["target"] for row in rows if row["owning_item"].startswith("C025.") for proof in row["rust_proofs"] if rust_target_parts(proof["target"])[0] is None]
    fail(not bare, f"C025 synthesis retained {len(bare)} bare proof targets")
    return normalized_count


def synthesize_reconciliation(document: dict[str, Any]) -> dict[str, Any]:
    """Merge exact enriched owner evidence into the fixed 3443-row reconciliation."""
    refreshed = copy.deepcopy(document)
    validate_pinned_owner_inventories()
    c016_owner = load(C016_OWNERSHIP)
    c016_non_applicable = {candidate["stable_id"]: candidate for candidate in c016_owner.get("non_applicable_java_test_rows", [])}
    c016_executable = {candidate["stable_id"]: candidate for candidate in c016_owner.get("java_test_rows", [])}
    ledger_by_id = {source["id"]: source for source in load(LEDGER)["rows"]}
    commands_by_argv: dict[tuple[str, ...], dict[str, Any]] = {}
    external_seed_ids = {
        command_id
        for defect in refreshed["compatibility_defects"]
        if not defect.get("affected_stable_ids")
        for command_id in defect.get("command_ids", [])
    }
    c023_owner = load(C023_OWNERSHIP)
    c023_non_applicable = {
        candidate["stable_id"]: candidate
        for candidate in c023_owner.get("rows", [])
        if candidate.get("kind") == "java_test" and candidate.get("disposition") == "reviewed_non_applicable"
    }
    for command in refreshed["proof_commands"]:
        if command["id"] in external_seed_ids:
            commands_by_argv[tuple(command["argv"])] = command
    for row in refreshed["rows"]:
        row["treatment"] = source_treatment(ledger_by_id[row["stable_id"]])
        c016_exclusion = c016_non_applicable.get(row["stable_id"])
        if c016_exclusion is not None:
            constraint = c016_exclusion["constraint"]
            row["behavior_claims"] = [constraint]
            row["applicability"] = {"type": "non_applicable", "rationale": constraint}
            row["rust_proofs"] = []
            row["proof_command_id"] = None
            row["observable_result"] = None
            continue
        c023_exclusion = c023_non_applicable.get(row["stable_id"])
        if c023_exclusion is not None:
            reason = c023_exclusion["applicability"]["reason"]
            row["behavior_claims"] = [reason]
            row["applicability"] = {"type": "non_applicable", "rationale": reason}
            row["rust_proofs"] = []
            row["proof_command_id"] = None
            row["observable_result"] = c023_non_applicable_result(c023_exclusion)
            owner_link = f"docs/oracles/c023-ownership-reconciliation.v1.json#{row['stable_id']}"
            ledger_links = [link for link in row["fixture_links"] if link.partition("#")[0] == "docs/oracles/java-test-ownership.v1.json"]
            row["fixture_links"] = list(dict.fromkeys([*ledger_links, owner_link]))
            continue
        if row["applicability"]["type"] == "non_applicable" and row["stable_id"] not in c016_executable:
            continue
        selected: tuple[str, str, str, str, list[str], str] | None = None
        c016_candidate = c016_executable.get(row["stable_id"])
        if c016_candidate is not None:
            selector, expected, rust_test = authoritative_fields(c016_candidate)
            target = canonical_rust_target(C016_OWNERSHIP, c016_candidate)
            argv = canonical_proof_argv(c016_candidate, target) if target else None
            claim = first_string(c016_candidate, ("behavior_claim", "rationale"))
            if all((selector, expected, rust_test, target, argv, claim)):
                selected = ("docs/oracles/c016-ownership-reconciliation.v1.json", selector, target, expected, argv, claim)
        owner_chunk = row["owning_item"].split(".", 1)[0].lower()
        owner_path = f"docs/oracles/{owner_chunk}-ownership-reconciliation.v1.json"
        owner_link = f"{owner_path}#{row['stable_id']}"
        links = [*([owner_link] if (ROOT / owner_path).is_file() else []), *(link for link in row["fixture_links"] if link != owner_link)]
        fallback: tuple[str, Any, str] | None = None
        for link in ([] if selected is not None else links):
            linked = linked_json_row(row, link)
            if linked is None or linked[0] == LEDGER:
                continue
            path, candidate, token = linked
            selector, expected, rust_test = authoritative_fields(candidate)
            fallback_claim: Any = first_string(candidate, ("equivalence_basis", "equivalence", "rationale", "reason", "decision", "covered_contract", "disposition", "java_case", "case_symbol", "evidence_family"))
            if fallback_claim is None and isinstance(candidate.get("java_observation"), dict) and candidate["java_observation"]:
                fallback_claim = candidate["java_observation"]
            if expected and fallback_claim and fallback is None:
                fallback = (expected, fallback_claim, str(path.relative_to(ROOT)))
            target = canonical_rust_target(path, candidate)
            argv = canonical_proof_argv(candidate, target) if target else None
            if not all((selector, expected, rust_test, target, argv)):
                continue
            claim: Any = first_string(candidate, ("behavior_claim", "java_behavior", "observation", "rationale", "behavior", "assertion_family", "operation", "case", "java_case", "case_symbol", "evidence_family", "disposition"))
            if claim is None and isinstance(candidate.get("java_observation"), dict) and candidate["java_observation"]:
                claim = candidate["java_observation"]
            if claim is None:
                slices = candidate.get("behavior_slices")
                claim = slices[0] if isinstance(slices, list) and slices and isinstance(slices[0], str) else None
            if claim:
                selected = (str(path.relative_to(ROOT)), selector, target, expected, argv, claim)
                break
        if selected is None:
            row["rust_proofs"] = []
            row["proof_command_id"] = None
            if fallback is not None:
                expected, claim, artifact = fallback
                row["behavior_claims"] = [claim]
                row["observable_result"] = expected
                row["applicability"] = {"type": "non_applicable", "rationale": f"Authoritative stable-ID row in {artifact} retains an exact observed result but supplies no exact executable Rust proof command; no execution credit is assigned."}
            else:
                row["behavior_claims"] = []
                row["observable_result"] = None
            continue
        artifact, selector, target, expected, argv, claim = selected
        exact_fixture_link = f"{artifact}#{selector}"
        if exact_fixture_link not in row["fixture_links"]:
            row["fixture_links"].append(exact_fixture_link)
        command_key = tuple(argv)
        command = commands_by_argv.get(command_key)
        if command is None:
            command_id = "C029-PROOF-" + hashlib.sha256("\0".join(argv).encode()).hexdigest()[:16].upper()
            command = {
                "id": command_id, "cwd": "rust-tron", "argv": argv, "timeout_seconds": 1800,
                "environment": {"HOME": "${RUN_HOME}", "TMPDIR": "${RUN_TMP}", "LANG": "C", "LC_ALL": "C", "TZ": "UTC", "RUST_TEST_THREADS": "1", "CARGO_NET_OFFLINE": "true"},
                "result_contract": {"expected_exit": 0, "minimum_executed_tests": 1, "forbid_ignored": True, "forbid_skipped": True, "observable_projection": ["stable_id", "fixture_selector", "expected_result", "rust_test"]},
                "owning_item": "C029.06",
            }
            commands_by_argv[command_key] = command
        row["behavior_claims"] = [claim]
        row["applicability"] = {"type": "covered", "rationale": f"Exact stable-ID owner join to {artifact} supplies a concrete selector, observable result, Rust test symbol, and canonical exact command."}
        row["rust_proofs"] = [{"artifact": artifact, "selector": selector, "target": target}]
        row["proof_command_id"] = command["id"]
        row["observable_result"] = expected
    normalize_c025_proofs(refreshed["rows"])
    incomplete = [row["stable_id"] for row in refreshed["rows"] if row["applicability"]["type"] == "covered" and (not row["rust_proofs"] or row["observable_result"] is None or row["proof_command_id"] is None)]
    unmapped = [row["stable_id"] for row in refreshed["rows"] if row["applicability"]["type"] == "unmapped"]
    fail(not incomplete and not unmapped, f"synthesis retained {len(incomplete)} incomplete covered and {len(unmapped)} unmapped rows")
    refreshed["proof_commands"] = sorted(commands_by_argv.values(), key=lambda value: value["id"])
    expected_by_command: dict[str, set[str]] = {command["id"]: set() for command in refreshed["proof_commands"]}
    for row in refreshed["rows"]:
        if row["proof_command_id"] is None:
            continue
        expected_by_command[row["proof_command_id"]].update(rust_target_parts(proof["target"])[1] for proof in row["rust_proofs"])
    external_command_ids = {
        command_id
        for defect in refreshed["compatibility_defects"]
        if not defect.get("affected_stable_ids")
        for command_id in defect.get("command_ids", [])
    }
    non_exact = []
    for command in refreshed["proof_commands"]:
        if command["id"] in external_command_ids:
            continue
        argv = command["argv"]
        suffix = argv[argv.index("--") + 1:] if "--" in argv else []
        expected = expected_by_command[command["id"]]
        if len(expected) != 1 or suffix != [next(iter(expected), ""), "--exact", "--test-threads=1"]:
            non_exact.append(command["id"])
    fail(not non_exact, f"synthesis retained {len(non_exact)} non-exact proof commands")
    c023_defect = next((defect for defect in refreshed["compatibility_defects"] if defect.get("finding_id") == "C023-R1-001"), None)
    fail(c023_defect is not None, "C023-R1-001: compatibility-defect record is absent")
    c023_defect["fixture_ids"] = ["rust-tron/crates/tron-apis/src/http_routes.rs#HTTP_ROUTES"]
    referenced_command_ids = {row["proof_command_id"] for row in refreshed["rows"] if row["proof_command_id"] is not None} | external_command_ids
    refreshed["proof_commands"] = [command for command in refreshed["proof_commands"] if command["id"] in referenced_command_ids]
    fail({command["id"] for command in refreshed["proof_commands"]} == referenced_command_ids, "synthesis proof commands differ from row and external-defect command set")
    rows_by_id = {row["stable_id"]: row for row in refreshed["rows"]}
    for defect in refreshed["compatibility_defects"]:
        if not defect["affected_stable_ids"]:
            validate_external_defect(defect)
            continue
        defect["command_ids"] = sorted({
            rows_by_id[stable_id]["proof_command_id"]
            for stable_id in defect["affected_stable_ids"]
            if stable_id in rows_by_id and rows_by_id[stable_id]["proof_command_id"] is not None
        })
        fail(defect["command_ids"], f"{defect['finding_id']}: affected stable IDs resolve to no executable proof commands")
    validate_c016_synthesis(refreshed, commands_by_argv)
    validate_c023_synthesis(refreshed, commands_by_argv)
    refreshed["unsupported_by_owning_artifact_repair"] = {}
    counts = dict(refreshed["accounting"])
    mapped = sum(row["applicability"]["type"] != "unmapped" for row in refreshed["rows"])
    counts.update({"mapped": mapped, "unmapped": len(refreshed["rows"]) - mapped, "generic": 0, "applicable": sum(row["applicability"]["type"] == "covered" for row in refreshed["rows"]), "non_applicable": sum(row["applicability"]["type"] == "non_applicable" for row in refreshed["rows"]), "semantic_rehomes": mapped, "compatibility_defects": len(refreshed["compatibility_defects"]), "review_findings": len(refreshed["review_findings"])})
    refreshed["accounting"] = counts
    return refreshed



def refreshed_document(document: dict[str, Any], ledger: dict[str, Any]) -> dict[str, Any]:
    # Regeneration may enrich evidence and refresh ledger metadata, but reviewed
    # stable IDs, sources, count, and order remain byte-for-byte exact.
    refreshed = synthesize_reconciliation(document)
    projection = ledger_projection(ledger["rows"])
    refreshed["source_ledger"] = {"path": "docs/oracles/java-test-ownership.v1.json", "sha256": sha256_path(LEDGER), "row_count": len(ledger["rows"]), "ordering": ledger["regeneration"]["ordering"], "ordered_identity_sha256": sha256_bytes(canonical(projection)), "identity_projection": projection}
    refreshed["gate_source"] = {"path": "tools/regression/c029_gate.py", "sha256": sha256_path(Path(__file__))}
    validate_artifact(refreshed, ledger)
    return refreshed


def atomic_write(path: Path, value: dict[str, Any]) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=False, ensure_ascii=False)
            stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try: os.unlink(temporary)
        except FileNotFoundError: pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = parser.parse_args()
    fail(LEDGER.is_file(), "docs/oracles/java-test-ownership.v1.json: missing generated ledger")
    fail(ARTIFACT.is_file(), "--write is merge-only: complete reviewed reconciliation artifact is missing")
    ledger = load(LEDGER); document = load(ARTIFACT)
    if args.write:
        refreshed = refreshed_document(document, ledger)
        atomic_write(ARTIFACT, refreshed)
        print(f"C029 write OK: rows={len(refreshed['rows'])} sha256={sha256_path(ARTIFACT)}")
        return 0

    baseline = repository_snapshot(ROOT)
    temporary: tempfile.TemporaryDirectory[str] | None = None
    rust_tools: dict[str, Any] | None = None
    prior_handlers: dict[int, Any] = {}
    def interrupted(signum: int, _frame: Any) -> None:
        raise GateError(f"interrupted by signal {signal.Signals(signum).name}")
    try:
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            prior_handlers[signum] = signal.signal(signum, interrupted)
        validate_artifact(document, ledger)
        verify_manifest(document)
        mutation_self_checks(document, ledger)
        require_disk(Path(tempfile.gettempdir()), 512 * 1024**2, "disposable current-tree and isolated runtime state")
        commands = {command["id"]: command for command in document["proof_commands"]}
        plans = referenced_targets(ROOT, document) if commands else {}
        if commands:
            missing_targets, required_bytes = compilation_budget(Path("/nonexistent-c029-private-target"), plans)
            require_disk(Path(tempfile.gettempdir()), required_bytes + PINNED_RUST_TOOLCHAIN["total_file_bytes"], f"{missing_targets} isolated Rust test target(s) plus private pinned toolchain")
        temporary = tempfile.TemporaryDirectory(prefix="c029-gate-")
        temporary_root = Path(temporary.name)
        tree = temporary_root / "repo"; tree.mkdir()
        scratch = temporary_root / "scratch"; scratch.mkdir()
        target = scratch / "cargo-target"; target.mkdir()
        if commands:
            rust_tools = {}
            resolve_rust_tools(scratch, rust_tools)
        copy_current_tree(tree, baseline)
        materialize_java_reference(tree / "java-tron")
        seed = tree_snapshot(tree)
        if commands:
            validate_mapped_source_snapshot(tree, document, baseline)
            assert rust_tools is not None
            run_proofs(tree, scratch, target, plans, commands, document, rust_tools)
        java_head = subprocess.run(["git", "-C", str(tree / "java-tron"), "rev-parse", "HEAD"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        java_status = subprocess.run(["git", "-C", str(tree / "java-tron"), "status", "--porcelain=v1", "--untracked-files=all"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        fail(java_head.returncode == 0 and java_head.stdout.strip() == PIN, "disposable Java identity changed during proof execution")
        fail(java_status.returncode == 0 and not java_status.stdout.strip(), "disposable Java tree changed during proof execution")
        try:
            verify_java_reference(ROOT, phase="after disposable Java proof execution")
        except JavaReferenceError as error:
            raise GateError(str(error)) from error
        fail(tree_snapshot(tree) == seed, "disposable execution tree changed from pristine seed")
    finally:
        integrity_error: Exception | None = None
        if rust_tools is not None:
            try:
                verify_rust_inputs_unchanged(rust_tools)
            except Exception as error:
                integrity_error = error
        for signum, handler in prior_handlers.items():
            signal.signal(signum, handler)
        if temporary is not None:
            make_tree_writable(Path(temporary.name) / "repo" / "java-tron")
            make_tree_writable(Path(temporary.name) / "scratch")
            temporary.cleanup()
        after = repository_snapshot(ROOT)
        if after != baseline:
            added = sorted(after.keys() - baseline.keys()); removed = sorted(baseline.keys() - after.keys()); changed = sorted(key for key in after.keys() & baseline.keys() if after[key] != baseline[key])
            raise GateError(f"repository clean-state protection failed: added={added[:10]} removed={removed[:10]} changed={changed[:10]}")
        if integrity_error is not None:
            raise integrity_error
    print(f"C029 check OK: rows={len(document['rows'])} proofs={len(document['proof_commands'])} defects={len(document['compatibility_defects'])} sha256={sha256_path(ARTIFACT)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (GateError, subprocess.TimeoutExpired, OSError, KeyError, TypeError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
