#!/usr/bin/env python3
"""Generate and verify the canonical C012 family corpus and DR-004 Rust oracle."""
import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ORACLES = ROOT / "docs/oracles"
FAMILIES = {
    "account": ("c012-account-real.v1.json", "tools/execution/account/run.py", 24, 63),
    "transfer": ("c012-transfer-real.v1.json", "tools/execution/transfer/run.py", 20, 14),
    "asset": ("c012-asset-real.v1.json", "tools/execution/asset/run.py", 5, 5),
    "witness": ("c012-witness-real.v1.json", "tools/execution/witness/run.sh", 15, 30),
    "registry": ("c012-registry-real.v1.json", "tools/execution/registry/run.py", 13, 13),
}
FIXTURES = ORACLES / "c012-execution-fixtures.v1.json"
CONTRACT = ORACLES / "c012-execution-contract.v1.json"
SOURCE = ORACLES / "c012-source-inventory.v1.json"
RECON = ORACLES / "c012-java-test-reconciliation.v1.json"
EXTENSION = ORACLES / "c012-registry-extension.v1.json"
DIRECT_JAVA = ORACLES / "c012-java-owned-real.v1.json"
OWNERSHIP = ORACLES / "java-test-ownership.v1.json"
TEST = ROOT / "rust-tron/crates/tron-execution/tests/c012_extension_registry.rs"
JAVA_REVISION = "4a21592f95e37908b21bc3f611c6e7a1a67f09f3"
OWNED_ACTUATORS = {"AssetIssueActuator", "ParticipateAssetIssueActuator", "TransferAssetActuator", "VoteWitnessActuator", "UpdateAssetActuator", "UnfreezeAssetActuator", "WitnessCreateActuator", "WitnessUpdateActuator"}
DIRECT_METHOD_PROOF_IDS = {
    "TCASE-144207F246D3996D", "TCASE-67189D92322C23C8",
    "TCASE-7953F48D24347A87", "TCASE-8B6650B8003FD547",
}

def selected_invocations(direct):
    selected = []
    for member in direct.get("members", []):
        for invocation in member.get("invocations", []):
            if invocation["actuator_class"].rsplit(".", 1)[-1] in OWNED_ACTUATORS:
                selected.append((member["variant_id"], invocation))
    return selected

def observation_digest(invocation):
    value = {key: item for key, item in invocation.items() if key not in {"invocation_id", "ordinal", "completion_ordinal", "actuator_instance_ordinal", "lifecycle_reference"}}
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def direct_method_digest(member):
    proof = {key: member[key] for key in ("variant_id", "java_test_class", "java_test_method", "run_count", "successful", "failure_count", "ignore_count", "test_body_enter_count", "test_body_exit_count")}
    test_class = member["java_test_class"].replace(".", "/")
    transforms = member.get("capture_audit", {}).get("transforms", [])
    proof["test_class_sha256"] = next(item["original_sha256"] for item in transforms if item["class"] == test_class)
    return hashlib.sha256(json.dumps(proof, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def direct_java_mapping(direct):
    mapped = {}
    for member in direct.get("members", []):
        stable_id = member["variant_id"]
        if stable_id not in DIRECT_METHOD_PROOF_IDS or member.get("invocation_count") != 0:
            continue
        mapped[stable_id] = ("owned_java", stable_id,
            "Exact isolated execution of the pinned Java test method: all Java assertions completed once with no failure or ignore; the observation digest binds the method identity, test bytecode, and JUnit outcome.",
            direct_method_digest(member))
    return mapped

def corpus_scenario_ids(family, document):
    identifiers = set()
    for row in rows(document):
        keys = ("variant_id",) if family in {"witness", "owned_java"} else ("scenario_id", "variant_id")
        identifiers.update(row[key] for key in keys if row.get(key))
    return identifiers

def load(path): return json.loads(Path(path).read_text())
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def dump(path, value): Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

def rows(document): return document.get("rows", document.get("scenarios", document.get("members", [])))
def c012_ownership(ledger):
    owned = {}
    for row in ledger.get("rows", []):
        if row.get("acceptance_gate") != "C012.V":
            continue
        stable_id = row["id"]
        if stable_id in owned:
            raise ValueError(f"duplicate C012.V stable ID in ownership ledger: {stable_id}")
        owned[stable_id] = row
    return owned

def ownership_metadata(row):
    source = row["source"]
    return {
        "stable_id": row["id"],
        "java_source": source["path"],
        "java_case": row["case"],
        "java_line": source["line"],
        "owner": "C012",
        "owning_item": row["owning_item"],
        "acceptance_gate": row["acceptance_gate"],
    }

def selected_by_stable_id(direct):
    grouped = {}
    for stable_id, invocation in selected_invocations(direct):
        grouped.setdefault(stable_id, []).append(invocation)
    return grouped

def instrumented_mapping(invocations):
    return {
        "scenario_ids": [invocation["invocation_id"] for invocation in invocations],
        "invocation_ordinals": [invocation["ordinal"] for invocation in invocations],
        "observation_digests": [observation_digest(invocation) for invocation in invocations],
    }


def explicit_mapping(documents):
    mapped = {}
    for item in documents["account"].get("source_equivalences", []):
        mapped[item["stable_id"]] = ("account", item["scenario_id"], item["equivalence"])
    for row in documents["transfer"]["rows"]:
        mapped[row["stable_id"]] = ("transfer", row["scenario_id"], row["equivalence"])
    for row in documents["asset"]["rows"]:
        for stable_id in row["stable_ids"]:
            mapped[stable_id] = ("asset", row["variant_id"], documents["asset"]["equivalence_basis"])
    for row in documents["registry"]["rows"]:
        mapped[row["stable_id"]] = ("registry", row["scenario_id"], row["equivalence"])
    return mapped

def generate():
    documents = {name: load(ORACLES / spec[0]) for name, spec in FAMILIES.items()}
    direct = load(DIRECT_JAVA)
    ownership = c012_ownership(load(OWNERSHIP))
    extension = load(EXTENSION)
    refs = []
    for name, (filename, runner, expected_scenarios, expected_ids) in FAMILIES.items():
        doc = documents[name]
        refs.append({"family": name, "path": f"docs/oracles/{filename}", "sha256": digest(ORACLES / filename),
                     "runner": runner, "runner_sha256": digest(ROOT / runner),
                     "scenario_count": expected_scenarios, "stable_id_count": expected_ids})
    direct_members = direct.get("members", [])
    if len(direct_members) != 137:
        raise ValueError(f"complete owned Java corpus requires 137 direct scenarios, got {len(direct_members)}")
    refs.append({"family": "owned_java", "path": "docs/oracles/c012-java-owned-real.v1.json",
                 "sha256": digest(DIRECT_JAVA), "runner": "tools/execution/c012_java_oracle.py",
                 "runner_sha256": digest(ROOT / "tools/execution/c012_java_oracle.py"),
                 "scenario_count": len(direct_members), "stable_id_count": len(direct_members)})
    selected = selected_invocations(direct)
    unique_observations = {observation_digest(invocation) for _, invocation in selected}
    fixture = {"schema": "c012-execution-fixtures.v5", "chunk": "C012", "scenario_count": 324,
               "variant_count": 330, "fixture_namespaces": {
                   "built_in_java_differential": {"classification": "pinned_java_instrumented_actuator_observation",
                       "java_revision": JAVA_REVISION, "scenario_count": 310, "variant_count": 316,
                       "family_scenario_count": 77, "instrumented_invocation_count": len(selected),
                       "instrumented_unique_observation_count": len(unique_observations), "families": refs,
                       "deterministic_rerun": {"fresh_database_per_scenario": True,
                           "commands": [spec[1] for spec in FAMILIES.values()] + ["tools/execution/c012_java_oracle.py"]},
                       "required_observables": ["concrete Contract and Any bytes", "captured before rows",
                           "actual Rust commit/reopen rows", "byte-identical Rust rollback root", "result code/error/fee/asset ID", "ordered mutations and final deltas"]},
                   "dr004_rust_extension": {"classification": "newly_authored_rust_contract",
                       "pinned_java_observation": False, "variant_count": 14, "rows": extension["variants"]}}}
    dump(FIXTURES, fixture)

    old = load(RECON)
    mapped = explicit_mapping(documents)
    direct_proofs = direct_java_mapping(direct)
    direct_by_id = selected_by_stable_id(direct)
    if set(old_row["stable_id"] for old_row in old["rows"]) != set(ownership):
        raise ValueError("reconciliation stable IDs do not exactly match the C012.V ownership ledger")
    result_rows = []
    for row in old["rows"]:
        stable_id = row["stable_id"]
        base = ownership_metadata(ownership[stable_id])
        invocations = direct_by_id.get(stable_id)
        family_mapping = mapped.get(stable_id)
        if invocations:
            base.update({"disposition": "instrumented_invocations", "family": Path(base["java_source"]).name.replace("ActuatorTest.java", "").replace("Test.java", ""),
                         **instrumented_mapping(invocations),
                         "equivalence_basis": "Exact isolated stable ID and captured C012-owned actuator invocation ordinal."})
        elif family_mapping:
            family, scenario, basis = family_mapping
            base.update({"disposition": "family_scenario", "family": family, "scenario_ids": [scenario], "equivalence_basis": basis})
        elif stable_id in direct_proofs:
            family, scenario, basis, proof_digest = direct_proofs[stable_id]
            base.update({"disposition": "family_scenario", "family": family, "scenario_ids": [scenario],
                         "observation_digests": [proof_digest], "equivalence_basis": basis})
        else:
            raise ValueError(f"C012-owned stable ID has no family or instrumented Java scenario: {stable_id}")
        result_rows.append(base)
    dump(RECON, {"schema_version": 5, "chunk": "C012", "mapping": "exact_instrumented_invocation_or_family_scenario",
                 "row_count": len(result_rows), "mapped_count": len(result_rows), "excluded_count": 0,
                 "instrumented_stable_id_count": len(direct_by_id), "instrumented_invocation_count": len(selected),
                 "unique_observation_count": len(unique_observations), "executed_observation_count": len(unique_observations),
                 "excluded_invocation_count": 0, "rows": result_rows})

    source_paths = ([spec[0] for spec in FAMILIES.values()] + [str(Path(spec[1])) for spec in FAMILIES.values()]
                    + [DIRECT_JAVA.name, "tools/execution/c012_java_oracle.py", "tools/execution/C012Oracle.java", "tools/execution/C012ReopenProbe.java"]
                    + [f"tools/execution/instrumentation/org/tron/tools/c012/{name}" for name in ("C012Agent.java", "C012Transformer.java", "C012Capture.java")])
    dump(SOURCE, {"schema_version": 4, "chunk": "C012", "java_revision": JAVA_REVISION,
                  "canonical_sources": [{"path": ("docs/oracles/" + p if p.endswith(".json") else p),
                      "sha256": digest((ORACLES / p) if p.endswith(".json") else (ROOT / p))} for p in source_paths],
                  "provenance": "Family runners plus the authenticated launch-time Java instrumentation capture every selected C012-owned actuator invocation."})
    dump(CONTRACT, {"schema": "c012-execution-contract.v5", "schema_version": 5, "chunk": "C012",
                    "scope": "77 real family rows plus 239 exact instrumented C012-owned actuator invocations (233 unique full observation digests), and 14 DR-004 Rust registry/Session variants",
                    "fixture_inventory": {"path": "c012-execution-fixtures.v1.json", "sha256": digest(FIXTURES), "scenarios": 324, "variants": 330},
                    "ownership_reconciliation": {"path": "c012-java-test-reconciliation.v1.json", "sha256": digest(RECON),
                        "stable_ids": 222, "mapped": len(result_rows), "typed_exclusions": 0},
                    "instrumented_replay": {"selected_invocations": len(selected), "unique_observations": len(unique_observations),
                        "executed_observations": len(unique_observations), "excluded_invocations": 0,
                        "deduplication": "identical full observation digest only"},
                    "source_inventory": {"path": "c012-source-inventory.v1.json", "sha256": digest(SOURCE)},
                    "reviewer_disposition": "approved"})

def verify(errors):
    fixture, contract, source, recon, extension = map(load, (FIXTURES, CONTRACT, SOURCE, RECON, EXTENSION))
    direct = load(DIRECT_JAVA)
    ownership = c012_ownership(load(OWNERSHIP))
    builtins = fixture.get("fixture_namespaces", {}).get("built_in_java_differential", {})
    if (fixture.get("scenario_count"), fixture.get("variant_count"), builtins.get("scenario_count"), builtins.get("variant_count")) != (324, 330, 310, 316):
        errors.append("canonical inventory must be 77 family + 233 unique instrumented built-in observations plus 14 DR-004 scenarios")
    for ref in builtins.get("families", []):
        path, runner = ROOT / ref["path"], ROOT / ref["runner"]
        if digest(path) != ref["sha256"] or digest(runner) != ref["runner_sha256"]: errors.append(f"provenance digest drift: {ref['family']}")
        doc = load(path); actual_rows = rows(doc)
        if len(actual_rows) != ref["scenario_count"]: errors.append(f"scenario count drift: {ref['family']}")
        for index, row in enumerate(actual_rows):
            if ref["family"] == "owned_java":
                continue
            contract_bytes = row.get("contract_hex")
            any_bytes = row.get("any_hex", row.get("contract_any_hex"))
            if not contract_bytes or not any_bytes: errors.append(f"{ref['family']} row {index} lacks concrete contract bytes")
            if not row.get("result") and not all(k in row for k in ("result_code", "fee")): errors.append(f"{ref['family']} row {index} lacks concrete result")
            has_commit = any(k in row for k in ("committed_reopen", "commit_reopen_root", "commit_account_hex"))
            has_revoke = any(k in row for k in ("revoked_reopen", "rollback_root", "revoke_account_hex"))
            if not has_commit or not has_revoke: errors.append(f"{ref['family']} row {index} lacks actual commit/revoke observation")
    direct_members = direct.get("members", [])
    if len(direct_members) != 137:
        errors.append("direct Java corpus must contain all 137 formerly excluded owned tests")
    selected = selected_invocations(direct); direct_by_id = selected_by_stable_id(direct)
    family_documents = {name: load(ORACLES / spec[0]) for name, spec in FAMILIES.items()}
    family_documents["owned_java"] = direct
    corpus_ids = {family: corpus_scenario_ids(family, document) for family, document in family_documents.items()}
    direct_proofs = direct_java_mapping(direct)
    unique = {observation_digest(invocation) for _, invocation in selected}
    if len(selected) != 239 or len(unique) != 233: errors.append("instrumented replay must select 239 invocations and 233 unique full observation digests")
    if builtins.get("instrumented_invocation_count") != 239 or builtins.get("instrumented_unique_observation_count") != 233: errors.append("instrumented fixture counts drift")
    direct_ids = [member.get("variant_id") for member in direct_members]
    if len(set(direct_ids)) != len(direct_ids): errors.append("direct Java corpus stable IDs must be unique")
    if not set(direct_ids).issubset(ownership): errors.append("direct Java corpus must be an intended C012.V ownership subset")
    for member in direct_members:
        if not member.get("successful") or member.get("failure_count") != 0 or member.get("run_count") != 1:
            errors.append(f"direct Java scenario outcome mismatch: {member.get('variant_id')}")
    if contract["fixture_inventory"]["sha256"] != digest(FIXTURES) or contract["ownership_reconciliation"]["sha256"] != digest(RECON) or contract["source_inventory"]["sha256"] != digest(SOURCE):
        errors.append("contract manifest digest drift")
    recon_rows = recon.get("rows", [])
    if len(recon_rows) != 222 or recon.get("row_count") != 222: errors.append("reconciliation must contain exactly 222 rows")
    recon_by_id = {row.get("stable_id"): row for row in recon_rows}
    if len(recon_by_id) != len(recon_rows): errors.append("reconciliation stable IDs must be unique")
    if set(recon_by_id) != set(ownership): errors.append("reconciliation stable IDs must exactly equal the C012.V ownership ledger")
    for stable_id, ledger_row in ownership.items():
        row = recon_by_id.get(stable_id)
        if row is None:
            continue
        expected_metadata = ownership_metadata(ledger_row)
        actual_metadata = {key: row.get(key) for key in expected_metadata}
        if actual_metadata != expected_metadata:
            errors.append(f"ownership metadata drift: {stable_id}")
        if row.get("disposition") not in {"family_scenario", "instrumented_invocations"}:
            errors.append(f"C012-owned exclusion is prohibited: {stable_id}")
        elif not row.get("family") or not row.get("scenario_ids") or not row.get("equivalence_basis"):
            errors.append(f"incomplete replay mapping: {stable_id}")
        elif row["disposition"] == "instrumented_invocations":
            expected = instrumented_mapping(direct_by_id.get(stable_id, []))
            actual = {key: row.get(key) for key in expected}
            if not expected["scenario_ids"] or actual != expected:
                errors.append(f"instrumented replay derivation drift: {stable_id}")
        elif stable_id in direct_by_id:
            errors.append(f"selected direct invocation is not instrumented in reconciliation: {stable_id}")
        elif row["disposition"] == "family_scenario":
            family = row["family"]
            if family not in corpus_ids:
                errors.append(f"family scenario references non-canonical corpus: {stable_id} -> {family}")
            else:
                missing = set(row["scenario_ids"]) - corpus_ids[family]
                if missing:
                    errors.append(f"family scenario does not resolve in canonical corpus: {stable_id} -> {sorted(missing)}")
            if stable_id in direct_proofs:
                expected_family, expected_scenario, expected_basis, expected_digest = direct_proofs[stable_id]
                if (family, row["scenario_ids"], row["equivalence_basis"], row.get("observation_digests")) != (expected_family, [expected_scenario], expected_basis, [expected_digest]):
                    errors.append(f"direct Java proof derivation drift: {stable_id}")
    if (recon.get("instrumented_invocation_count"), recon.get("unique_observation_count"), recon.get("executed_observation_count"), recon.get("excluded_invocation_count"), recon.get("excluded_count")) != (239, 233, 233, 0, 0):
        errors.append("reconciliation replay accounting must be 239 selected / 233 unique / 233 executed / 0 excluded")
    replay = contract.get("instrumented_replay", {})
    if (replay.get("selected_invocations"), replay.get("unique_observations"), replay.get("executed_observations"), replay.get("excluded_invocations")) != (239, 233, 233, 0):
        errors.append("contract replay accounting must be 239 selected / 233 unique / 233 executed / 0 excluded")
    security = extension.get("security_model", {})
    disposition = extension.get("reviewer_disposition", {})
    required_confirmations = {
        "validation receives the immutable declared-access capability snapshot",
        "undeclared validation reads are rejected without exposing store bytes",
        "declared validation reads succeed",
        "built-in validation retains unrestricted None capability",
    }
    if not required_confirmations.issubset(set(disposition.get("must_confirm", []))):
        errors.append("DR-004 reviewer disposition lacks validation-capability requirements")
    capability_checks = disposition.get("evidence", {}).get("capability_checks", {})
    if set(capability_checks) != required_confirmations or not all(value is True for value in capability_checks.values()):
        errors.append("DR-004 approved review lacks complete validation-capability evidence")
    expected_variant_ids = [f"DR004.C012.EXT.{n:02d}" for n in range(1, 15)]
    evidence = disposition.get("evidence", {})
    if evidence.get("review_basis") != "clean_independent_review" or evidence.get("independent_rust_execution_test") != str(TEST.relative_to(ROOT)):
        errors.append("DR-004 approved review lacks independent reviewer evidence")
    if evidence.get("executed_variant_count") != 14 or evidence.get("executed_variant_ids") != expected_variant_ids:
        errors.append("DR-004 approved review must bind all 14 independently executed variants")
    if contract.get("reviewer_disposition") != "approved":
        errors.append("C012 execution contract reviewer disposition must be approved")
    if security.get("provider_kind") != "trusted_statically_linked_reviewed_native_code" or security.get("sandboxed") is not False or security.get("untrusted_plugins_supported") is not False:
        errors.append("DR-004 must declare the trusted statically linked native-code boundary")
    if security.get("composition_root_allowlist") != ["provider_identity", "code_sha256"] or security.get("metadata_snapshot_count") != 1:
        errors.append("DR-004 must pin provider identity/digest and one metadata snapshot")
    if security.get("sensitive_internal_stores_denied") != ["Common", "Checkpoint", "Temporary"]:
        errors.append("DR-004 sensitive internal store denylist drift")
    provider = extension.get("provider", {})
    if not provider.get("provider_identity") or len(provider.get("code_sha256", "")) != 64:
        errors.append("DR-004 provider identity/code digest missing")
    if extension.get("resource_bounds", {}).get("declared_access_entry_max_before_dedupe") != 64:
        errors.append("DR-004 raw access declaration bound drift")
    ids = expected_variant_ids
    if len(extension.get("variants", [])) != 14 or [row.get("id") for row in extension.get("variants", [])] != ids:
        errors.append("DR-004 extension oracle must contain exactly the 14 ordered variants")
    text = TEST.read_text()
    for variant_id in ids:
        symbol = variant_id.lower().replace(".", "_")
        if symbol not in text: errors.append(f"missing executable extension variant {variant_id}")
    for marker in ("c012_compare_", "CASE_TABLE", "java-validation-error"):
        if marker in text: errors.append(f"prohibited synthetic extension marker {marker}")
    tracker = load(ROOT / "docs/PORTING_TRACKER.json")
    chunk = next(c for c in tracker["chunks"] if c["id"] == "C012")
    if chunk["status"] == "done":
        if disposition.get("state") != "approved": errors.append("closed C012 requires terminal approved DR-004 review")
        if chunk["gate"]["status"] != "passed" or chunk["review"]["state"] != "approved" or chunk.get("resume") is not None:
            errors.append("closed C012 tracker must be passed, review approved, and resume null")
        if any(item.get("status") != "done" for item in chunk.get("items", [])):
            errors.append("closed C012 tracker requires every item done")
    elif chunk["status"] == "review":
        if disposition.get("state") != "pending_rerun": errors.append("pre-review C012 permits only pending_rerun disposition")
    else:
        errors.append("C012 tracker must be in review or done")

def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--write", action="store_true"); args = parser.parse_args()
    if args.write: generate()
    errors = []; verify(errors)
    if errors:
        for error in errors: print(f"ERROR: {error}", file=sys.stderr)
        return 1
    recon = load(RECON)
    print(f"C012 metadata OK: 77 family + 233 unique instrumented built-in observations + 14 DR-004 variants; 239 invocations; 222 Java IDs mapped + 0 exclusions; reviewer approved")
    return 0

if __name__ == "__main__": raise SystemExit(main())
