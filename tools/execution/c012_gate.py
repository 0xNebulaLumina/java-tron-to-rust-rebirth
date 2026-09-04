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
TEST = ROOT / "rust-tron/crates/tron-execution/tests/c012_extension_registry.rs"
JAVA_REVISION = "4a21592f95e37908b21bc3f611c6e7a1a67f09f3"


def load(path): return json.loads(Path(path).read_text())
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def dump(path, value): Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

def rows(document): return document.get("rows", document.get("scenarios", document.get("members", [])))

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
    fixture = {"schema": "c012-execution-fixtures.v4", "chunk": "C012", "scenario_count": 226,
               "variant_count": 226, "fixture_namespaces": {
                   "built_in_java_differential": {"classification": "pinned_java_direct_actuator_observation",
                       "java_revision": JAVA_REVISION, "scenario_count": 214, "variant_count": 214,
                       "families": refs, "deterministic_rerun": {"fresh_database_per_scenario": True,
                           "commands": [spec[1] for spec in FAMILIES.values()] + ["tools/execution/c012_java_oracle.py"]},
                       "required_observables": ["concrete Contract and Any bytes", "actual commit/reopen rows",
                           "actual revoke/reopen rows or byte-identical rollback root", "result code/error/fee"]},
                   "dr004_rust_extension": {"classification": "newly_authored_rust_contract",
                       "pinned_java_observation": False, "variant_count": 12, "rows": extension["variants"]}}}
    dump(FIXTURES, fixture)

    old = load(RECON)
    mapped = explicit_mapping(documents)
    direct_ids = {member["variant_id"] for member in direct_members}
    result_rows = []
    for row in old["rows"]:
        base = {key: row.get(key) for key in ("stable_id", "java_source", "java_case", "java_line", "owner", "owning_item", "acceptance_gate")}
        if row["stable_id"] in mapped:
            family, scenario, basis = mapped[row["stable_id"]]
        elif row["stable_id"] in direct_ids:
            family = Path(row["java_source"]).name.replace("ActuatorTest.java", "").replace("Test.java", "")
            scenario = row["stable_id"]
            basis = "Isolated execution of this exact pinned Java test method; the stable ID is the direct scenario ID."
        else:
            raise ValueError(f"C012-owned stable ID has no family or direct Java scenario: {row['stable_id']}")
        base.update({"disposition": "family_scenario", "family": family, "scenario_ids": [scenario], "equivalence_basis": basis})
        result_rows.append(base)
    dump(RECON, {"schema_version": 3, "chunk": "C012", "mapping": "complete_explicit_family_or_direct_java_scenario",
                 "row_count": len(result_rows), "mapped_count": len(result_rows), "excluded_count": 0, "rows": result_rows})

    source_paths = ([spec[0] for spec in FAMILIES.values()] + [str(Path(spec[1])) for spec in FAMILIES.values()]
                    + [DIRECT_JAVA.name, "tools/execution/c012_java_oracle.py", "tools/execution/C012Oracle.java",
                       "tools/execution/overlay/org/tron/core/actuator/AbstractActuator.java"])
    dump(SOURCE, {"schema_version": 3, "chunk": "C012", "java_revision": JAVA_REVISION,
                  "canonical_sources": [{"path": ("docs/oracles/" + p if p.endswith(".json") else p),
                      "sha256": digest((ORACLES / p) if p.endswith(".json") else (ROOT / p))} for p in source_paths],
                  "provenance": "Each family runner creates deterministic fresh Java databases and overwrites its authenticated real artifact."})
    dump(CONTRACT, {"schema": "c012-execution-contract.v4", "schema_version": 4, "chunk": "C012",
                    "scope": "214 real built-in family/direct Java scenarios plus 12 DR-004 Rust registry/Session variants",
                    "fixture_inventory": {"path": "c012-execution-fixtures.v1.json", "sha256": digest(FIXTURES), "scenarios": 226, "variants": 226},
                    "ownership_reconciliation": {"path": "c012-java-test-reconciliation.v1.json", "sha256": digest(RECON),
                        "stable_ids": 222, "mapped": len(result_rows), "typed_exclusions": 0},
                    "source_inventory": {"path": "c012-source-inventory.v1.json", "sha256": digest(SOURCE)},
                    "reviewer_disposition": "pending_rerun"})

def verify(errors):
    fixture, contract, source, recon, extension = map(load, (FIXTURES, CONTRACT, SOURCE, RECON, EXTENSION))
    direct = load(DIRECT_JAVA)
    builtins = fixture.get("fixture_namespaces", {}).get("built_in_java_differential", {})
    if (fixture.get("scenario_count"), fixture.get("variant_count"), builtins.get("scenario_count"), builtins.get("variant_count")) != (226, 226, 214, 214):
        errors.append("canonical inventory must be 214 built-in plus 12 DR-004 scenarios/variants")
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
    for member in direct_members:
        if not member.get("successful") or member.get("failure_count") != 0 or member.get("run_count") != 1:
            errors.append(f"direct Java scenario outcome mismatch: {member.get('variant_id')}")
    if contract["fixture_inventory"]["sha256"] != digest(FIXTURES) or contract["ownership_reconciliation"]["sha256"] != digest(RECON) or contract["source_inventory"]["sha256"] != digest(SOURCE):
        errors.append("contract manifest digest drift")
    if len(recon.get("rows", [])) != 222 or recon.get("row_count") != 222: errors.append("reconciliation must contain exactly 222 rows")
    stable = [r.get("stable_id") for r in recon.get("rows", [])]
    if len(set(stable)) != 222: errors.append("reconciliation stable IDs must be unique")
    for row in recon.get("rows", []):
        if row.get("disposition") != "family_scenario":
            errors.append(f"C012-owned exclusion is prohibited: {row.get('stable_id')}")
        elif not row.get("family") or not row.get("scenario_ids") or not row.get("equivalence_basis"):
            errors.append(f"incomplete family mapping: {row.get('stable_id')}")
    security = extension.get("security_model", {})
    if extension.get("reviewer_disposition", {}).get("state") != "pending_rerun": errors.append("DR-004 reviewer disposition must remain pending rerun")
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
    ids = [f"DR004.C012.EXT.{n:02d}" for n in range(1, 13)]
    text = TEST.read_text()
    for variant_id in ids:
        symbol = variant_id.lower().replace(".", "_")
        if symbol not in text: errors.append(f"missing executable extension variant {variant_id}")
    for marker in ("c012_compare_", "CASE_TABLE", "java-validation-error"):
        if marker in text: errors.append(f"prohibited synthetic extension marker {marker}")
    tracker = load(ROOT / "docs/PORTING_TRACKER.json")
    chunk = next(c for c in tracker["chunks"] if c["id"] == "C012")
    if chunk["status"] != "active" or chunk["gate"]["status"] != "not_run": errors.append("tracker must remain C012 active/not_run")

def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--write", action="store_true"); args = parser.parse_args()
    if args.write: generate()
    errors = []; verify(errors)
    if errors:
        for error in errors: print(f"ERROR: {error}", file=sys.stderr)
        return 1
    recon = load(RECON)
    print(f"C012 metadata OK: 214 built-in + 12 DR-004 variants; 222 Java IDs = {recon['mapped_count']} mapped + 0 exclusions; reviewer pending")
    return 0

if __name__ == "__main__": raise SystemExit(main())
