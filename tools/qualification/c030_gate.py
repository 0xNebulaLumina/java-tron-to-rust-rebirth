#!/usr/bin/env python3
"""Validate the frozen C030 qualification contract without fabricating results."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import os
from pathlib import Path

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError
from c030_result import ResultVerificationError, canonical_output_path, verify_result

ROOT = Path(__file__).resolve().parents[2]
ORACLES = ROOT / "docs/oracles"
SPEC = ORACLES / "c030-qualification-spec.v1.json"
SCHEMA = ORACLES / "schemas/c030-qualification-spec-v1.schema.json"
SCENARIOS = ORACLES / "c030-scenario-manifest.v1.json"
SCENARIO_SCHEMA = ORACLES / "schemas/c030-scenario-manifest-v1.schema.json"
RESULT_SCHEMA = ORACLES / "schemas/c030-qualification-result-v1.schema.json"
MANIFEST = ORACLES / "manifest.v1.json"
TRACKER = ROOT / "docs/PORTING_TRACKER.json"
EXPECTED_SPEC_SHA256 = "a7fb1ebbb4c5afc0dab41ade6c136fe83f90c92be856ea23d905a33e0ffaabd6"
EXPECTED_SCHEMA_SHA256 = "6dff6e795a0bbba91568e13794d741e4e85638f76c321c2d7c577900330dcc2c"

PLACEHOLDER = re.compile(r"\b(todo|tbd|placeholder|not implemented|coming soon|fill[ -]?me)\b", re.I)


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def lifecycle_schedule(contract: dict) -> tuple[list[list[list[int]]], list[dict]]:
    seed = contract["seed"]
    actions = contract["action_order"]
    counts = contract["per_run_action_counts"]
    phase_count = contract["phase_count_per_run"]
    phase_duration = contract["phase_duration_seconds"]
    matrices, rows = [], []
    for run_index in range(contract["run_count"]):
        assigned = {phase_index: [] for phase_index in range(phase_count)}
        for action in actions:
            ranked = sorted(
                range(phase_count),
                key=lambda phase_index: hashlib.sha256(
                    f"{seed}:{run_index}:{action}:{phase_index}".encode()
                ).digest(),
            )
            for occurrence_index, phase_index in enumerate(sorted(ranked[: counts[action]])):
                assigned[phase_index].append((action, occurrence_index))
        matrix = []
        for phase_index in range(phase_count):
            matrix.append([sum(action == expected for action, _ in assigned[phase_index]) for expected in actions])
            ordered = sorted(assigned[phase_index], key=lambda row: actions.index(row[0]))
            for phase_action_slot, (action, occurrence_index) in enumerate(ordered):
                start = run_index * phase_count * phase_duration + phase_index * phase_duration + 60 + phase_action_slot * 90
                rows.append({
                    "action": action,
                    "action_end_second": start + 60,
                    "action_start_second": start,
                    "exclusion_end_second": start + 120,
                    "exclusion_start_second": start,
                    "fork_activation": action == "reorg" and occurrence_index == 0,
                    "occurrence_index": occurrence_index,
                    "phase_index": phase_index,
                    "run_index": run_index,
                })
        matrices.append(matrix)
    return matrices, rows


def require(ok: bool, message: str) -> None:
    if not ok:
        raise RuntimeError(message)


def repository_path(path: str) -> Path:
    candidate = (ROOT / path).resolve()
    require(candidate == ROOT or ROOT in candidate.parents, f"path escapes repository: {path}")
    return candidate


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from strings(item)


def registered_c017_c028(manifest: dict) -> dict[str, tuple[str, str]]:
    answer = {}
    for key, value in manifest.items():
        if not re.fullmatch(r"c0(?:1[7-9]|2[0-8])_[a-z0-9_]+", key):
            continue
        if isinstance(value, dict) and isinstance(value.get("path"), str) and isinstance(value.get("sha256"), str):
            relative, digest = value["path"], value["sha256"]
        elif isinstance(value, str):
            relative = value
            path = ORACLES / relative
            if not path.is_file():
                continue
            digest = sha256(path)
        else:
            continue
        public_path = relative if relative.startswith(("tools/", "rust-tron/")) else f"docs/oracles/{relative}"
        answer[key] = (public_path, digest)
    return answer


def validate_metadata() -> dict:
    spec, schema, manifest = load(SPEC), load(SCHEMA), load(MANIFEST)
    spec_sha256 = sha256(SPEC)
    require(spec_sha256 == EXPECTED_SPEC_SHA256, "frozen specification digest mismatch")
    require(sha256(SCHEMA) == EXPECTED_SCHEMA_SHA256, "frozen schema digest mismatch")
    try:
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        validator.validate(spec)
    except (SchemaError, ValidationError) as error:
        location = "/".join(map(str, error.absolute_path))
        raise RuntimeError(f"Draft 2020-12 validation failed at {location or '<root>'}: {error.message}") from error
    for document_path, document_schema_path, label in ((SCENARIOS, SCENARIO_SCHEMA, "scenario manifest"),):
        try:
            document_schema = load(document_schema_path)
            Draft202012Validator.check_schema(document_schema)
            Draft202012Validator(document_schema).validate(load(document_path))
        except (SchemaError, ValidationError) as error:
            location = "/".join(map(str, error.absolute_path))
            raise RuntimeError(f"{label} validation failed at {location or '<root>'}: {error.message}") from error
    try:
        Draft202012Validator.check_schema(load(RESULT_SCHEMA))
    except SchemaError as error:
        raise RuntimeError(f"result schema is invalid: {error.message}") from error
    mutations = []
    missing = json.loads(json.dumps(spec)); del missing["security"]["severity_rules"]
    renamed = json.loads(json.dumps(spec)); renamed["profiles"]["release"]["soak_seconds"] = renamed["profiles"]["release"].pop("soak_duration_seconds")
    unknown = json.loads(json.dumps(spec)); unknown["performance"]["unexpected"] = True
    schedule_digest = json.loads(json.dumps(spec)); schedule_digest["workloads"]["lifecycle_schedule"]["canonical_schedule_sha256"] = "0" * 64
    suite_duration = json.loads(json.dumps(spec)); suite_duration["performance"]["suite_orchestration"]["maximum_suite_duration_seconds"] = 344999
    lifecycle_timeout = json.loads(json.dumps(spec)); lifecycle_timeout["workloads"]["lifecycle_schedule"]["command_timeout_seconds"] = 43200
    wrong_mode = json.loads(json.dumps(spec)); wrong_mode["future_tool_contracts"]["mode_items"]["C030.01"] = "lifecycle"
    for name, mutation in (("missing", missing), ("renamed", renamed), ("unknown", unknown), ("schedule-digest", schedule_digest), ("suite-duration", suite_duration), ("lifecycle-timeout", lifecycle_timeout), ("wrong-mode-binding", wrong_mode)):
        require(not validator.is_valid(mutation), f"schema accepted {name}-field mutation")
        mutations.append(name)
    bad = [text for text in strings(spec) if PLACEHOLDER.search(text)]
    require(not bad, "placeholder text is forbidden" + (f": {bad[0]!r}" if bad else ""))
    release = spec["profiles"]["release"]
    require(release["soak_duration_seconds"] == 259200, "release soak drift")
    require(release["block_requirement"]["no_exclusion_minimum_blocks"] == 86314, "availability-derived block floor drift")
    require(release["block_requirement"]["availability_minimum"] == 0.999, "availability target drift")
    orchestration = spec["performance"]["suite_orchestration"]
    workload_seconds = 8 * sum(row["per_implementation_timeout_seconds"] for row in spec["performance"]["metric_workloads"].values())
    require(workload_seconds == orchestration["scheduled_workload_timeout_seconds"] == 344160, "performance workload duration drift")
    require(orchestration["orchestration_margin_seconds"] == 840, "performance orchestration margin drift")
    require(orchestration["maximum_suite_duration_seconds"] == 345000, "performance maximum suite duration drift")
    require(workload_seconds + orchestration["orchestration_margin_seconds"] == orchestration["maximum_suite_duration_seconds"], "performance suite duration formula mismatch")
    contract = spec["workloads"]["lifecycle_schedule"]
    lifecycle = spec["workloads"]["lifecycle_schedule"]
    scheduled = lifecycle["run_count"] * lifecycle["phase_count_per_run"] * lifecycle["phase_duration_seconds"]
    require(scheduled == lifecycle["scheduled_duration_seconds"] == 43200, "lifecycle scheduled duration drift")
    require(lifecycle["orchestration_margin_seconds"] == 3600, "lifecycle orchestration margin drift")
    require(lifecycle["command_timeout_seconds"] == 46800, "lifecycle command timeout drift")
    require(scheduled + lifecycle["orchestration_margin_seconds"] == lifecycle["command_timeout_seconds"], "lifecycle command timeout formula mismatch")
    tracker = load(TRACKER)
    c030 = next(chunk for chunk in tracker["chunks"] if chunk["id"] == "C030")
    lifecycle_command = next(command for command in c030["gate"]["commands"] if command["name"] == "C030 lifecycle qualification")
    require(lifecycle_command["timeout_seconds"] == lifecycle["command_timeout_seconds"], "tracker lifecycle command timeout drift")
    matrices, schedule = lifecycle_schedule(contract)
    require(matrices == contract["per_run_phase_action_counts"], "lifecycle per-phase allocation drift")
    schedule_bytes = json.dumps(schedule, sort_keys=True, separators=(",", ":")).encode()
    require(hashlib.sha256(schedule_bytes).hexdigest() == contract["canonical_schedule_sha256"] == "1fe1e560db153fb01d9fc06e9c857f0c3ba2774ce678d3bcecced662a47898f0", "lifecycle schedule digest mismatch")
    totals = {action: sum(row["action"] == action for row in schedule) for action in contract["action_order"]}
    require(totals == {action: contract["run_count"] * count for action, count in contract["per_run_action_counts"].items()}, "lifecycle action totals drift")
    require(sum(row["fork_activation"] for row in schedule) == 2, "lifecycle fork activation count drift")
    require(sum(row["exclusion_end_second"] - row["exclusion_start_second"] for row in schedule) == 6720, "lifecycle exclusion windows drift")
    require(spec["profiles"]["developer"]["qualifies_release"] is False, "developer profile must not qualify")
    require(spec["version_pins"]["mutable_tags_allowed"] is False and spec["version_pins"]["network_downloads_allowed"] is False, "mutable tags and downloads must be forbidden")
    require(spec["clean_environment"]["downloads_during_run"] is False, "qualification downloads forbidden")
    require(spec["license_and_provenance"]["independent_approvals"]["required_roles"] == ["license-compliance-lead", "release-provenance-lead"], "license/provenance approval roles drift")
    require(spec["security"]["independent_approvals"]["required_roles"] == ["security-lead", "owning-domain-owner"], "security approval roles drift")
    expected_items = [f"C030.{n:02d}" for n in range(1, 9)]
    require([row["item"] for row in spec["artifacts"]] == expected_items, "result ownership must be exact C030.01-.08 order")
    future = spec["future_tool_contracts"]
    implemented = future["implemented_contract"]
    require(implemented == {"executable_scenario_count":4,"future_contract_count":44,"item":"C030.01","link_count":22,"mode":"harness","node_count":8,"output_path":"docs/oracles/results/c030/c030-01-harness-result.v1.json"}, "C030.01 implementation contract drift")
    expected_modes = dict(zip(expected_items, future["command_modes"], strict=True))
    require(future["mode_items"] == expected_modes, "C030 result item/mode binding drift")
    require(future["mode_outputs"] == {row["item"]: row["result_path"] for row in spec["artifacts"]}, "C030 result item/output binding drift")
    scenarios = load(SCENARIOS)
    require(scenarios.get("frozen_spec") == {"commit": "76d6d03", "path": "docs/oracles/c030-qualification-spec.v1.json", "sha256": spec_sha256}, "scenario manifest frozen specification binding mismatch")
    require(len(scenarios["topology"]["nodes"]) == implemented["node_count"], "scenario node count drift")
    require(len(scenarios["topology"]["links"]) == implemented["link_count"], "scenario link count drift")
    executable = [row for row in scenarios["scenarios"] if row["execution_state"] == "executable"]
    contracts = [row for row in scenarios["scenarios"] if row["execution_state"] == "contract-only"]
    require(len(executable) == implemented["executable_scenario_count"] and all(row["item"] == "C030.01" for row in executable), "executable scenario set drift")
    require(len(contracts) == implemented["future_contract_count"] and all(row.get("result_claimed") is False for row in contracts), "future scenario contract set drift")
    require((future["runner"], future["harness"], future["scenario_manifest"], future["scenario_schema"], future["result_schema"]) == ("tools/qualification/c030_qualification.py","tools/qualification/c030_harness.py","docs/oracles/c030-scenario-manifest.v1.json","docs/oracles/schemas/c030-scenario-manifest-v1.schema.json","docs/oracles/schemas/c030-qualification-result-v1.schema.json"), "C030.01 evidence path drift")
    qualification_commands = c030["gate"]["commands"][2:10]
    for item, command in zip(expected_items, qualification_commands, strict=True):
        expected_argv = ["python3", future["runner"], expected_modes[item], "--spec", "docs/oracles/c030-qualification-spec.v1.json"]
        if item == "C030.01":
            expected_argv.extend(["--profile", "release"])
        expected_argv.extend(["--output", future["mode_outputs"][item]])
        require(command["argv"] == expected_argv, f"tracker {item} mode/profile/output drift")
    final_command = c030["gate"]["commands"][10]
    require(qualification_commands[0]["timeout_seconds"] == 280800, "tracker release harness timeout drift")
    require(final_command["argv"] == ["python3", "tools/qualification/c030_gate.py", "all", "--trust-store-env", "C030_QUALIFICATION_TRUST_STORE"], "tracker final qualification trust-store interface drift")
    frozen = registered_c017_c028(manifest)
    actual = {row["registry_key"]:(row["path"],row["sha256"]) for row in spec["artifact_references"]}
    require(actual == frozen, "C017-C028 artifact reference set/path/digest drift")
    expected_registry = {
        "c030_qualification_spec": ("c030-qualification-spec.v1.json", EXPECTED_SPEC_SHA256),
        "c030_qualification_schema": ("schemas/c030-qualification-spec-v1.schema.json", EXPECTED_SCHEMA_SHA256),
        "c030_qualification_runner_source": ("tools/qualification/c030_qualification.py", None),
        "c030_harness_source": ("tools/qualification/c030_harness.py", None),
        "c030_scenario_manifest": ("c030-scenario-manifest.v1.json", None),
        "c030_scenario_schema": ("schemas/c030-scenario-manifest-v1.schema.json", None),
        "c030_result_schema": ("schemas/c030-qualification-result-v1.schema.json", None),
        "c030_result_source": ("tools/qualification/c030_result.py", None),
    }
    for key, (relative, digest) in expected_registry.items():
        entry = manifest.get(key)
        require(isinstance(entry, dict) and entry.get("path") == relative and isinstance(entry.get("sha256"), str) and (digest is None or entry["sha256"] == digest), f"manifest synchronized mutation or missing {key}")
    gate_entry = manifest.get("c030_gate_source")
    require(isinstance(gate_entry, dict) and gate_entry.get("path") == "tools/qualification/c030_gate.py", "manifest missing c030_gate_source")
    return {"schema":"draft-2020-12","referenced_artifacts":len(actual),"platform":"P-LINUX-X64","release_soak_seconds":release["soak_duration_seconds"],"no_exclusion_minimum_blocks":86314,"performance_maximum_suite_seconds":345000,"lifecycle_scheduled_seconds":scheduled,"lifecycle_orchestration_margin_seconds":lifecycle["orchestration_margin_seconds"],"lifecycle_command_timeout_seconds":lifecycle["command_timeout_seconds"],"lifecycle_schedule_sha256":contract["canonical_schedule_sha256"],"lifecycle_actions":len(schedule),"harness_nodes":len(scenarios["topology"]["nodes"]),"harness_links":len(scenarios["topology"]["links"]),"executable_scenarios":len(executable),"future_contracts":len(contracts),"result_overwrite_guard":implemented["output_path"],"schema_mutation_tests":mutations}


def validate_hashes() -> dict:
    spec, manifest = load(SPEC), load(MANIFEST)
    checked = 0
    for row in spec["artifact_references"]:
        path = repository_path(row["path"])
        require(path.is_file(), f"missing referenced artifact: {row['path']}")
        require(sha256(path) == row["sha256"], f"referenced artifact digest mismatch: {row['path']}")
        checked += 1
    execution_inputs = spec["topology"]["configuration_sources"] + spec["version_pins"]["execution_inputs"]
    for row in execution_inputs:
        path = repository_path(row["path"])
        require(path.is_file() and sha256(path) == row["sha256"], f"execution input digest mismatch: {row['path']}")
    keys = ("c030_qualification_spec", "c030_qualification_schema", "c030_qualification_runner_source", "c030_harness_source", "c030_scenario_manifest", "c030_scenario_schema", "c030_result_schema", "c030_result_source", "c030_gate_source")
    for key in keys:
        entry = manifest[key]
        path = (ORACLES / entry["path"]) if not entry["path"].startswith(("tools/", "rust-tron/")) else ROOT / entry["path"]
        require(path.is_file() and sha256(path) == entry["sha256"], f"manifest digest mismatch: {entry['path']}")
    return {"verified_referenced_digests":checked,"verified_execution_input_digests":len(execution_inputs),"verified_c030_registry_entries":len(keys)}


def qualification_trust_store(env_name: str | None) -> Path:
    require(env_name == "C030_QUALIFICATION_TRUST_STORE", "--trust-store-env must be C030_QUALIFICATION_TRUST_STORE")
    raw = os.environ.get(env_name, "")
    require(bool(raw), f"{env_name} is not set")
    unresolved = Path(raw).expanduser()
    require(not unresolved.is_symlink(), f"{env_name} must not name a symlink")
    path = unresolved.resolve(strict=True)
    require(path.is_file(), f"{env_name} must name an external regular file")
    require(ROOT not in path.parents, f"{env_name} must not name a repository-owned trust store")
    return path


def validate_full(trust_store: Path) -> dict:
    spec = load(SPEC)
    scenarios = load(SCENARIOS)
    spec_sha256 = sha256(SPEC)
    scenario_manifest_sha256 = sha256(SCENARIOS)
    require(scenarios.get("frozen_spec", {}).get("sha256") == spec_sha256, "scenario manifest is stale against the frozen specification")
    future = spec["future_tool_contracts"]
    for path in (future["runner"], future["harness"], future["scenario_manifest"], future["scenario_schema"], future["result_schema"]):
        require(repository_path(path).is_file(), f"C030 implementation evidence absent: {path}")
    require(trust_store.is_file() and not trust_store.is_symlink(), "--trust-store must name an external qualification trust store")
    result_schema = load(RESULT_SCHEMA)
    verified = []
    for row in spec["artifacts"]:
        path = repository_path(row["result_path"])
        require(path.is_file(), f"qualification result absent: {row['result_path']}")
        result = load(path)
        try:
            Draft202012Validator(result_schema).validate(result)
            verify_result(result, trust_store, expected_item=row["item"],
                          expected_mode=future["mode_items"][row["item"]],
                          expected_output_path=canonical_output_path(path),
                          expected_spec_sha256=spec_sha256,
                          expected_scenario_manifest_sha256=scenario_manifest_sha256,
                          scenario_manifest=scenarios)
        except (ValidationError, ResultVerificationError) as error:
            raise RuntimeError(f"invalid signed qualification result {row['item']}: {error}") from error
        require(result["scenario_id"] == row["item"] and result["profile"] == "release" and result["overall_status"] == "pass", f"non-passing or mismatched qualification result: {row['item']}")
        verified.append(row["item"])
    return {"verified_signed_release_results": verified, "threshold": spec["result_contract"]["signature"]["threshold"]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("metadata", "check", "all"))
    parser.add_argument("--trust-store-env")
    args = parser.parse_args()
    try:
        metadata = validate_metadata()
        output = {"metadata":metadata}
        if args.mode in {"check", "all"}:
            output["digests"] = validate_hashes()
        if args.mode == "all":
            output["qualification"] = validate_full(qualification_trust_store(args.trust_store_env))
    except (OSError, json.JSONDecodeError, RuntimeError) as error:
        print(f"C030 {args.mode}: FAIL: {error}")
        return 1
    print(json.dumps(output, sort_keys=True))
    print(f"C030 {args.mode}: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
