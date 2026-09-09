#!/usr/bin/env python3
"""Authenticate the complete C028 release, recovery, ownership, and CI contract."""
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import importlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
import sys
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
ORACLES = ROOT / "docs/oracles"
EXPECTED = {
    "c028_production_reconciliation": "c028-production-reconciliation.v1.json",
    "c028_command_manifest": "c028-command-manifest.v1.json",
    "c028_recovery_matrix": "c028-recovery-matrix.v1.json",
    "c028_reconciliation_schema": "schemas/c028-production-reconciliation-v1.schema.json",
    "c028_command_schema": "schemas/c028-command-manifest-v1.schema.json",
    "c028_recovery_schema": "schemas/c028-recovery-matrix-v1.schema.json",
    "c028_release_schema": "schemas/c028-release-contract-v1.schema.json",
    "c028_busybox_schema": "schemas/c028-busybox-material-v1.schema.json",
    "c028_release_contract": "c028-release-contract.v1.json",
    "c028_busybox_material": "c028-busybox-material.v1.json",
    "c028_workflow_metadata": "c028-workflow-metadata.v1.json",
    "c028_workflow_metadata_schema": "schemas/c028-workflow-metadata-v1.schema.json",
    "c028_gate_source": "tools/release/c028_gate.py",
    "c028_release_source": "tools/release/c028_release.py",
    "c028_signer_source": "tools/release/c028_sign_candidate.py",
    "c028_drills_source": "tools/release/c028_drills.py",
    "c028_case_storage_source": "tools/release/c028_cases/storage.py",
    "c028_schema_tests": "tools/release/tests/test_c028_schema_validation.py",
    "c028_case_snapshot_source": "tools/release/c028_cases/snapshot.py",
    "c028_case_release_source": "tools/release/c028_cases/release.py",
    "c028_case_platform_source": "tools/release/c028_cases/platform.py",
    "c028_case_runtime_source": "tools/release/c028_cases/runtime.py",
    "c028_case_container_source": "tools/release/c028_cases/container.py",
}
SCHEMAS = {
    "c028-command-manifest.v1.json": "c028-command-manifest-v1.schema.json",
    "c028-production-reconciliation.v1.json": "c028-production-reconciliation-v1.schema.json",
    "c028-recovery-matrix.v1.json": "c028-recovery-matrix-v1.schema.json",
    "c028-release-contract.v1.json": "c028-release-contract-v1.schema.json",
    "c028-busybox-material.v1.json": "c028-busybox-material-v1.schema.json",
    "c028-workflow-metadata.v1.json": "c028-workflow-metadata-v1.schema.json",
}
SIGNER_AUTHORITY_WORKFLOW = ".github/workflows/c028-release-sign.yml"
RELEASE_ID_REGEX = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
RELEASE_ID_GUARDS = {
    "c028-release-candidate.yml": '[[ "$RELEASE_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]',
    "c028-release-sign.yml": '[[ "$RELEASE_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]',
    "c028-release-publish.yml": '[[ "$EXPECTED_RELEASE_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]',
}


TEST_FILES = (
    "tools/release/c028_cases/storage.py",
    "tools/release/c028_cases/snapshot.py",
    "tools/release/c028_cases/release.py",
    "tools/release/c028_cases/platform.py",
    "tools/release/c028_cases/runtime.py",
    "tools/release/c028_cases/container.py",
    "rust-tron/crates/tron-crypto/tests/c028_artifact_auth.rs",
    "rust-tron/crates/tron-network/tests/c028_backup_auth.rs",
    "rust-tron/crates/tron-storage/tests/c028_snapshot.rs",
    "rust-tron/crates/tron-node/tests/c028_bootstrap.rs",
    "rust-tron/crates/tron-node/tests/c028_deployment.rs",
    "rust-tron/crates/tron-toolkit/tests/c028_release_verify.rs",
    "tools/release/tests/test_c028_release_identity.py",
    "tools/release/tests/test_c028_signing_authority.py",
    "tools/release/tests/test_c028_schema_validation.py",
    "rust-tron/crates/tron-network/tests/c028_production.rs",
    "rust-tron/crates/tron-node/tests/c026_replica.rs",
)

def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))

def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)

def validate_document(instance: object, schema: dict, name: str) -> None:
    try:
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(instance)
    except (SchemaError, ValidationError) as error:
        location = "/".join(str(part) for part in error.absolute_path)
        where = f" at {location}" if location else ""
        raise RuntimeError(f"{name}: Draft 2020-12 validation failed{where}: {error.message}") from error


def verify_schemas() -> dict:
    for document_name, schema_name in SCHEMAS.items():
        validate_document(load(ORACLES / document_name), load(ORACLES / "schemas" / schema_name), document_name)
    return {"validated_documents": len(SCHEMAS), "json_schema_draft": "2020-12"}

def verify_registry() -> None:
    registry = load(ORACLES / "manifest.v1.json")
    for key, relative in EXPECTED.items():
        entry = registry.get(key)
        require(isinstance(entry, dict), f"oracle registry missing {key}")
        require(entry.get("path") == relative, f"oracle registry path mismatch for {key}")
        path = (ORACLES / relative) if not relative.startswith("tools/") else ROOT / relative
        require(path.is_file(), f"missing registered artifact {relative}")
        require(entry.get("sha256") == sha(path), f"oracle registry hash mismatch for {relative}")

def verify_ownership(reconciliation: dict | None = None) -> dict:
    ledger = load(ORACLES / "production-ownership.v1.json")
    canonical = [row for row in ledger["rows"] if row.get("acceptance_gate") == "C028.V"]
    reconciliation = reconciliation or load(ORACLES / "c028-production-reconciliation.v1.json")
    rows = reconciliation["rows"]
    require(reconciliation.get("production_rows") == 62 and reconciliation.get("java_test_rows") == 0, "C028 reconciliation metadata must be exact 62/0")
    require(len(canonical) == 62 and len(rows) == 62, "C028 production accounting must be exactly 62")
    require({row["id"] for row in canonical} == {row["production_id"] for row in rows}, "C028 production IDs drift")
    require(len({row["production_id"] for row in rows}) == 62, "duplicate C028 production row")
    by_id = {row["id"]: row for row in canonical}
    proof_observations = {}
    for row in rows:
        source = by_id[row["production_id"]]
        require(row["source"]["path"] == source["source"]["path"] and row["source"]["line"] == source["source"]["line"], f"source drift for {row['production_id']}")
        require(row["owning_item"] == source["owning_item"], f"owner drift for {row['production_id']}")
        require(row["result"] in {"rust_equivalent", "retained_reference_only", "reviewed_non_applicable"}, "invalid result")
        source_path = ROOT / row["source"]["path"]
        require(source_path.is_file() and row["source"].get("sha256") == sha(source_path), f"unauthenticated Java source {row['production_id']}")
        require("Pinned SHA-256" in row["reason"] and "reference-only" in row["reason"], f"missing source-specific rationale {row['production_id']}")
        require(row["proof"]["path"] != "tools/release/c028_gate.py", f"checker cannot prove production row {row['production_id']}")
        if row["result"] == "retained_reference_only":
            require(row["proof"] == {"path": row["source"]["path"], "symbol": "sha256:" + row["source"]["sha256"]}, f"retained source proof drift {row['production_id']}")
        else:
            proof = ROOT / row["proof"]["path"]
            require(proof.is_file() and row["proof"]["symbol"] in proof.read_text(encoding="utf-8"), f"missing executable Rust proof {row['production_id']}")
        observation = (row["result"], row["proof"]["path"], row["proof"]["symbol"])
        source_observation=(row["source"]["path"],row["source"]["sha256"])
        require(observation not in proof_observations or source_observation == proof_observations[observation], f"unjustified catchall evidence reuse {row['production_id']}")
        proof_observations[observation] = source_observation
    java_tests = load(ORACLES / "java-test-ownership.v1.json")
    test_rows = [row for row in java_tests["rows"] if row.get("acceptance_gate") == "C028.V"]
    require(not test_rows, "C028 must own zero Java tests")
    return {"production_rows": len(rows), "java_test_rows": len(test_rows)}

def load_case_registry():
    registry={}; owners={}
    for name in ("storage","snapshot","release","platform","runtime","container"):
        cases=getattr(importlib.import_module(f"tools.release.c028_cases.{name}"),"CASES",None)
        require(isinstance(cases,dict),f"case module {name} lacks CASES")
        for case,fn in cases.items():
            require(case not in registry,f"duplicate case ownership {case}: {owners.get(case)} and {name}")
            require(callable(fn),f"case {case} is not callable")
            registry[case]=fn; owners[case]=name
    return registry,owners

def verify_drills(commands: dict | None = None, recovery: dict | None = None) -> dict:
    commands = commands or load(ORACLES / "c028-command-manifest.v1.json")
    recovery = recovery or load(ORACLES / "c028-recovery-matrix.v1.json")
    validate_document(commands, load(ORACLES / "schemas/c028-command-manifest-v1.schema.json"), "c028-command-manifest.v1.json")
    validate_document(recovery, load(ORACLES / "schemas/c028-recovery-matrix-v1.schema.json"), "c028-recovery-matrix.v1.json")
    rows = commands["commands"]
    ids = [row["id"] for row in rows]
    require(len(ids) == 44 and len(set(ids)) == 44, "command manifest must contain 44 unique drills")
    require(ids == recovery["drill_ids"], "recovery and command drill order drift")
    platforms = load(ORACLES / "c028-release-contract.v1.json")["platforms"]
    require({row["platform_id"] for row in rows} == {recovery["platform_id"]} == {platforms[0]["platform_id"]}, "schema/platform cross-document drift")
    negative_ids = {row["id"] for row in rows if row["expected_result"] == "reject_before_mutation"}
    require(negative_ids == set(recovery["negative_drill_ids"]), "negative drill IDs drift from expected results")
    registry, owners = load_case_registry()
    require(set(registry) == set(ids), "case modules must form exact 44-key union")
    expected_counts = {"storage": 10, "snapshot": 13, "release": 15, "platform": 3, "runtime": 2, "container": 1}
    actual = {name: list(owners.values()).count(name) for name in expected_counts}
    require(actual == expected_counts, f"case ownership partition drift: {actual}")
    assertions = ["exact_case_identity", "actual_command_or_api", "authenticated_observation", "protected_tree_invariant"]
    for row in rows:
        case = row["id"]
        fn = registry[case]
        owner = owners[case]
        expected_path = f"tools/release/c028_cases/{owner}.py"
        require(row["owning_item"] == ("C028.07" if case.startswith("C028-D") else "C028.10"), f"owning item drift in {case}")
        require(row["expected_exit"] == 0 and row["timeout_seconds"] == 300 and row["assertions"] == assertions, f"execution contract drift in {case}")
        require(row.get("scenario") == {"id": case, "module": owner, "function": fn.__name__}, f"case module/function substitution in {case}")
        require(row["proof"] == {"path": expected_path, "symbol": fn.__name__}, f"case proof substitution in {case}")
        require(row["argv"] == ["python3", "tools/release/c028_drills.py", "scenario", "--command-manifest", "docs/oracles/c028-command-manifest.v1.json", "--id", case], f"non-canonical scenario command in {case}")
    require("c028_case_probe" not in json.dumps(commands) and not (ROOT / "tools/release/c028_case_probe.py").exists(), "synthetic case probe remains reachable")
    return {"drills": 44, "semantic_cases": 44, "case_modules": actual}

def verify_mutation_guards() -> dict:
    commands = load(ORACLES / "c028-command-manifest.v1.json")
    recovery = load(ORACLES / "c028-recovery-matrix.v1.json")
    document_mutations: list[tuple[str, dict, str]] = []

    def mutate(document: dict, label: str, change) -> None:
        value = copy.deepcopy(document)
        change(value)
        document_mutations.append((label, value, "commands" if document is commands else "recovery"))

    mutate(commands, "command schema", lambda value: value.__setitem__("schema", "c028-command-manifest-v2"))
    mutate(commands, "command platform", lambda value: value["commands"][0].__setitem__("platform_id", "P-OTHER"))
    mutate(commands, "command owner", lambda value: value["commands"][0].__setitem__("owning_item", "C028.10"))
    mutate(commands, "command expected exit", lambda value: value["commands"][0].__setitem__("expected_exit", 1))
    mutate(commands, "command assertions", lambda value: value["commands"][0]["assertions"].pop())
    mutate(commands, "command timeout", lambda value: value["commands"][0].__setitem__("timeout_seconds", 0))
    mutate(commands, "command id pattern", lambda value: value["commands"][0].__setitem__("id", "invalid"))
    mutate(commands, "command extra root", lambda value: value.__setitem__("extra", True))
    mutate(commands, "command extra nested", lambda value: value["commands"][0]["scenario"].__setitem__("extra", True))
    mutate(commands, "scenario substitution", lambda value: value["commands"][0].__setitem__("scenario", copy.deepcopy(value["commands"][1]["scenario"])))
    mutate(commands, "proof substitution", lambda value: value["commands"][0].__setitem__("proof", copy.deepcopy(value["commands"][1]["proof"])))
    mutate(commands, "argv substitution", lambda value: value["commands"][0]["argv"].__setitem__(-1, value["commands"][1]["id"]))
    mutate(commands, "unexecuted row", lambda value: value["commands"].pop())
    mutate(commands, "duplicate row", lambda value: value["commands"].__setitem__(-1, copy.deepcopy(value["commands"][0])))
    mutate(recovery, "recovery schema", lambda value: value.__setitem__("schema", "c028-recovery-matrix-v2"))
    mutate(recovery, "recovery platform", lambda value: value.__setitem__("platform_id", "P-OTHER"))
    mutate(recovery, "negative ids", lambda value: value["negative_drill_ids"].pop())
    mutate(recovery, "fault phases", lambda value: value["fault_phases"].reverse())
    mutate(recovery, "recovery matrix drift", lambda value: value["drill_ids"].reverse())
    mutate(recovery, "recovery extra root", lambda value: value.__setitem__("extra", True))
    for label, mutated, kind in document_mutations:
        try:
            verify_drills(mutated, recovery) if kind == "commands" else verify_drills(commands, mutated)
        except RuntimeError:
            pass
        else:
            raise RuntimeError(f"{label} mutation was accepted")

    standalone = []
    for document_name, schema_name in SCHEMAS.items():
        document = load(ORACLES / document_name)
        schema = load(ORACLES / "schemas" / schema_name)
        root_extra = copy.deepcopy(document)
        root_extra["reviewer_extra"] = True
        standalone.append((document_name + " extra root", root_extra, schema))
    reconciliation = load(ORACLES / "c028-production-reconciliation.v1.json")
    changed_owner = copy.deepcopy(reconciliation); changed_owner["rows"][0]["owning_item"] = "C028.bad"
    nested_extra = copy.deepcopy(reconciliation); nested_extra["rows"][0]["source"]["extra"] = True
    standalone.extend((("reconciliation owner", changed_owner, load(ORACLES / "schemas/c028-production-reconciliation-v1.schema.json")), ("reconciliation nested extra", nested_extra, load(ORACLES / "schemas/c028-production-reconciliation-v1.schema.json"))))
    release = load(ORACLES / "c028-release-contract.v1.json")
    release_nested = copy.deepcopy(release); release_nested["platforms"][0]["extra"] = True
    standalone.append(("release nested extra", release_nested, load(ORACLES / "schemas/c028-release-contract-v1.schema.json")))
    busybox = load(ORACLES / "c028-busybox-material.v1.json")
    busybox_type = copy.deepcopy(busybox); busybox_type["elf"]["class"] = "64"
    busybox_pattern = copy.deepcopy(busybox); busybox_pattern["material"]["sha256"] = "not-a-digest"
    standalone.extend((("busybox nested type", busybox_type, load(ORACLES / "schemas/c028-busybox-material-v1.schema.json")), ("busybox nested pattern", busybox_pattern, load(ORACLES / "schemas/c028-busybox-material-v1.schema.json"))))
    for label, document, schema in standalone:
        try:
            validate_document(document, schema, label)
        except RuntimeError:
            pass
        else:
            raise RuntimeError(f"{label} mutation was accepted")
    return {"mutation_guards": len(document_mutations) + len(standalone)}

def canonical_release_id(value: str) -> bool:
    return re.fullmatch(RELEASE_ID_REGEX, value) is not None


def workflow_shell_interpolations(workflow: str) -> list[str]:
    findings = []
    lines = workflow.splitlines()
    for index, line in enumerate(lines):
        match = re.match(r"^(\s*)(?:-\s+)?run:\s*(.*)$", line)
        if match is None:
            continue
        indentation = len(match.group(1))
        scalar = match.group(2).strip()
        if scalar not in ("|", ">", "|-"):
            body = [scalar]
        else:
            body = []
            for candidate in lines[index + 1:]:
                if candidate.strip() and len(candidate) - len(candidate.lstrip()) <= indentation:
                    break
                body.append(candidate)
        findings.extend(re.findall(r"\$\{\{\s*(?:inputs\.|github\.event\.)[^}]+\}\}", "\n".join(body)))
    return findings


def verify_release_id_workflow_guards(workflows: dict[str, str]) -> None:
    expected_counts = {
        "c028-release-candidate.yml": 1,
        "c028-release-sign.yml": 1,
        "c028-release-publish.yml": 2,
    }
    for name, guard in RELEASE_ID_GUARDS.items():
        require(workflows[name].count(guard) == expected_counts[name], f"{name} release ID guard missing or drifted")
    candidate = workflows["c028-release-candidate.yml"]
    require(candidate.index(RELEASE_ID_GUARDS["c028-release-candidate.yml"]) < candidate.index("c028_release.py build"), "candidate release ID guard must precede artifact assembly")
    signing = workflows["c028-release-sign.yml"]
    require(signing.index(RELEASE_ID_GUARDS["c028-release-sign.yml"]) < signing.index("Provision independently authenticated signing keys"), "signing release ID guard must precede secret provisioning")
    publish = workflows["c028-release-publish.yml"]
    guard_name = "- name: Validate untrusted dispatch inputs before privileged operations"
    require(publish.count(guard_name) == 2 and publish.index(guard_name) < publish.index("actions/checkout@"), "publish input guards must precede privileged operations")


def verify_workflow_shell_safety(workflows: dict[str, str]) -> None:
    for name, workflow in workflows.items():
        findings = workflow_shell_interpolations(workflow)
        require(not findings, f"untrusted GitHub expression embedded in shell source in {name}: {findings[0] if findings else ''}")
    verify_release_id_workflow_guards(workflows)


def verify_fresh_runner_inputs(candidate: str, publish: str) -> None:
    rust_install = "rustup toolchain install 1.85.1 --profile minimal --component cargo --target x86_64-unknown-linux-gnu"
    rust_override = "rustup override set 1.85.1 rust-tron"
    rust_identity = 'test "$(cd rust-tron && rustc --version)" = "rustc 1.85.1 (4eb161250 2025-03-15)"'
    expected_rust_steps = {"candidate": (1, 2), "publish": (2, 2)}
    for name, workflow in (("candidate", candidate), ("publish", publish)):
        expected_install, expected_identity = expected_rust_steps[name]
        require(workflow.count(rust_install) == expected_install and workflow.count(rust_override) == expected_install and workflow.count(rust_identity) == expected_identity,
                f"{name} workflow permits ambient or unverified Rust toolchain fallback")
    busybox_tokens = (
        "docs/oracles/c028-busybox-material.v1.json", "BUSYBOX_PACKAGE_SHA256",
        "print('TRON_BUSYBOX_SHA256='+policy['material']['sha256'])",
        "TRON_BUSYBOX_VERSION", "TRON_BUSYBOX_LICENSE", "TRON_BUSYBOX_PROVENANCE",
        "dpkg-deb --extract", "sha256sum --check --strict",
        'echo "TRON_BUSYBOX=$RUNNER_TEMP/c028-inputs/busybox" >> "$GITHUB_ENV"',
    )
    for name, workflow in (("candidate", candidate), ("publish", publish)):
        for token in busybox_tokens:
            require(token in workflow, f"{name} workflow permits ambient BusyBox fallback: {token}")
    require(publish.index("Run canonical C028 gate before entering release environment") < publish.index("environment: release"),
            "publish gate must run in the pre-secret job")


def signing_trigger_allowed(event: dict, repository: str, default_branch: str, current_default_sha: str) -> bool:
    run = event.get("workflow_run", {})
    run_repository = run.get("repository") or {}
    head_repository = run.get("head_repository") or {}
    return (
        run.get("name") == "C028 release candidate"
        and run.get("path") == ".github/workflows/c028-release-candidate.yml"
        and run.get("event") == "workflow_dispatch"
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
        and run_repository.get("full_name") == repository
        and head_repository.get("full_name") == repository
        and run.get("head_branch") == default_branch
        and re.fullmatch(r"[0-9a-f]{40}", run.get("head_sha", "")) is not None
        and run.get("head_sha") == current_default_sha
    )

def verify_signing_authority(candidate: str, signing: str, transfer: dict) -> None:
    authority = transfer["signer_authority"]
    require(authority == {
        "candidate_repository_signer_authoritative": False,
        "provisioning": "protected c028-release-signing environment secrets supply base64 signer bytes and independently recorded SHA-256 digests",
        "signing_workflow": SIGNER_AUTHORITY_WORKFLOW,
        "signing_workflow_source": "GitHub workflow_run definition from the protected default branch; trusted checkout is exactly github.workflow_sha",
        "signer_digest_source": "protected signing environment; never workflow input, candidate artifact, or candidate source",
        "signer_execution": "hash-verified trusted signer only; candidate archive is inert data and is never executed",
        "trigger_policy": ["successful C028 release candidate workflow_dispatch", "same repository and head repository", "protected default branch", "head SHA equals current default-branch SHA", "exact candidate workflow path"],
        "scrub": ["signer", "signing keys", "extracted unsigned candidate"],
    }, "protected default-branch signer authority drift")
    require(transfer["signing_job_candidate_checkout"] is False, "candidate revision checkout contract drift")
    require(transfer["signing_job_candidate_execution"] is False and transfer["signing_key_scrub"] is True, "signing isolation contract drift")
    for forbidden in ("sign-candidate:", "environment:", "secrets.", "SIGNER_SHA256", "SIGNER_B64", "SIGNING_KEY_", "c028_sign_candidate.py"):
        require(forbidden not in candidate, f"candidate workflow contains signing authority: {forbidden}")
    required = (
        "workflow_run:", "workflows: [C028 release candidate]", "types: [completed]",
        "github.event.workflow_run.conclusion == 'success'", "github.event.workflow_run.event == 'workflow_dispatch'",
        "github.event.workflow_run.repository.full_name == github.repository",
        "github.event.workflow_run.head_repository.full_name == github.repository",
        "github.event.workflow_run.head_branch == github.event.repository.default_branch",
        "environment: c028-release-signing", "ref: ${{ github.workflow_sha }}", "submodules: false",
        'test "$(jq -r .path <<<"$RUN_JSON")" = ".github/workflows/c028-release-candidate.yml"',
        'DEFAULT_SHA=$(gh api "repos/$REPOSITORY/commits/$DEFAULT_BRANCH" --jq .sha)',
        'test "$DEFAULT_SHA" = "$RUN_HEAD_SHA"', "C028_SIGNER_SOURCE_SHA256",
        "tools/release/c028_sign_candidate.py | sha256sum --check --strict",
        "run-id: ${{ steps.trigger.outputs.run_id }}", "C028_RELEASE_SIGNING_KEY_1_B64",
        "C028_RELEASE_SIGNING_KEY_1_SHA256", "C028_RELEASE_SIGNING_KEY_2_B64",
        "C028_RELEASE_SIGNING_KEY_2_SHA256", "candidate archive member", "source.extractall(destination, filter=\"data\")",
        'test "$SOURCE_REVISION" = "$EXPECTED_SOURCE_REVISION"',
        'test "$EXPECTED_ARTIFACT_NAME" = "c028-unsigned-$RELEASE_ID-$EXPECTED_SHA256"',
        'signing_workflow:".github/workflows/c028-release-sign.yml"', "if: always()", "rm -rf",
    )
    for token in required:
        require(token in signing, f"signing workflow lacks protected authority control: {token}")
    for forbidden in ("github.event.workflow_run.head_sha }}\n          submodules", "ref: ${{ github.event.workflow_run.head_sha }}", "ref: ${{ github.event.workflow_run.head_branch }}", "ref: ${{ github.head_ref }}", "ref: ${{ github.ref }}", "checkout candidate"):
        require(forbidden not in signing, f"signing workflow permits candidate-controlled checkout: {forbidden}")
    require(signing.count("actions/checkout@") == 1, "signing workflow must perform exactly one trusted checkout")
    metadata_schema = load(ORACLES / "schemas/c028-workflow-metadata-v1.schema.json")
    require(metadata_schema["properties"]["release_id"]["pattern"] == RELEASE_ID_REGEX, "workflow metadata release ID regex drift")
    require(metadata_schema["properties"]["unsigned_artifact_name"]["pattern"] == f"^c028-unsigned-{RELEASE_ID_REGEX[1:-1]}-[0-9a-f]{{64}}$", "unsigned artifact release ID regex drift")
    require(metadata_schema["properties"]["signed_artifact_name"]["pattern"] == f"^c028-candidate-{RELEASE_ID_REGEX[1:-1]}-[0-9a-f]{{64}}$", "signed artifact release ID regex drift")
    require("workflow_call:" not in signing and "workflow_dispatch:" not in signing, "signing workflow must be reachable only through workflow_run")

def verify_release_contract() -> dict:
    contract = load(ORACLES / "c028-release-contract.v1.json")
    require(contract["platforms"] == [{"architecture": "x86_64", "backend": "rustlog", "backend_format": "rustlog-v1", "features": ["rustlog-v1"], "os": "linux", "platform_id": "P-LINUX-X64", "target": "x86_64-unknown-linux-gnu"}], "platform contract drift")
    require(contract["binaries"] == ["tron-fullnode", "tron-solidity", "tron-toolkit", "tron-release-verify"], "binary inventory drift")
    require(contract["reproducibility"]["independent_builds"] == 2, "two independent builds required")
    require(contract["reproducibility"]["outputs"] == ["native-archive", "config-archive", "oci-layout"], "reproducible output inventory drift")
    require(contract["oci"]["layer_digest"] == "sha256(deterministic gzip layer bytes)" and contract["oci"]["diff_id"] == "sha256(normalized uncompressed rootfs tar bytes)", "OCI digest semantics drift")
    require(contract["oci"]["entrypoint"] == "/usr/local/bin/entrypoint.sh" and contract["oci"]["runtime_source"] == "emitted OCI layout", "OCI runtime topology drift")
    require(contract["sapling"]["packaged_bytes"] is False and len(contract["sapling"]["operator_inputs"]) == 2, "Sapling exclusion contract drift")
    require(contract["release_authentication"]["offline_verification"] is True, "offline release verification required")
    require(contract["snapshot_authentication"]["offline_verification"] is True, "offline snapshot verification required")
    require(contract["snapshot_authentication"]["scope"] == "snapshot:<network>", "canonical snapshot role scope contract drift")
    require(contract["snapshot_authentication"]["scope_enforcement"] == "exact canonical snapshot:<network> trust-role scope is verified before import mutation; role-name match alone is insufficient", "snapshot scope enforcement contract drift")
    busybox = contract["immutable_inputs"]["busybox"]
    require(busybox == {"policy": "docs/oracles/c028-busybox-material.v1.json", "path": "TRON_BUSYBOX absolute path", "validation": ["repository-pinned source package digest", "repository-pinned material digest", "static ELF64 x86-64 inspection", "embedded version marker"], "execution_during_assembly": False}, "BusyBox immutable-input contract drift")
    transfer = contract["workflow_transfer"]
    require(transfer["immutable_artifact_binding"] == ["repository", "candidate_run_id", "signing_run_id", "signing_workflow", "signing_workflow_sha", "unsigned_artifact_name", "unsigned_artifact_sha256", "signed_artifact_name", "signed_archive_name", "candidate_sha256", "release_id", "channel", "source_revision"], "candidate and signing run binding drift")
    require(transfer["release_destination_binding"] == ["release_id", "channel", "tag", "peeled_tag_commit", "checkout_commit", "source_revision"], "publish destination source revision binding drift")
    require(transfer["tag_resolution"] == "exact refs/tags/<release-id>^{commit}; branch names are not release tags", "exact release tag resolution drift")
    workflows = [ROOT / ".github/workflows/c028-release-candidate.yml", ROOT / ".github/workflows/c028-release-publish.yml"]
    guard = "python3 tools/reference-runner/java_reference_guard.py"
    for workflow in workflows:
        text = workflow.read_text(encoding="utf-8")
        require("--locked" in text and "--offline" in text and "tron-release-verify" in text, f"workflow lacks offline authenticated release controls: {workflow}")
        require("submodules: recursive" in text and "submodules: false" not in text, f"workflow does not initialize recursive submodules: {workflow}")
        require(guard in text and text.index(guard) < text.index("--gate C028"), f"workflow does not guard java-tron before C028 gate: {workflow}")
        require("busybox-static" not in text and "apt-get install --yes --no-install-recommends skopeo umoci busybox" not in text, f"workflow admits mutable apt BusyBox: {workflow}")
    candidate_text = workflows[0].read_text(encoding="utf-8")
    for token in ("docs/oracles/c028-busybox-material.v1.json", "BUSYBOX_PACKAGE_SHA256", "TRON_BUSYBOX_SHA256", "dpkg-deb --extract", "sha256sum --check --strict"):
        require(token in candidate_text, f"candidate workflow lacks repository-pinned BusyBox material control: {token}")
    require("busybox_url:" not in candidate_text and "busybox_sha256:" not in candidate_text, "workflow dispatch must not supply BusyBox trust policy")
    generator = (ROOT / "tools/release/c028_release.py").read_text(encoding="utf-8")
    require('os.environ.get("TRON_BUSYBOX","")' in generator and 'shutil.which("busybox")' not in generator, "release generator permits BusyBox PATH fallback")
    require("subprocess.run([str(path)]" not in generator and 'subprocess.run(["file"' not in generator, "release generator executes BusyBox or delegates ELF trust to file(1)")
    require("_validate_static_elf" in generator and "BUSYBOX_POLICY" in generator, "release generator lacks static repository-pinned BusyBox inspection")
    for token in ("production_materials", "SPDXRef-Package-BusyBox", 'uri":busybox["provenance"]'):
        require(token in generator, f"release metadata lacks BusyBox binding: {token}")
    candidate = workflows[0].read_text(encoding="utf-8")
    publish = workflows[1].read_text(encoding="utf-8")
    signing = (ROOT / SIGNER_AUTHORITY_WORKFLOW).read_text(encoding="utf-8")
    verify_fresh_runner_inputs(candidate, publish)
    verify_workflow_shell_safety({
        "c028-release-candidate.yml": candidate,
        "c028-release-publish.yml": publish,
        "c028-release-sign.yml": signing,
    })
    transfer = contract["workflow_transfer"]
    verify_signing_authority(candidate, signing, transfer)
    for token in ("build-candidate:", "c028-unsigned-", "actions/upload-artifact@"):
        require(token in candidate, f"candidate workflow lacks immutable unsigned handoff: {token}")
    privileged_publish = publish.split("  publish:", 1)[1]
    require("BUSYBOX" not in privileged_publish and "busybox" not in privileged_publish, "privileged publish runner must not materialize or execute production BusyBox")
    for token in ("actions/download-artifact@", "run-id: ${{ inputs.signing_run_id }}", "sha256sum --check --strict", "stage-publish", "validate-publish-identity", "--workflow-metadata", "PUBLICATION_STAGING", "AUTHENTICATED_RELEASE_ID", 'refs/tags/$RELEASE_TAG^{commit}', '--repo "$GITHUB_WORKSPACE"', 'signing_workflow "$RUNNER_TEMP/download/workflow-metadata.json"', 'signing_workflow_sha "$RUNNER_TEMP/download/workflow-metadata.json"', 'signed_artifact_name "$RUNNER_TEMP/download/workflow-metadata.json"', 'candidate_sha256 "$RUNNER_TEMP/download/workflow-metadata.json"', 'test "$ARTIFACT_NAME" = "c028-candidate-$EXPECTED_RELEASE_ID-$EXPECTED_SHA256"', "Verify protected signing run and exact artifact identity", '--expected-signing-run-id "$SIGNING_RUN_ID"'):
        require(token in publish, f"publish workflow lacks bound signed transfer control: {token}")
    require("/opt/tron-candidates" not in publish and "GITHUB_REF_NAME" not in publish, "publish destination must not depend on runner state or triggering ref")
    publish_step = publish.split("- name: Publish exact staged bytes", 1)[-1]
    require("CANDIDATE" not in publish_step and "$PUBLICATION_STAGING" in publish_step, "publish step must never reopen candidate bytes")
    verifier = (ROOT / "rust-tron/crates/tron-toolkit/src/bin/tron-release-verify.rs").read_text(encoding="utf-8")
    release_tests = (ROOT / "rust-tron/crates/tron-toolkit/tests/c028_release_verify.rs").read_text(encoding="utf-8")
    require("stage-publish" in verifier and "staged_publication_uses_retained_verified_bytes_after_candidate_substitution" in release_tests, "post-verify substitution protection is not executable")
    require("pub source_revision: String" in (ROOT / "rust-tron/crates/tron-toolkit/src/release.rs").read_text(encoding="utf-8"), "publication inventory omits authenticated source revision")
    identity_tests = (ROOT / "tools/release/tests/test_c028_release_identity.py").read_text(encoding="utf-8")
    for symbol in ("test_real_signer_output_fixture_validates_for_publisher", "test_lightweight_and_annotated_tags_peel_to_authenticated_commit", "test_mismatched_lightweight_and_annotated_tags_are_rejected", "test_branch_name_cannot_substitute_for_missing_tag", "test_checkout_must_equal_authenticated_tag_and_artifact_revision", "test_invalid_or_noncanonical_revision_is_rejected", "test_every_metadata_field_mutation_missing_and_extra_field_is_rejected", "test_mutated_workflow_metadata_is_rejected"):
        require(symbol in identity_tests, f"source identity mutation test missing: {symbol}")
    signing_tests = (ROOT / "tools/release/tests/test_c028_signing_authority.py").read_text(encoding="utf-8")
    for symbol in ("test_signer_cannot_checkout_candidate_revision", "test_workflow_name_or_path_spoof_is_rejected", "test_fork_branch_failure_and_stale_head_guards_are_required", "test_action_policy_simulation_accepts_only_protected_default_head", "test_all_workflow_shell_source_is_free_of_untrusted_expressions", "test_release_id_boundaries_match_at_candidate_signer_and_publish", "test_release_id_guard_removal_or_weakening_is_rejected"):
        require(symbol in signing_tests, f"signing authority mutation test missing: {symbol}")
    return {"platform_rows": 1, "binaries": 4, "workflows": 3}

def verify_compose_contract() -> dict:
    compose = (ROOT / "rust-tron/packaging/container/compose.yaml").read_text(encoding="utf-8")
    require("fullnode:\n    <<: *tron-service\n    profiles: [full]" in compose, "FullNode must be selected only by the full profile")
    require("solidity:\n    <<: *tron-service\n    command: [\"solidity\"]\n    profiles: [solidity]" in compose, "SolidityNode must be selected only by the solidity profile")
    require('TRON_COMPOSE_PROFILES: "${COMPOSE_PROFILES:-}"' in compose, "Compose must carry raw profile selection to the entrypoint guard")
    launcher = (ROOT / "tools/release/c028_compose.py").read_text(encoding="utf-8")
    for token in ('MODES = {"full", "solidity"}', 'len(argv) != 1', 'injected != mode', '["docker", "compose", "--profile", mode, "up", "--detach"]', 'child_env["COMPOSE_PROFILES"] = mode'):
        require(token in launcher, f"supported Compose launcher lacks structural single-mode control: {token}")
    entrypoint = (ROOT / "rust-tron/packaging/container/entrypoint.sh").read_text(encoding="utf-8")
    require('multiple or unknown Compose profiles are forbidden' in entrypoint and 'fullnode:full|solidity:solidity' in entrypoint, "entrypoint lacks raw dual-profile and mode-match guard")
    deployment = (ROOT / "docs/operations/c028-deployment.md").read_text(encoding="utf-8")
    for command in ("python3 tools/release/c028_compose.py full", "python3 tools/release/c028_compose.py solidity"):
        require(command in deployment, f"deployment documentation lacks supported launcher command: {command}")
    require("docker compose --profile" not in deployment, "deployment documentation must not advertise raw profile invocation")
    drill = (ROOT / "tools/release/c028_cases/container.py").read_text(encoding="utf-8")
    for token in ('("zero", [], None)', '("dual", ["full", "solidity"], None)', '("dual_injection", ["full"], "full,solidity")', '[sys.executable, str(launcher), profile]', 'running_services != [mode]', 'live_surfaces != expected_surfaces'):
        require(token in drill, f"container drill lacks guarded launcher assertion: {token}")
    require('[*base, "up", "--detach"]' not in drill, "container drill must start production modes through the supported launcher")
    return {"compose_profiles": ["full", "solidity"], "compose_default": "reject_before_docker", "launcher": "tools/release/c028_compose.py"}


def verify_snapshot_checkpoint_policy() -> dict:
    for name in ("fullnode.deployment.json", "solidity.deployment.json"):
        policy = load(ROOT / "rust-tron" / "packaging" / "config" / name)["snapshot_policy"]
        checkpoint = policy["trusted_checkpoint"]
        require(checkpoint["height"] > 0, f"{name}: zero trusted checkpoint height is forbidden")
        require(policy["minimum_acceptable_height"] == checkpoint["height"], f"{name}: packaged minimum height must equal trusted checkpoint height")
        for field in ("block_id", "state_root"):
            value = checkpoint[field]
            require(re.fullmatch(r"[0-9a-fA-F]{64}", value) is not None and int(value, 16) != 0, f"{name}: placeholder trusted checkpoint {field} is forbidden")
    source = (ROOT / "rust-tron/crates/tron-node/src/snapshot_trust.rs").read_text(encoding="utf-8")
    require("manifest.height != checkpoint.height" in source, "snapshot verifier must require exact checkpoint height")
    require("verify_dsse_scoped" in source and 'format!("snapshot:{}", descriptor.identity.network)' in source, "snapshot verifier must enforce canonical network scope")
    deployment_tests = (ROOT / "rust-tron/crates/tron-node/tests/c028_deployment.rs").read_text(encoding="utf-8")
    for symbol in ("matching_snapshot_role_with_wrong_scope_is_rejected", "signed_cross_network_snapshot_role_cannot_authorize_mainnet_import"):
        require(symbol in deployment_tests, f"snapshot scope mutation test missing: {symbol}")
    require("manifest.block_id != checkpoint.block_id" in source and "manifest.state_root != checkpoint.state_root" in source, "snapshot verifier must require exact checkpoint identity")
    return {"snapshot_checkpoint_policy": "exact-independent-tuple"}

def verify_runtime() -> dict:
    runtime_env = dict(os.environ)
    if not runtime_env.get("TRON_BUSYBOX"):
        busybox = Path("/usr/bin/busybox")
        require(busybox.is_file() and not busybox.is_symlink(), "canonical C028 gate requires repository-policy-matching /usr/bin/busybox or explicit TRON_BUSYBOX")
        runtime_env["TRON_BUSYBOX"] = str(busybox)
    subprocess.run(["python3", "tools/release/c028_release.py", "self-check"], cwd=ROOT, env=runtime_env, check=True)
    subprocess.run(["python3", "tools/release/c028_drills.py", "self-check"], cwd=ROOT, env=runtime_env, check=True)
    with tempfile.TemporaryDirectory(prefix="c028-native-gate-") as directory:
        root = Path(directory)
        release = root / "release"
        subprocess.run(["python3", "tools/release/c028_release.py", "build", "--out", str(release)], cwd=ROOT, env=runtime_env, check=True)
        completed=subprocess.run(["python3","tools/release/c028_drills.py","drills","--command-manifest","docs/oracles/c028-command-manifest.v1.json","--candidate-dir",str(release)],cwd=ROOT,env=runtime_env,check=True,text=True,stdout=subprocess.PIPE)
        drill_result=json.loads(completed.stdout.strip().splitlines()[-1])
        executed=drill_result.get("results",[])
        require(len(executed)==44 and {row.get("scenario") for row in executed}=={row["id"] for row in load(ORACLES/"c028-command-manifest.v1.json")["commands"]}, "canonical all did not execute 44/44 scenarios")
        bundle=release/"bundle"
        for binary in ("tron-fullnode","tron-solidity","tron-toolkit","tron-release-verify"):
            require((bundle/"bin"/binary).is_file() and (bundle/"bin"/binary).stat().st_mode & 0o111, f"clean candidate lacks executable bin/{binary}")
        require((bundle/"tron-config.tar.gz").is_file() and (bundle/"index.json").is_file() and (bundle/"oci-layout").is_file(), "clean candidate lacks packaged config/conforming OCI layout")
        import importlib.util
        release_spec=importlib.util.spec_from_file_location("c028_release_runtime",ROOT/"tools/release/c028_release.py")
        release_module=importlib.util.module_from_spec(release_spec); release_spec.loader.exec_module(release_module)
        release_module.validate_oci_layout(bundle)
        spec=importlib.util.spec_from_file_location("c028_drills_runtime",ROOT/"tools/release/c028_drills.py")
        drills=importlib.util.module_from_spec(spec); spec.loader.exec_module(drills)
        clean_install=drills.authenticated_clean_install(ROOT,release)
    return {"runtime": "passed", "native_builds": 2, "executed_drills": len(executed), "clean_install": clean_install}

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("metadata", "all"), default="all", nargs="?")
    args = parser.parse_args()
    verify_registry()
    result = {**verify_schemas(), **verify_ownership(), **verify_drills(), **verify_mutation_guards(), **verify_release_contract(), **verify_compose_contract(), **verify_snapshot_checkpoint_policy()}
    if args.command == "all":
        result.update(verify_runtime())
    print(json.dumps({"schema": "c028-gate-result-v1", **result}, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
