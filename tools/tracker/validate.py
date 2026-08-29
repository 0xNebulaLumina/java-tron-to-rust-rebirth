#!/usr/bin/env python3
"""Dependency-free governance validator; it reports state and never mutates it."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TRACKER = ROOT / "docs/PORTING_TRACKER.json"
CHECKLIST = ROOT / "docs/PORTING_CHECKLIST.md"
ITEM_ID = r"C\d{3}\.(?:\d{2}[A-Z]?|V)"
ITEM = re.compile(rf"^- \[( |-|x|D)\] \*\*({ITEM_ID})\*\*")
DEPS = re.compile(r'^  \*\*dependencies\[\]:\*\* `(\[.*\])`$')
EV_ID = re.compile(r"^EV-[0-9]{4,}$")
RV_ID = re.compile(r"^RV-[0-9]{4,}$")
C000_TARGETS = {f"C000.{n:02d}" for n in range(10, 16)}
TODAY = dt.date.today()


def load(path: Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def fail(errors: list[str], message: str):
    errors.append(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def repository_revision(errors: list[str]) -> str | None:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, text=True, capture_output=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        fail(errors, f"cannot resolve repository revision: {exc}")
        return None


def checklist_projection(errors: list[str]):
    rows, pending = {}, None
    for number, line in enumerate(CHECKLIST.read_text(encoding="utf-8").splitlines(), 1):
        item = ITEM.match(line)
        if item:
            pending = (item.group(2), f"[{item.group(1)}]", number)
            continue
        dep = DEPS.match(line)
        if dep and pending:
            ident, status, item_line = pending
            if ident in rows:
                fail(errors, f"checklist:{item_line}: duplicate {ident}")
            try:
                dependencies = json.loads(dep.group(1))
            except json.JSONDecodeError as exc:
                fail(errors, f"checklist:{number}: invalid dependencies JSON: {exc}")
                dependencies = []
            rows[ident] = (status, dependencies)
            pending = None
    if pending:
        fail(errors, f"checklist:{pending[2]}: missing dependencies[] for {pending[0]}")
    return rows


def graph_contract(tracker, projection, errors):
    records = tracker.get("records")
    if not isinstance(records, list):
        fail(errors, "tracker records must be an array")
        return {}, {}
    by_id, edge_count = {}, 0
    for index, record in enumerate(records):
        ident = record.get("id")
        if not isinstance(ident, str) or not re.fullmatch(ITEM_ID, ident):
            fail(errors, f"records[{index}]: invalid id")
            continue
        if ident in by_id:
            fail(errors, f"duplicate tracker record {ident}")
        by_id[ident] = record
        dependencies = record.get("dependencies")
        if not isinstance(dependencies, list):
            fail(errors, f"{ident}: dependencies must be an explicit array")
            continue
        edge_count += len(dependencies)
        if len(dependencies) != len(set(dependencies)):
            fail(errors, f"{ident}: duplicate dependency")
        if ident in dependencies:
            fail(errors, f"{ident}: self dependency")
        if record.get("status") not in {"[ ]", "[-]", "[x]", "[D]"}:
            fail(errors, f"{ident}: illegal status")
        if record.get("readiness") not in {"ready", "blocked"}:
            fail(errors, f"{ident}: illegal readiness")
    unknown = duplicate = self_edges = 0
    for ident, record in by_id.items():
        dependencies = record.get("dependencies", [])
        duplicate += len(dependencies) - len(set(dependencies))
        self_edges += ident in dependencies
        for dependency in dependencies:
            if dependency not in by_id:
                unknown += 1
                fail(errors, f"{ident}: unknown dependency {dependency}")
        projected = projection.get(ident)
        if projected is None:
            fail(errors, f"{ident}: missing checklist projection")
        elif projected != (record.get("status"), dependencies):
            fail(errors, f"{ident}: checklist status/dependencies mismatch")
    for ident in projection.keys() - by_id.keys():
        fail(errors, f"{ident}: checklist record missing from tracker")
    state, cycles = {}, set()
    def visit(ident):
        if state.get(ident) == 1:
            cycles.add(ident)
            return
        if state.get(ident) == 2:
            return
        state[ident] = 1
        for dep in by_id[ident].get("dependencies", []):
            if dep in by_id:
                visit(dep)
        state[ident] = 2
    for ident in by_id:
        visit(ident)
    for ident in sorted(cycles):
        fail(errors, f"cycle includes {ident}")
    missing_children = 0
    chunks = {}
    for record in by_id.values():
        chunks.setdefault(record.get("chunk"), []).append(record)
    for chunk, rows in chunks.items():
        gate = by_id.get(f"{chunk}.V")
        children = {row["id"] for row in rows if row.get("kind") == "substantive"}
        missing = children - set(gate.get("dependencies", []) if gate else [])
        missing_children += len(missing)
        if missing:
            fail(errors, f"{chunk}.V: missing substantive child dependencies: {sorted(missing)}")
    stats = {"records": len(by_id), "projection_records": len(projection), "edges": edge_count, "unknown_edges": unknown, "duplicate_edges": duplicate, "self_edges": self_edges, "cycle_records": len(cycles), "v_missing_children": missing_children, "roots": sorted(ident for ident, row in by_id.items() if not row.get("dependencies"))}
    return by_id, stats


def artifact_ok(entry, label: str, errors: list[str]) -> bool:
    if not isinstance(entry, dict):
        fail(errors, f"{label}: malformed artifact reference: expected object")
        return False
    path_value = entry.get("path")
    sha256 = entry.get("sha256")
    if not isinstance(path_value, str) or not path_value:
        fail(errors, f"{label}: malformed artifact reference: path must be a non-empty string")
        return False
    if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256):
        fail(errors, f"{label}: malformed artifact reference: sha256 must be 64 lowercase hex characters")
        return False
    path = ROOT / path_value
    if not path.is_file():
        fail(errors, f"{label}: missing artifact {path_value}")
        return False
    actual = digest(path)
    if actual != sha256:
        fail(errors, f"{label}: digest drift for {path_value}")
        return False
    return True


def evidence_contract(revision: str | None, by_id, errors: list[str]):
    records, valid = {}, set()
    required = {"schema_version", "evidence_id", "owning_item", "command", "environment", "run_id", "cases", "started_at", "ended_at", "observed_exit_code", "observed_status", "expected", "observed", "stdout", "stderr", "artifacts", "invalidation_edges", "review_bindings", "retention_until"}
    environment_fields = {"repository_revision", "tree_state", "toolchains", "platform_row", "target", "host_os", "host_architecture", "execution", "working_directory", "cells", "backend", "features"}
    for path in sorted((ROOT / "docs/governance/evidence").glob("*.json")):
        before = len(errors)
        try:
            ev = load(path)
        except (OSError, json.JSONDecodeError) as exc:
            fail(errors, f"{path.relative_to(ROOT)}: invalid JSON: {exc}")
            continue
        if not isinstance(ev, dict):
            fail(errors, f"{path.relative_to(ROOT)}: evidence must be an object")
            continue
        ident = ev.get("evidence_id")
        if not isinstance(ident, str) or not EV_ID.fullmatch(ident) or path.stem != ident:
            fail(errors, f"{path.relative_to(ROOT)}: invalid evidence identity")
            continue
        if ident in records:
            fail(errors, f"duplicate evidence {ident}")
        records[ident] = ev
        missing, unknown = required - ev.keys(), set(ev) - required
        if ev.get("schema_version") != 1 or missing or unknown:
            fail(errors, f"{ident}: schema fields invalid; missing={sorted(missing)} unknown={sorted(unknown)}")
        owner = ev.get("owning_item")
        if owner not in by_id:
            fail(errors, f"{ident}: unknown owning item {owner}")
        command = ev.get("command")
        if not isinstance(command, list) or not command or not all(isinstance(arg, str) and arg for arg in command):
            fail(errors, f"{ident}: command must be a non-empty string array")
        environment = ev.get("environment")
        if not isinstance(environment, dict) or set(environment) != environment_fields:
            fail(errors, f"{ident}: environment schema fields invalid")
            environment = {}
        if revision and environment.get("repository_revision") != revision:
            fail(errors, f"{ident}: repository revision is stale")
        if environment.get("tree_state") not in {"clean", "dirty"} or not isinstance(environment.get("toolchains"), dict) or not environment.get("toolchains"):
            fail(errors, f"{ident}: invalid tree state/toolchain binding")
        features = environment.get("features")
        if not isinstance(features, list) or not all(isinstance(feature, str) for feature in features) or len(features) != len(set(features)):
            fail(errors, f"{ident}: invalid feature binding")
        cells = environment.get("cells")
        cells_valid = isinstance(cells, list) and all(isinstance(cell, str) and cell in {"compile", "differential", "unit", "native_resource", "ffi", "packaging", "smoke"} for cell in cells) and len(cells) == len(set(cells))
        if not cells_valid or (owner == "C000.14" and not cells):
            fail(errors, f"{ident}: invalid platform cell binding")
        if environment.get("execution") != "native" or not all(isinstance(environment.get(field), str) and environment[field] for field in ("target", "host_os", "host_architecture", "working_directory", "platform_row", "backend")):
            fail(errors, f"{ident}: invalid target/native host/working-directory binding")
        bindings = ev.get("review_bindings")
        if not isinstance(bindings, list) or not all(isinstance(binding, str) and RV_ID.fullmatch(binding) for binding in bindings) or len(bindings) != len(set(bindings)):
            fail(errors, f"{ident}: invalid review bindings")
        try:
            started = dt.datetime.fromisoformat(ev["started_at"].replace("Z", "+00:00"))
            ended = dt.datetime.fromisoformat(ev["ended_at"].replace("Z", "+00:00"))
            if ended < started:
                fail(errors, f"{ident}: evidence ends before it starts")
        except (KeyError, AttributeError, TypeError, ValueError):
            fail(errors, f"{ident}: invalid evidence timestamps")
        try:
            if dt.date.fromisoformat(ev["retention_until"]) < TODAY:
                fail(errors, f"{ident}: retention expired")
        except (KeyError, TypeError, ValueError):
            fail(errors, f"{ident}: invalid retention date")
        for name in ("stdout", "stderr"):
            artifact_ok(ev.get(name), f"{ident}.{name}", errors)
        artifacts = ev.get("artifacts")
        if not isinstance(artifacts, list):
            fail(errors, f"{ident}: artifacts must be an array")
            artifacts = []
        for index, artifact in enumerate(artifacts):
            artifact_ok(artifact, f"{ident}.artifacts[{index}]", errors)
        edges = ev.get("invalidation_edges")
        if not isinstance(edges, list) or not edges:
            fail(errors, f"{ident}: invalidation_edges must be non-empty")
            edges = []
        for index, edge in enumerate(edges):
            if not isinstance(edge, dict) or set(edge) != {"kind", "identity", "sha256"} or edge.get("kind") not in {"source", "schema", "config", "fixture", "dependency", "toolchain", "generator", "normalization", "platform-manifest"}:
                fail(errors, f"{ident}.invalidation_edges[{index}]: schema invalid")
                continue
            artifact_ok({"path": edge.get("identity"), "sha256": edge.get("sha256")}, f"{ident}.invalidation_edges[{index}]", errors)
        cases = ev.get("cases")
        if not isinstance(cases, list) or not cases:
            fail(errors, f"{ident}: no cases")
            cases = []
        case_ids = []
        for index, case in enumerate(cases):
            if not isinstance(case, dict) or set(case) != {"id", "outcome", "expected", "observed", "skip_disposition"}:
                fail(errors, f"{ident}.cases[{index}]: schema invalid")
                continue
            case_ids.append(case.get("id"))
            if case.get("outcome") not in {"pass", "fail", "skip"}:
                fail(errors, f"{ident}:{case.get('id')}: invalid outcome")
            if case.get("outcome") == "skip":
                disposition = case.get("skip_disposition")
                if not isinstance(disposition, dict) or set(disposition) != {"status", "reason", "owner", "unblock_condition", "review_by"} or disposition.get("status") not in {"deferred", "unavailable", "not-applicable"}:
                    fail(errors, f"{ident}:{case.get('id')}: ungoverned skip")
            elif case.get("skip_disposition") is not None:
                fail(errors, f"{ident}:{case.get('id')}: unexpected skip disposition")
        if len(case_ids) != len(set(case_ids)):
            fail(errors, f"{ident}: duplicate case id")
        if ev.get("observed_status") not in {"pass", "fail"} or not isinstance(ev.get("observed_exit_code"), int):
            fail(errors, f"{ident}: invalid observed result")
        if ev.get("observed_status") == "pass" and (ev.get("observed_exit_code") != 0 or any(case.get("outcome") != "pass" for case in cases)):
            fail(errors, f"{ident}: pass status contradicts exit/case outcome")
        if len(errors) == before:
            valid.add(ident)
    return records, valid


def review_contract(revision: str | None, by_id, evidence, valid_evidence, errors: list[str]):
    records, valid = {}, set()
    required = {"schema_version", "review_id", "owning_gate", "review_class", "scope_rows", "seam_rows", "covered_revisions", "covered_artifacts", "reviewers", "findings", "reruns", "closure", "retention_until", "invalidation_triggers"}
    for path in sorted((ROOT / "docs/governance/reviews").glob("*.json")):
        before = len(errors)
        try:
            review = load(path)
        except (OSError, json.JSONDecodeError) as exc:
            fail(errors, f"{path.relative_to(ROOT)}: invalid JSON: {exc}")
            continue
        if not isinstance(review, dict):
            fail(errors, f"{path.relative_to(ROOT)}: review must be an object")
            continue
        ident = review.get("review_id")
        if not isinstance(ident, str) or not RV_ID.fullmatch(ident) or path.stem != ident:
            fail(errors, f"{path.relative_to(ROOT)}: invalid review identity")
            continue
        if ident in records:
            fail(errors, f"duplicate review {ident}")
        records[ident] = review
        if review.get("schema_version") != 1 or required - review.keys() or set(review) - required:
            fail(errors, f"{ident}: schema version/fields invalid")
        gate = review.get("owning_gate")
        if gate not in by_id or not isinstance(gate, str) or not gate.endswith(".V"):
            fail(errors, f"{ident}: invalid owning gate")
        if review.get("review_class") not in {"architecture", "security", "license"}:
            fail(errors, f"{ident}: invalid review class")
        for field in ("scope_rows", "seam_rows", "reruns", "invalidation_triggers"):
            value = review.get(field)
            strings = isinstance(value, list) and all(isinstance(entry, str) and entry for entry in value)
            if not strings or (field in {"scope_rows", "invalidation_triggers"} and not value) or (strings and len(value) != len(set(value))):
                fail(errors, f"{ident}: invalid {field}")
        if isinstance(review.get("scope_rows"), list) and any(row not in by_id for row in review["scope_rows"]):
            fail(errors, f"{ident}: scope contains unknown tracker row")
        covered = review.get("covered_revisions")
        if not isinstance(covered, dict) or set(covered) != {"repository"} or (revision and covered.get("repository") != revision):
            fail(errors, f"{ident}: covered revision is stale or malformed")
        artifacts = review.get("covered_artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            fail(errors, f"{ident}: covered_artifacts must be non-empty")
            artifacts = []
        for index, artifact in enumerate(artifacts):
            artifact_ok(artifact, f"{ident}.covered_artifacts[{index}]", errors)
        reviewers = review.get("reviewers")
        if not isinstance(reviewers, list) or not reviewers:
            fail(errors, f"{ident}: reviewers must be a non-empty array")
            reviewers = []
        identities = []
        for index, reviewer in enumerate(reviewers):
            if not isinstance(reviewer, dict) or set(reviewer) != {"identity", "role", "independent_of_authors", "conflicts", "recusals"} or reviewer.get("independent_of_authors") is not True or reviewer.get("role") not in {"primary", "secondary", "security", "license", "closure"} or not isinstance(reviewer.get("conflicts"), list) or not isinstance(reviewer.get("recusals"), list):
                fail(errors, f"{ident}.reviewers[{index}]: schema/independence invalid")
                continue
            identities.append(reviewer.get("identity"))
        if len(identities) != len(set(identities)):
            fail(errors, f"{ident}: duplicate reviewer identity")
        rerun_values = review.get("reruns", [])
        reruns = set(rerun_values) if isinstance(rerun_values, list) and all(isinstance(value, str) for value in rerun_values) else set()
        for rerun in reruns:
            if rerun not in evidence:
                fail(errors, f"{ident}: unknown rerun evidence {rerun}")
            elif rerun not in valid_evidence or evidence[rerun].get("observed_status") != "pass":
                fail(errors, f"{ident}: rerun evidence is not current and passing: {rerun}")
        findings = review.get("findings")
        if not isinstance(findings, list):
            fail(errors, f"{ident}: findings must be an array")
            findings = []
        finding_ids = []
        for index, finding in enumerate(findings):
            fields = {"id", "severity", "disposition", "fix_revision", "required_rerun_ids"}
            if not isinstance(finding, dict) or set(finding) != fields:
                fail(errors, f"{ident}.findings[{index}]: schema invalid")
                continue
            finding_ids.append(finding.get("id"))
            required_reruns = set(finding.get("required_rerun_ids", [])) if isinstance(finding.get("required_rerun_ids"), list) else set()
            if not required_reruns.issubset(reruns):
                fail(errors, f"{ident}:{finding.get('id')}: required rerun is not review-bound")
        if len(finding_ids) != len(set(finding_ids)):
            fail(errors, f"{ident}: duplicate finding id")
        closure = review.get("closure")
        if not isinstance(closure, dict) or set(closure) != {"status", "reviewer", "date", "approval"} or closure.get("status") not in {"pending", "approved", "rejected"}:
            fail(errors, f"{ident}: closure schema invalid")
            closure = {}
        if closure.get("status") == "approved":
            if closure.get("approval") is not True or closure.get("reviewer") not in identities or not reviewers:
                fail(errors, f"{ident}: approval lacks independent registered closure")
            if any(f.get("disposition") != "fixed" or f.get("fix_revision") != revision or not f.get("required_rerun_ids") for f in findings):
                fail(errors, f"{ident}: approved review has unresolved or stale findings")
        elif closure.get("approval") is not False:
            fail(errors, f"{ident}: non-approved closure claims approval")
        try:
            if dt.date.fromisoformat(review["retention_until"]) < TODAY:
                fail(errors, f"{ident}: retention expired")
        except (KeyError, TypeError, ValueError):
            fail(errors, f"{ident}: invalid retention date")
        if len(errors) == before:
            valid.add(ident)
    return records, valid


def platform_contract(revision, evidence, valid_evidence, reviews, valid_reviews, errors: list[str]) -> bool:
    manifest = load(ROOT / "docs/architecture/platform-manifest.v1.json")
    expected_initial = {"P-LINUX-X64"}
    expected_reserved = {"P-LINUX-ARM64", "P-MACOS-X64", "P-MACOS-ARM64"}
    rows = manifest.get("rows", [])
    reserved_rows = manifest.get("planned_platform_enablement", [])
    ids = [row.get("id") for row in rows]
    reserved_ids = [row.get("id") for row in reserved_rows]
    initial_ids = {row.get("id") for row in rows if row.get("support") == "initial"}
    required = set(manifest.get("cell_contract", {}).get("required", []))
    if manifest.get("schema_version") != 1 or manifest.get("repository_revision") != revision:
        fail(errors, "platform manifest schema/repository revision is stale")
    if initial_ids != expected_initial or set(ids) != expected_initial or len(ids) != len(expected_initial):
        fail(errors, "platform manifest must contain the initial Linux x86_64 policy row exactly once")
    if set(reserved_ids) != expected_reserved or len(reserved_ids) != len(expected_reserved) or any(row.get("support") != "reserved_later_enablement" or row.get("c000_blocker") is not False for row in reserved_rows):
        fail(errors, "platform manifest must contain each non-blocking reserved later-enablement row exactly once")
    if required != {"compile", "differential", "unit", "native_resource", "ffi", "packaging", "smoke"}:
        fail(errors, "platform manifest cell contract is incomplete")
    feature_sets = manifest.get("feature_sets", [])
    features_by_id = {entry.get("id"): entry.get("features") for entry in feature_sets if isinstance(entry, dict)}
    if features_by_id.get("F-PRODUCTION-DEFAULT") != []:
        fail(errors, "F-PRODUCTION-DEFAULT must match the Cargo workspace's empty declared feature set")
    backends = {entry.get("id") for entry in manifest.get("backend_sets", []) if isinstance(entry, dict)}
    complete = True
    passing_count = 0
    reviewed_not_applicable_count = 0
    runner = ROOT / manifest.get("runner", "")
    if not runner.is_file() or not runner.stat().st_mode & 0o111:
        fail(errors, "platform runner is missing or not executable")
        complete = False
    for row in rows:
        if not isinstance(row, dict):
            fail(errors, "platform manifest row must be an object")
            complete = False
            continue
        row_id = row.get("id")
        cells = row.get("cells", {})
        if not isinstance(cells, dict):
            fail(errors, f"{row_id}: cells must be an object")
            complete = False
            continue
        row_features = features_by_id.get(row.get("feature_set"))
        if row.get("support") != "initial" or row.get("execution") != "native" or row.get("backend") not in backends or row_features is None:
            fail(errors, f"{row_id}: invalid initial/native/backend/feature binding")
            complete = False
        if set(cells) != required:
            fail(errors, f"{row_id}: incomplete cell matrix")
            complete = False
        for cell_name, cell in cells.items():
            label = f"{row_id}.{cell_name}"
            if not isinstance(cell, dict):
                fail(errors, f"{label}: cell must be an object")
                complete = False
                continue
            disposition = cell.get("disposition")
            refs = cell.get("evidence")
            refs_valid = isinstance(refs, list) and all(isinstance(ref, str) for ref in refs)
            if disposition not in {"runnable", "deferred", "unavailable", "not_applicable"} or not refs_valid or (refs_valid and len(refs) != len(set(refs))):
                fail(errors, f"{label}: invalid disposition/evidence list")
                complete = False
                continue
            argv = cell.get("argv")
            if disposition == "runnable":
                cwd = cell.get("cwd")
                executable = argv[0] if isinstance(argv, list) and argv else None
                if not executable or not all(isinstance(arg, str) and arg for arg in argv) or not isinstance(cwd, str) or not (ROOT / cwd).is_dir() or ("/" in executable and not (ROOT / executable).is_file()) or ("/" not in executable and shutil.which(executable) is None):
                    fail(errors, f"{label}: runnable command/cwd does not exist")
                    complete = False
            elif not isinstance(cell.get("reason"), str) or not cell.get("reason"):
                fail(errors, f"{label}: governed disposition lacks reason")
                complete = False
            else:
                availability = row.get("availability")
                row_unblock = availability.get("unblock_condition") if isinstance(availability, dict) else None
                if disposition != "not_applicable" and not (cell.get("unblock_condition") or row_unblock):
                    fail(errors, f"{label}: blocking disposition lacks unblock condition")
                    complete = False
            passing = False
            if disposition == "runnable":
                for ref in refs:
                    if not EV_ID.fullmatch(ref):
                        fail(errors, f"{label}: invalid evidence id {ref!r}")
                        continue
                    ev = evidence.get(ref)
                    if not isinstance(ev, dict):
                        fail(errors, f"{label}: unknown evidence {ref}")
                        continue
                    environment = ev.get("environment")
                    if not isinstance(environment, dict):
                        environment = {}
                    executable = argv[0] if isinstance(argv, list) and argv else None
                    required_tools = {"cargo", "rustc"} if executable == "cargo" else {"python"}
                    expected_cwd = cell.get("cwd", ".")
                    toolchains = environment.get("toolchains")
                    bound = ref in valid_evidence and ev.get("owning_item") == "C000.14" and ev.get("observed_status") == "pass" and ev.get("command") == argv and environment.get("platform_row") == row_id and environment.get("target") == row.get("target") and environment.get("host_os") == row.get("os") and environment.get("host_architecture") == row.get("architecture") and environment.get("execution") == "native" and environment.get("working_directory") == expected_cwd and environment.get("backend") == row.get("backend") and environment.get("features") == row_features and cell_name in environment.get("cells", []) and isinstance(toolchains, dict) and required_tools.issubset(toolchains)
                    if not bound:
                        fail(errors, f"{label}: evidence {ref} lacks full command/target/native/toolchain/backend/feature/cell binding")
                    passing |= bound
            if disposition == "not_applicable":
                review_refs = cell.get("review_bindings")
                refs_well_formed = isinstance(review_refs, list) and bool(review_refs) and all(isinstance(ref, str) and RV_ID.fullmatch(ref) for ref in review_refs)
                reviewed = refs_well_formed and len(review_refs) == len(set(review_refs))
                for ref in review_refs if refs_well_formed else []:
                    review = reviews.get(ref)
                    closure = review.get("closure") if isinstance(review, dict) else None
                    reviewed &= ref in valid_reviews and isinstance(closure, dict) and review.get("owning_gate") == "C000.V" and closure.get("status") == "approved" and closure.get("approval") is True
                reviewed &= not refs
                if not reviewed or not all(isinstance(cell.get(field), str) and cell[field] for field in ("review_scope", "reopen_condition")):
                    fail(errors, f"{label}: not_applicable disposition lacks approved bound review/reopen contract")
                passing = reviewed
                if passing:
                    reviewed_not_applicable_count += 1
            elif disposition == "runnable" and passing:
                passing_count += 1
            if disposition not in {"runnable", "not_applicable"} or not passing:
                complete = False
    computed = {"initial_supported_rows": len(expected_initial), "manifest_rows": len(rows), "reserved_later_rows": len(reserved_rows), "missing_initial_rows": len(expected_initial - initial_ids), "duplicates": len(ids) - len(set(ids)), "native_cells_required": len(expected_initial) * len(required), "native_cells_passing": passing_count, "reviewed_not_applicable_cells": reviewed_not_applicable_count, "result": "complete" if complete else "incomplete"}
    if manifest.get("coverage") != computed:
        fail(errors, f"platform coverage is stale; computed {computed}")
    return complete

def adoption_contract(by_id, errors: list[str]):
    decisions = load(ROOT / "docs/governance/dependency-decisions.v1.json")
    decision_rows = decisions.get("decisions", []) if isinstance(decisions, dict) else []
    decision_ids = {entry.get("id") for entry in decision_rows if isinstance(entry, dict) and re.fullmatch(r"DD-[0-9]{3}", str(entry.get("id", "")))}
    if not isinstance(decision_rows, list) or len(decision_ids) != len(decision_rows):
        fail(errors, "dependency decisions contain malformed or duplicate IDs")
    adoption = load(ROOT / "docs/governance/adoption-inventory.v1.json")
    sources = adoption.get("generated_from", []) if isinstance(adoption, dict) else []
    if not isinstance(sources, list):
        fail(errors, "adoption inventory: generated_from must be an array")
        sources = []
    for index, source in enumerate(sources):
        artifact_ok(source, f"dependency inventory input[{index}]", errors)
    instances = adoption.get("instances", []) if isinstance(adoption, dict) else []
    if not isinstance(instances, list):
        fail(errors, "adoption inventory: instances must be an array")
        instances = []
    records, valid = {}, set()
    for index, instance in enumerate(instances):
        before = len(errors)
        if not isinstance(instance, dict):
            fail(errors, f"adoption inventory instance[{index}]: expected object")
            continue
        ident = instance.get("id")
        label = ident if isinstance(ident, str) else f"adoption inventory instance[{index}]"
        if not isinstance(ident, str) or not re.fullmatch(r"AD-[0-9]{4,}", ident) or ident in records:
            fail(errors, f"{label}: invalid or duplicate adoption id")
        records[ident] = instance
        consumer, gate = instance.get("consuming_item"), instance.get("local_gate")
        if consumer not in by_id or gate not in by_id or not isinstance(gate, str) or not gate.endswith(".V"):
            fail(errors, f"{label}: invalid consumer/local gate binding")
        if instance.get("decision") not in decision_ids:
            fail(errors, f"{label}: unknown dependency decision")
        for field in ("security", "license"):
            disposition = instance.get(field)
            if not isinstance(disposition, dict) or disposition.get("status") not in {"approved", "not_applicable", "recorded", "review_required", "rejected"} or not isinstance(disposition.get("rationale"), str) or not disposition.get("rationale"):
                fail(errors, f"{label}: malformed {field} disposition")
        if instance.get("status") not in {"recorded", "review_required", "approved", "rejected", "retired"}:
            fail(errors, f"{label}: invalid adoption status")
        source = instance.get("source")
        exact = instance.get("exact_version")
        if isinstance(source, str) and (ROOT / source).is_file() and isinstance(exact, str) and exact.startswith("sha256:") and exact[7:] != digest(ROOT / source):
            fail(errors, f"{label}: source digest drift")
        if len(errors) == before and instance.get("status") in {"recorded", "approved"} and all(instance[field]["status"] in {"approved", "not_applicable"} for field in ("security", "license")):
            valid.add(ident)
    return records, valid


def artifact_contract(by_id, revision, errors):
    predicates = {"ledger": True, "projection": True}
    seams = load(ROOT / "docs/architecture/cross-domain-seams.v1.json")
    ids = [row.get("id") for row in seams.get("rows", [])]
    if len(ids) != len(set(ids)):
        fail(errors, "duplicate seam id")
    for row in seams.get("rows", []):
        ownership = all(isinstance(row.get(field), str) and row.get(field).strip() for field in ("primary", "secondary"))
        if not ownership or row.get("review_gate") not in by_id:
            fail(errors, f"{row.get('id')}: incomplete/unknown seam ownership")
    for name in ("production-ownership.v1.json", "java-test-ownership.v1.json"):
        ledger = load(ROOT / "docs/oracles" / name)
        rows = ledger.get("rows", [])
        ok = isinstance(rows, list) and ledger.get("row_count") == len(rows) and ledger.get("java_source_revision") == revision and ledger.get("regeneration", {}).get("unknown_policy") == "fail"
        row_ids = [row.get("id") for row in rows if isinstance(row, dict)]
        ok &= len(row_ids) == len(rows) == len(set(row_ids))
        for row in rows:
            if not isinstance(row, dict) or row.get("owning_item") not in by_id or row.get("acceptance_gate") not in by_id:
                ok = False
                break
        if not ok:
            fail(errors, f"docs/oracles/{name}: stale or incomplete ownership ledger")
            predicates["ledger"] = False
    oracle_manifest = load(ROOT / "docs/oracles/manifest.v1.json")
    if "C000.V execution and approval not complete" in str(oracle_manifest.get("status", "")):
        predicates["projection"] = False
    for path in (ROOT / "docs").rglob("behavior-manifest*.json"):
        if path.name.endswith(".schema.json"):
            continue
        coverage = load(path).get("coverage", {})
        if coverage.get("result") != "pass" or any(coverage.get(key) != 0 for key in ("unowned", "duplicate_owned", "missing_case", "unknown_owner")):
            fail(errors, f"{path.relative_to(ROOT)}: behavior ownership coverage gap")
            predicates["ledger"] = False
    return predicates


def derived_contract(tracker, by_id, evidence, valid_evidence, reviews, valid_reviews, adoptions, valid_adoptions, platform_complete, predicates, stats, errors):
    effective, visiting = {}, set()
    def completed(ident):
        if ident in effective:
            return effective[ident]
        if ident in visiting:
            return False
        visiting.add(ident)
        row = by_id[ident]
        refs = row.get("evidence")
        if not isinstance(refs, list):
            fail(errors, f"{ident}: evidence must be an exact EV-id array")
            refs = []
        evidence_ok = bool(refs)
        for ref in refs:
            if not isinstance(ref, str) or not EV_ID.fullmatch(ref):
                fail(errors, f"{ident}: invalid evidence reference {ref!r}")
                evidence_ok = False
            elif ref not in evidence:
                fail(errors, f"{ident}: unknown evidence {ref}")
                evidence_ok = False
            elif ref not in valid_evidence or evidence[ref].get("owning_item") != ident or evidence[ref].get("observed_status") != "pass":
                fail(errors, f"{ident}: evidence {ref} is stale, failed, or owned elsewhere")
                evidence_ok = False
        adoption_refs = row.get("adoptions", [])
        adoption_ok = isinstance(adoption_refs, list)
        for ref in adoption_refs if isinstance(adoption_refs, list) else []:
            if ref not in adoptions:
                fail(errors, f"{ident}: unknown adoption {ref}")
                adoption_ok = False
            elif ref not in valid_adoptions or adoptions[ref].get("consuming_item") != ident:
                fail(errors, f"{ident}: adoption {ref} is unapproved, stale, or owned elsewhere")
                adoption_ok = False
        deps_ok = all(completed(dep) for dep in row.get("dependencies", []) if dep in by_id)
        gate_ok = True
        if ident in {"C000.08", "C000.09"}:
            gate_ok &= predicates["ledger"]
        if ident == "C000.14":
            gate_ok &= platform_complete
        if ident == "C000.V":
            approved = {review.get("review_class") for ref, review in reviews.items() if ref in valid_reviews and review.get("owning_gate") == ident and review.get("closure", {}).get("status") == "approved" and review.get("closure", {}).get("approval")}
            gate_ok &= approved == {"architecture", "security", "license"} and platform_complete and predicates["ledger"] and predicates["projection"]
        effective[ident] = row.get("status") == "[x]" and deps_ok and evidence_ok and adoption_ok and gate_ok
        visiting.remove(ident)
        return effective[ident]
    for ident in by_id:
        completed(ident)
    for ident, row in by_id.items():
        derived = "ready" if all(effective.get(dep, False) for dep in row.get("dependencies", [])) else "blocked"
        if row.get("readiness") != derived:
            fail(errors, f"{ident}: asserted readiness {row.get('readiness')} != derived {derived}")
        if row.get("status") == "[x]" and not effective[ident]:
            fail(errors, f"{ident}: completed without effective current evidence/dependencies/adoptions/gates")
        if row.get("status") in {"[-]", "[x]"} and not row.get("owner"):
            fail(errors, f"{ident}: active/completed state lacks owner")
        if row.get("status") == "[D]":
            blocker = row.get("blocker")
            if not isinstance(blocker, dict) or not all(blocker.get(key) for key in ("owner", "unblock_condition", "decision", "evidence", "review_by")):
                fail(errors, f"{ident}: deferred state lacks governed blocker")
    summary = tracker.get("validation", {})
    for key, value in stats.items():
        if key in summary and summary.get(key) != value:
            fail(errors, f"tracker validation summary {key} is stale")
    if summary.get("result") == "pass" and errors:
        fail(errors, "tracker validation summary claims pass for an invalid state")


def governance_contract(by_id, errors):
    for ident in C000_TARGETS:
        record = by_id.get(ident, {})
        if record.get("owner") != "c000-governance":
            fail(errors, f"{ident}: owner must be c000-governance")
        if record.get("last_updated") != "2026-08-29":
            fail(errors, f"{ident}: last_updated must be 2026-08-29")


def main():
    errors = []
    tracker = load(TRACKER)
    revision = repository_revision(errors)
    projection = checklist_projection(errors)
    by_id, stats = graph_contract(tracker, projection, errors)
    governance_contract(by_id, errors)
    evidence, valid_evidence = evidence_contract(revision, by_id, errors)
    reviews, valid_reviews = review_contract(revision, by_id, evidence, valid_evidence, errors)
    platform_complete = platform_contract(revision, evidence, valid_evidence, reviews, valid_reviews, errors)
    adoptions, valid_adoptions = adoption_contract(by_id, errors)
    predicates = artifact_contract(by_id, revision, errors)
    derived_contract(tracker, by_id, evidence, valid_evidence, reviews, valid_reviews, adoptions, valid_adoptions, platform_complete, predicates, stats, errors)
    report = {"schema_version": 1, "validator": "tools/tracker/validate.py", "repository_revision": revision, "result": "fail" if errors else "pass", "derived": {"platform_complete": platform_complete, "evidence_records": len(evidence), "valid_evidence_records": len(valid_evidence), "review_records": len(reviews), "valid_review_records": len(valid_reviews), "adoption_records": len(adoptions), "valid_adoption_records": len(valid_adoptions), **predicates}, "errors": errors}
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
