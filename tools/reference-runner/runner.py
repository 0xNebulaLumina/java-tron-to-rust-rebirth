#!/usr/bin/env python3
"""Behavior-neutral C000 reference-runner protocol harness."""
import argparse
import copy
import fnmatch
import hashlib
import json
import math
import re
import sys
from pathlib import Path

REVISION = "df50ce9676b94de0b10a605076adfd8728811384"
PROTOCOL = 1
ROOT = Path(__file__).resolve().parents[2]
ORACLES = ROOT / "docs/oracles"
POLICY = ORACLES / "normalization-policy-v1.json"
FIXTURE_SCHEMA = ORACLES / "schemas/oracle-fixture-v1.schema.json"
RESULT_SCHEMA = ORACLES / "schemas/oracle-result-v1.schema.json"


def _unique_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON key: {key}")
        out[key] = value
    return out


def _reject_constant(value):
    raise ValueError(f"non-finite JSON number: {value}")


def load_json(path):
    text = Path(path).read_text(encoding="utf-8") if path else sys.stdin.read()
    return json.loads(text, object_pairs_hook=_unique_object, parse_constant=_reject_constant)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode()


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def identify(kind, implementation, toolchain):
    return {
        "implementation": implementation,
        "java_source_revision": REVISION,
        "runner_protocol": PROTOCOL,
        "toolchain": toolchain,
    }


def _resolve_ref(ref, root):
    if ref.startswith("#/"):
        value = root
        for part in ref[2:].split("/"):
            value = value[part.replace("~1", "/").replace("~0", "~")]
        return value, root
    filename, _, fragment = ref.partition("#")
    document = json.loads((FIXTURE_SCHEMA.parent / filename).read_text(encoding="utf-8"))
    value = document
    if fragment.startswith("/"):
        for part in fragment[1:].split("/"):
            value = value[part.replace("~1", "/").replace("~0", "~")]
    return value, document


def _schema_errors(value, schema, root, pointer=""):
    errors = []
    if "$ref" in schema:
        target, target_root = _resolve_ref(schema["$ref"], root)
        return _schema_errors(value, target, target_root, pointer)
    if "oneOf" in schema:
        matches = [branch for branch in schema["oneOf"] if not _schema_errors(value, branch, root, pointer)]
        if len(matches) != 1:
            errors.append(f"{pointer or '/'}: must match exactly one schema branch")
            return errors
    if "anyOf" in schema and not any(not _schema_errors(value, branch, root, pointer) for branch in schema["anyOf"]):
        errors.append(f"{pointer or '/'}: must match at least one schema branch")
        return errors
    if "const" in schema and value != schema["const"]:
        errors.append(f"{pointer or '/'}: must equal {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{pointer or '/'}: value is not allowed")
    expected_type = schema.get("type")
    type_ok = {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }.get(expected_type, True)
    if not type_ok:
        return errors + [f"{pointer or '/'}: expected {expected_type}"]
    if isinstance(value, str) and "pattern" in schema and re.search(schema["pattern"], value) is None:
        errors.append(f"{pointer or '/'}: string does not match required pattern")
    if isinstance(value, int) and not isinstance(value, bool) and value < schema.get("minimum", value):
        errors.append(f"{pointer or '/'}: integer is below minimum")
    if isinstance(value, dict):
        required = schema.get("required", [])
        for key in required:
            if key not in value:
                errors.append(f"{pointer or '/'}/{key}: required property is missing")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for key in value.keys() - properties.keys():
                errors.append(f"{pointer or '/'}/{key}: additional property is forbidden")
        for key, child in value.items():
            child_schema = properties.get(key, schema.get("additionalProperties"))
            if isinstance(child_schema, dict):
                escaped = key.replace("~", "~0").replace("/", "~1")
                errors.extend(_schema_errors(child, child_schema, root, f"{pointer}/{escaped}"))
    if isinstance(value, list):
        if schema.get("uniqueItems") and len({canonical(item) for item in value}) != len(value):
            errors.append(f"{pointer or '/'}: array items must be unique")
        if isinstance(schema.get("items"), dict):
            for index, child in enumerate(value):
                errors.extend(_schema_errors(child, schema["items"], root, f"{pointer}/{index}"))
    for conditional in schema.get("allOf", []):
        if "if" in conditional:
            branch = conditional.get("then") if not _schema_errors(value, conditional["if"], root, pointer) else conditional.get("else")
            if branch:
                errors.extend(_schema_errors(value, branch, root, pointer))
        else:
            errors.extend(_schema_errors(value, conditional, root, pointer))
    if "not" in schema and not _schema_errors(value, schema["not"], root, pointer):
        errors.append(f"{pointer or '/'}: forbidden schema matched")
    return errors


def validate_schema(value, path):
    schema = json.loads(path.read_text(encoding="utf-8"))
    return _schema_errors(value, schema, schema)


def _invariant_errors(value, fixture=False):
    target = value["expected"] if fixture else value
    errors = []
    status, error, exit_code = target["status"], target.get("error"), target["exit_code"]
    if status == "ok" and (error is not None or exit_code != 0):
        errors.append("ok status requires null error and exit_code 0")
    if status == "error" and (error is None or exit_code != 10):
        errors.append("error status requires a typed error and exit_code 10")
    if status == "invalid_fixture" and (error is None or error.get("code") != "INVALID_FIXTURE" or exit_code != 64):
        errors.append("invalid_fixture requires INVALID_FIXTURE error and exit_code 64")
    for field in ("state_deltas", "events", "logs"):
        sequences = [row["sequence"] for row in target[field]]
        if sequences != list(range(len(sequences))):
            errors.append(f"{field} sequence must be unique, ordered, and contiguous from zero")
    if fixture:
        initial = value.get("initial_state", [])
        keys = [(row["store"].encode(), bytes.fromhex(row["key"]["value"])) for row in initial]
        if keys != sorted(keys) or len(keys) != len(set(keys)):
            errors.append("initial_state must be unique and ordered by store/key bytes")
    return errors


def invalid_result(kind, identity, message, case_id="INVALID"):
    result = {
        "schema_version": 1,
        "case_id": case_id if isinstance(case_id, str) else "INVALID",
        "oracle_class": "harness",
        "runner": kind,
        "identity": identity,
        "status": "invalid_fixture",
        "exit_code": 64,
        "output": {"presence": "absent"},
        "error": {"domain": "fixture", "code": "INVALID_FIXTURE", "message": message, "retryable": False},
        "state_deltas": [], "events": [], "logs": [], "normalizations_applied": [],
        "diagnostics": [message],
    }
    return result


def _pointer_get(value, pointer):
    current = value
    for part in pointer.split("/")[1:]:
        token = part.replace("~1", "/").replace("~0", "~")
        current = current[int(token)] if isinstance(current, list) else current[token]
    return current


def _pointer_set(value, pointer, replacement):
    parts = pointer.split("/")[1:]
    current = value
    for part in parts[:-1]:
        token = part.replace("~1", "/").replace("~0", "~")
        current = current[int(token)] if isinstance(current, list) else current[token]
    token = parts[-1].replace("~1", "/").replace("~0", "~")
    if isinstance(current, list): current[int(token)] = replacement
    else: current[token] = replacement


def _constraint_ok(rule, value):
    if rule == "ephemeral_port": return isinstance(value, int) and not isinstance(value, bool) and 1024 <= value <= 65535
    if rule == "process_id": return isinstance(value, int) and not isinstance(value, bool) and value > 0
    if rule == "log_prefix": return isinstance(value, str) and bool(value)
    return False


def _pointer_allowed(pointer, patterns):
    return any(fnmatch.fnmatchcase(pointer, pattern) for pattern in patterns)
def _leaf_pointers(value, pointer=""):
    if isinstance(value, dict):
        for key, child in value.items():
            escaped = key.replace("~", "~0").replace("/", "~1")
            yield from _leaf_pointers(child, f"{pointer}/{escaped}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _leaf_pointers(child, f"{pointer}/{index}")
    else:
        yield pointer or "/", value


def _apply_requested_normalizations(result, requested, policy_by_id):
    for rule_id in requested:
        rule = policy_by_id[rule_id]
        if result["oracle_class"] not in rule["allowed_classes"]:
            raise ValueError(f"normalization {rule_id} is forbidden for oracle class {result['oracle_class']}")
        for pointer, original in list(_leaf_pointers(result)):
            if not _pointer_allowed(pointer, rule["allowed_pointers"]):
                continue
            if not _constraint_ok(rule_id, original):
                raise ValueError(f"normalization {rule_id} value violates its central constraint at {pointer}")
            replacement = rule["replacement"]
            _pointer_set(result, pointer, replacement)
            result["normalizations_applied"].append({
                "rule": rule_id, "json_pointer": pointer, "original_value": original,
                "before_sha256": hashlib.sha256(canonical(original)).hexdigest(),
                "after_sha256": hashlib.sha256(canonical(replacement)).hexdigest(),
            })




def _validate_normalization(applied, oracle_class, result, policy_by_id):
    rule = policy_by_id.get(applied.get("rule"))
    if not rule: return "normalization rule is not in the closed central allowlist"
    pointer = applied.get("json_pointer", "")
    if oracle_class not in rule["allowed_classes"]: return "normalization rule is forbidden for this oracle class"
    if not _pointer_allowed(pointer, rule["allowed_pointers"]): return "normalization rule is forbidden at this JSON pointer"
    original = applied.get("original_value")
    if not _constraint_ok(rule["id"], original): return "normalization value violates the central rule constraint"
    if applied.get("before_sha256") != hashlib.sha256(canonical(original)).hexdigest(): return "normalization before digest does not match original value"
    if applied.get("after_sha256") != hashlib.sha256(canonical(rule["replacement"])).hexdigest(): return "normalization after digest does not match replacement"
    try:
        if _pointer_get(result, pointer) != rule["replacement"]: return "normalized result does not contain the central replacement"
    except (KeyError, IndexError, ValueError, TypeError):
        return "normalization JSON pointer does not resolve"
    return None


def run_fixture(fixture, kind, identity):
    schema_errors = validate_schema(fixture, FIXTURE_SCHEMA)
    if not schema_errors:
        schema_errors = _invariant_errors(fixture, fixture=True)
    operation = fixture.get("input", {}).get("operation") if isinstance(fixture.get("input"), dict) else None
    allowed_mutations = {None, "output", "state", "error", "unknown_rule", "forbidden_class", "forbidden_pointer"}
    mutation = fixture.get("input", {}).get("harness_mutation") if isinstance(fixture.get("input"), dict) else None
    if operation != "protocol_skeleton": schema_errors.append("unsupported harness operation")
    if mutation not in allowed_mutations: schema_errors.append("unsupported harness mutation")
    if schema_errors:
        return invalid_result(kind, identity, "; ".join(schema_errors), fixture.get("case_id", "INVALID"))
    expected = fixture["expected"]
    result = {
        "schema_version": 1, "case_id": fixture["case_id"], "oracle_class": fixture["oracle_class"],
        "runner": kind, "identity": identity, "status": expected["status"], "exit_code": expected["exit_code"],
        "output": copy.deepcopy(expected["output"]), "error": copy.deepcopy(expected.get("error")),
        "state_deltas": copy.deepcopy(expected["state_deltas"]), "events": copy.deepcopy(expected["events"]),
        "logs": copy.deepcopy(expected["logs"]), "normalizations_applied": [], "diagnostics": [],
    }
    policy = json.loads(POLICY.read_text(encoding="utf-8")); rules = {row["id"]: row for row in policy["rules"]}
    try:
        _apply_requested_normalizations(result, fixture["normalizations"], rules)
    except ValueError as exc:
        return invalid_result(kind, identity, str(exc), fixture["case_id"])
    if kind == "rust" and mutation:
        if mutation == "output": result["output"] = {"presence": "present", "value": "deliberate-rust-output-mismatch"}
        elif mutation == "state": result["state_deltas"][0]["after"] = {"presence": "present", "value": {"encoding": "hex-lower", "value": "ff"}}
        elif mutation == "error": result["error"]["code"] = "DELIBERATE_RUST_ERROR"
        else:
            policy = json.loads(POLICY.read_text(encoding="utf-8")); rules = {row["id"]: row for row in policy["rules"]}
            rule_id, pointer, original = {
                "unknown_rule": ("consensus_height", "/output/value/height", 1),
                "forbidden_class": ("ephemeral_port", "/logs/0/fields/local_port", 12345),
                "forbidden_pointer": ("process_id", "/events/0/fields/process_id", 12345),
            }[mutation]
            if mutation == "forbidden_class": result["oracle_class"] = "consensus"
            rule = rules.get(rule_id, {"replacement": "<UNKNOWN>"})
            if mutation != "unknown_rule":
                container = result["logs"][0]["fields"] if mutation == "forbidden_class" else result["events"][0]["fields"]
                container[pointer.rsplit("/", 1)[1]] = rule["replacement"]
            result["normalizations_applied"] = [{
                "rule": rule_id, "json_pointer": pointer, "original_value": original,
                "before_sha256": hashlib.sha256(canonical(original)).hexdigest(),
                "after_sha256": hashlib.sha256(canonical(rule["replacement"])).hexdigest(),
            }]
    result_errors = validate_schema(result, RESULT_SCHEMA) + _invariant_errors(result)
    if result_errors:
        return invalid_result(kind, identity, "emitted result violated schema: " + "; ".join(result_errors), fixture["case_id"])
    return result


def mismatch_kind(pointer):
    if pointer.startswith("/state_deltas"): return "state"
    if pointer.startswith("/error"): return "error"
    if pointer.startswith("/events"): return "event"
    if pointer.startswith("/logs"): return "log"
    if pointer.startswith("/exit_code") or pointer.startswith("/status"): return "exit"
    if pointer.startswith("/identity"): return "identity"
    return "output"


def differences(left, right, pointer=""):
    if type(left) is not type(right): return [(pointer or "/", left, right)]
    if isinstance(left, dict):
        rows = []
        for key in sorted(set(left) | set(right)):
            p = pointer + "/" + key.replace("~", "~0").replace("/", "~1")
            if key not in left: rows.append((p, None, right[key]))
            elif key not in right: rows.append((p, left[key], None))
            else: rows.extend(differences(left[key], right[key], p))
        return rows
    if isinstance(left, list):
        rows = []
        for i in range(max(len(left), len(right))):
            p = pointer + f"/{i}"
            if i >= len(left): rows.append((p, None, right[i]))
            elif i >= len(right): rows.append((p, left[i], None))
            else: rows.extend(differences(left[i], right[i], p))
        return rows
    return [] if left == right else [(pointer or "/", left, right)]


def compare(java, rust):
    policy = json.loads(POLICY.read_text(encoding="utf-8")); policy_by_id = {row["id"]: row for row in policy["rules"]}
    mismatches = []
    for label, result in (("java", java), ("rust", rust)):
        errors = validate_schema(result, RESULT_SCHEMA)
        if not errors: errors = _invariant_errors(result)
        for message in errors:
            mismatches.append({"kind": "schema", "json_pointer": f"/{label}", "expected": "schema-valid canonical result", "actual": message})
        for applied in result.get("normalizations_applied", []):
            message = _validate_normalization(applied, result.get("oracle_class"), result, policy_by_id)
            if message:
                mismatches.append({"kind": "forbidden_normalization", "json_pointer": applied.get("json_pointer", "/normalizations_applied"), "expected": "central rule class, pointer, and value constraints", "actual": applied.get("rule"), "message": message})
    ignored = {"runner", "normalizations_applied", "diagnostics"}
    jl = copy.deepcopy({k: v for k, v in java.items() if k not in ignored}); rl = copy.deepcopy({k: v for k, v in rust.items() if k not in ignored})
    jl.get("identity", {}).pop("implementation", None); jl.get("identity", {}).pop("toolchain", None)
    rl.get("identity", {}).pop("implementation", None); rl.get("identity", {}).pop("toolchain", None)
    for pointer, expected, actual in differences(jl, rl):
        mismatches.append({"kind": mismatch_kind(pointer), "json_pointer": pointer, "expected": expected, "actual": actual})
    return {"schema_version": 1, "case_id": java.get("case_id", rust.get("case_id", "UNKNOWN")), "match": not mismatches, "mismatches": mismatches, "compared_result_digests": {"java": digest(java), "rust": digest(rust)}, "normalization_policy_digest": "sha256:" + hashlib.sha256(POLICY.read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runner", choices=("java", "rust"), default="java")
    parser.add_argument("--implementation")
    parser.add_argument("--toolchain")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run"); run.add_argument("--fixture")
    sub.add_parser("identify")
    cmp_parser = sub.add_parser("compare"); cmp_parser.add_argument("--java-result", required=True); cmp_parser.add_argument("--rust-result", required=True)
    args = parser.parse_args()
    implementation = args.implementation or f"c000-{args.runner}-protocol-adapter"
    toolchain = args.toolchain or "python3-stdlib behavior-neutral protocol core"
    identity = identify(args.runner, implementation, toolchain)
    if args.command == "identify": value, code = identity, 0
    elif args.command == "run":
        try:
            fixture = load_json(args.fixture)
            if not isinstance(fixture, dict): raise ValueError("fixture root must be an object")
            value = run_fixture(fixture, args.runner, identity)
        except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
            value = invalid_result(args.runner, identity, str(exc))
        code = 0 if value["status"] == "ok" else value["exit_code"]
    else:
        try:
            value = compare(load_json(args.java_result), load_json(args.rust_result)); code = 0 if value["match"] else 20
        except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
            sys.stderr.write(f"runner protocol error: {exc}\n"); return 64
    sys.stdout.buffer.write(canonical(value)); return code


if __name__ == "__main__":
    sys.exit(main())
