#!/usr/bin/env python3
"""Canonical C030 qualification-result signing and offline verification."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import math
import re
from datetime import datetime, timezone
from pathlib import Path
import os
from collections.abc import Mapping
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ROLES = ("qualification-operator", "independent-release-approver")
ALGORITHM = "ed25519-v1"
CANONICALIZATION = "RFC 8785 excluding signature"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
MODE_BY_ITEM = {
    "C030.01": "harness",
    "C030.02": "lifecycle",
    "C030.03": "network-fault",
    "C030.04": "api-load",
    "C030.05": "endurance",
    "C030.06": "security",
    "C030.07": "license",
    "C030.08": "performance",
}


def canonical_output_path(path: str | Path) -> str:
    """Return the absolute, symlink-resolved output identity bound into a result."""
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    return str(candidate.resolve(strict=False))


def trust_store_path_from_environment(
    variable: str = "C030_QUALIFICATION_TRUST_STORE",
    environment: Mapping[str, str] | None = None,
) -> Path:
    """Resolve a trust store only from the named environment binding."""
    value = (os.environ if environment is None else environment).get(variable)
    if not isinstance(value, str) or not value:
        _fail(f"{variable} must bind the qualification trust store path")
    path = Path(value).expanduser()
    if not path.is_absolute():
        _fail(f"{variable} must contain an absolute path")
    if path.is_symlink() or not path.is_file():
        _fail(f"{variable} must name a regular, non-symlink trust store")
    return path.resolve(strict=True)


def load_trust_store_from_environment(
    variable: str = "C030_QUALIFICATION_TRUST_STORE",
    environment: Mapping[str, str] | None = None,
    *,
    expected_path: str | Path | None = None,
) -> tuple[dict[str, Any], Path]:
    """Load a trust store while preserving its authoritative environment/path identity."""
    path = trust_store_path_from_environment(variable, environment)
    if expected_path is not None and path != Path(expected_path).expanduser().resolve(strict=True):
        _fail("qualification trust store path binding mismatch")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ResultVerificationError(f"invalid qualification trust store: {path}") from error
    if not isinstance(value, dict):
        _fail("qualification trust store must be an object")
    return value, path


class ResultVerificationError(ValueError):
    """The result is not an authentic, current release qualification."""


def _fail(message: str) -> None:
    raise ResultVerificationError(message)


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail(f"{field} must be a UTC RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ResultVerificationError(f"invalid {field}") from error
    if parsed.tzinfo is None:
        _fail(f"{field} must include UTC timezone")
    return parsed.astimezone(timezone.utc)


def _validate_json(value: Any) -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        if abs(value) > 9007199254740991:
            _fail("canonical JSON integer exceeds the interoperable range")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            _fail("canonical JSON cannot contain NaN or infinity")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json(item)
        return
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            _fail("canonical JSON object keys must be strings")
        for item in value.values():
            _validate_json(item)
        return
    _fail(f"unsupported canonical JSON value: {type(value).__name__}")


def canonicalize_result(result_without_signature: dict[str, Any]) -> bytes:
    """Return deterministic UTF-8 JSON with RFC 8785 key ordering and escaping.

    C030 documents use integral counters and ordinary finite measurements. Python's
    shortest-round-trip number encoder is used for the latter; non-JSON and
    non-interoperable integer values are rejected rather than ambiguously signed.
    """
    if not isinstance(result_without_signature, dict):
        _fail("qualification result must be an object")
    if "signature" in result_without_signature:
        _fail("canonicalize_result input must exclude signature")
    _validate_json(result_without_signature)
    return json.dumps(result_without_signature, ensure_ascii=False, allow_nan=False,
                      sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest_payload(result: dict[str, Any]) -> bytes:
    payload = copy.deepcopy(result)
    payload.pop("signature", None)
    payload.pop("result_sha256", None)
    return canonicalize_result(payload)


def _result_digest(result: dict[str, Any]) -> str:
    return hashlib.sha256(_digest_payload(result)).hexdigest()


def _scope(result: dict[str, Any]) -> str:
    profile = result.get("profile")
    platform = result.get("platform_id")
    if not isinstance(profile, str) or not isinstance(platform, str) or not platform:
        _fail("result lacks profile/platform binding")
    return f"qualification:{profile}:{platform}"


def _validate_release_result(result: dict[str, Any], approvals: list[dict[str, Any]]) -> None:
    if result.get("schema") != "c030-qualification-result-v1":
        _fail("wrong qualification result schema")
    if result.get("profile") != "release" or result.get("overall_status") != "pass":
        _fail("only a passing release-profile result may be signed")
    for field in ("spec_sha256", "scenario_manifest_sha256", "release_manifest_sha256", "environment_sha256", "host_attestation_sha256", "cache_inventory_sha256"):
        if not isinstance(result.get(field), str) or not _SHA256.fullmatch(result[field]):
            _fail(f"result lacks valid {field} binding")
    item = result.get("scenario_id")
    mode = result.get("mode")
    if item not in MODE_BY_ITEM:
        _fail("result lacks a valid C030 item binding")
    if mode != MODE_BY_ITEM[item]:
        _fail("result item/mode binding mismatch")
    output_path = result.get("output_path")
    if not isinstance(output_path, str) or not Path(output_path).is_absolute() or canonical_output_path(output_path) != output_path:
        _fail("result lacks a canonical absolute output path binding")
    if not re.fullmatch(r"[0-9a-f]{40}", str(result.get("source_revision", ""))):
        _fail("result lacks valid source revision binding")
    if result.get("failures") != []:
        _fail("passing result must have zero failures")
    scenarios = result.get("scenario_results")
    invariants = result.get("invariants")
    if not isinstance(scenarios, list) or not scenarios or any(row.get("status") != "pass" or row.get("synthetic") is not False or row.get("skipped") is not False for row in scenarios if isinstance(row, dict)) or any(not isinstance(row, dict) for row in scenarios):
        _fail("every scenario must be a real, unskipped pass")
    if not isinstance(invariants, list) or not invariants or any(not isinstance(row, dict) or row.get("status") != "pass" for row in invariants):
        _fail("every invariant must pass")
    if result.get("harness", {}).get("synthetic_results") not in (None, 0) or result.get("harness", {}).get("skipped_results") not in (None, 0):
        _fail("release result contains synthetic or skipped harness results")
    started = _timestamp(result.get("started_at"), "started_at")
    completed = _timestamp(result.get("completed_at"), "completed_at")
    expires = _timestamp(result.get("expires_at"), "expires_at")
    if not started <= completed < expires:
        _fail("invalid qualification result time window")
    if len(approvals) != 2:
        _fail("exactly two human approvals are required")
    roles = {item.get("role") for item in approvals}
    identities = {item.get("identity") for item in approvals}
    if roles != set(ROLES) or len(identities) != 2:
        _fail("approvals require both roles and two distinct humans")
    for item in approvals:
        if item.get("human") is not True or item.get("decision") != "approve":
            _fail("release approvals must be explicit human approvals")
        approved = _timestamp(item.get("approved_at"), "approval approved_at")
        approval_expires = _timestamp(item.get("expires_at"), "approval expires_at")
        if not completed <= approved <= expires or approval_expires < expires:
            _fail("approval is outside the bound result window")

def _validate_manifest_evidence(result: dict[str, Any], manifest: dict[str, Any]) -> None:
    item = result["scenario_id"]
    expected_scenarios = [row for row in manifest.get("scenarios", []) if row.get("item") == item]
    expected_ids = [row.get("id") for row in expected_scenarios]
    if not expected_scenarios or result.get("scenario_ids") != expected_ids:
        _fail("qualification result scenario IDs do not exactly match the scenario manifest")
    scenario_results = result.get("scenario_results")
    if not isinstance(scenario_results, list) or [row.get("id") for row in scenario_results if isinstance(row, dict)] != expected_ids:
        _fail("qualification result scenario rows do not exactly match the scenario manifest")
    observations = result.get("observations")
    if not isinstance(observations, list) or any(not isinstance(row, dict) for row in observations):
        _fail("qualification result lacks measured observations")
    observation_by_id: dict[str, dict[str, Any]] = {}
    for observation in observations:
        observation_id = observation.get("id")
        if not isinstance(observation_id, str) or observation_id in observation_by_id:
            _fail("qualification result contains invalid or duplicate observation IDs")
        observation_by_id[observation_id] = observation
    evidence = result.get("evidence_files", {}).get("files", [])
    evidence_paths = {row.get("path") for row in evidence if isinstance(row, dict)}
    consumed: list[str] = []
    for contract, scenario in zip(expected_scenarios, scenario_results, strict=True):
        observation_ids = scenario.get("observation_ids")
        expected_subjects = contract.get("expected_observations")
        if not isinstance(observation_ids, list) or not isinstance(expected_subjects, list) or len(observation_ids) != len(expected_subjects):
            _fail(f"scenario observation coverage mismatch: {contract.get('id')}")
        bound = [observation_by_id.get(observation_id) for observation_id in observation_ids]
        if any(row is None for row in bound) or [row.get("subject") for row in bound] != expected_subjects:
            _fail(f"scenario observation subjects do not match manifest: {contract.get('id')}")
        scenario_evidence = scenario.get("evidence_paths")
        if not isinstance(scenario_evidence, list) or not scenario_evidence or any(path not in evidence_paths for path in scenario_evidence):
            _fail(f"scenario evidence is absent from the signed inventory: {contract.get('id')}")
        for observation in bound:
            if observation.get("status") != "pass":
                _fail(f"scenario observation did not pass: {observation.get('id')}")
            expected, actual = observation.get("expected"), observation.get("actual")
            if expected is None or actual is None or isinstance(expected, bool) or isinstance(actual, bool):
                _fail(f"scenario observation is a status boolean, not measured evidence: {observation.get('id')}")
            if observation.get("evidence_path") not in evidence_paths or observation["evidence_path"] not in scenario_evidence:
                _fail(f"observation evidence is not bound to its scenario inventory: {observation.get('id')}")
        consumed.extend(observation_ids)
    if consumed != list(observation_by_id):
        _fail("qualification result observations are missing, reordered, or not scenario-bound")


def _load_private(path: Path) -> tuple[Ed25519PrivateKey, bytes, str]:
    raw = path.read_bytes()
    try:
        key = serialization.load_pem_private_key(raw, password=None)
    except (TypeError, ValueError) as error:
        raise ResultVerificationError(f"invalid signing key: {path}") from error
    if not isinstance(key, Ed25519PrivateKey):
        _fail(f"signing key is not Ed25519: {path}")
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return key, public, hashlib.sha256(b"ed25519-v1\0" + public).hexdigest()


def sign_result(result: dict[str, Any], approval_records: list[dict[str, Any]], key_paths: list[Path]) -> dict[str, Any]:
    """Return a threshold-signed release result; inputs are not mutated."""
    approvals = copy.deepcopy(approval_records)
    unsigned = copy.deepcopy(result)
    unsigned.pop("signature", None)
    unsigned["approvals"] = approvals
    _validate_release_result(unsigned, approvals)
    if len(key_paths) != 2:
        _fail("exactly two independently provisioned signing keys are required")
    loaded = [_load_private(Path(path)) for path in key_paths]
    if len({entry[2] for entry in loaded}) != 2:
        _fail("duplicate signing keys do not satisfy threshold")
    unsigned["result_sha256"] = _result_digest(unsigned)
    payload = canonicalize_result(unsigned)
    signatures = []
    scope = _scope(unsigned)
    for approval, (key, _public, key_id) in zip(approvals, loaded):
        signatures.append({"key_id": key_id, "algorithm": ALGORITHM, "identity": approval["identity"],
                           "role": approval["role"], "scope": scope, "signed_at": approval["approved_at"],
                           "signature_base64": base64.b64encode(key.sign(payload)).decode("ascii")})
    unsigned["signature"] = {"algorithm": "ed25519", "canonicalization": CANONICALIZATION,
                             "threshold": 2, "signatures": signatures}
    return unsigned


def verify_result(
    result: dict[str, Any],
    trust_store: dict[str, Any] | str | Path,
    *,
    expected_item: str,
    expected_mode: str,
    expected_output_path: str | Path,
    expected_host_attestation_sha256: str | None = None,
    expected_cache_inventory_sha256: str | None = None,
    expected_spec_sha256: str | None = None,
    expected_scenario_manifest_sha256: str | None = None,
    scenario_manifest: dict[str, Any] | None = None,
) -> None:
    """Verify release authority and exact aggregation-slot/attestation bindings."""
    if isinstance(trust_store, (str, Path)):
        trust_store = json.loads(Path(trust_store).read_text(encoding="utf-8"))
    if not isinstance(result, dict) or not isinstance(trust_store, dict):
        _fail("result and trust store must be objects")
    signature = result.get("signature")
    approvals = result.get("approvals")
    if not isinstance(signature, dict) or not isinstance(approvals, list):
        _fail("unsigned result is not release authority")
    _validate_release_result(result, approvals)
    if result.get("scenario_id") != expected_item:
        _fail("qualification result item binding mismatch")
    if result.get("mode") != expected_mode:
        _fail("qualification result mode binding mismatch")
    if result.get("output_path") != canonical_output_path(expected_output_path):
        _fail("qualification result output path binding mismatch")
    if expected_spec_sha256 is not None and result.get("spec_sha256") != expected_spec_sha256:
        _fail("qualification result specification binding mismatch")
    if expected_scenario_manifest_sha256 is not None and result.get("scenario_manifest_sha256") != expected_scenario_manifest_sha256:
        _fail("qualification result scenario manifest binding mismatch")
    if scenario_manifest is not None:
        _validate_manifest_evidence(result, scenario_manifest)
    for field, expected in (("host_attestation_sha256", expected_host_attestation_sha256),
                            ("cache_inventory_sha256", expected_cache_inventory_sha256)):
        actual = result.get(field)
        if not isinstance(actual, str) or not _SHA256.fullmatch(actual):
            _fail(f"qualification result lacks valid {field}")
        if expected is not None and actual != expected:
            _fail(f"qualification result {field} binding mismatch")
    if result.get("result_sha256") != _result_digest(result):
        _fail("qualification result digest mismatch")
    if signature.get("algorithm") != "ed25519" or signature.get("canonicalization") != CANONICALIZATION or signature.get("threshold") != 2:
        _fail("unsupported result signature policy")
    now = _timestamp(trust_store.get("verification_time") or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), "verification_time")
    if now > _timestamp(trust_store.get("expires"), "trust store expires"):
        _fail("trust store is expired")
    completed = _timestamp(result.get("completed_at"), "completed_at")
    expires = _timestamp(result.get("expires_at"), "expires_at")
    if not completed <= now <= expires:
        _fail("qualification result is not current at verification time")
    keys_list = trust_store.get("keys")
    roles_list = trust_store.get("roles")
    if not isinstance(keys_list, list) or not isinstance(roles_list, list):
        _fail("malformed trust store")
    keys: dict[str, dict[str, Any]] = {}
    for item in keys_list:
        if not isinstance(item, dict) or not isinstance(item.get("key_id"), str) or item["key_id"] in keys:
            _fail("trust store contains invalid or duplicate key IDs")
        keys[item["key_id"]] = item
    roles: dict[str, dict[str, Any]] = {}
    for item in roles_list:
        if not isinstance(item, dict) or item.get("name") in roles:
            _fail("trust store contains invalid or duplicate roles")
        roles[item.get("name")] = item
    entries = signature.get("signatures")
    if not isinstance(entries, list) or len(entries) != 2:
        _fail("signature threshold is not exactly satisfied")
    if len({entry.get("key_id") for entry in entries if isinstance(entry, dict)}) != 2:
        _fail("duplicate signatures do not satisfy threshold")
    if len({entry.get("identity") for entry in entries if isinstance(entry, dict)}) != 2:
        _fail("signatures must represent distinct humans")
    payload_obj = copy.deepcopy(result)
    payload_obj.pop("signature")
    payload = canonicalize_result(payload_obj)
    expected_scope = _scope(result)
    approval_by_role = {item.get("role"): item for item in approvals}
    seen_roles = set()
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("algorithm") != ALGORITHM:
            _fail("unsupported signature entry")
        role_name = entry.get("role")
        key_id = entry.get("key_id")
        key_record = keys.get(key_id)
        role_record = roles.get(role_name)
        if key_record is None:
            _fail("signature uses unknown key")
        if key_record.get("revoked") is not False:
            _fail("signature uses revoked key")
        if key_record.get("production_authority") is not True or key_record.get("origin") != "externally-provisioned":
            _fail("test or deterministic key is not production authority")
        if key_record.get("algorithm") != ALGORITHM:
            _fail("trusted key algorithm mismatch")
        role_key_ids = role_record.get("key_ids") if isinstance(role_record, dict) else None
        if (not isinstance(role_record, dict) or role_record.get("name") != role_name
                or role_record.get("scope") != expected_scope or role_record.get("threshold") != 1
                or not isinstance(role_key_ids, list) or key_id not in role_key_ids):
            _fail("signature key role or scope mismatch")
        if role_name not in ROLES or role_name in seen_roles or entry.get("scope") != expected_scope:
            _fail("signature role mismatch")
        approval = approval_by_role.get(role_name)
        if not approval or entry.get("identity") != approval.get("identity") or entry.get("signed_at") != approval.get("approved_at"):
            _fail("signature is not bound to its human approval")
        signed_at = _timestamp(entry.get("signed_at"), "signed_at")
        if not _timestamp(key_record.get("not_before"), "key not_before") <= signed_at <= _timestamp(key_record.get("not_after"), "key not_after"):
            _fail("signature key was not valid when used")
        try:
            public = base64.b64decode(key_record.get("public_key_base64", ""), validate=True)
            if len(public) != 32 or hashlib.sha256(b"ed25519-v1\0" + public).hexdigest() != key_id:
                _fail("trusted key ID does not match public key")
            raw_signature = base64.b64decode(entry.get("signature_base64", ""), validate=True)
            Ed25519PublicKey.from_public_bytes(public).verify(raw_signature, payload)
        except (ValueError, InvalidSignature) as error:
            raise ResultVerificationError("invalid qualification result signature") from error
        seen_roles.add(role_name)
    if seen_roles != set(ROLES):
        _fail("both required signature roles are mandatory")
