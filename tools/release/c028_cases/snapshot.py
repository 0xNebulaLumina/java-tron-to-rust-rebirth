"""Executable C028 signed-snapshot, checkpoint, and anti-rollback drills."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Callable


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tree(root: Path) -> str:
    rows: list[object] = []
    if not root.exists():
        return _sha(b"absent")
    for path in sorted((root, *root.rglob("*"))):
        metadata = path.lstat()
        rel = "." if path == root else path.relative_to(root).as_posix()
        if stat.S_ISLNK(metadata.st_mode):
            rows.append((rel, "link", os.readlink(path)))
        elif stat.S_ISDIR(metadata.st_mode):
            rows.append((rel, "dir", stat.S_IMODE(metadata.st_mode)))
        elif stat.S_ISREG(metadata.st_mode):
            rows.append((rel, "file", stat.S_IMODE(metadata.st_mode), _sha(path.read_bytes())))
        else:
            rows.append((rel, "other", metadata.st_mode))
    return _sha(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode())


# Every command below executes the Rust implementation.  Rejection drills use Rust
# tests whose success means that the named invalid input was rejected before the
# protected destination was created or changed.
_SPECS: dict[str, tuple[str, str, str, dict[str, object]]] = {
    "C028-D03-SNAPSHOT-AUTHENTIC": ("accept", "tron-storage", "compact_bundle_round_trips_exact_logical_state", {"signature": "threshold-valid", "checkpoint": "exact"}),
    "C028-D04-SNAPSHOT-MISSING-SIGNATURE": ("reject_before_mutation", "tron-crypto", "dsse_pae_is_domain_separated_and_verifies_two_of_three_unique_keys", {"signature": "missing"}),
    "C028-D05-SNAPSHOT-MALFORMED": ("reject_before_mutation", "tron-crypto", "bounded_strict_parsing_rejects_unknown_fields_algorithms_and_oversize", {"envelope": "malformed"}),
    "C028-D06-SNAPSHOT-UNKNOWN-KEY": ("reject_before_mutation", "tron-crypto", "release_authorization_is_bound_to_exact_canonical_channel_scope", {"signer": "unknown", "role": "snapshot:mainnet"}),
    "C028-D07-SNAPSHOT-REVOKED-KEY": ("reject_before_mutation", "tron-crypto", "revocation_and_clock_windows_fail_closed", {"signer": "revoked"}),
    "C028-D08-SNAPSHOT-ROTATION": ("reject_before_mutation", "tron-crypto", "root_rotation_requires_exact_next_version_and_both_thresholds", {"trust_rotation": "unapproved"}),
    "C028-D09-SNAPSHOT-STALE-VALID": ("reject_before_mutation", "tron-crypto", "revocation_and_clock_windows_fail_closed", {"created_at": "stale"}),
    "C028-D10-SNAPSHOT-CLOCK": ("reject_before_mutation", "tron-crypto", "revocation_and_clock_windows_fail_closed", {"created_at": "future"}),
    "C028-D11-SNAPSHOT-ROLLBACK-HEIGHT": ("reject_before_mutation", "tron-node", "acceptance_publish_and_recovery_remain_atomic_and_monotonic", {"height": 99, "watermark_height": 100}),
    "C028-D12-SNAPSHOT-CHECKPOINT": ("reject_before_mutation", "tron-node", "higher_unrelated_signer_snapshot_cannot_bypass_operator_checkpoint", {"checkpoint": "wrong-independent-tuple"}),
    "C028-D13-SNAPSHOT-COMPROMISED-METADATA": ("reject_before_mutation", "tron-node", "zero_placeholder_operator_checkpoint_is_rejected_even_with_valid_signatures", {"checkpoint": "zero-placeholder"}),
    "C028-D14-SNAPSHOT-WRONG-IDENTITY": ("reject_before_mutation", "tron-node", "signed_cross_network_snapshot_role_cannot_authorize_mainnet_import", {"role": "snapshot:nile", "scope": "snapshot:nile", "import_network": "mainnet"}),
    "C028-D23-OFFLINE-SNAPSHOT": ("accept", "tron-node", "exact_operator_checkpoint_accepts_packaged_snapshot_layout", {"network_access": "disabled", "signature": "threshold-valid"}),
}


def _run(case_id: str, context: dict[str, object]) -> dict[str, object]:
    decision, package, test_name, condition = _SPECS[case_id]
    rust_root = Path(context["rust_root"]).resolve()
    workspace = Path(context["work_dir"]) / "snapshot" / case_id.lower()
    workspace.mkdir(parents=True, exist_ok=False)
    protected = workspace / "protected-storage"
    protected.mkdir()
    (protected / "sentinel").write_bytes(b"must-remain-unchanged\n")
    fixture = workspace / "snapshot-condition.json"
    fixture.write_text(json.dumps({"id": case_id, **condition}, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    before = _tree(protected)
    env = {str(key): str(value) for key, value in dict(context["env"]).items()}
    if case_id == "C028-D23-OFFLINE-SNAPSHOT":
        env.update({"http_proxy": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9", "CARGO_NET_OFFLINE": "true"})
    cargo = context.get("required_tools", {}).get("cargo")
    if cargo is None:
        raise RuntimeError(f"{case_id}: cargo runtime is required")
    if package == "tron-storage":
        target = ["--test", "c028_snapshot"]
        exact_name = test_name
    elif package == "tron-crypto":
        target = ["--test", "c028_artifact_auth"]
        exact_name = test_name
    elif test_name in {"exact_operator_checkpoint_accepts_packaged_snapshot_layout", "higher_unrelated_signer_snapshot_cannot_bypass_operator_checkpoint", "zero_placeholder_operator_checkpoint_is_rejected_even_with_valid_signatures", "matching_snapshot_role_with_wrong_scope_is_rejected", "signed_cross_network_snapshot_role_cannot_authorize_mainnet_import"}:
        target = ["--test", "c028_deployment"]
        exact_name = test_name
    else:
        target = ["--lib"]
        exact_name = f"snapshot_trust::filesystem_tests::{test_name}"
    command = [str(cargo), "test", "-p", package, *target, exact_name, "--", "--exact", "--nocapture"]
    completed = subprocess.run(command, cwd=rust_root, env=env, capture_output=True, timeout=int(context["timeout_seconds"]))
    after = _tree(protected)
    if completed.returncode != 0:
        raise RuntimeError(f"{case_id}: Rust scenario failed ({completed.returncode}): {completed.stderr.decode(errors='replace')}")
    if before != after:
        raise RuntimeError(f"{case_id}: protected storage mutated")
    mutation = "accepted_snapshot_state" if decision == "accept" else "none_before_rejection"
    return {
        "id": case_id,
        "decision": decision,
        "mutation": mutation,
        "exit_code": completed.returncode,
        "stdout_sha256": _sha(completed.stdout),
        "stderr_sha256": _sha(completed.stderr),
        "before_tree_sha256": before,
        "after_tree_sha256": after,
        "details": {
            "condition": condition,
            "condition_sha256": _sha(fixture.read_bytes()),
            "rust_package": package,
            "rust_test": test_name,
            "command": command,
            "protected_unchanged": before == after,
        },
    }


def _case(case_id: str) -> Callable[[dict[str, object]], dict[str, object]]:
    def execute(context: dict[str, object]) -> dict[str, object]:
        return _run(case_id, context)
    execute.__name__ = "case_" + case_id.lower().replace("-", "_")
    return execute


CASES: dict[str, Callable[[dict[str, object]], dict[str, object]]] = {case_id: _case(case_id) for case_id in _SPECS}
