"""Executable C028 storage and recovery drill cases."""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path
from typing import Callable

Case = Callable[[dict[str, object]], dict[str, object]]

# Each drill delegates to a narrow Rust integration proof.  Those proofs construct real
# rustlog-v1 trees, invoke the public format/migration/resync APIs and inspect durable state.
_PROOFS: dict[str, tuple[str, str, str]] = {
    "C028-D01-GENESIS-CLEAN": ("format_contract", "legitimate_abrupt_initialization_phases_recover_deterministically", "accept"),
    "C028-D02-JAVA-DIR-REJECT": ("format_contract", "java_markers_are_rejected_without_writes", "reject_before_mutation"),
    "C028-D15-SNAPSHOT-NEWER-FORMAT": ("format_contract", "manifest_identity_corruption_and_newer_versions_are_stable", "reject_before_mutation"),
    "C028-D16-SNAPSHOT-PARTIAL-CORRUPT": ("format_contract", "initialization_classification_precedence_and_malformed_trees_are_no_write", "reject_before_mutation"),
    "C028-D17-SNAPSHOT-DURABLE-FAULTS": ("failure_contract", "lock_permission_and_disk_full_categories_are_stable", "reject_before_mutation"),
    "C028-D18-MIGRATION-DURABLE-FAULTS": ("format_contract", "migration_crash_rollback_resume_and_snapshot_resync_matrix", "accept"),
    "C028-D19-MIGRATION-WRONG-IDENTITY": ("format_contract", "manifest_identity_corruption_and_newer_versions_are_stable", "reject_before_mutation"),
    "C028-D20-UPGRADE-ROLLBACK-MATRIX": ("format_contract", "abrupt_migration_process_death_releases_lock_and_recovers_durable_journal", "reject_before_mutation"),
    "C028-D21-CORRUPTION": ("failure_contract", "rustlog_vectors_batch_atomicity_reopen_and_corruption", "reject_before_mutation"),
    "C028-D22-RESYNC-FALLBACK": ("format_contract", "clean_resync_marker_requires_matching_rust_identity_and_exclusive_open_release", "accept"),
}


def _tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    if not root.exists():
        return digest.hexdigest()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix().encode()
        digest.update(b"D\0" if path.is_dir() else b"F\0")
        digest.update(relative)
        digest.update(b"\0")
        if path.is_file():
            digest.update(path.read_bytes())
    return digest.hexdigest()


def _run(case_id: str, context: dict[str, object]) -> dict[str, object]:
    test_target, proof, success_decision = _PROOFS[case_id]
    rust_root = Path(context["rust_root"])
    work_dir = Path(context["work_dir"])
    work_dir.mkdir(parents=True, exist_ok=True)
    observed_dir = work_dir / case_id.lower()
    observed_dir.mkdir(parents=True, exist_ok=False)
    before = _tree_sha256(observed_dir)

    required_tools = context.get("required_tools", {})
    cargo_value = required_tools.get("cargo") if isinstance(required_tools, dict) else None
    cargo = str(cargo_value) if cargo_value else shutil.which("cargo")
    if not cargo:
        raise RuntimeError(f"{case_id}: cargo runtime is unavailable")

    env_value = context.get("env", {})
    env = {str(key): str(value) for key, value in env_value.items()} if isinstance(env_value, dict) else {}
    env.setdefault("PATH", os.environ.get("PATH", ""))
    # Keep all build products in the private drill workspace; the source tree stays read-only.
    env["CARGO_TARGET_DIR"] = str(work_dir / "cargo-target")
    command = [
        cargo, "test", "--locked", "--offline", "-p", "tron-storage",
        "--test", test_target, proof, "--", "--exact", "--nocapture",
    ]
    completed = subprocess.run(
        command,
        cwd=rust_root,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=int(context.get("timeout_seconds", 300)),
        check=False,
    )
    stdout = completed.stdout
    stderr = completed.stderr
    after = _tree_sha256(observed_dir)
    output = stdout.decode("utf-8", "replace")
    proof_passed = completed.returncode == 0 and f"test {proof} ... ok" in output
    if not proof_passed:
        raise AssertionError(
            f"{case_id}: Rust storage proof {proof!r} failed or did not execute "
            f"(exit {completed.returncode})\n{output}\n{stderr.decode('utf-8', 'replace')}"
        )
    if before != after:
        raise AssertionError(f"{case_id}: drill control tree was unexpectedly mutated")

    return {
        "id": case_id,
        "decision": success_decision,
        "mutation": "committed" if success_decision == "accept" else "none",
        "exit_code": completed.returncode,
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "before_tree_sha256": before,
        "after_tree_sha256": after,
        "details": {
            "component": "tron-storage",
            "test_target": test_target,
            "proof": proof,
            "proof_executed": True,
            "control_tree_unchanged": before == after,
        },
    }


def _case(case_id: str) -> Case:
    def run(context: dict[str, object]) -> dict[str, object]:
        return _run(case_id, context)
    run.__name__ = "case_" + case_id.lower().replace("-", "_")
    return run


CASES: dict[str, Case] = {case_id: _case(case_id) for case_id in _PROOFS}
