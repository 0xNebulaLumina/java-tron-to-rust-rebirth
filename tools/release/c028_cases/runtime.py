"""Executable C028 runtime endpoint and lifecycle cases."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Callable

Case = Callable[[dict[str, object]], dict[str, object]]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tree(root: Path) -> str:
    rows: list[tuple[str, str, int]] = []
    if root.exists():
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root).as_posix()
            if path.is_file():
                rows.append((relative, _sha(path.read_bytes()), path.stat().st_mode & 0o7777))
            elif path.is_dir():
                rows.append((relative + "/", "", path.stat().st_mode & 0o7777))
    return _sha(json.dumps(rows, separators=(",", ":")).encode())


def _binary(context: dict[str, object], name: str) -> Path:
    for key in ("installed_prefix", "candidate_dir"):
        root = context.get(key)
        if root:
            candidate = Path(root) / "bin" / name
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate
    candidate = Path(context["rust_root"]) / "target" / "debug" / name
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return candidate
    raise RuntimeError(f"required executable {name} is not installed or built")


def _run(argv: list[str], *, cwd: Path, env: dict[str, str], timeout: int) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if completed.returncode != 0:
        raise RuntimeError(f"runtime proof failed ({completed.returncode}): {' '.join(argv)}\n{completed.stderr.decode(errors='replace')}")
    return completed


def _cargo_proof(rust_root: Path, env: dict[str, str], timeout: int, package: str, test: str, symbol: str) -> subprocess.CompletedProcess[bytes]:
    result = _run(["cargo", "test", "-p", package, "--test", test, symbol, "--", "--exact", "--nocapture"], cwd=rust_root, env=env, timeout=timeout)
    transcript = result.stdout + result.stderr
    if b"1 passed" not in transcript or symbol.encode() not in transcript:
        raise RuntimeError(f"{package}/{test}: proof {symbol} did not execute exactly once")
    return result


def _case(context: dict[str, object], case_id: str, mode: str) -> dict[str, object]:
    if context.get("fixture_mode"):
        raise RuntimeError("runtime acceptance cases forbid fixture mode")
    rust_root = Path(context["rust_root"])
    work = Path(context["work_dir"]) / case_id.lower()
    work.mkdir(parents=True, exist_ok=False)
    before = _tree(work)
    env = {str(k): str(v) for k, v in dict(context["env"]).items()}
    env.setdefault("CARGO_TERM_COLOR", "never")
    timeout = int(context["timeout_seconds"])
    binary_name = "tron-fullnode" if mode == "full" else "tron-solidity"
    commands: list[subprocess.CompletedProcess[bytes]] = []
    identity = _run([str(_binary(context, binary_name)), "--version"], cwd=rust_root, env=env, timeout=timeout)
    commands.append(identity)
    try:
        build = json.loads(identity.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{binary_name} emitted non-JSON build identity") from error
    if build.get("backend") != "rustlog" or build.get("backend_format") != "rustlog-v1":
        raise RuntimeError(f"unexpected {binary_name} storage identity: {build!r}")

    common = [
        ("tron-node", "c025_lifecycle", "concrete_queue_zeromq_prometheus_and_readiness_adapters_stop_cleanly"),
        ("tron-node", "c025_lifecycle", "readiness_and_all_stop_conditions_share_one_control_path"),
    ]
    full = [
        ("tron-network", "c028_production", "two_production_owners_handshake_sync_fetch_admit_and_join"),
        ("tron-network", "c028_production", "shutdown_cancels_a_session_blocked_in_handshake_and_releases_the_listener"),
        ("tron-network", "c028_backup_auth", "authenticates_exact_identity_endpoints_session_sequence_and_payload"),
        ("tron-execution", "c016_pending", "admission_publishes_state_and_queue_only_after_success"),
        ("tron-execution", "c019_fork_switch", "multi_branch_switch_rewinds_head_first_and_replays_oldest_first"),
        ("tron-node", "c025_lifecycle", "full_graph_keeps_all_mode_admin_and_api_and_starts_every_required_service"),
    ]
    solidity = [
        ("tron-node", "c026_replica", "retries_same_height_then_applies_exact_sequence_and_persists"),
        ("tron-node", "c026_replica", "startup_reconciles_stale_marker_to_committed_head_before_fetching_next_height"),
        ("tron-node", "c026_replica", "durable_solidity_cursor_remains_readable_after_database_source_closes"),
        ("tron-node", "c026_replica", "interrupt_cancels_inflight_replica_read_and_closes_database_source"),
        ("tron-node", "c025_lifecycle", "solidity_graph_keeps_all_mode_admin_and_api_and_starts_required_services_without_p2p"),
        ("tron-node", "c028_deployment", "packaged_surfaces_match_runtime_and_solidity_json_rpc_is_forbidden"),
    ]
    proofs = common + (full if mode == "full" else solidity)
    for package, test, symbol in proofs:
        commands.append(_cargo_proof(rust_root, env, timeout, package, test, symbol))

    observation = {
        "binary": binary_name,
        "build_identity": build,
        "mode": mode,
        "proofs": [symbol for _, _, symbol in proofs],
        "semantics": (["p2p_handshake", "sync_fetch", "block_admission", "transaction_pending_atomicity", "fork_head_replay", "authenticated_backup", "metrics", "signal_shutdown"] if mode == "full" else ["solidity_sync", "cursor_reopen", "head_reconciliation", "database_shutdown", "metrics", "signal_shutdown", "p2p_forbidden", "jsonrpc_forbidden"]),
    }
    (work / "observation.json").write_text(json.dumps(observation, sort_keys=True, separators=(",", ":")) + "\n")
    stdout = b"".join(command.stdout for command in commands)
    stderr = b"".join(command.stderr for command in commands)
    after = _tree(work)
    if before == after:
        raise RuntimeError("runtime case produced no durable observation")
    return {"id": case_id, "decision": "accept", "mutation": "observation_written_after_runtime_proofs", "exit_code": 0, "stdout_sha256": _sha(stdout), "stderr_sha256": _sha(stderr), "before_tree_sha256": before, "after_tree_sha256": after, "details": observation}


def clean_endpoints_full(context: dict[str, object]) -> dict[str, object]:
    return _case(context, "C028-R19-CLEAN-ENDPOINTS-FULL", "full")


def clean_endpoints_solidity(context: dict[str, object]) -> dict[str, object]:
    return _case(context, "C028-R20-CLEAN-ENDPOINTS-SOLIDITY", "solidity")


CASES: dict[str, Case] = {
    "C028-R19-CLEAN-ENDPOINTS-FULL": clean_endpoints_full,
    "C028-R20-CLEAN-ENDPOINTS-SOLIDITY": clean_endpoints_solidity,
}
