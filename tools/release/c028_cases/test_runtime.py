from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

MODULE = Path(__file__).with_name("runtime.py")
SPEC = importlib.util.spec_from_file_location("c028_runtime_cases", MODULE)
assert SPEC and SPEC.loader
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


def test_runtime_case_registry_has_exact_owned_ids() -> None:
    assert set(runtime.CASES) == {
        "C028-R19-CLEAN-ENDPOINTS-FULL",
        "C028-R20-CLEAN-ENDPOINTS-SOLIDITY",
    }
    assert all(callable(case) for case in runtime.CASES.values())


def test_acceptance_runtime_cases_refuse_fixture_mode(tmp_path: Path) -> None:
    context = {
        "repo_root": tmp_path,
        "rust_root": tmp_path,
        "work_dir": tmp_path / "work",
        "candidate_dir": None,
        "installed_prefix": None,
        "env": {},
        "timeout_seconds": 1,
        "required_tools": {},
        "fixture_mode": True,
    }
    for case in runtime.CASES.values():
        with pytest.raises(RuntimeError, match="forbid fixture mode"):
            case(context)


def test_semantic_inventory_covers_required_full_and_solidity_behavior() -> None:
    source = MODULE.read_text()
    for semantic in (
        "p2p_handshake", "sync_fetch", "block_admission", "transaction_pending_atomicity",
        "fork_head_replay", "authenticated_backup", "cursor_reopen", "head_reconciliation",
        "database_shutdown", "metrics", "signal_shutdown", "p2p_forbidden", "jsonrpc_forbidden",
    ):
        assert semantic in source
