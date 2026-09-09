from __future__ import annotations

import importlib.util
import os
import shutil
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO / "tools" / "release" / "c028_cases" / "storage.py"
SPEC = importlib.util.spec_from_file_location("c028_storage_cases", MODULE_PATH)
assert SPEC and SPEC.loader
storage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(storage)


class StorageCasesTest(unittest.TestCase):
    def context(self, work_dir: Path) -> dict[str, object]:
        return {
            "repo_root": REPO,
            "rust_root": REPO / "rust-tron",
            "work_dir": work_dir,
            "candidate_dir": None,
            "installed_prefix": None,
            "env": dict(os.environ),
            "timeout_seconds": 600,
            "required_tools": {"cargo": shutil.which("cargo")},
            "fixture_mode": False,
        }

    def test_exports_exact_storage_family(self) -> None:
        self.assertEqual(set(storage.CASES), set(storage._PROOFS))
        self.assertEqual(len(storage.CASES), 10)

    def test_java_rejection_executes_real_no_write_proof(self) -> None:
        with tempfile.TemporaryDirectory(prefix="c028-storage-case-") as directory:
            result = storage.CASES["C028-D02-JAVA-DIR-REJECT"](self.context(Path(directory)))
        self.assertEqual(result["decision"], "reject_before_mutation")
        self.assertEqual(result["mutation"], "none")
        self.assertEqual(result["before_tree_sha256"], result["after_tree_sha256"])
        self.assertTrue(result["details"]["proof_executed"])

    def test_migration_faults_execute_rollback_resume_proof(self) -> None:
        with tempfile.TemporaryDirectory(prefix="c028-storage-case-") as directory:
            result = storage.CASES["C028-D18-MIGRATION-DURABLE-FAULTS"](self.context(Path(directory)))
        self.assertEqual(result["decision"], "accept")
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["details"]["proof"], "migration_crash_rollback_resume_and_snapshot_resync_matrix")
    def test_all_storage_recovery_ids_execute_their_rust_proofs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="c028-storage-family-") as directory:
            context = self.context(Path(directory))
            results = {case_id: case(context) for case_id, case in storage.CASES.items()}
        self.assertEqual(set(results), set(storage._PROOFS))
        for case_id, result in results.items():
            self.assertEqual(result["id"], case_id)
            self.assertEqual(result["exit_code"], 0)
            self.assertTrue(result["details"]["proof_executed"])
            self.assertEqual(result["before_tree_sha256"], result["after_tree_sha256"])


if __name__ == "__main__":
    unittest.main()
