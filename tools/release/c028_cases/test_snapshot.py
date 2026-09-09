from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE = Path(__file__).with_name("snapshot.py")
SPEC = importlib.util.spec_from_file_location("c028_snapshot_cases", MODULE)
assert SPEC and SPEC.loader
snapshot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(snapshot)


class Completed:
    returncode = 0
    stdout = b"running 1 test\ntest result: ok. 1 passed; 0 failed\n"
    stderr = b""


class SnapshotCasesTest(unittest.TestCase):
    def test_exports_owned_snapshot_ids(self):
        self.assertEqual(set(snapshot.CASES), set(snapshot._SPECS))
        self.assertNotIn("C028-D15-SNAPSHOT-NEWER-FORMAT", snapshot.CASES)
        self.assertNotIn("C028-D16-SNAPSHOT-PARTIAL-CORRUPT", snapshot.CASES)

    def test_each_case_uses_rust_and_preserves_reject_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = {
                "repo_root": root,
                "rust_root": root / "rust-tron",
                "work_dir": root / "work",
                "candidate_dir": None,
                "installed_prefix": None,
                "env": {"PATH": "/usr/bin"},
                "timeout_seconds": 10,
                "required_tools": {"cargo": "/usr/bin/cargo"},
                "fixture_mode": False,
            }
            context["rust_root"].mkdir()
            context["work_dir"].mkdir()
            with patch.object(snapshot.subprocess, "run", return_value=Completed()) as run:
                for case_id, execute in snapshot.CASES.items():
                    result = execute(context)
                    self.assertEqual(result["id"], case_id)
                    self.assertEqual(result["exit_code"], 0)
                    self.assertEqual(result["before_tree_sha256"], result["after_tree_sha256"])
                    self.assertTrue(result["details"]["protected_unchanged"])
                    self.assertEqual(run.call_args.args[0][0], "/usr/bin/cargo")
                    self.assertIn("--exact", run.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
