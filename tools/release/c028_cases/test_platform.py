from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("platform.py")
SPEC = importlib.util.spec_from_file_location("c028_platform_cases", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
PLATFORM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PLATFORM)


class PlatformCasesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo = Path(__file__).resolve().parents[3]
        cls.rust = cls.repo / "rust-tron"
        cls.tools = {
            "tron-fullnode": cls.rust / "target" / "debug" / "tron-fullnode",
            "tron-toolkit": cls.rust / "target" / "debug" / "tron-toolkit",
        }
        missing = [name for name, path in cls.tools.items() if not path.is_file()]
        if missing:
            raise unittest.SkipTest(f"actual debug binaries unavailable: {', '.join(missing)}")

    def test_owned_cases_execute_real_policy_checks_without_install_mutation(self) -> None:
        self.assertEqual(
            set(PLATFORM.CASES),
            {"C028-R14-PLATFORM", "C028-R15-SAPLING-EXCLUSION", "C028-R17-OFFLINE-RELEASE"},
        )
        for case_id, case in PLATFORM.CASES.items():
            with self.subTest(case_id=case_id), tempfile.TemporaryDirectory(prefix="c028-platform-test-") as directory:
                root = Path(directory)
                installed = root / "installed"
                installed.mkdir()
                (installed / "sentinel").write_text("must remain unchanged\n")
                work = root / "work"
                work.mkdir()
                result = case({
                    "repo_root": self.repo,
                    "rust_root": self.rust,
                    "work_dir": work,
                    "candidate_dir": None,
                    "installed_prefix": installed,
                    "env": os.environ.copy(),
                    "timeout_seconds": 300,
                    "required_tools": self.tools,
                    "fixture_mode": False,
                })
                self.assertEqual(result["id"], case_id)
                self.assertEqual(result["decision"], "reject_before_mutation")
                self.assertFalse(result["mutation"])
                self.assertEqual(result["exit_code"], 0)
                self.assertEqual(result["before_tree_sha256"], result["after_tree_sha256"])
                self.assertEqual((installed / "sentinel").read_text(), "must remain unchanged\n")
                self.assertEqual(len(result["stdout_sha256"]), 64)
                self.assertEqual(len(result["stderr_sha256"]), 64)
                self.assertIsInstance(result["details"], dict)


if __name__ == "__main__":
    unittest.main()
