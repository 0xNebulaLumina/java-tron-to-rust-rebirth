#!/usr/bin/env python3
from __future__ import annotations
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).with_name("java_reference_guard.py")
SPEC = importlib.util.spec_from_file_location("java_reference_guard_under_test", MODULE_PATH)
GUARD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(GUARD)
PIN = GUARD.PINNED_REVISION


def git_answers(*, index=f"160000 {PIN} 0\tjava-tron\n", status=""):
    def answer(root, *args):
        command = " ".join(args)
        if command.startswith("ls-tree HEAD"):
            return f"160000 commit {PIN}\tjava-tron\n"
        if command.startswith("ls-files --stage"):
            return index
        if command == "rev-parse HEAD":
            return PIN + "\n"
        if command.startswith("status --porcelain"):
            return status
        raise AssertionError(command)
    return answer


class GuardTests(unittest.TestCase):
    def test_unmerged_index_is_rejected(self):
        rows = (
            f"160000 {PIN} 1\tjava-tron\n"
            f"160000 {PIN} 2\tjava-tron\n"
            f"160000 {PIN} 3\tjava-tron\n"
        )
        with mock.patch.object(GUARD, "_git", side_effect=git_answers(index=rows)):
            with self.assertRaisesRegex(GUARD.JavaReferenceError, "exactly one stage-0"):
                GUARD.verify_java_reference(Path("/repo"))

    def test_dirty_source_is_rejected(self):
        with mock.patch.object(
            GUARD, "_git", side_effect=git_answers(status=" M actuator/A.java\n")
        ):
            with self.assertRaisesRegex(GUARD.JavaReferenceError, "tracked"):
                GUARD.verify_java_reference(Path("/repo"))

    def test_source_mutation_during_capture_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            tree = Path(temporary)
            source = tree / "A.java"
            source.write_text("clean")
            session = object.__new__(GUARD.JavaReferenceSession)
            session.root = Path("/repo")
            session.tree = tree
            session.source_paths = (Path("A.java"),)
            session.source_tree_sha256 = GUARD._tree_digest(tree, session.source_paths)
            session.identity = {}
            source.write_text("mutated")
            with mock.patch.object(GUARD, "verify_java_reference", return_value=PIN):
                with self.assertRaisesRegex(GUARD.JavaReferenceError, "materialization changed"):
                    session.guard(phase="after JVM")

    def test_poisoned_ignored_classes_change_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            classes = Path(temporary)
            target = classes / "Poison.class"
            target.write_bytes(b"clean")
            first = GUARD.classpath_identity(str(classes))
            target.write_bytes(b"poison")
            second = GUARD.classpath_identity(str(classes))
            self.assertNotEqual(first, second)

    def test_abrupt_partial_member_never_replaces_previous_batch(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "batch.json"
            GUARD.atomic_write_json(output, {"members": ["valid"]})
            before = output.read_bytes()
            with mock.patch("os.replace", side_effect=RuntimeError("abrupt")):
                with self.assertRaises(RuntimeError):
                    GUARD.atomic_write_json(output, {"members": ["partial"]})
            self.assertEqual(before, output.read_bytes())

    def test_resume_requires_exact_member_identity(self):
        identity = {"source_tree_sha256": "a", "classpath": [{"sha256": "b"}]}
        members = [
            {"variant_id": "ok", "reference_identity": identity},
            {"variant_id": "bad", "reference_identity": {"source_tree_sha256": "x"}},
        ]
        resumed = [member for member in members if member.get("reference_identity") == identity]
        self.assertEqual(["ok"], [member["variant_id"] for member in resumed])


if __name__ == "__main__":
    unittest.main()
