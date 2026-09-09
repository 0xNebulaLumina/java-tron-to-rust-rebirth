from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("c028_release", ROOT / "tools/release/c028_release.py")
release = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(release)
FIXTURE = ROOT / "docs/oracles/c028-workflow-metadata.v1.json"


class PublishIdentityTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="c028-publish-identity-")
        self.repo = Path(self.temporary.name) / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "C028")
        self.git("config", "user.email", "c028@example.invalid")
        (self.repo / "source").write_text("first\n")
        self.git("add", "source")
        self.git("commit", "-q", "-m", "first")
        self.metadata = Path(self.temporary.name) / "workflow-metadata.json"
        self.first = self.git("rev-parse", "HEAD")
        self.digest = "a" * 64
        self.inventory = Path(self.temporary.name) / "publication-inventory.json"
        self.fixture = json.loads(FIXTURE.read_text())
        self.fixture["source_revision"] = self.first

    def tearDown(self):
        self.temporary.cleanup()

    def git(self, *args: str) -> str:
        return subprocess.check_output(["git", "-C", str(self.repo), *args], text=True).strip()

    def write_inventory(self, revision: str, release_id: str = "release-1") -> None:
        self.inventory.write_text(json.dumps({"release_id": release_id, "channel": "stable", "source_revision": revision}))
        metadata = copy.deepcopy(self.fixture)
        metadata["release_id"] = release_id
        metadata["source_revision"] = revision
        self.metadata.write_text(json.dumps(metadata))

    def validate(self, tag: str = "release-1"):
        return release.validate_publish_identity(
            self.inventory, self.metadata, f"c028-candidate-release-1-{self.digest}", self.digest,
            "release-1", "stable", tag, self.repo, self.fixture["repository"],
            self.fixture["candidate_run_id"], self.fixture["signing_run_id"], self.fixture["signing_workflow_sha"],
        )

    def test_real_signer_output_fixture_validates_for_publisher(self):
        self.write_inventory(self.first)
        self.git("tag", "release-1")
        result = self.validate()
        self.assertEqual(result["source_revision"], self.first)

    def test_lightweight_and_annotated_tags_peel_to_authenticated_commit(self):
        self.write_inventory(self.first)
        self.git("tag", "release-1")
        self.assertEqual(self.validate()["source_revision"], self.first)
        self.git("tag", "-d", "release-1")
        self.git("tag", "-a", "release-1", "-m", "release")
        self.assertEqual(self.validate()["tag_commit"], self.first)

    def test_mismatched_lightweight_and_annotated_tags_are_rejected(self):
        self.write_inventory(self.first)
        (self.repo / "source").write_text("second\n")
        self.git("commit", "-qam", "second")
        for annotated in (False, True):
            if annotated:
                self.git("tag", "-a", "release-1", "-m", "release")
            else:
                self.git("tag", "release-1")
            with self.assertRaisesRegex(RuntimeError, "tag commit does not match"):
                self.validate()
            self.git("tag", "-d", "release-1")

    def test_branch_name_cannot_substitute_for_missing_tag(self):
        self.write_inventory(self.first)
        self.git("branch", "release-1", self.first)
        with self.assertRaisesRegex(RuntimeError, "exact repository tag"):
            self.validate()

    def test_checkout_must_equal_authenticated_tag_and_artifact_revision(self):
        self.write_inventory(self.first)
        self.git("tag", "release-1", self.first)
        (self.repo / "source").write_text("second\n")
        self.git("commit", "-qam", "second")
        with self.assertRaisesRegex(RuntimeError, "publish checkout does not match"):
            self.validate()

    def test_invalid_or_noncanonical_revision_is_rejected(self):
        self.git("tag", "release-1")
        for revision in ("f" * 64, "F" * 40, "f" * 39, "g" * 40, "refs/heads/main"):
            self.write_inventory(revision)
            with self.assertRaisesRegex(RuntimeError, "canonical lowercase 40-hex"):
                self.validate()

    def test_every_metadata_field_mutation_missing_and_extra_field_is_rejected(self):
        self.git("tag", "release-1")
        self.write_inventory(self.first)
        original = json.loads(self.metadata.read_text())
        mutations = []
        for field, value in original.items():
            mutated = copy.deepcopy(original)
            if isinstance(value, int):
                mutated[field] = value + 1
            elif field == "channel":
                mutated[field] = "beta"
            else:
                mutated[field] = "mutated"
            mutations.append((field, mutated))
        missing = copy.deepcopy(original)
        missing.pop("repository")
        mutations.append(("missing", missing))
        extra = copy.deepcopy(original)
        extra["reviewer_extra"] = True
        mutations.append(("extra", extra))
        for label, metadata in mutations:
            with self.subTest(label=label):
                self.metadata.write_text(json.dumps(metadata))
                with self.assertRaises(RuntimeError):
                    self.validate()

    def test_mutated_workflow_metadata_is_rejected(self):
        self.git("tag", "release-1")
        self.write_inventory(self.first)
        metadata = json.loads(self.metadata.read_text())
        metadata["source_revision"] = "0" * 40
        self.metadata.write_text(json.dumps(metadata))
        with self.assertRaisesRegex(RuntimeError, "workflow metadata source_revision does not match"):
            self.validate()


if __name__ == "__main__":
    unittest.main()
