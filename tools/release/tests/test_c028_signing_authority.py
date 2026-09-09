from __future__ import annotations

import copy
import importlib.util
import json
import unittest
import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("c028_gate_signing_tests", ROOT / "tools/release/c028_gate.py")
assert SPEC is not None and SPEC.loader is not None
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class SigningAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.candidate = (ROOT / ".github/workflows/c028-release-candidate.yml").read_text()
        self.signing = (ROOT / ".github/workflows/c028-release-sign.yml").read_text()
        self.publish = (ROOT / ".github/workflows/c028-release-publish.yml").read_text()
        contract = json.loads((ROOT / "docs/oracles/c028-release-contract.v1.json").read_text())
        self.transfer = contract["workflow_transfer"]

    def assert_rejected(self, candidate: str | None = None, signing: str | None = None, transfer: dict | None = None) -> None:
        with self.assertRaises(RuntimeError):
            GATE.verify_signing_authority(candidate or self.candidate, signing or self.signing, transfer or self.transfer)

    def test_production_signing_is_default_branch_workflow_run_authority(self) -> None:
        GATE.verify_signing_authority(self.candidate, self.signing, self.transfer)
        self.assertNotIn("secrets.", self.candidate)
        self.assertNotIn("sign-candidate:", self.candidate)
        self.assertIn("environment: c028-release-signing", self.signing)
        self.assertIn("ref: ${{ github.workflow_sha }}", self.signing)

    def test_signer_cannot_checkout_candidate_revision(self) -> None:
        for candidate_ref in (
            "${{ github.event.workflow_run.head_sha }}",
            "${{ github.event.workflow_run.head_branch }}",
            "${{ github.ref }}",
        ):
            mutated = self.signing.replace("${{ github.workflow_sha }}", candidate_ref)
            self.assert_rejected(signing=mutated)

    def test_workflow_name_or_path_spoof_is_rejected(self) -> None:
        self.assert_rejected(signing=self.signing.replace("workflows: [C028 release candidate]", "workflows: [Attacker candidate]"))
        self.assert_rejected(signing=self.signing.replace(".github/workflows/c028-release-candidate.yml", ".github/workflows/spoof.yml"))

    def test_fork_branch_failure_and_stale_head_guards_are_required(self) -> None:
        guards = (
            "github.event.workflow_run.conclusion == 'success'",
            "github.event.workflow_run.head_repository.full_name == github.repository",
            "github.event.workflow_run.head_branch == github.event.repository.default_branch",
            'test "$DEFAULT_SHA" = "$RUN_HEAD_SHA"',
        )
        for guard in guards:
            self.assert_rejected(signing=self.signing.replace(guard, "true"))

    def test_candidate_cannot_supply_signer_digest_or_bytes(self) -> None:
        mutated = self.candidate + "\nSIGNER_SHA256: " + "0" * 64 + "\nSIGNER_B64: candidate-controlled\n"
        self.assert_rejected(candidate=mutated)

    def test_contract_cannot_move_digest_authority_to_candidate(self) -> None:
        transfer = copy.deepcopy(self.transfer)
        transfer["signer_authority"]["signer_digest_source"] = "candidate workflow input"
        self.assert_rejected(transfer=transfer)

    def test_direct_or_reusable_signing_trigger_is_rejected(self) -> None:
        self.assert_rejected(signing=self.signing + "\nworkflow_dispatch:\n")
        self.assert_rejected(signing=self.signing + "\nworkflow_call:\n")

    def test_action_policy_simulation_accepts_only_protected_default_head(self) -> None:
        sha = "a" * 40
        repository = "0xNebulaLumina/java-tron-to-rust-rebirth"
        event = {"workflow_run": {
            "name": "C028 release candidate",
            "path": ".github/workflows/c028-release-candidate.yml",
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "success",
            "repository": {"full_name": repository},
            "head_repository": {"full_name": repository},
            "head_branch": "main",
            "head_sha": sha,
        }}
        self.assertTrue(GATE.signing_trigger_allowed(event, repository, "main", sha))
        mutations = (
            ("name", "C028 release candidate spoof"),
            ("path", ".github/workflows/spoof.yml"),
            ("event", "pull_request"),
            ("status", "in_progress"),
            ("conclusion", "failure"),
            ("repository", {"full_name": "attacker/fork"}),
            ("head_repository", {"full_name": "attacker/fork"}),
            ("head_branch", "feature"),
            ("head_sha", "b" * 40),
        )
        for field, value in mutations:
            mutated = copy.deepcopy(event)
            mutated["workflow_run"][field] = value
            self.assertFalse(GATE.signing_trigger_allowed(mutated, repository, "main", sha), field)

    def test_all_workflow_shell_source_is_free_of_untrusted_expressions(self) -> None:
        workflows = {
            "c028-release-candidate.yml": self.candidate,
            "c028-release-sign.yml": self.signing,
            "c028-release-publish.yml": self.publish,
        }
        GATE.verify_workflow_shell_safety(workflows)
        mutations = {
            "c028-release-candidate.yml": self.candidate + '\n      - run: echo "${{ inputs.release_id }}"\n',
            "c028-release-sign.yml": self.signing + '\n      - run: echo "${{ github.event.workflow_run.head_branch }}"\n',
            "c028-release-publish.yml": self.publish.replace('test -n "$RELEASE_TAG"', 'test -n "${{ inputs.release_tag }}"'),
        }
        for name, mutation in mutations.items():
            changed = dict(workflows)
            changed[name] = mutation
            with self.assertRaisesRegex(RuntimeError, "embedded in shell source"):
                GATE.verify_workflow_shell_safety(changed)

    def test_release_id_boundaries_match_at_candidate_signer_and_publish(self) -> None:
        accepted = ("A", "A" * 128, "R1.2_beta-3")
        rejected = ("", "-option", ".hidden", "_private", "A" * 129, "release\ncommand")
        for value in accepted:
            self.assertTrue(GATE.canonical_release_id(value), repr(value))
        for value in rejected:
            self.assertFalse(GATE.canonical_release_id(value), repr(value))

        guards = (
            (GATE.RELEASE_ID_GUARDS["c028-release-candidate.yml"], "RELEASE_ID"),
            (GATE.RELEASE_ID_GUARDS["c028-release-sign.yml"], "RELEASE_ID"),
            (GATE.RELEASE_ID_GUARDS["c028-release-publish.yml"], "EXPECTED_RELEASE_ID"),
        )
        for guard_script, variable in guards:
            for value in accepted:
                result = subprocess.run(["bash", "-c", guard_script], env={**os.environ, variable: value})
                self.assertEqual(result.returncode, 0, (variable, repr(value)))
            for value in rejected:
                result = subprocess.run(["bash", "-c", guard_script], env={**os.environ, variable: value})
                self.assertNotEqual(result.returncode, 0, (variable, repr(value)))

    def test_release_id_guard_removal_or_weakening_is_rejected(self) -> None:
        workflows = {
            "c028-release-candidate.yml": self.candidate,
            "c028-release-sign.yml": self.signing,
            "c028-release-publish.yml": self.publish,
        }
        for name, guard in GATE.RELEASE_ID_GUARDS.items():
            for replacement in ("true", guard.replace("{0,127}", "*")):
                mutated = dict(workflows)
                mutated[name] = mutated[name].replace(guard, replacement)
                with self.assertRaisesRegex(RuntimeError, "release ID guard missing or drifted"):
                    GATE.verify_workflow_shell_safety(mutated)


if __name__ == "__main__":
    unittest.main()
