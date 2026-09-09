from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).with_name("release.py")
SPEC = importlib.util.spec_from_file_location("c028_release_cases", MODULE)
release = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(release)
REPO = MODULE.parents[3]
VERIFIER = REPO / "rust-tron/target/debug/tron-release-verify"


class ReleaseCasesTest(unittest.TestCase):
    def test_all_release_ids_execute_real_verifier_and_observe_rejection_boundary(self):
        expected = {
            "C028-R01-AUTHENTIC-BUNDLE", "C028-R02-MISSING-MANIFEST", "C028-R03-MALFORMED-SIGNATURE",
            "C028-R04-MISMATCHED-MANIFEST", "C028-R05-UNKNOWN-KEY", "C028-R06-EXPIRED-POLICY",
            "C028-R07-REVOKED-KEY", "C028-R08-THRESHOLD", "C028-R09-MISSING-EXTRA-ARTIFACT",
            "C028-R10-SUBSTITUTED-MIRROR-BYTES", "C028-R11-DETACHED-SBOM", "C028-R12-DETACHED-PROVENANCE",
            "C028-R13-MIXED-RELEASE", "C028-R16-TRUST-ROTATION", "C028-R18-PREINSTALL-NO-MUTATION",
        }
        self.assertEqual(set(release.CASES), expected)
        self.assertTrue(VERIFIER.is_file(), "targeted test requires the actual tron-release-verify binary")
        with tempfile.TemporaryDirectory(prefix="c028-release-cases-") as directory:
            context = {"repo_root": REPO, "rust_root": REPO / "rust-tron", "work_dir": Path(directory),
                       "fixture_mode": False, "required_tools": {"tron-release-verify": str(VERIFIER.resolve())}}
            results = {case_id: case(context) for case_id, case in release.CASES.items()}
        for case_id, result in results.items():
            self.assertEqual(result["id"], case_id)
            self.assertEqual(len(result["stdout_sha256"]), 64)
            self.assertEqual(len(result["stderr_sha256"]), 64)
            if case_id == "C028-R01-AUTHENTIC-BUNDLE":
                self.assertEqual((result["exit_code"], result["decision"]), (0, "accept"))
                self.assertEqual(result["details"]["threshold"], 2)
                self.assertEqual(result["details"]["oci_layout"], "bundle/oci/index.json")
            else:
                self.assertNotEqual(result["exit_code"], 0)
                self.assertEqual(result["decision"], "reject_before_mutation")
                self.assertFalse(result["mutation"])
                self.assertEqual(result["before_tree_sha256"], result["after_tree_sha256"])
        preinstall = results["C028-R18-PREINSTALL-NO-MUTATION"]["details"]
        self.assertFalse(preinstall["current_exists"])
        self.assertFalse(preinstall["receipt_exists"])
        self.assertEqual(preinstall["slots"], [])
        self.assertEqual(preinstall["fault"], "noncanonical-release-id-before-install")
        self.assertEqual(preinstall["release_id"], "../escape")

    def test_fixture_mode_and_missing_runtime_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            base = {"repo_root": REPO, "work_dir": Path(directory), "required_tools": {"tron-release-verify": str(VERIFIER)}}
            with self.assertRaisesRegex(RuntimeError, "fixture_mode=False"):
                release.CASES["C028-R01-AUTHENTIC-BUNDLE"]({**base, "fixture_mode": True})
            with self.assertRaisesRegex(RuntimeError, "runtime is unavailable"):
                release.CASES["C028-R01-AUTHENTIC-BUNDLE"]({**base, "fixture_mode": False, "required_tools": {"tron-release-verify": "/missing/verifier"}})
    def test_busybox_and_signing_workflow_cannot_capture_release_keys(self):
        candidate = (REPO / ".github/workflows/c028-release-candidate.yml").read_text()
        signing = (REPO / ".github/workflows/c028-release-sign.yml").read_text()
        publish = (REPO / ".github/workflows/c028-release-publish.yml").read_text()
        generator = (REPO / "tools/release/c028_release.py").read_text()
        self.assertNotIn("SIGNING_KEY_", candidate)
        self.assertNotIn("secrets.", candidate)
        self.assertNotIn("sign-candidate:", candidate)
        self.assertIn("workflow_run:", signing)
        self.assertIn("environment: c028-release-signing", signing)
        self.assertIn("ref: ${{ github.workflow_sha }}", signing)
        self.assertNotIn("ref: ${{ github.event.workflow_run.head_sha }}", signing)
        self.assertIn("C028_SIGNER_SOURCE_SHA256", signing)
        self.assertIn("run-id: ${{ inputs.signing_run_id }}", publish)
        self.assertIn("Run canonical C028 gate before entering release environment", publish)
        privileged_publish = publish.split("  publish:", 1)[1]
        self.assertNotIn("BUSYBOX", privileged_publish)
        self.assertNotIn("busybox", privileged_publish)
        self.assertNotIn("subprocess.run([str(path)]", generator)
        self.assertNotIn('subprocess.run(["file"', generator)
        self.assertIn("_validate_static_elf", generator)

    def test_busybox_policy_is_repository_owned_and_digest_complete(self):
        import json
        policy = json.loads((REPO / "docs/oracles/c028-busybox-material.v1.json").read_text())
        self.assertEqual(policy["schema"], "c028-busybox-material-v1")
        self.assertEqual(len(policy["source"]["sha256"]), 64)
        self.assertEqual(len(policy["material"]["sha256"]), 64)
        self.assertEqual(policy["material"]["license"], "GPL-2.0-only")
        workflow = (REPO / ".github/workflows/c028-release-candidate.yml").read_text()
        self.assertNotIn("busybox_url:", workflow)
        self.assertNotIn("busybox_sha256:", workflow)
    def test_fresh_runner_workflows_reject_ambient_toolchain_and_busybox_fallback(self):
        candidate = (REPO / ".github/workflows/c028-release-candidate.yml").read_text()
        publish = (REPO / ".github/workflows/c028-release-publish.yml").read_text()
        gate_path = REPO / "tools/release/c028_gate.py"
        spec = importlib.util.spec_from_file_location("c028_gate_contract", gate_path)
        gate = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(gate)
        gate.verify_fresh_runner_inputs(candidate, publish)
        mutations = (
            (candidate.replace("rustup toolchain install 1.85.1", "rustup toolchain list # 1.85.1", 1), publish),
            (candidate.replace("print('TRON_BUSYBOX_SHA256='+policy['material']['sha256'])", "print('TRON_BUSYBOX_SHA256='+os.environ['AMBIENT_BUSYBOX_SHA256'])", 1), publish),
            (candidate, publish.replace("rustup override set 1.85.1 rust-tron", "rustc --version", 1)),
            (candidate, publish.replace("dpkg-deb --extract", "command -v busybox #", 1)),
        )
        for changed_candidate, changed_publish in mutations:
            with self.assertRaises(RuntimeError):
                gate.verify_fresh_runner_inputs(changed_candidate, changed_publish)
    def test_isolated_signer_rejects_noncanonical_source_revision_before_signing(self):
        import base64, json, subprocess, sys
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "candidate"
            (candidate / "bundle").mkdir(parents=True)
            (candidate / "release-manifest.json").write_text(json.dumps({"source_revision": "ATTACKER", "artifacts": []}))
            (candidate / "bundle/provenance.dsse.json").write_text(json.dumps({"payloadType": "application/vnd.in-toto+json", "payload": base64.b64encode(b"{}").decode(), "signatures": []}))
            one = Path(directory) / "one.pem"; two = Path(directory) / "two.pem"
            one.write_text("not reached"); two.write_text("not reached")
            completed = subprocess.run([sys.executable, str(REPO / "tools/release/c028_sign_candidate.py"), "--candidate", str(candidate), "--signing-key", str(one), "--signing-key", str(two)], text=True, capture_output=True)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("canonical lowercase 40-hex", completed.stderr)
            self.assertEqual(json.loads((candidate / "bundle/provenance.dsse.json").read_text())["signatures"], [])


if __name__ == "__main__":
    unittest.main()
