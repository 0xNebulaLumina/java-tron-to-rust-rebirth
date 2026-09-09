from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
import subprocess
import sys
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("container.py")
SPEC = importlib.util.spec_from_file_location("c028_container_cases", MODULE_PATH)
container = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(container)
ROOT = Path(__file__).resolve().parents[3]
LAUNCHER_PATH = ROOT / "tools" / "release" / "c028_compose.py"
LAUNCHER_SPEC = importlib.util.spec_from_file_location("c028_compose", LAUNCHER_PATH)
launcher = importlib.util.module_from_spec(LAUNCHER_SPEC)
assert LAUNCHER_SPEC.loader
LAUNCHER_SPEC.loader.exec_module(launcher)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def make_layout(root: Path) -> Path:
    layout = root / "layout"
    blobs = layout / "blobs" / "sha256"
    blobs.mkdir(parents=True)
    raw_buffer = io.BytesIO()
    with tarfile.open(fileobj=raw_buffer, mode="w") as archive:
        for name in ("opt/tron", "etc/tron", "var/lib/tron"):
            member = tarfile.TarInfo(name)
            member.type = tarfile.DIRTYPE
            member.mode = 0o755
            member.uid = member.gid = 65532
            archive.addfile(member)
        for name in ("usr/local/bin/entrypoint.sh", "usr/local/bin/tron-release-verify", "opt/tron/current/bin/tron-fullnode", "opt/tron/current/bin/tron-solidity", "bin/sh"):
            payload = b"#!/bin/sh\nexit 0\n"
            member = tarfile.TarInfo(name)
            member.mode = 0o755
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
    raw = raw_buffer.getvalue()
    compressed = gzip.compress(raw, mtime=0)
    layer_digest = hashlib.sha256(compressed).hexdigest()
    (blobs / layer_digest).write_bytes(compressed)
    config = canonical({"architecture": "amd64", "os": "linux", "config": {"User": "65532:65532", "Entrypoint": ["/usr/local/bin/entrypoint.sh"]}, "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(raw).hexdigest()]}})
    config_digest = hashlib.sha256(config).hexdigest()
    (blobs / config_digest).write_bytes(config)
    manifest = canonical({"schemaVersion": 2, "config": {"digest": "sha256:" + config_digest, "size": len(config)}, "layers": [{"digest": "sha256:" + layer_digest, "size": len(compressed)}]})
    manifest_digest = hashlib.sha256(manifest).hexdigest()
    (blobs / manifest_digest).write_bytes(manifest)
    (layout / "oci-layout").write_bytes(canonical({"imageLayoutVersion": "1.0.0"}))
    (layout / "index.json").write_bytes(canonical({"schemaVersion": 2, "manifests": [{"digest": "sha256:" + manifest_digest, "size": len(manifest)}]}))
    return layout


class ContainerCasesTest(unittest.TestCase):
    def test_registry_exports_manifest_case(self) -> None:
        self.assertEqual(set(container.CASES), {"C028-R21-CONTAINER-SERVICE"})
        self.assertIs(container.CASES["C028-R21-CONTAINER-SERVICE"], container.container_service)

    def test_oci_loader_authenticates_diffid_and_executable_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            layout = make_layout(root)
            index, config, digest = container._load_oci(layout, root / "rootfs")
            self.assertEqual(index["schemaVersion"], 2)
            self.assertEqual(config["config"]["User"], "65532:65532")
            self.assertTrue(digest.startswith("sha256:"))

    def test_oci_loader_rejects_false_diffid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            layout = make_layout(root)
            index = json.loads((layout / "index.json").read_text())
            manifest_path = layout / "blobs" / "sha256" / index["manifests"][0]["digest"][7:]
            manifest = json.loads(manifest_path.read_text())
            config_path = layout / "blobs" / "sha256" / manifest["config"]["digest"][7:]
            config = json.loads(config_path.read_text())
            config["rootfs"]["diff_ids"] = ["sha256:" + "0" * 64]
            changed = canonical(config)
            changed_digest = hashlib.sha256(changed).hexdigest()
            (layout / "blobs" / "sha256" / changed_digest).write_bytes(changed)
            manifest["config"] = {"digest": "sha256:" + changed_digest, "size": len(changed)}
            changed_manifest = canonical(manifest)
            changed_manifest_digest = hashlib.sha256(changed_manifest).hexdigest()
            (layout / "blobs" / "sha256" / changed_manifest_digest).write_bytes(changed_manifest)
            index["manifests"] = [{"digest": "sha256:" + changed_manifest_digest, "size": len(changed_manifest)}]
            (layout / "index.json").write_bytes(canonical(index))
            with self.assertRaisesRegex(RuntimeError, "diffID"):
                container._load_oci(layout, root / "rootfs")

    def test_compose_requires_exactly_one_explicit_node_profile(self) -> None:
        text = (ROOT / "rust-tron" / "packaging" / "container" / "compose.yaml").read_text()
        self.assertIn("fullnode:\n    <<: *tron-service\n    profiles: [full]", text)
        self.assertIn("solidity:\n    <<: *tron-service\n    command: [\"solidity\"]\n    profiles: [solidity]", text)
    def test_launcher_constructs_one_profile_and_rejects_all_other_shapes(self) -> None:
        for mode in ("full", "solidity"):
            command, env = launcher.compose_command([mode], {})
            self.assertEqual(command, ["docker", "compose", "--profile", mode, "up", "--detach"])
            self.assertEqual(env["COMPOSE_PROFILES"], mode)
        for arguments, env in (([], {}), (["full", "solidity"], {}), (["archive"], {}), (["full"], {"COMPOSE_PROFILES": "full,solidity"}), (["full"], {"COMPOSE_PROFILES": "solidity"})):
            with self.assertRaises(ValueError):
                launcher.compose_command(arguments, env)

    def test_invalid_launcher_inputs_reject_before_docker_lookup(self) -> None:
        for arguments, env in (([], {}), (["full", "solidity"], {}), (["unknown"], {}), (["full"], {"COMPOSE_PROFILES": "full,solidity"})):
            child_env = {"PATH": "/definitely/no/docker", **env}
            result = subprocess.run([sys.executable, str(LAUNCHER_PATH), *arguments], env=child_env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 64)
            self.assertIn("usage" if arguments != ["full"] else "COMPOSE_PROFILES", result.stderr)

    def test_entrypoint_rejects_dual_profile_before_material_checks(self) -> None:
        entrypoint = ROOT / "rust-tron" / "packaging" / "container" / "entrypoint.sh"
        env = dict(container.os.environ, TRON_COMPOSE_PROFILES="full,solidity", TRON_VERIFICATION_TIME="2026-09-08T12:00:00Z")
        result = subprocess.run(["/bin/sh", str(entrypoint), "fullnode"], env=env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 64)
        self.assertIn("multiple or unknown Compose profiles", result.stderr)
        self.assertNotIn("mandatory deployment material", result.stderr)

    def test_packaged_compose_and_systemd_load_with_real_tools(self) -> None:
        if not container.shutil.which("docker") or not container.shutil.which("systemd-analyze"):
            self.skipTest("docker Compose and systemd-analyze are not installed")
        with tempfile.TemporaryDirectory() as temporary:
            observed = container._packaging(ROOT, Path(temporary), "sha256:" + "a" * 64)
        self.assertEqual(observed["default_services"], [])
        self.assertEqual(observed["compose_profiles"]["full"]["service"], "fullnode")
        self.assertEqual(observed["compose_profiles"]["solidity"]["service"], "solidity")

    def test_entrypoint_rejects_missing_and_malformed_time_before_material_checks(self) -> None:
        entrypoint = ROOT / "rust-tron" / "packaging" / "container" / "entrypoint.sh"
        for value in (None, "2026-09-08 12:00:00", "2026-09-08T12:00:00+00:00", "2026-99-08T12:00:00Z"):
            env = dict(container.os.environ)
            if value is None:
                env.pop("TRON_VERIFICATION_TIME", None)
            else:
                env["TRON_VERIFICATION_TIME"] = value
            result = subprocess.run(["/bin/sh", str(entrypoint), "fullnode"], env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 64)
            self.assertIn("TRON_VERIFICATION_TIME", result.stderr)
            self.assertNotIn("mandatory deployment material", result.stderr)


if __name__ == "__main__":
    unittest.main()
