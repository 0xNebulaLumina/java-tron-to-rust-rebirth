"""Executable C028 release authentication and pre-install scenarios."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

VERIFY_TIME = "2026-09-08T12:00:00Z"
PLATFORM = "P-LINUX-X64"
RELEASE_TYPE = "application/vnd.tron.release-manifest.v1+json"
PROVENANCE_TYPE = "application/vnd.in-toto+json"


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_sha(path: Path) -> str:
    return _sha(path.read_bytes())


def _tree(root: Path) -> str:
    rows = []
    if root.exists():
        for path in sorted(root.rglob("*")):
            rel = path.relative_to(root).as_posix()
            if path.is_symlink():
                rows.append((rel, "link", os.readlink(path)))
            elif path.is_file():
                rows.append((rel, "file", _file_sha(path), path.stat().st_mode & 0o777))
            else:
                rows.append((rel, "dir", path.stat().st_mode & 0o777))
    return _sha(_canonical(rows))


def _ctx_path(ctx: dict[str, object], name: str, default: Path) -> Path:
    value = ctx.get(name)
    return Path(value) if value is not None else default


def _keys() -> tuple[list[Ed25519PrivateKey], list[str], list[str]]:
    private = [Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32) for seed in (71, 72, 73)]
    public = [key.public_key().public_bytes_raw() for key in private]
    ids = [_sha(b"ed25519-v1\0" + item) for item in public]
    encoded = [base64.b64encode(item).decode() for item in public]
    return private, ids, encoded


def _sign(payload_type: str, payload: bytes, private: list[Ed25519PrivateKey], ids: list[str], signers=(0, 1)) -> dict[str, object]:
    pae = b"DSSEv1 " + str(len(payload_type)).encode() + b" " + payload_type.encode() + b" " + str(len(payload)).encode() + b" " + payload
    return {"payload_type": payload_type, "payload": base64.b64encode(payload).decode(), "signatures": [
        {"key_id": ids[index], "algorithm": "ed25519-v1", "signature": base64.b64encode(private[index].sign(pae)).decode()}
        for index in signers
    ]}


def _fixture(root: Path) -> dict[str, object]:
    bundle = root / "bundle"
    bundle.mkdir(parents=True)
    prefix, config, receipt = root / "install", root / "config", root / "state/receipt.json"
    private, ids, encoded = _keys()
    trust = {"schema": "tron-trust-store-v1", "version": 1, "expires": "2027-01-01T00:00:00Z", "keys": [
        {"key_id": kid, "algorithm": "ed25519-v1", "public_key_base64": pub, "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z", "revoked": False}
        for kid, pub in zip(ids, encoded)
    ], "roles": [
        {"name": "root", "key_ids": ids, "threshold": 2, "scope": "trust-store"},
        {"name": "release:stable", "key_ids": ids, "threshold": 2, "scope": "release:stable"},
        {"name": f"provenance:{PLATFORM}", "key_ids": ids, "threshold": 2, "scope": f"provenance:{PLATFORM}"},
    ]}
    trust_path = root / "external-release-root.json"
    trust_path.write_bytes(_canonical(trust))
    oci_blob = b'{"architecture":"amd64","os":"linux"}\n'
    oci_digest = _sha(oci_blob)
    specs = {
        "tron-fullnode": ("bin/tron-fullnode", "binary", b"fullnode\n", 0o755),
        "tron-solidity": ("bin/tron-solidity", "binary", b"solidity\n", 0o755),
        "tron-toolkit": ("bin/tron-toolkit", "binary", b"toolkit\n", 0o755),
        "tron-release-verify": ("bin/tron-release-verify", "binary", b"verifier\n", 0o755),
        "native-archive": ("archives/native.tar.zst", "archive", b"native archive\n", 0o644),
        "config-archive": ("archives/config.tar.zst", "archive", b"config archive\n", 0o644),
        "oci-image": ("oci/index.json", "oci-index", _canonical({"schemaVersion": 2, "manifests": [{"digest": "sha256:" + oci_digest, "size": len(oci_blob)}]}), 0o644),
        "oci-config-blob": ("blobs/sha256/" + oci_digest, "oci-blob", oci_blob, 0o644),
    }
    artifacts = []
    for logical, (relative, kind, data, mode) in specs.items():
        path = bundle / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data); path.chmod(mode)
        artifacts.append({"logical_name": logical, "path": relative, "kind": kind, "platform_id": PLATFORM, "sha256": _sha(data), "size": len(data), "mode": mode, "media_type": "application/octet-stream", "release_id": "release-fixture"})
    sbom = {"spdxVersion": "SPDX-2.3", "files": [{"fileName": a["path"], "checksums": [{"algorithm": "SHA256", "checksumValue": a["sha256"]}]} for a in artifacts], "packages": []}
    sbom_bytes = _canonical(sbom); (bundle / "sbom.spdx.json").write_bytes(sbom_bytes)
    artifacts.append({"logical_name": "sbom", "path": "sbom.spdx.json", "kind": "sbom", "platform_id": PLATFORM, "sha256": _sha(sbom_bytes), "size": len(sbom_bytes), "mode": 0o644, "media_type": "application/spdx+json", "release_id": "release-fixture"})
    statement = {"_type": "https://in-toto.io/Statement/v1", "subject": [{"name": a["path"], "digest": {"sha256": a["sha256"]}} for a in artifacts], "predicateType": "https://slsa.dev/provenance/v1", "predicate": {"materials": [{"uri": "git+urn:tron:source", "digest": {"gitCommit": "11" * 20}}]}}
    provenance = _canonical(_sign(PROVENANCE_TYPE, _canonical(statement), private, ids))
    (bundle / "provenance.dsse.json").write_bytes(provenance)
    artifacts.append({"logical_name": "provenance", "path": "provenance.dsse.json", "kind": "provenance", "platform_id": PLATFORM, "sha256": _sha(provenance), "size": len(provenance), "mode": 0o644, "media_type": "application/vnd.dsse.envelope.v1+json", "release_id": "release-fixture"})
    manifest = {"schema": "tron-release-manifest-v1", "release_id": "release-fixture", "version": "1.0.0", "release_sequence": 2, "channel": "stable", "source_revision": "11" * 20, "source_date_epoch": 1, "install_prefix": str(prefix), "current_target": str(prefix / "current"), "config_root": str(config), "receipt_path": str(receipt), "production_materials": [{"name": "busybox", "sha256": "22" * 32, "version": "v1.36.1", "license": "GPL-2.0-only", "provenance": "fixture:c028-release-cases/busybox-v1.36.1"}], "platforms": [{"platform_id": PLATFORM, "os": "linux", "architecture": "x86_64", "target": "x86_64-unknown-linux-gnu", "backend": "rustlog", "backend_format": "rustlog-v1", "features": [], "enabled": True}], "artifacts": artifacts, "operator_inputs": [], "compatibility": {"minimum_sequence": 1, "native_resources": []}}
    manifest_path = root / "release-manifest.dsse.json"
    manifest_path.write_bytes(_canonical(_sign(RELEASE_TYPE, _canonical(manifest), private, ids)))
    return {"root": root, "bundle": bundle, "prefix": prefix, "config": config, "receipt": receipt, "trust": trust_path, "trust_value": trust, "manifest": manifest_path, "manifest_value": manifest, "private": private, "ids": ids}


def _rewrite_manifest(fx: dict[str, object], *, signers=(0, 1)) -> None:
    payload = _canonical(fx["manifest_value"])
    Path(fx["manifest"]).write_bytes(_canonical(_sign(RELEASE_TYPE, payload, fx["private"], fx["ids"], signers)))


def _refresh_artifact(fx: dict[str, object], relative: str) -> None:
    path = Path(fx["bundle"]) / relative
    artifact = next(a for a in fx["manifest_value"]["artifacts"] if a["path"] == relative)
    artifact["sha256"], artifact["size"], artifact["mode"] = _file_sha(path), path.stat().st_size, path.stat().st_mode & 0o777


def _run(verifier: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run([str(verifier), *args, "--verification-time", VERIFY_TIME], text=True, capture_output=True, env={**os.environ, "CARGO_NET_OFFLINE": "true"})


def _base_args(fx: dict[str, object]) -> list[str]:
    return ["--trust-store", str(fx["trust"]), "--manifest", str(fx["manifest"]), "--bundle", str(fx["bundle"]), "--platform", PLATFORM, "--channel", "stable", "--minimum-sequence", "1"]


def _result(case_id: str, proc: subprocess.CompletedProcess[str], before: str, after: str, details: dict[str, object], accept: bool = False) -> dict[str, object]:
    decision = "accept" if accept else "reject_before_mutation"
    if accept and proc.returncode != 0:
        raise AssertionError(f"{case_id}: expected success: {proc.stderr}")
    if not accept and proc.returncode == 0:
        raise AssertionError(f"{case_id}: expected rejection")
    if not accept and before != after:
        raise AssertionError(f"{case_id}: rejected operation mutated install state")
    return {"id": case_id, "decision": decision, "mutation": before != after, "exit_code": proc.returncode, "stdout_sha256": _sha(proc.stdout.encode()), "stderr_sha256": _sha(proc.stderr.encode()), "before_tree_sha256": before, "after_tree_sha256": after, "details": details}


def _execute(ctx: dict[str, object], case_id: str, mutate: Callable[[dict[str, object]], tuple[str, list[str], dict[str, object]]]) -> dict[str, object]:
    if ctx.get("fixture_mode") is not False:
        raise RuntimeError(f"{case_id}: canonical release drill requires fixture_mode=False")
    repo = _ctx_path(ctx, "repo_root", Path(__file__).resolve().parents[3])
    work_dir = ctx.get("work_dir")
    if work_dir is None:
        raise RuntimeError(f"{case_id}: work_dir is required")
    tools = ctx.get("required_tools") or {}
    verifier_value = tools.get("tron-release-verify") if isinstance(tools, dict) else None
    verifier = Path(verifier_value) if verifier_value else repo / "rust-tron/target/debug/tron-release-verify"
    if not verifier.is_file():
        raise RuntimeError(f"tron-release-verify runtime is unavailable: {verifier}")
    root = Path(work_dir) / case_id.lower()
    root.mkdir(parents=True, exist_ok=False)
    fx = _fixture(root)
    command, extra, details = mutate(fx)
    before = _tree(Path(fx["prefix"]))
    proc = _run(verifier, [command, *_base_args(fx), *extra] if command in {"verify", "install"} else [command, *extra])
    after = _tree(Path(fx["prefix"]))
    if case_id == "C028-R18-PREINSTALL-NO-MUTATION":
        details.update({"current_exists": (Path(fx["prefix"]) / "current").exists(), "receipt_exists": Path(fx["receipt"]).exists(), "slots": sorted(p.name for p in (Path(fx["prefix"]) / "releases").glob("*") if p.is_dir()) if (Path(fx["prefix"]) / "releases").exists() else []})
    return _result(case_id, proc, before, after, details, accept=case_id == "C028-R01-AUTHENTIC-BUNDLE")


def _authentic(fx): return "verify", [], {"threshold": 2, "channel": "stable", "external_root": str(fx["trust"]), "oci_layout": "bundle/oci/index.json"}
def _missing_manifest(fx): Path(fx["manifest"]).unlink(); return "verify", [], {"fault": "missing-manifest"}
def _malformed_signature(fx):
    env=json.loads(Path(fx["manifest"]).read_text()); env["signatures"][1]["signature"]="not-base64"; Path(fx["manifest"]).write_bytes(_canonical(env)); return "verify", [], {"fault":"malformed-signature"}
def _mismatched_manifest(fx): fx["manifest_value"]["release_id"]="other-release"; _rewrite_manifest(fx); return "verify", [], {"fault":"artifact-release-binding"}
def _unknown_key(fx):
    env=json.loads(Path(fx["manifest"]).read_text()); env["signatures"][0]["key_id"]="00"*32; env["signatures"]=env["signatures"][:1]; Path(fx["manifest"]).write_bytes(_canonical(env)); return "verify", [], {"fault":"unknown-key-id"}
def _expired(fx): fx["trust_value"]["expires"]="2026-01-02T00:00:00Z"; Path(fx["trust"]).write_bytes(_canonical(fx["trust_value"])); return "verify", [], {"fault":"expired-policy"}
def _revoked(fx): fx["trust_value"]["keys"][0]["revoked"]=True; Path(fx["trust"]).write_bytes(_canonical(fx["trust_value"])); return "verify", [], {"fault":"revoked-threshold-signer"}
def _threshold(fx): _rewrite_manifest(fx,signers=(0,)); return "verify", [], {"fault":"threshold-2-with-one-signature"}
def _missing_extra(fx): (Path(fx["bundle"])/"archives/config.tar.zst").unlink(); return "verify", [], {"fault":"missing-required-artifact"}
def _substituted(fx): (Path(fx["bundle"])/"bin/tron-fullnode").write_bytes(b"mirror substitution\n"); return "verify", [], {"fault":"post-manifest-byte-substitution"}
def _detached_sbom(fx): p=Path(fx["bundle"])/"sbom.spdx.json"; value=json.loads(p.read_text()); value["files"].pop(); p.write_bytes(_canonical(value)); _refresh_artifact(fx,"sbom.spdx.json"); _rewrite_manifest(fx); return "verify", [], {"fault":"sbom-subject-detached"}
def _detached_provenance(fx):
    p=Path(fx["bundle"])/"provenance.dsse.json"; env=json.loads(p.read_text()); payload=json.loads(base64.b64decode(env["payload"])); payload["subject"].pop(); p.write_bytes(_canonical(_sign(PROVENANCE_TYPE,_canonical(payload),fx["private"],fx["ids"]))); _refresh_artifact(fx,"provenance.dsse.json"); _rewrite_manifest(fx); return "verify", [], {"fault":"provenance-subject-detached"}
def _mixed(fx): fx["manifest_value"]["artifacts"][0]["release_id"]="release-from-other-candidate"; _rewrite_manifest(fx); return "verify", [], {"fault":"mixed-release-artifact"}
def _rotation(fx):
    candidate=dict(fx["trust_value"]); candidate["version"]=2; candidate["keys"]=list(candidate["keys"]); candidate["keys"][0]=dict(candidate["keys"][0]); candidate["keys"][0]["revoked"]=True
    payload=_canonical(candidate); path=Path(fx["root"])/"release-trust-update.dsse.json"; path.write_bytes(_canonical(_sign("application/vnd.tron.trust-store.v1+json",payload,fx["private"],fx["ids"],signers=(0,))))
    return "verify-trust-update", ["--current",str(fx["trust"]),"--candidate",str(path)], {"fault":"rotation-below-root-threshold","candidate_version":2}
def _preinstall(fx):
    fx["manifest_value"]["release_id"] = "../escape"
    for artifact in fx["manifest_value"]["artifacts"]: artifact["release_id"] = "../escape"
    _rewrite_manifest(fx)
    return "install", ["--prefix",str(fx["prefix"]),"--config-root",str(fx["config"]),"--receipt",str(fx["receipt"]),"--retained-slots","2"], {"fault":"noncanonical-release-id-before-install","release_id":"../escape","current_exists":False,"receipt_exists":False,"slots":[]}

_MUTATORS = {
"C028-R01-AUTHENTIC-BUNDLE":_authentic,"C028-R02-MISSING-MANIFEST":_missing_manifest,"C028-R03-MALFORMED-SIGNATURE":_malformed_signature,"C028-R04-MISMATCHED-MANIFEST":_mismatched_manifest,"C028-R05-UNKNOWN-KEY":_unknown_key,"C028-R06-EXPIRED-POLICY":_expired,"C028-R07-REVOKED-KEY":_revoked,"C028-R08-THRESHOLD":_threshold,"C028-R09-MISSING-EXTRA-ARTIFACT":_missing_extra,"C028-R10-SUBSTITUTED-MIRROR-BYTES":_substituted,"C028-R11-DETACHED-SBOM":_detached_sbom,"C028-R12-DETACHED-PROVENANCE":_detached_provenance,"C028-R13-MIXED-RELEASE":_mixed,"C028-R16-TRUST-ROTATION":_rotation,"C028-R18-PREINSTALL-NO-MUTATION":_preinstall}

def _case(case_id: str):
    def run(ctx: dict[str, object]) -> dict[str, object]: return _execute(ctx, case_id, _MUTATORS[case_id])
    run.__name__ = "case_" + case_id.lower().replace("-", "_")
    return run

CASES: dict[str, Callable[[dict[str, object]], dict[str, object]]] = {case_id: _case(case_id) for case_id in _MUTATORS}
