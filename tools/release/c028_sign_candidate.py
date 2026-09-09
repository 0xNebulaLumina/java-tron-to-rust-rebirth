#!/usr/bin/env python3
"""Minimal offline signer for an already-built C028 unsigned candidate.

This command never executes candidate content. It accepts only regular files, signs the
existing provenance statement and resulting release manifest, and writes metadata only.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path

PROVENANCE_TYPE = "application/vnd.in-toto+json"
RELEASE_TYPE = "application/vnd.tron.release-manifest.v1+json"


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def regular(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise RuntimeError(f"signing input must be a single-link regular file: {path}")


def read_json(path: Path) -> dict:
    regular(path)
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise RuntimeError(f"signing input must be a JSON object: {path}")
    return value


def sign(payload_type: str, payload: bytes, key: Path) -> dict:
    regular(key)
    pae = b"DSSEv1 " + str(len(payload_type)).encode() + b" " + payload_type.encode() + b" " + str(len(payload)).encode() + b" " + payload
    public = subprocess.check_output(["/usr/bin/openssl", "pkey", "-in", str(key), "-pubout", "-outform", "DER"])
    if len(public) < 32:
        raise RuntimeError("invalid Ed25519 public key")
    key_id = sha256(b"ed25519-v1\0" + public[-32:])
    with tempfile.NamedTemporaryFile(prefix="c028-signing-message-", dir=os.environ.get("RUNNER_TEMP")) as message:
        message.write(pae)
        message.flush()
        signature = subprocess.check_output(["/usr/bin/openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", message.name])
    return {"key_id": key_id, "algorithm": "ed25519-v1", "signature": base64.b64encode(signature).decode()}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--signing-key", type=Path, action="append", required=True)
    args = parser.parse_args()
    candidate = args.candidate.resolve(strict=True)
    if len(args.signing_key) < 2:
        raise RuntimeError("candidate authentication requires two signing keys")
    for path in candidate.rglob("*"):
        if path.is_symlink():
            raise RuntimeError(f"candidate symlink is forbidden: {path}")
        if path.is_file():
            regular(path)

    provenance_path = candidate / "bundle/provenance.dsse.json"
    manifest_path = candidate / "release-manifest.json"
    manifest = read_json(manifest_path)
    source_revision = manifest.get("source_revision")
    if not isinstance(source_revision, str) or len(source_revision) != 40 or any(character not in "0123456789abcdef" for character in source_revision):
        raise RuntimeError("source_revision must be a canonical lowercase 40-hex Git SHA-1")
    envelope = read_json(provenance_path)
    payload_type = envelope.get("payloadType", envelope.get("payload_type"))
    if payload_type != PROVENANCE_TYPE or envelope.get("signatures") != []:
        raise RuntimeError("candidate provenance must be the unsigned canonical envelope")
    payload = base64.b64decode(envelope["payload"], validate=True)
    json.loads(payload)
    signatures = [sign(payload_type, payload, key.resolve(strict=True)) for key in args.signing_key]
    if len({item["key_id"] for item in signatures}) != len(signatures):
        raise RuntimeError("candidate signing keys are not independent")
    provenance_path.write_bytes(canonical({"payload_type": payload_type, "payload": base64.b64encode(payload).decode(), "signatures": signatures}))

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise RuntimeError("release manifest artifacts are missing")
    matches = [item for item in artifacts if isinstance(item, dict) and item.get("path") == "provenance.dsse.json"]
    if len(matches) != 1:
        raise RuntimeError("release manifest must contain exactly one provenance subject")
    matches[0]["sha256"] = sha256(provenance_path.read_bytes())
    matches[0]["size"] = provenance_path.stat().st_size
    manifest_raw = canonical(manifest)
    manifest_path.write_bytes(manifest_raw)
    release_signatures = [sign(RELEASE_TYPE, manifest_raw, key.resolve(strict=True)) for key in args.signing_key]
    (candidate / "release-manifest.dsse.json").write_bytes(canonical({"payload_type": RELEASE_TYPE, "payload": base64.b64encode(manifest_raw).decode(), "signatures": release_signatures}))
    inventory = {"schema": "tron-candidate-inventory-v1", "release_id": manifest["release_id"], "channel": manifest["channel"], "release_sequence": manifest["release_sequence"], "source_revision": source_revision, "manifest_sha256": sha256(manifest_raw)}
    (candidate / "candidate-inventory.json").write_bytes(canonical(inventory))
    print(json.dumps(inventory, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
