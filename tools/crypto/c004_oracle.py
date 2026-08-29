#!/usr/bin/env python3
"""Compile and run the pinned Java 8 C004 oracle with authenticated Gradle artifacts."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tools/crypto/C004Oracle.java"
OUTPUT = ROOT / "docs/oracles/c004-crypto-fixture-manifest.v1.json"
JAVA_REVISION = "4a21592f95e37908b21bc3f611c6e7a1a67f09f3"
BC_VERSION = "1.84"
BC_JAR_SHA256 = "64d6c5a6121fcd927152dd182cbed39afe0fda641a970d9bcc0c9cb1858b2731"
BC_POM_SHA256 = "ce7abb4a91ba5d2a73fdf17a3df4762e3605a0392cc7983ef2f1ae16cd384cc3"
MAVEN = "https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/1.84"
DISPATCH = {
    "C004.HASH.SHA256": "java_oracle_hash_vectors",
    "C004.HASH.SM3": "java_oracle_hash_vectors",
    "C004.HASH.KECCAK256": "java_oracle_hash_vectors",
    "C004.HASH.KECCAK512": "java_oracle_hash_vectors",
    "C004.HASH.RIPEMD160": "java_oracle_hash_vectors",
    "C004.KEY.SECP256K1": "java_oracle_key_and_address_vectors",
    "C004.KEY.SM2": "java_oracle_key_and_address_vectors",
    "C004.SIG.SECP256K1": "java_oracle_signature_vectors",
    "C004.SIG.SECP256K1.HIGH_S": "java_oracle_signature_vectors",
    "C004.SIG.SM2": "java_oracle_signature_vectors",
    "C004.BASE58.SECP256K1": "java_oracle_base58check_vectors",
    "C004.BASE58.SM2": "java_oracle_base58check_vectors",
    "C004.ADDRESS.INVALID_PREFIX": "java_oracle_base58check_vectors",
    "C004.WIRE.INGRESS_64": "java_oracle_wire_boundary_vectors",
    "C004.WIRE.INGRESS_65": "java_oracle_wire_boundary_vectors",
    "C004.WIRE.INGRESS_68": "java_oracle_wire_boundary_vectors",
    "C004.WIRE.INGRESS_69": "java_oracle_wire_boundary_vectors",
    "C004.WIRE.CONSENSUS_69": "both_engines_recover_padded_permission_signatures",
    "C004.PERMISSION.TOO_MANY": "fork_aware_permission_duplicate_vectors",
    "C004.PERMISSION.NONMEMBER": "fork_aware_permission_duplicate_vectors",
    "C004.PERMISSION.DUPLICATE_PRE_471": "fork_aware_permission_duplicate_vectors",
    "C004.PERMISSION.DUPLICATE_POST_471": "fork_aware_permission_duplicate_vectors",
    "C004.FORMULA.TOP_LEVEL": "java_oracle_contract_formula_vectors",
    "C004.FORMULA.CREATE.POSITIVE": "java_oracle_contract_formula_vectors",
    "C004.FORMULA.CREATE.NEGATIVE": "java_oracle_contract_formula_vectors",
    "C004.FORMULA.CREATE2": "java_oracle_contract_formula_vectors",
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def artifact(name: str, expected: str, cache: Path) -> Path:
    gradle = Path.home() / ".gradle/caches/modules-2/files-2.1/org.bouncycastle/bcprov-jdk18on" / BC_VERSION
    candidates = list(gradle.glob(f"*/{name}")) + [cache / name]
    for path in candidates:
        if path.is_file() and sha(path) == expected:
            return path
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / name
    with urllib.request.urlopen(f"{MAVEN}/{name}", timeout=30) as response:
        target.write_bytes(response.read())
    if sha(target) != expected:
        target.unlink(missing_ok=True)
        raise RuntimeError(f"authenticated artifact digest mismatch: {name}")
    return target


def generate() -> dict:
    if subprocess.check_output(["git", "-C", str(ROOT / "java-tron"), "rev-parse", "HEAD"], text=True).strip() != JAVA_REVISION:
        raise RuntimeError("java-tron gitlink is not the pinned C004 revision")
    with tempfile.TemporaryDirectory(prefix="c004-oracle-") as temporary:
        temp = Path(temporary)
        jar = artifact(f"bcprov-jdk18on-{BC_VERSION}.jar", BC_JAR_SHA256, temp / "deps")
        artifact(f"bcprov-jdk18on-{BC_VERSION}.pom", BC_POM_SHA256, temp / "deps")
        classes = temp / "classes"
        classes.mkdir()
        subprocess.run(["javac", "--release", "8", "-cp", str(jar), "-d", str(classes), str(SOURCE)], check=True)
        raw = subprocess.check_output(["java", "-cp", os.pathsep.join((str(classes), str(jar))), "C004Oracle"], text=True)
    value = json.loads(raw)
    ids = [row["id"] for row in value["vectors"]]
    if len(ids) != len(set(ids)) or set(ids) != set(DISPATCH):
        raise RuntimeError("Java oracle vector IDs and exhaustive Rust dispatch differ")
    value["rust_dispatch"] = DISPATCH
    payload = json.dumps(value["vectors"], sort_keys=True, separators=(",", ":")).encode()
    value["vectors_sha256"] = hashlib.sha256(payload).hexdigest()
    return value


def encoded(value: dict) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="regenerate the checked-in single artifact")
    args = parser.parse_args()
    expected = encoded(generate())
    if args.write:
        OUTPUT.write_bytes(expected)
        print(f"wrote {OUTPUT.relative_to(ROOT)} ({len(DISPATCH)} Java vectors)")
        return 0
    actual = OUTPUT.read_bytes() if OUTPUT.is_file() else b""
    if actual != expected:
        print("C004 oracle output drift; run tools/crypto/c004_oracle.py --write", file=sys.stderr)
        return 1
    print(f"C004 oracle verified: {len(DISPATCH)} vectors, sha256 {hashlib.sha256(actual).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
