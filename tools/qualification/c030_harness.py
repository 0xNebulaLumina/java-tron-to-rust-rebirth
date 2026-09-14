#!/usr/bin/env python3
"""Fail-closed mixed Java/Rust process harness for C030 qualification."""
from __future__ import annotations

import contextlib
import errno
import dataclasses
import hashlib
import http.client
import json
import base64
from datetime import datetime, timezone

import os
import resource
import selectors
import signal
import socket
import struct
import subprocess
import time
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey




@dataclasses.dataclass(frozen=True)
class PreflightRequirement:
    name: str
    kind: str
    status: str
    detail: str
    paths: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class HarnessPreflight:
    requirements: tuple[PreflightRequirement, ...]

    def as_dict(self) -> dict[str, object]:
        missing_external = [item.as_dict() for item in self.requirements if item.kind == "external" and item.status == "missing"]
        unavailable_repository = [item.as_dict() for item in self.requirements if item.kind == "repository" and item.status != "ready"]
        return {
            "schema": "c030-harness-preflight-v1",
            "decision": "ready" if not missing_external and not unavailable_repository else "blocked_external_prerequisites" if missing_external else "repository_incomplete",
            "repository_owned_inputs": [item.as_dict() for item in self.requirements if item.kind == "repository"],
            "external_prerequisites": [item.as_dict() for item in self.requirements if item.kind == "external"],
            "missing_external_prerequisites": missing_external,
            "unavailable_repository_inputs": unavailable_repository,
        }


class HarnessError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
def blake2b_file(path: Path) -> str:
    digest = hashlib.blake2b(digest_size=64)
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_closed_environment(env: Mapping[str, str], allowed: Mapping[str, str], *, label: str) -> dict[str, str]:
    """Return an exact child environment, rejecting inherited or altered values."""
    unexpected = sorted(set(env) - set(allowed))
    missing = sorted(set(allowed) - set(env))
    changed = sorted(key for key in set(env) & set(allowed) if env[key] != allowed[key])
    if unexpected or missing or changed:
        raise HarnessError(f"{label} environment is not closed: unexpected={unexpected}, missing={missing}, changed={changed}")
    return dict(allowed)


def verify_ed25519_private_keys(paths: Sequence[Path]) -> tuple[dict[str, object], ...]:
    """Verify private-key algorithm and require distinct public identities."""
    identities: set[str] = set()
    rows = []
    for path in paths:
        if not path.is_file() or path.is_symlink():
            raise HarnessError(f"signing key must be a non-symlink regular file: {path}")
        completed = subprocess.run(
            ["openssl", "pkey", "-in", str(path), "-pubout", "-outform", "DER"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=10,
        )
        if completed.returncode != 0:
            raise HarnessError(f"unparseable signing key {path}: {completed.stderr.decode('utf-8', 'replace')[-500:]}")
        # SubjectPublicKeyInfo for Ed25519 contains the id-Ed25519 OID 1.3.101.112.
        if b"\x06\x03\x2b\x65\x70" not in completed.stdout:
            raise HarnessError(f"signing key is not Ed25519: {path}")
        identity = hashlib.sha256(completed.stdout).hexdigest()
        if identity in identities:
            raise HarnessError(f"duplicate Ed25519 signing identity: {path}")
        identities.add(identity)
        rows.append({"path": str(path.resolve()), "public_identity_sha256": identity})
    if len(rows) < 2:
        raise HarnessError("at least two distinct Ed25519 signing identities are required")
    return tuple(rows)


def verify_busybox(path: Path, material: Mapping[str, object]) -> dict[str, object]:
    expected = material["material"]
    elf = material["elf"]
    if sha256_file(path) != expected["sha256"]:
        raise HarnessError("BusyBox SHA-256 does not match frozen C028 material")
    header = path.read_bytes()[:64]
    if len(header) < 64 or header[:4] != b"\x7fELF" or header[4] != 2 or header[5] != 1:
        raise HarnessError("BusyBox must be a little-endian ELF64 executable")
    machine = struct.unpack_from("<H", header, 18)[0]
    if machine != 62 or elf != {"class": 64, "endianness": "little", "machine": "x86_64", "static": True}:
        raise HarnessError("BusyBox must be the frozen x86_64 ELF material")
    program_offset = struct.unpack_from("<Q", header, 32)[0]
    program_entry_size = struct.unpack_from("<H", header, 54)[0]
    program_count = struct.unpack_from("<H", header, 56)[0]
    with path.open("rb") as stream:
        stream.seek(program_offset)
        program_headers = stream.read(program_entry_size * program_count)
    dynamic = any(struct.unpack_from("<I", program_headers, i * program_entry_size)[0] == 2 for i in range(program_count))
    if dynamic:
        raise HarnessError("BusyBox must be statically linked")
    completed = subprocess.run([str(path), "--help"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10, check=False)
    marker = str(expected["version_marker"])
    if completed.returncode != 0 or marker.encode() not in completed.stdout.splitlines()[0]:
        raise HarnessError(f"BusyBox version marker must be exactly {marker}")
    return {"path": str(path.resolve()), "sha256": expected["sha256"], "elf_class": 64, "endianness": "little", "machine": "x86_64", "static": True, "version": expected["version"]}


def frozen_tree_inventory(root: Path) -> tuple[list[dict[str, object]], str]:
    rows: list[dict[str, object]] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise HarnessError(f"frozen inventory contains symlink: {path}")
        if path.is_file():
            rows.append({"path": path.relative_to(root).as_posix(), "size": path.stat().st_size, "sha256": sha256_file(path)})
    return rows, canonical_sha256(rows)


def verify_frozen_tree(root: Path, expected_inventory: Sequence[Mapping[str, object]], expected_digest: str, *, label: str) -> dict[str, object]:
    inventory, digest = frozen_tree_inventory(root)
    if inventory != list(expected_inventory) or digest != expected_digest:
        raise HarnessError(f"{label} frozen inventory/digest mismatch")
    return {"path": str(root.resolve()), "inventory": inventory, "digest": digest}
def _timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise HarnessError(f"{label} must be an RFC3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise HarnessError(f"invalid {label}") from error
    if parsed.tzinfo is None:
        raise HarnessError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def verify_signed_envelope(path: Path, trust_store_path: Path, *, payload_type: str, role: str,
                           verification_time: str) -> tuple[dict[str, object], dict[str, object]]:
    """Authenticate one canonical JSON payload under an externally supplied Ed25519 trust role."""
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
        trust = json.loads(trust_store_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise HarnessError(f"malformed authenticated input: {error}") from error
    if not isinstance(envelope, dict) or not isinstance(trust, dict):
        raise HarnessError("authenticated envelope and trust store must be JSON objects")
    if envelope.get("payload_type", envelope.get("payloadType")) != payload_type:
        raise HarnessError(f"authenticated envelope payload type must be {payload_type}")
    try:
        payload = base64.b64decode(envelope["payload"], validate=True)
        document = json.loads(payload)
    except (KeyError, ValueError, json.JSONDecodeError) as error:
        raise HarnessError(f"malformed authenticated envelope payload: {error}") from error
    if not isinstance(document, dict) or payload != json.dumps(document, sort_keys=True, separators=(",", ":")).encode():
        raise HarnessError("authenticated envelope payload is not canonical JSON")
    now = _timestamp(verification_time, "verification time")
    if now > _timestamp(trust.get("expires"), "trust store expiry"):
        raise HarnessError("authenticated input trust store is expired")
    roles = [item for item in trust.get("roles", []) if isinstance(item, dict) and item.get("name") == role and item.get("scope") == role]
    if len(roles) != 1:
        raise HarnessError(f"trust store must authorize exactly one {role} role")
    policy = roles[0]
    authorized = policy.get("key_ids")
    threshold = policy.get("threshold")
    if not isinstance(authorized, list) or not authorized or not isinstance(threshold, int) or threshold < 1:
        raise HarnessError(f"invalid {role} trust policy")
    keys = {item.get("key_id"): item for item in trust.get("keys", []) if isinstance(item, dict)}
    pae = b"DSSEv1 " + str(len(payload_type)).encode() + b" " + payload_type.encode() + b" " + str(len(payload)).encode() + b" " + payload
    verified: set[str] = set()
    for signature in envelope.get("signatures", []):
        if not isinstance(signature, dict) or signature.get("algorithm") != "ed25519-v1":
            continue
        key_id = signature.get("key_id")
        key = keys.get(key_id)
        if key_id not in authorized or not isinstance(key, dict) or key.get("algorithm") != "ed25519-v1" or key.get("revoked") is not False:
            continue
        if not (_timestamp(key.get("not_before"), "key not_before") <= now <= _timestamp(key.get("not_after"), "key not_after")):
            continue
        try:
            public = base64.b64decode(key["public_key_base64"], validate=True)
            raw_signature = base64.b64decode(signature["signature"], validate=True)
            if hashlib.sha256(b"ed25519-v1\0" + public).hexdigest() != key_id:
                continue
            Ed25519PublicKey.from_public_bytes(public).verify(raw_signature, pae)
        except (KeyError, ValueError, InvalidSignature):
            continue
        verified.add(key_id)
    if len(verified) < threshold:
        raise HarnessError(f"authenticated input lacks the authorized {role} Ed25519 threshold")
    return document, {"role": role, "key_ids": sorted(verified), "payload_sha256": hashlib.sha256(payload).hexdigest()}


def verify_gradle_cache_inventory(root: Path, envelope_path: Path, trust_store_path: Path, *, verification_time: str) -> dict[str, object]:
    document, authentication = verify_signed_envelope(
        envelope_path, trust_store_path, payload_type="application/vnd.tron.c030-gradle-cache-inventory.v1+json",
        role="c030-gradle-cache-inventory", verification_time=verification_time)
    if set(document) != {"schema", "root", "inventory", "digest"} or document.get("schema") != "c030-gradle-cache-inventory-v1":
        raise HarnessError("invalid signed Gradle cache inventory contract")
    if document.get("root") != str(root.resolve()):
        raise HarnessError("signed Gradle cache inventory is bound to a different canonical root")
    inventory = document.get("inventory")
    if not isinstance(inventory, list) or any(not isinstance(row, dict) or set(row) != {"path", "size", "sha256"} for row in inventory):
        raise HarnessError("signed Gradle cache inventory records must contain exactly path, size, and sha256")
    if inventory != sorted(inventory, key=lambda row: row["path"]) or len({row["path"] for row in inventory}) != len(inventory):
        raise HarnessError("signed Gradle cache inventory paths must be unique and lexicographically ordered")
    for row in inventory:
        path = row["path"]
        if not isinstance(path, str) or not path or path.startswith("/") or ".." in Path(path).parts or not isinstance(row["size"], int) or row["size"] < 0 or not isinstance(row["sha256"], str) or len(row["sha256"]) != 64:
            raise HarnessError("invalid signed Gradle cache inventory record")
    if document.get("digest") != canonical_sha256(inventory):
        raise HarnessError("signed Gradle cache canonical digest mismatch")
    verified = verify_frozen_tree(root, inventory, document["digest"], label="Gradle cache")
    return {**verified, "authentication": authentication}


def verify_host_attestation(envelope_path: Path, trust_store_path: Path, *, verification_time: str,
                            expected: Mapping[str, object]) -> dict[str, object]:
    document, authentication = verify_signed_envelope(
        envelope_path, trust_store_path, payload_type="application/vnd.tron.c030-host-attestation.v1+json",
        role="c030-host-attestation", verification_time=verification_time)
    required = {"schema", "not_before", "not_after", "host_identity", "session_id", "spec_sha256", "release_id", "release_sequence", "source_revision", "measurements"}
    if set(document) != required or document.get("schema") != "c030-host-attestation-v1":
        raise HarnessError("invalid signed host-attestation contract")
    now = _timestamp(verification_time, "verification time")
    if not (_timestamp(document["not_before"], "attestation not_before") <= now <= _timestamp(document["not_after"], "attestation not_after")):
        raise HarnessError("signed host attestation is outside its validity window")
    for field, value in expected.items():
        if document.get(field) != value:
            raise HarnessError(f"signed host attestation has wrong {field}")
    measurements = document.get("measurements")
    if not isinstance(measurements, dict):
        raise HarnessError("signed host attestation measurements must be an object")
    return {**measurements, "host_identity": document["host_identity"], "session_id": document["session_id"], "authentication": authentication}



def verify_sapling(path: Path, expected: Mapping[str, object], *, operator_authorized: bool) -> dict[str, object]:
    if not operator_authorized:
        raise HarnessError("Sapling upstream build requires explicit operator authority")
    observed = {"size": path.stat().st_size, "blake2b": blake2b_file(path)}
    if observed != {"size": expected["size"], "blake2b": expected["blake2b"]}:
        raise HarnessError(f"Sapling parameter identity mismatch: {path}")
    return {"path": str(path.resolve()), **observed, "operator_authorized": True}


def extract_head(body: Mapping[str, object]) -> int:
    candidates = (
        body.get("height"), body.get("head"), body.get("block_number"),
        (body.get("block_header") or {}).get("raw_data", {}).get("number") if isinstance(body.get("block_header"), Mapping) else None,
    )
    for value in candidates:
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    raise HarnessError("readiness response did not contain a measurable head height")


def require_head(body: Mapping[str, object], minimum: int) -> int:
    height = extract_head(body)
    if height < minimum:
        raise HarnessError(f"observed head {height} is below required minimum {minimum}")
    return height


def process_children(pid: int) -> list[int]:
    children_path = Path(f"/proc/{pid}/task/{pid}/children")
    try:
        return [int(value) for value in children_path.read_text().split()]
    except FileNotFoundError:
        return []


def process_descendants(pids: Iterable[int]) -> list[int]:
    descendants: set[int] = set()
    pending = list(pids)
    while pending:
        pid = pending.pop()
        for child in process_children(pid):
            if child not in descendants:
                descendants.add(child)
                pending.append(child)
    return sorted(descendants)


def assert_processes_absent(pids: Iterable[int], *, label: str) -> dict[str, object]:
    checked = sorted(set(pids))
    present = [pid for pid in checked if Path(f"/proc/{pid}").exists()]
    if present:
        raise HarnessError(f"{label} remain present: {present}")
    return {"label": label, "checked_pids": checked, "absent": True, "observed_at": utc_now()}


def assert_paths_absent(paths: Iterable[Path], *, label: str) -> dict[str, object]:
    present = [str(path) for path in paths if path.exists()]
    if present:
        raise HarnessError(f"{label} remains present: {present}")
    return {"label": label, "checked_paths": [str(path) for path in paths], "absent": True, "observed_at": utc_now()}


def assert_ports_released(addresses: Iterable[tuple[str, int, int]]) -> list[dict[str, object]]:
    observations = []
    reservation = PortReservation(addresses)
    try:
        for host, port, socktype in addresses:
            observations.append({"host": host, "port": port, "transport": "udp" if socktype == socket.SOCK_DGRAM else "tcp", "bindable": True})
    finally:
        reservation.close()
    return observations


def assert_ports_bound(addresses: Iterable[tuple[str, int, int]]) -> list[dict[str, object]]:
    observations = []
    for host, port, socktype in addresses:
        probe = socket.socket(socket.AF_INET, socktype)
        try:
            try:
                probe.bind((host, port))
            except OSError as error:
                if error.errno != errno.EADDRINUSE:
                    raise
                observations.append({"host": host, "port": port,
                                     "transport": "udp" if socktype == socket.SOCK_DGRAM else "tcp",
                                     "bound": True, "observed_at": utc_now()})
            else:
                raise HarnessError(f"declared port is not bound: {host}:{port}/{socktype}")
        finally:
            probe.close()
    return observations


def verify_evidence_closure(root: Path, expected_paths: Sequence[str]) -> dict[str, object]:
    actual = sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file())
    expected = sorted(expected_paths)
    if actual != expected:
        raise HarnessError(f"evidence closure mismatch: missing={sorted(set(expected)-set(actual))}, unexpected={sorted(set(actual)-set(expected))}")
    files = [EvidenceFile.capture(root / path, root).__dict__ for path in actual]
    return {"paths": actual, "files": files, "closure_sha256": canonical_sha256(files)}
def verify_measured_observations(scenarios: Sequence[Mapping[str, object]], measured: Mapping[str, Mapping[str, object]]) -> dict[str, object]:
    """Close expected observations against concrete evidence-bearing measurements."""
    expected = [str(name) for scenario in scenarios for name in scenario.get("expected_observations", [])]
    missing = sorted(set(expected) - set(measured))
    unexpected = sorted(set(measured) - set(expected))
    invalid = sorted(name for name, value in measured.items()
                     if not isinstance(value, Mapping) or not value or not value.get("evidence_path")
                     or isinstance(value.get("expected"), (bool, type(None)))
                     or isinstance(value.get("actual"), (bool, type(None))))
    if missing or unexpected or invalid:
        raise HarnessError(f"measured observation closure failed: missing={missing}, unexpected={unexpected}, invalid={invalid}")
    rows = [{"id": name, **dict(measured[name])} for name in expected]
    return {"observations": rows, "closure_sha256": canonical_sha256(rows)}

def verify_clean_host(measured: Mapping[str, object], contract: Mapping[str, object]) -> dict[str, object]:
    """Validate every clean-host claim against an explicit measurement."""
    cpu, disk, memory, clock = contract["cpu"], contract["disk"], contract["memory"], contract["clock"]
    checks = {
        "memory_bytes": int(measured.get("memory_bytes", 0)) >= int(memory["bytes"]),
        "swap_disabled": measured.get("swap_enabled") is False,
        "cpu_cores": int(measured.get("logical_cores", 0)) >= int(cpu["logical_cores"]),
        "cpu_governor": measured.get("governor") == cpu["governor"],
        "turbo_recorded_fixed": measured.get("turbo_policy") == cpu["turbo_policy"],
        "load_average": float(measured.get("load_average_15m", float("inf"))) <= float(cpu["load_average_15m_max"]),
        "filesystem": measured.get("filesystem") == disk["filesystem"],
        "dedicated_volume": measured.get("dedicated_data_volume") is disk["dedicated_data_volume"],
        "disk_free": int(measured.get("filesystem_free_bytes", 0)) >= int(disk["free_bytes_minimum"]),
        "no_co_tenants": measured.get("no_co_tenants") is True,
        "clock_synchronized": measured.get("clock_synchronized") is clock["synchronized"],
        "clock_offset": abs(float(measured.get("clock_offset_ms", float("inf")))) <= float(clock["maximum_offset_ms"]),
        "timezone": measured.get("timezone") == clock["timezone"],
        "sysctl_inventory": isinstance(measured.get("sysctl_inventory_sha256"), str) and len(str(measured["sysctl_inventory_sha256"])) == 64,
        "limits_inventory": isinstance(measured.get("limits_inventory_sha256"), str) and len(str(measured["limits_inventory_sha256"])) == 64,
    }
    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        raise HarnessError(f"clean-host requirements failed: {failed}")
    return {"measurements": dict(measured), "checks": checks, "all_passed": True}
class AllExitCleanup:
    """Idempotent outer boundary whose independent cleanup steps preserve every error."""

    def __init__(self, secret_paths: Iterable[Path], evidence_root: Path | None = None):
        self.secret_paths = tuple(secret_paths)
        self.evidence_root = evidence_root
        self.harness: ProcessHarness | None = None
        self.observations: dict[str, object] = {}
        self.error: HarnessError | None = None

    def attach(self, harness: "ProcessHarness") -> "ProcessHarness":
        self.harness = harness
        return harness

    def close(self) -> dict[str, object]:
        if self.observations:
            if self.error is not None:
                raise self.error
            return self.observations
        failures: list[str] = []
        supervised = [item.process.pid for item in self.harness.processes] if self.harness is not None else []
        descendants = process_descendants(supervised)
        shutdown: list[dict[str, object]] = []
        try:
            shutdown = self.harness.shutdown() if self.harness is not None else []
        except BaseException as error:
            failures.append(f"shutdown: {error}")
        for path in self.secret_paths:
            try:
                if path.is_file() and not path.is_symlink():
                    size = path.stat().st_size
                    with path.open("r+b", buffering=0) as stream:
                        stream.write(b"\0" * size)
                        stream.flush()
                        os.fsync(stream.fileno())
                    path.unlink()
            except BaseException as error:
                failures.append(f"scrub {path}: {error}")
        try:
            secret_observation = assert_paths_absent(self.secret_paths, label="key material")
        except BaseException as error:
            failures.append(f"key absence: {error}")
            secret_observation = {"label": "key material", "checked_paths": [str(path) for path in self.secret_paths], "absent": False}
        try:
            supervised_observation = assert_processes_absent(supervised, label="supervised processes")
        except BaseException as error:
            failures.append(f"supervised absence: {error}")
            supervised_observation = {"label": "supervised processes", "checked_pids": supervised, "absent": False}
        try:
            child_observation = assert_processes_absent(descendants, label="descendant processes")
        except BaseException as error:
            failures.append(f"descendant absence: {error}")
            child_observation = {"label": "descendant processes", "checked_pids": descendants, "absent": False}
        try:
            ports = assert_ports_released(self.harness.endpoints) if self.harness is not None else []
        except BaseException as error:
            failures.append(f"port release: {error}")
            ports = []
        try:
            if self.evidence_root is None:
                evidence_inventory = {"paths": [], "files": [], "closure_sha256": canonical_sha256([])}
            else:
                expected_paths = sorted(path.relative_to(self.evidence_root).as_posix()
                                        for path in self.evidence_root.rglob("*") if path.is_file())
                evidence_inventory = verify_evidence_closure(self.evidence_root, expected_paths)
        except BaseException as error:
            failures.append(f"evidence closure: {error}")
            evidence_inventory = {"paths": [], "files": [], "closure_sha256": None}
        self.observations = {"shutdown": shutdown, "supervised_absence": supervised_observation,
                             "child_absence": child_observation, "key_scrub": secret_observation,
                             "ports": ports, "evidence_inventory": evidence_inventory, "failures": failures}
        if failures:
            self.error = HarnessError("all-exit cleanup failed: " + "; ".join(failures))
            raise self.error
        return self.observations

    def __enter__(self) -> "AllExitCleanup":
        return self

    def __exit__(self, exc_type: object, exc: BaseException | None, _: object) -> bool:
        try:
            self.close()
        except BaseException as cleanup_error:
            if exc is not None:
                raise HarnessError(f"qualification failed: {exc}; cleanup failed: {cleanup_error}") from cleanup_error
            raise
        return False

@dataclasses.dataclass(frozen=True)
class EvidenceFile:
    path: str
    sha256: str
    size: int

    @classmethod
    def capture(cls, path: Path, root: Path) -> "EvidenceFile":
        resolved = path.resolve()
        try:
            name = resolved.relative_to(root.resolve()).as_posix()
        except ValueError:
            name = str(resolved)
        return cls(name, sha256_file(resolved), resolved.stat().st_size)


@dataclasses.dataclass(frozen=True)
class NodePlan:
    node_id: str
    implementation: str
    role: str
    ports: Mapping[str, int]
    argv: Sequence[str]
    cwd: Path
    env: Mapping[str, str]
    config: Path
    log: Path
    probe: Callable[[], Mapping[str, object]]


@dataclasses.dataclass
class ManagedProcess:
    plan: NodePlan
    process: subprocess.Popen[bytes]
    log_stream: object
    started_at: str


class PortReservation:
    """Reserve every frozen TCP/UDP endpoint until its owning process is launched."""

    def __init__(self, addresses: Iterable[tuple[str, int, int]]):
        self._sockets: dict[tuple[int, int], socket.socket] = {}
        for host, port, socktype in addresses:
            key = (port, socktype)
            if key in self._sockets:
                raise HarnessError(f"duplicate frozen endpoint {host}:{port}/{socktype}")
            sock = socket.socket(socket.AF_INET, socktype)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            try:
                sock.bind((host, port))
            except OSError as error:
                sock.close()
                self.close()
                raise HarnessError(f"frozen endpoint unavailable {host}:{port}: {error}") from error
            self._sockets[key] = sock

    def release(self, ports: Mapping[str, int]) -> None:
        for name, port in ports.items():
            kinds = (socket.SOCK_DGRAM,) if name == "backup_udp" else ((socket.SOCK_STREAM, socket.SOCK_DGRAM) if name == "p2p_tcp_udp" else (socket.SOCK_STREAM,))
            for kind in kinds:
                sock = self._sockets.pop((port, kind), None)
                if sock is not None:
                    sock.close()

    def close(self) -> None:
        for sock in self._sockets.values():
            sock.close()
        self._sockets.clear()



class ProcessHarness:
    def __init__(self, plans: Sequence[NodePlan], evidence_root: Path, startup_timeout: float = 120.0, shutdown_timeout: float = 30.0):
        self.plans = list(plans)
        self.evidence_root = evidence_root
        self.startup_timeout = startup_timeout
        self.shutdown_timeout = shutdown_timeout
        self.processes: list[ManagedProcess] = []
        endpoints = []
        for plan in plans:
            for name, port in plan.ports.items():
                endpoints.append(("127.0.0.1", port, socket.SOCK_DGRAM if name == "backup_udp" else socket.SOCK_STREAM))
                if name == "p2p_tcp_udp":
                    endpoints.append(("127.0.0.1", port, socket.SOCK_DGRAM))
        self.endpoints = endpoints
        self.reservation = PortReservation(endpoints)
    @staticmethod
    def _child_setup() -> None:
        os.setsid()
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_NOFILE, (4096, 4096))
        with contextlib.suppress(ValueError):
            resource.setrlimit(resource.RLIMIT_NPROC, (256, 256))
        address_space = 16 * 1024 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (address_space, address_space))


    def _assert_alive(self) -> None:
        dead = [(item.plan.node_id, item.process.returncode) for item in self.processes if item.process.poll() is not None]
        if dead:
            raise HarnessError(f"node exited before harness completion: {dead}")

    def start(self) -> list[dict[str, object]]:
        observations = []
        try:
            for plan in self.plans:
                plan.log.parent.mkdir(parents=True, exist_ok=True)
                self.reservation.release(plan.ports)
                log = plan.log.open("xb")
                try:
                    process = subprocess.Popen(
                        list(plan.argv), cwd=plan.cwd, env=dict(plan.env), stdin=subprocess.DEVNULL,
                        stdout=log, stderr=subprocess.STDOUT, preexec_fn=self._child_setup, close_fds=True,
                    )
                except BaseException:
                    log.close()
                    raise
                managed = ManagedProcess(plan, process, log, utc_now())
                self.processes.append(managed)
                deadline = time.monotonic() + self.startup_timeout
                last_error = "probe not attempted"
                successes = 0
                result = {}
                while time.monotonic() < deadline:
                    self._assert_alive()
                    try:
                        result = dict(plan.probe())
                        successes += 1
                        if successes == 3:
                            observations.append({"node_id": plan.node_id, "pid": process.pid, "started_at": managed.started_at, "ready_at": utc_now(), "consecutive_successes": successes, "probe": result})
                            break
                    except (OSError, TimeoutError, HarnessError, json.JSONDecodeError) as error:
                        successes = 0
                        last_error = str(error)
                    selector = selectors.DefaultSelector()
                    with contextlib.suppress(Exception):
                        selector.register(process.sentinel, selectors.EVENT_READ)
                        selector.select(timeout=min(0.25, max(0.0, deadline - time.monotonic())))
                    selector.close()
                else:
                    raise HarnessError(f"readiness timeout for {plan.node_id}: {last_error}")
            self._assert_alive()
            return observations
        except BaseException:
            self.shutdown()
            raise
        finally:
            self.reservation.close()

    def shutdown(self) -> list[dict[str, object]]:
        rows = []
        for item in reversed(self.processes):
            if item.process.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(item.process.pid, signal.SIGTERM)
        deadline = time.monotonic() + self.shutdown_timeout
        for item in reversed(self.processes):
            remaining = max(0.0, deadline - time.monotonic())
            try:
                code = item.process.wait(timeout=remaining)
                forced = False
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(item.process.pid, signal.SIGKILL)
                code = item.process.wait(timeout=5)
                forced = True
            item.log_stream.close()
            rows.append({"node_id": item.plan.node_id, "exit_code": code, "forced": forced, "completed_at": utc_now()})
        self.processes.clear()
        self.reservation.close()
        released = PortReservation(self.endpoints)
        released.close()
        return rows

    def __enter__(self) -> "ProcessHarness":
        return self

    def __exit__(self, *_: object) -> None:
        self.shutdown()


def tcp_probe(host: str, port: int, timeout: float = 1.0) -> dict[str, object]:
    with socket.create_connection((host, port), timeout=timeout) as stream:
        peer = stream.getpeername()
    return {"protocol": "tcp", "endpoint": f"{peer[0]}:{peer[1]}"}


def grpc_probe(host: str, port: int, timeout: float = 1.0) -> dict[str, object]:
    with socket.create_connection((host, port), timeout=timeout) as stream:
        stream.settimeout(timeout)
        stream.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + b"\x00\x00\x00\x04\x00\x00\x00\x00\x00")
        frame = stream.recv(9)
        if len(frame) != 9 or frame[3] not in (4, 7):
            raise HarnessError(f"endpoint {host}:{port} did not complete HTTP/2 settings handshake")
    return {"protocol": "grpc-http2", "endpoint": f"{host}:{port}", "frame_type": frame[3]}


def http_json_probe(host: str, port: int, route: str, method: str = "GET", body: bytes | None = None, timeout: float = 2.0) -> dict[str, object]:
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    headers = {"Content-Type": "application/json"} if body is not None else {}
    try:
        connection.request(method, route, body=body, headers=headers)
        response = connection.getresponse()
        payload = response.read(4 * 1024 * 1024)
    finally:
        connection.close()
    if response.status < 200 or response.status >= 300:
        raise HarnessError(f"HTTP probe {host}:{port}{route} returned {response.status}")
    parsed = json.loads(payload) if payload else {}
    return {"protocol": "http-json", "endpoint": f"{host}:{port}", "route": route, "status": response.status, "body_sha256": hashlib.sha256(payload).hexdigest(), "body": parsed}


def http_status_probe(host: str, port: int, route: str, timeout: float = 2.0) -> dict[str, object]:
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request("GET", route)
        response = connection.getresponse()
        payload = response.read(4 * 1024 * 1024)
    finally:
        connection.close()
    if response.status < 200 or response.status >= 300:
        raise HarnessError(f"HTTP probe {host}:{port}{route} returned {response.status}")
    return {"protocol": "http", "endpoint": f"{host}:{port}", "route": route, "status": response.status, "body_sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}


def rust_ready_probe(binary: Path, deployment: Path, env: Mapping[str, str], minimum_head: int = 1) -> Callable[[], Mapping[str, object]]:
    def probe() -> Mapping[str, object]:
        completed = subprocess.run(
            [str(binary), "probe", "--deployment-config", str(deployment), "--kind", "ready"],
            cwd=deployment.parent, env=dict(env), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=3, check=False,
        )
        if completed.returncode != 0:
            raise HarnessError(completed.stderr.decode("utf-8", "replace")[-1000:])
        try:
            body = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise HarnessError("authenticated readiness probe returned non-JSON output") from error
        if not isinstance(body, Mapping):
            raise HarnessError("authenticated readiness probe returned a non-object")
        height = require_head(body, minimum_head)
        return {"protocol": "authenticated-node-readiness", "deployment_sha256": sha256_file(deployment), "head": height, "body_sha256": hashlib.sha256(completed.stdout).hexdigest()}
    return probe
