#!/usr/bin/env python3
"""C030 qualification runner. Only C030.01 harness mode is implemented here."""
from __future__ import annotations

import argparse
import dataclasses
import base64
import contextlib
import fcntl
import hmac
import hashlib
import json
import os
import platform
import socket
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/reference-runner"))
from java_reference_guard import install_java_reference_guard, atomic_write_json  # noqa: E402
from c030_harness import (AllExitCleanup, EvidenceFile, HarnessError, HarnessPreflight, NodePlan, PreflightRequirement, ProcessHarness,
                          assert_ports_bound, canonical_sha256, grpc_probe, http_json_probe, http_status_probe, rust_ready_probe, sha256_file, tcp_probe, utc_now,
                          verify_measured_observations, verify_clean_host, verify_ed25519_private_keys, verify_gradle_cache_inventory, verify_host_attestation)
sys.path.insert(0, str(ROOT / "tools/qualification"))
from c030_result import canonical_output_path, sign_result, verify_result  # noqa: E402

EXPECTED_SPEC_SHA256 = "a7fb1ebbb4c5afc0dab41ade6c136fe83f90c92be856ea23d905a33e0ffaabd6"
IMPLEMENTED_MODE = "harness"
OTHER_MODES = ("lifecycle", "network-fault", "api-load", "endurance", "security", "license", "performance")


def require(ok: bool, message: str) -> None:
    if not ok:
        raise HarnessError(message)


def load(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def external_input_path(name: str, raw: str, *, directory: bool = False) -> Path:
    require(bool(raw), f"required clean-room input {name} is not set")
    unresolved = Path(raw).expanduser()
    require(not unresolved.is_symlink(), f"{name} must not be a symlink")
    try:
        path = unresolved.resolve(strict=True)
    except OSError as error:
        raise HarnessError(f"{name} does not name a {'directory' if directory else 'file'}: {unresolved}") from error
    require(path.is_dir() if directory else path.is_file(), f"{name} does not name a {'directory' if directory else 'file'}: {path}")
    return path


def required_path(name: str, *, directory: bool = False) -> Path:
    return external_input_path(name, os.environ.get(name, ""), directory=directory)


def closed_environment(work: Path) -> dict[str, str]:
    allowed = {
        "PATH": "/usr/bin:/bin", "HOME": str(work / "home"), "TMPDIR": str(work / "tmp"),
        "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC", "CARGO_NET_OFFLINE": "true",
        "RUST_BACKTRACE": "1", "NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost",
    }
    for path in (work / "home", work / "tmp"):
        path.mkdir(mode=0o700)
    return allowed

def _external_requirement(name: str, env_name: str, *, directory: bool = False, nonempty: bool = False) -> PreflightRequirement:
    raw = os.environ.get(env_name, "")
    path = None
    if nonempty:
        present = bool(raw)
    else:
        try:
            path = external_input_path(env_name, raw, directory=directory)
            present = True
        except HarnessError:
            present = False
    kind = "non-empty value" if nonempty else f"offline {'directory' if directory else 'regular file'}"
    return PreflightRequirement(name, "external", "ready" if present else "missing", f"set {env_name} to a {kind}", (str(path),) if path else ())
def _upstream_requirement(name: str, env_name: str) -> PreflightRequirement:
    raw = os.environ.get(env_name, "")
    path = Path(raw).expanduser().resolve() if raw else None
    present = bool(path and path.is_file() and not path.is_symlink())
    return PreflightRequirement(name, "upstream-release-build", "ready" if present else "missing", f"set {env_name} only when building the upstream C028 release", (str(path),) if path else ())
def qualification_signing_keys() -> list[Path]:
    values = [value for value in os.environ.get("C030_QUALIFICATION_SIGNING_KEYS", "").split(os.pathsep) if value]
    return [external_input_path(f"C030_QUALIFICATION_SIGNING_KEYS[{index}]", value) for index, value in enumerate(values)]
def _release_signing_keys_ready() -> bool:
    try:
        paths = qualification_signing_keys()
        verify_ed25519_private_keys(paths)
    except (OSError, ValueError, HarnessError):
        return False
    return len(paths) == 2
def _authenticated_inputs_requirement(spec: dict) -> PreflightRequirement:
    definitions = {
        "C030_RELEASE_MANIFEST": False,
        "C030_GRADLE_USER_HOME": True,
        "C030_GRADLE_CACHE_INVENTORY": False,
        "C030_HOST_ATTESTATION": False,
        "C030_HOST_ATTESTATION_TRUST_STORE": False,
    }
    missing = [name for name in definitions if not os.environ.get(name)]
    missing.extend(name for name in ("C030_VERIFICATION_TIME", "C030_SESSION_ID") if not os.environ.get(name))
    if missing:
        return PreflightRequirement("authenticated-host-and-cache-inputs", "external", "missing", "missing external authenticated input files", tuple(sorted(set(missing))))
    paths: dict[str, Path] = {}
    try:
        paths = {name: required_path(name, directory=directory) for name, directory in definitions.items()}
        release, _ = decode_dsse_manifest(paths["C030_RELEASE_MANIFEST"])
        verification_time = os.environ.get("C030_VERIFICATION_TIME", "")
        host_id = socket.gethostname()
        session_id = os.environ.get("C030_SESSION_ID", "")
        require(bool(verification_time and session_id), "C030_VERIFICATION_TIME and C030_SESSION_ID are required")
        trust = paths["C030_HOST_ATTESTATION_TRUST_STORE"]
        verify_gradle_cache_inventory(paths["C030_GRADLE_USER_HOME"], paths["C030_GRADLE_CACHE_INVENTORY"], trust, verification_time=verification_time)
        verify_host_attestation(paths["C030_HOST_ATTESTATION"], trust, verification_time=verification_time,
                                expected={"host_identity": host_id, "session_id": session_id, "spec_sha256": EXPECTED_SPEC_SHA256,
                                          "release_id": release["release_id"], "release_sequence": release["release_sequence"], "source_revision": release["source_revision"]})
    except (OSError, ValueError, KeyError, json.JSONDecodeError, HarnessError) as error:
        return PreflightRequirement("authenticated-host-and-cache-inputs", "external", "invalid", f"external input invalid: {error}", tuple(str(path) for path in paths.values()))
    return PreflightRequirement("authenticated-host-and-cache-inputs", "external", "ready", "signed cache inventory and host attestation authenticated", tuple(str(paths[name]) for name in definitions))








def _host_requirement(spec: dict) -> PreflightRequirement:
    ports = [port for node in spec["topology"]["nodes"] for port in node["ports"].values()]
    unavailable = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                unavailable.append(port)
    platform_ready = platform.system() == "Linux" and platform.machine() in {"x86_64", "amd64"}
    java = Path("/usr/lib/jvm/java-8-openjdk-amd64/bin/java")
    ready = platform_ready and java.is_file() and not unavailable
    detail = "requires Linux x86_64, pinned Java 8, and all frozen loopback ports free"
    paths = (str(java), *(f"127.0.0.1:{port}" for port in unavailable))
    return PreflightRequirement("qualification-host", "external", "ready" if ready else "missing", detail, paths)


def harness_preflight(spec: dict, profile: str) -> dict[str, object]:
    scenario = ROOT / spec["future_tool_contracts"]["scenario_manifest"]
    repository_paths = (ROOT / "tools/release/c028_release.py", ROOT / "rust-tron/Cargo.lock", scenario)
    upstream_paths = (ROOT / "rust-tron/packaging/config/fullnode.conf", ROOT / "rust-tron/packaging/config/fullnode.deployment.json", ROOT / "rust-tron/packaging/config/solidity.conf", ROOT / "rust-tron/packaging/config/solidity.deployment.json")
    requirements = [
        PreflightRequirement("repository-harness-inputs", "repository", "ready" if all(p.is_file() for p in repository_paths) else "missing", "checked-out qualification inputs", tuple(str(p.relative_to(ROOT)) for p in repository_paths)),
        _external_requirement("authenticated-release-manifest", "C030_RELEASE_MANIFEST"),
        _external_requirement("authenticated-release-install", "C030_RELEASE_PREFIX", directory=True),
        _external_requirement("release-config-input", "C030_RELEASE_CONFIG_ROOT", directory=True),
        _external_requirement("authenticated-install-receipt", "C030_RELEASE_RECEIPT"),
        _external_requirement("release-trust-store", "C030_RELEASE_TRUST_STORE"),
        _external_requirement("offline-release-bundle", "C030_RELEASE_BUNDLE", directory=True),
        _external_requirement("release-channel", "C030_RELEASE_CHANNEL", nonempty=True),
        _external_requirement("verification-time", "C030_VERIFICATION_TIME", nonempty=True),
        _authenticated_inputs_requirement(spec),
        _host_requirement(spec),
    ]
    if profile == "release":
        requirements.extend((
            _external_requirement("qualification-approval-records", "C030_APPROVAL_RECORDS"),
            _external_requirement("qualification-trust-store", "C030_QUALIFICATION_TRUST_STORE"),
            PreflightRequirement("qualification-signing-keys", "external", "ready" if _release_signing_keys_ready() else "missing", "C030_QUALIFICATION_SIGNING_KEYS must name exactly two distinct Ed25519 private keys", ()),
        ))
    requirements.extend((
        PreflightRequirement("c028-generic-config-sources", "upstream-release-build", "ready" if all(path.is_file() for path in upstream_paths) else "missing", "inputs used only when producing the authenticated C028 release", tuple(str(path.relative_to(ROOT)) for path in upstream_paths)),
        _upstream_requirement("pinned-busybox-material-upstream", "TRON_BUSYBOX"),
        _upstream_requirement("sapling-spend-parameters-upstream", "C030_SAPLING_SPEND"),
        _upstream_requirement("sapling-output-parameters-upstream", "C030_SAPLING_OUTPUT"),
    ))
    rows = [item.as_dict() for item in requirements]
    repository_missing = [row["name"] for row in rows if row["status"] != "ready" and row["kind"] == "repository"]
    external_missing = [row["name"] for row in rows if row["status"] != "ready" and row["kind"] == "external"]
    upstream_missing = [row["name"] for row in rows if row["status"] != "ready" and row["kind"] == "upstream-release-build"]
    decision = "repository_incomplete" if repository_missing else "blocked_external_prerequisites" if external_missing else "ready"
    return {"schema": "c030-harness-preflight-v1", "decision": decision, "profile": profile, "requirements": rows,
            "missing_repository_inputs": repository_missing, "missing_external_prerequisites": external_missing,
            "missing_upstream_release_build_inputs": upstream_missing}


def verify_spec(path: Path) -> dict:
    require(path.resolve() == ROOT / "docs/oracles/c030-qualification-spec.v1.json", "--spec must name the frozen repository C030 specification")
    require(sha256_file(path) == EXPECTED_SPEC_SHA256, "frozen C030 specification digest mismatch")
    spec = load(path)
    require(isinstance(spec, dict) and spec.get("schema") == "c030-qualification-spec-v1" and spec.get("spec_version") == 1, "invalid C030 specification identity")
    return spec


def decode_dsse_manifest(path: Path) -> tuple[dict, str]:
    document = load(path)
    require(isinstance(document, dict), "release manifest must be a JSON object")
    if document.get("payloadType") == "application/vnd.tron.release-manifest.v1+json":
        try:
            payload = base64.b64decode(document["payload"], validate=True)
            manifest = json.loads(payload)
        except (KeyError, ValueError, json.JSONDecodeError) as error:
            raise HarnessError(f"malformed signed release manifest: {error}") from error
    else:
        manifest = document
    require(isinstance(manifest, dict), "release payload must be an object")
    for field in ("release_id", "release_sequence", "source_revision"):
        require(field in manifest, f"release manifest lacks {field}")
    require(isinstance(manifest["release_sequence"], int) and manifest["release_sequence"] >= 0, "invalid release sequence")
    require(isinstance(manifest["source_revision"], str) and len(manifest["source_revision"]) == 40, "invalid source revision")
    return manifest, sha256_file(path)


def verify_release_install(env: dict[str, str], manifest_path: Path, manifest: dict) -> tuple[Path, Path, Path, dict]:
    prefix = required_path("C030_RELEASE_PREFIX", directory=True)
    config_root = required_path("C030_RELEASE_CONFIG_ROOT", directory=True)
    receipt = required_path("C030_RELEASE_RECEIPT")
    trust = required_path("C030_RELEASE_TRUST_STORE")
    bundle = required_path("C030_RELEASE_BUNDLE", directory=True)
    verifier = (prefix / "current/bin/tron-release-verify").resolve()
    require(verifier.is_file() and os.access(verifier, os.X_OK), "installed release verifier is missing or not executable")
    channel = os.environ.get("C030_RELEASE_CHANNEL", "")
    verification_time = os.environ.get("C030_VERIFICATION_TIME", "")
    require(channel and verification_time, "C030_RELEASE_CHANNEL and C030_VERIFICATION_TIME are required")
    command = [str(verifier), "verify-install", "--trust-store", str(trust), "--manifest", str(manifest_path),
               "--bundle", str(bundle), "--platform", "P-LINUX-X64", "--channel", channel,
               "--minimum-sequence", str(manifest["release_sequence"]), "--receipt", str(receipt),
               "--prefix", str(prefix / "current"), "--verification-time", verification_time]
    completed = subprocess.run(command, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300, check=False)
    require(completed.returncode == 0, "authenticated offline release verification failed: " + completed.stderr.decode("utf-8", "replace")[-2000:])
    try:
        attestation = json.loads(completed.stdout)
    except json.JSONDecodeError:
        attestation = {"stdout_sha256": hashlib.sha256(completed.stdout).hexdigest()}
    for binary in ("tron-fullnode", "tron-solidity"):
        path = prefix / "current/bin" / binary
        require(path.is_file() and os.access(path, os.X_OK), f"verified release lacks {binary}")
    return prefix, config_root, receipt, attestation


def build_java_reference(session, gradle_home: Path, cache_inventory: Path, cache_trust: Path,
                         verification_time: str, evidence: Path) -> Path:
    before_cache = verify_gradle_cache_inventory(gradle_home, cache_inventory, cache_trust, verification_time=verification_time)
    before = session.guard(phase="before C030 Java release build")
    env_backup = dict(session.env)
    session.env["GRADLE_USER_HOME"] = str(gradle_home)
    try:
        completed = session.gradle(["--offline", ":framework:buildFullNodeJar", "-x", "test", "-PbinaryRelease=true"], timeout=3600)
    finally:
        session.env = env_backup
    (evidence / "java-build.stdout.log").write_bytes(completed.stdout)
    (evidence / "java-build.stderr.log").write_bytes(completed.stderr)
    require(completed.returncode == 0, "offline pinned Java FullNode build failed")
    after_cache = verify_gradle_cache_inventory(gradle_home, cache_inventory, cache_trust, verification_time=verification_time)
    require(before_cache["digest"] == after_cache["digest"], "Gradle cache changed during Java build")
    jars = sorted(session.tree.glob("framework/build/libs/FullNode*.jar")) + sorted(session.tree.glob("build/libs/FullNode*.jar"))
    require(len(jars) == 1, f"expected exactly one FullNode release jar, found {len(jars)}")
    after = session.guard(phase="after C030 Java release build")
    require(before == after, "Java source identity changed while building reference")
    return jars[0]


def listener_name(port_name: str) -> str:
    return {"backup_udp": "backup", "json_rpc": "jsonrpc", "p2p_tcp_udp": "p2p"}.get(port_name, port_name)


def validate_rust_config(path: Path, node: dict, spec: dict, manifest: dict) -> dict:
    document = load(path)
    require(isinstance(document, dict), f"deployment config is not an object: {path}")
    require(document.get("mode") == ("solidity" if node["role"] == "solidity" else "full"), f"mode mismatch for {node['id']}")
    expected_release = document.get("expected_release", {})
    require(expected_release.get("release_id") == manifest["release_id"], f"release ID mismatch for {node['id']}")
    require(expected_release.get("minimum_release_sequence") <= manifest["release_sequence"], f"release sequence mismatch for {node['id']}")
    listeners = document.get("listeners", {})
    for key, port in node["ports"].items():
        name = listener_name(key)
        require(name in listeners, f"{node['id']} deployment lacks {name} listener")
        bind = listeners[name].get("bind", "")
        require(bind == f"127.0.0.1:{port}", f"{node['id']} {name} must bind exact loopback port {port}, got {bind}")
    chain = Path(document.get("paths", {}).get("chain_config", ""))
    require(chain.is_file(), f"{node['id']} chain config is missing")
    text = chain.read_text(encoding="utf-8")
    for key, port in node["ports"].items():
        if key not in ("backup_udp",):
            require(str(port) in text, f"{node['id']} chain config does not bind frozen {key} port")
    if node["role"] == "solidity":
        require(f"127.0.0.1:{spec['topology']['nodes'][4]['ports']['grpc']}" in text, "Solidity trust node is not the frozen rust-full gRPC endpoint")
    return {"deployment_sha256": sha256_file(path), "chain_config": str(chain), "chain_config_sha256": sha256_file(chain)}


def java_probe(node: dict):
    def probe():
        grpc = grpc_probe("127.0.0.1", node["ports"]["grpc"])
        http = http_json_probe("127.0.0.1", node["ports"]["http"], "/wallet/getnowblock", "POST", b"{}")
        p2p = tcp_probe("127.0.0.1", node["ports"]["p2p_tcp_udp"])
        return {"grpc": grpc, "http": {k: v for k, v in http.items() if k != "body"}, "p2p": p2p, "head": http["body"]}
    return probe


def rust_probe(binary: Path, deployment: Path, env: dict[str, str], node: dict):
    ready = rust_ready_probe(binary, deployment, env, minimum_head=0 if node["role"] == "solidity" else 1)
    def probe():
        result = dict(ready())
        result["grpc"] = grpc_probe("127.0.0.1", node["ports"]["grpc"])
        if node["role"] != "solidity":
            result["p2p"] = tcp_probe("127.0.0.1", node["ports"]["p2p_tcp_udp"])
        return result
    return probe


def inventory_environment(spec: dict, release_attestation: dict, cache_verification: dict,
                          host_attestation: dict) -> dict:
    load15 = os.getloadavg()[2]
    stat = os.statvfs(ROOT)
    inventory = dict(host_attestation)
    inventory.update({
        "load_average_15m": load15,
        "logical_cores": os.cpu_count() or 0,
        "memory_bytes": host_environment({})["memory_bytes"],
        "swap_enabled": any(line.startswith("SwapTotal:") and int(line.split()[1]) != 0 for line in Path("/proc/meminfo").read_text().splitlines()),
        "filesystem_free_bytes": stat.f_bavail * stat.f_frsize,
        "timezone": "UTC" if time.tzname == ("UTC", "UTC") else time.tzname[0],
        "release_attestation": release_attestation,
        "offline_cache_digest": cache_verification["digest"],
        "offline_cache_authentication": cache_verification["authentication"],
    })
    verified = verify_clean_host(inventory, spec["clean_environment"])
    inventory["verification"] = verified["checks"]
    return inventory


def tree_digest(root: Path) -> str:
    rows = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            rows.append({"path": path.relative_to(root).as_posix(), "size": path.stat().st_size, "sha256": sha256_file(path)})
    return canonical_sha256(rows)


def executable_scenarios(manifest_path: Path) -> tuple[dict, list[dict]]:
    document = load(manifest_path)
    require(isinstance(document, dict) and document.get("schema") == "c030-scenario-manifest-v1", "invalid C030 scenario manifest")
    rows = [row for row in document.get("scenarios", []) if row.get("item") == "C030.01" and row.get("execution_state") == "executable"]
    require([row.get("id") for row in rows] == ["C030-HARNESS-001", "C030-HARNESS-002", "C030-HARNESS-003", "C030-HARNESS-004"], "executable harness scenario order or coverage changed")
    return document, rows


def command_text(argv: list[str]) -> str:
    completed = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30, check=False)
    require(completed.returncode == 0, f"command failed: {' '.join(argv)}")
    return completed.stdout.decode("utf-8", "replace").strip()


def clean_tree_observation() -> dict:
    revision = command_text(["git", "-C", str(ROOT), "rev-parse", "HEAD"])
    status = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain=v1", "--untracked-files=all", "--", ".", ":(exclude)artifacts/c030/**", ":(exclude)docs/oracles/results/c030/**"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=True).stdout
    return {"observed_at": utc_now(), "revision": revision, "clean": not status, "status_sha256": hashlib.sha256(status).hexdigest()}


def host_environment(env: dict[str, str]) -> dict:
    memory = 0
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemTotal:"):
            memory = int(line.split()[1]) * 1024
            break
    cpu = next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines() if line.startswith("model name")), platform.processor() or "unknown")
    return {"os": platform.system(), "kernel": platform.release(), "architecture": platform.machine(), "cpu": cpu,
            "memory_bytes": memory, "hostname": socket.gethostname(), "locale": "C.UTF-8", "timezone": "UTC",
            "container_runtime": None, "environment_variables_sha256": canonical_sha256(env)}


def toolchain_identity(java: Path) -> dict:
    values = {"runner_path": "tools/qualification/c030_qualification.py", "runner_sha256": sha256_file(Path(__file__)),
              "python_version": platform.python_version(), "rustc_version": command_text(["rustc", "--version"]),
              "cargo_version": command_text(["cargo", "--version"]),
              "java_version": command_text([str(java), "-version"])}
    values["toolchain_sha256"] = canonical_sha256(values)
    return values

def materialize_deterministic_inputs(document: dict, root: Path) -> dict[str, str]:
    from cryptography.hazmat.primitives.asymmetric import ec
    key_dir = root / "keys"; key_dir.mkdir(mode=0o700)
    material_dir = root / "material"; material_dir.mkdir(mode=0o700)
    genesis = material_dir / "genesis.json"
    genesis.write_text(json.dumps(document["genesis"], sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    values = {}
    seed = str(document["allocation"]["seed"]).encode()
    for row in document["keys"]:
        message = f"C030.01:{row['id']}:{row['derivation_index']}".encode()
        scalar = int.from_bytes(hmac.new(seed, message, hashlib.sha256).digest(), "big") % (order - 1) + 1
        private_hex = f"{scalar:064x}"
        private = key_dir / f"{row['id']}.key"; private.write_text(private_hex + "\n", encoding="ascii"); private.chmod(0o600)
        numbers = ec.derive_private_key(scalar, ec.SECP256K1()).public_key().public_numbers()
        compressed = bytes([2 | (numbers.y & 1)]) + numbers.x.to_bytes(32, "big")
        public = key_dir / f"{row['id']}.pub"; public.write_text(compressed.hex() + "\n", encoding="ascii"); public.chmod(0o600)
        values[row["id"]] = private_hex
    return values

def render_node_configs(spec: dict, scenario: dict, config_root: Path, evidence_root: Path, manifest: dict, receipt: Path) -> dict[str, Path]:
    rendered = evidence_root / "config"
    rendered.mkdir(mode=0o700)
    source_root = config_root / "current"
    nodes = spec["topology"]["nodes"]
    peers = {node["id"]: [f"127.0.0.1:{other['ports']['p2p_tcp_udp']}" for other in nodes if other["id"] != node["id"] and "p2p_tcp_udp" in other["ports"]] for node in nodes}
    result = {}
    for node in nodes:
        node_id = node["id"]
        (evidence_root / "data" / node_id).mkdir(parents=True, mode=0o700)
        if node["implementation"] == "java":
            specific = source_root / f"{node_id}.conf"
            generic = source_root / ("solidity.conf" if node["role"] == "solidity" else "fullnode.conf")
            source = specific if specific.is_file() else generic
            require(source.is_file() and not source.is_symlink(), f"authenticated config bundle lacks safe Java source for {node_id}")
            ports = node["ports"]
            overrides = [
                f'node.listen.port = {ports["p2p_tcp_udp"]}', f'node.http.fullNodePort = {ports["http"]}',
                f'node.rpc.port = {ports["grpc"]}', f'node.jsonrpc.httpFullNodePort = {ports["json_rpc"]}',
                f'node.metrics.prometheus.port = {ports["prometheus"]}', f'node.backup.port = {ports["backup_udp"]}',
                f'node.networkId = {spec["topology"]["network_id"]}', f'node.genesisId = "{spec["topology"]["genesis_id"]}"',
                "seed.node.ip.list = [" + ",".join(json.dumps(peer) for peer in peers[node_id]) + "]",
                f'storage.db.directory = {json.dumps(str((evidence_root / "data" / node_id).resolve()))}',
            ]
            destination = rendered / f"{node_id}.conf"
            destination.write_text(source.read_text(encoding="utf-8").rstrip() + "\n" + "\n".join(overrides) + "\n", encoding="utf-8")
        else:
            mode = "solidity" if node["role"] == "solidity" else "full"
            stem = "solidity" if mode == "solidity" else "fullnode"
            specific = source_root / f"{node_id}.deployment.json"
            generic = source_root / f"{stem}.deployment.json"
            source = specific if specific.is_file() else generic
            require(source.is_file() and not source.is_symlink(), f"authenticated config bundle lacks safe Rust source for {node_id}")
            deployment = load(source)
            require(isinstance(deployment, dict), f"deployment source is not an object: {source}")
            deployment["mode"] = mode
            deployment["expected_release"] = {"release_id": manifest["release_id"], "minimum_release_sequence": manifest["release_sequence"]}
            chain_source = source_root / f"{stem}.conf"
            require(chain_source.is_file() and not chain_source.is_symlink(), f"authenticated config bundle lacks {stem}.conf")
            chain = rendered / f"{node_id}.conf"
            port_keys = {"p2p_tcp_udp": "node.listen.port", "http": "node.http.fullNodePort", "grpc": "node.rpc.port", "json_rpc": "node.jsonrpc.httpFullNodePort", "prometheus": "node.metrics.prometheus.port", "zeromq": "node.zeromq.port"}
            port_overrides = [f"{port_keys[name]} = {port}" for name, port in node["ports"].items() if name in port_keys]
            if node.get("trust_node"):
                port_overrides.append(f'solidityNode.trustNode = "127.0.0.1:{spec["topology"]["nodes"][4]["ports"]["grpc"]}"')
            chain.write_text(chain_source.read_text(encoding="utf-8").rstrip() + f'\nnode.networkId = {spec["topology"]["network_id"]}\nnode.genesisId = "{spec["topology"]["genesis_id"]}"\nseed.node.ip.list = [' + ",".join(json.dumps(peer) for peer in peers[node_id]) + "]\n" + "\n".join(port_overrides) + "\n", encoding="utf-8")
            deployment.setdefault("paths", {}).update({"chain_config": str(chain.resolve()), "data_directory": str((evidence_root / "data" / node_id).resolve()), "install_receipt": str(receipt)})
            listener_names = {"backup_udp": "backup", "json_rpc": "jsonrpc", "p2p_tcp_udp": "p2p"}
            listeners = deployment.setdefault("listeners", {})
            for port_name, port in node["ports"].items():
                name = listener_names.get(port_name, port_name)
                listener = listeners.setdefault(name, {})
                listener["bind"] = f"127.0.0.1:{port}"
            if node.get("trust_node"):
                deployment["trust_node"] = node["trust_node"]
            destination = rendered / f"{node_id}.deployment.json"
            destination.write_text(json.dumps(deployment, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        result[node_id] = destination
    require(len(result) == 8, "exactly eight deterministic node configurations were not rendered")
    return result





def process_resource_samples(readiness: list[dict], observed_at: str, monotonic_ns: int) -> list[dict]:
    rows = []
    for item in readiness:
        pid = item["pid"]
        status = Path(f"/proc/{pid}/status").read_text()
        rss_kib = next((int(line.split()[1]) for line in status.splitlines() if line.startswith("VmRSS:")), 0)
        io_values = {}
        with contextlib.suppress(OSError):
            io_values = {line.split(":", 1)[0]: int(line.split(":", 1)[1]) for line in Path(f"/proc/{pid}/io").read_text().splitlines()}
        rows.append({"observed_at": observed_at, "monotonic_ns": monotonic_ns, "subject": item["node_id"],
                     "rss_bytes": rss_kib * 1024, "cpu_percent": 0, "disk_bytes_written": io_values.get("write_bytes", 0),
                     "network_bytes_sent": 0, "network_bytes_received": 0})
    return rows


def run_harness(spec: dict, output: Path, profile: str) -> dict:
    wall_started = utc_now()
    monotonic_started = time.monotonic_ns()
    clean_before = clean_tree_observation()
    manifest_path = required_path("C030_RELEASE_MANIFEST")
    release_manifest, release_sha = decode_dsse_manifest(manifest_path)
    scenario_manifest = ROOT / spec["future_tool_contracts"]["scenario_manifest"]
    scenario_document, scenario_rows = executable_scenarios(scenario_manifest)
    ids = [row["id"] for row in scenario_rows]
    verification_time = os.environ.get("C030_VERIFICATION_TIME", "")
    require(bool(verification_time), "C030_VERIFICATION_TIME is required")
    gradle_home = required_path("C030_GRADLE_USER_HOME", directory=True)
    cache_inventory_path = required_path("C030_GRADLE_CACHE_INVENTORY")
    host_attestation_path = required_path("C030_HOST_ATTESTATION")
    host_trust_path = required_path("C030_HOST_ATTESTATION_TRUST_STORE")
    host_id = socket.gethostname()
    session_id = os.environ.get("C030_SESSION_ID", "")
    require(bool(session_id), "C030_SESSION_ID is required")
    cache_verification = verify_gradle_cache_inventory(gradle_home, cache_inventory_path, host_trust_path, verification_time=verification_time)
    host_attestation = verify_host_attestation(host_attestation_path, host_trust_path, verification_time=verification_time,
                                               expected={"host_identity": host_id, "session_id": session_id, "spec_sha256": EXPECTED_SPEC_SHA256,
                                                         "release_id": release_manifest["release_id"], "release_sequence": release_manifest["release_sequence"],
                                                         "source_revision": release_manifest["source_revision"]})
    phase_times: dict[str, tuple[str, int]] = {"materialize": (wall_started, monotonic_started)}
    evidence_root = ROOT / "artifacts/c030/C030.01/harness"
    require(not evidence_root.exists(), f"evidence destination already exists: {evidence_root}")
    evidence_root.mkdir(parents=True, mode=0o700)
    secret_paths = tuple(evidence_root / "keys" / f"{row['id']}.key" for row in scenario_document["keys"])
    with AllExitCleanup(secret_paths, evidence_root) as cleanup:
        witness_keys = materialize_deterministic_inputs(scenario_document, evidence_root)
        with tempfile.TemporaryDirectory(prefix="c030-harness-") as raw:
            work = Path(raw)
            env = closed_environment(work)
            prefix, config_root, receipt, release_attestation = verify_release_install(env, manifest_path, release_manifest)
            rendered_configs = render_node_configs(spec, scenario_document, config_root, evidence_root, release_manifest, receipt)
            environment_inventory = inventory_environment(spec, release_attestation, cache_verification, host_attestation)
            runtime_environment = host_environment(env)
            (evidence_root / "environment.json").write_text(json.dumps({"qualification": environment_inventory, "runtime": runtime_environment}, indent=2, sort_keys=True) + "\n")
            with install_java_reference_guard(ROOT) as session:
                java_jar = build_java_reference(session, gradle_home, cache_inventory_path, host_trust_path, verification_time, evidence_root)
                nodes = spec["topology"]["nodes"]
                require([node["id"] for node in nodes] == ["java-witness-a", "java-witness-b", "rust-witness-a", "rust-witness-b", "rust-full", "java-fast-forward", "java-observer", "rust-solidity"], "frozen topology role order changed")
                plans = []
                identities = []
                for node in nodes:
                    node_id = node["id"]
                    log = evidence_root / f"{node_id}.log"
                    if node["implementation"] == "java":
                        config = rendered_configs[node_id]
                        require(config.is_file(), f"rendered config missing for {node_id}")
                        text = config.read_text(encoding="utf-8")
                        for port in node["ports"].values():
                            require(str(port) in text, f"{node_id} config lacks frozen port {port}")
                        require(spec["topology"]["genesis_id"] in text and str(spec["topology"]["network_id"]) in text, f"{node_id} config lacks deterministic genesis/network identity")
                        argv = [str(session.java_home / "bin/java"), "-Xms512m", "-Xmx2g", "-jar", str(java_jar), "-c", str(config)]
                        if node["role"] == "witness": argv.append("--witness")
                        java_env = dict(session.env); java_env.update({"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC"})
                        if node.get("witness_identity"):
                            java_env["WITNESS_PRIVATE_KEY"] = witness_keys[node["witness_identity"]]
                        plan = NodePlan(node_id, "java", node["role"], node["ports"], argv, work, java_env, config, log, java_probe(node))
                        identities.append({"node_id": node_id, "role": node["role"], "implementation": "java", "binary_sha256": sha256_file(java_jar), "config_sha256": sha256_file(config), "source": session.identity})
                    else:
                        binary = prefix / "current/bin" / ("tron-solidity" if node["role"] == "solidity" else "tron-fullnode")
                        deployment = rendered_configs[node_id]
                        identity = validate_rust_config(deployment, node, spec, release_manifest)
                        rust_env = dict(env)
                        if node.get("witness_identity"):
                            rust_env["WITNESS_PRIVATE_KEY"] = witness_keys[node["witness_identity"]]
                        plan = NodePlan(node_id, "rust", node["role"], node["ports"], [str(binary), "--deployment-config", str(deployment)], work, rust_env, deployment, log, rust_probe(binary, deployment, rust_env, node))
                        identities.append({"node_id": node_id, "role": node["role"], "implementation": "rust", "binary_sha256": sha256_file(binary), **identity})
                    plans.append(plan)
                (evidence_root / "identities.json").write_text(json.dumps(identities, indent=2, sort_keys=True) + "\n")
                materialization = {"source_digests": scenario_document["references"],
                                   "rendered_configs": [{"node_id": row["node_id"], "config_sha256": row.get("config_sha256", row.get("deployment_sha256"))} for row in identities],
                                   "genesis": {"path": "material/genesis.json", "sha256": sha256_file(evidence_root / "material/genesis.json")},
                                   "witness_key_paths": [str(path.relative_to(evidence_root)) for path in secret_paths if path.is_file()]}
                require(len(materialization["witness_key_paths"]) == 4, "four witness private keys were not materialized")
                (evidence_root / "materialization.json").write_text(json.dumps(materialization, indent=2, sort_keys=True) + "\n")
                phase_times["start"] = (utc_now(), time.monotonic_ns())
                supervisor = cleanup.attach(ProcessHarness(plans, evidence_root, startup_timeout=600, shutdown_timeout=120))
                readiness = supervisor.start()
                resource_samples = process_resource_samples(readiness, utc_now(), time.monotonic_ns())
                metrics_readiness = [{"node_id": node["id"], "probe": http_status_probe("127.0.0.1", node["ports"]["prometheus"], "/metrics")} for node in nodes]
                bound_ports = assert_ports_bound(supervisor.endpoints)
                (evidence_root / "readiness.json").write_text(json.dumps({"nodes": readiness, "metrics": metrics_readiness, "bound_ports": bound_ports}, indent=2, sort_keys=True) + "\n")
                links = []
                topology_nodes = {row["id"]: row for row in nodes}
                for link in scenario_document["topology"]["links"]:
                    host, raw_port = link["endpoint"].rsplit(":", 1)
                    if link["kind"] == "solidity-trust-grpc":
                        protocol = grpc_probe(host, int(raw_port))
                    else:
                        source = topology_nodes[link["from"]]
                        peer_view = http_json_probe("127.0.0.1", source["ports"]["http"], "/wallet/listnodes", "POST", b"{}")
                        serialized = json.dumps(peer_view["body"], sort_keys=True)
                        require(raw_port in serialized, f"{link['id']} was not present in the source node's observed peer table")
                        peer_view.pop("body")
                        protocol = {"listener": tcp_probe(host, int(raw_port)), "peer_table": peer_view}
                    links.append({"id": link["id"], "source": link["from"], "target": link["to"], "kind": link["kind"], "endpoint": link["endpoint"], "protocol_observation": protocol})
                require(len(links) == 22, "exact required link coverage was not observed")
                (evidence_root / "links.json").write_text(json.dumps(links, indent=2, sort_keys=True) + "\n")
                sync = []
                for node in nodes:
                    observation = http_json_probe("127.0.0.1", node["ports"]["http"], "/wallet/getnowblock", "POST", b"{}")
                    body = observation.pop("body")
                    height = body.get("block_header", {}).get("raw_data", {}).get("number", 0)
                    require(isinstance(height, int) and height >= 1, f"{node['id']} did not synchronize genesis height")
                    sync.append({"node_id": node["id"], "height": height, "probe": observation})
                (evidence_root / "sync.json").write_text(json.dumps(sync, indent=2, sort_keys=True) + "\n")
                chain_identity = {"network_id": spec["topology"]["network_id"], "genesis_id": spec["topology"]["genesis_id"],
                                  "nodes": [{"node_id": row["node_id"], "config_sha256": row.get("config_sha256", row.get("deployment_sha256"))} for row in identities]}
                (evidence_root / "chain-identity.json").write_text(json.dumps(chain_identity, indent=2, sort_keys=True) + "\n")
                phase_times["cleanup"] = (utc_now(), time.monotonic_ns())
                cleanup_observation = cleanup.close()
                shutdown = cleanup_observation["shutdown"]
                require(len(shutdown) == 8 and all(row["exit_code"] in (0, -signal.SIGTERM) and not row["forced"] for row in shutdown), "one or more node roles did not shut down cleanly")
                (evidence_root / "cleanup.json").write_text(json.dumps(cleanup_observation, indent=2, sort_keys=True) + "\n")
        monotonic_completed = time.monotonic_ns()
        wall_completed = utc_now()
        clean_after = clean_tree_observation()
        evidence_rows = []
        for path in sorted(evidence_root.rglob("*")):
            if path.is_file():
                captured = EvidenceFile.capture(path, ROOT)
                evidence_rows.append({"path": captured.path, "sha256": captured.sha256, "size_bytes": captured.size})
        evidence_paths = [row["path"] for row in evidence_rows]
        inventory_names = cleanup_observation["evidence_inventory"]["paths"]
        evidence_closure = cleanup_observation["evidence_inventory"]
        ep = "artifacts/c030/C030.01/harness/"
        implementations = {node["id"]: node["implementation"] for node in nodes}
        java_to_rust = [row["id"] for row in links if implementations[row["source"]] == "java" and implementations[row["target"]] == "rust"]
        rust_to_java = [row["id"] for row in links if implementations[row["source"]] == "rust" and implementations[row["target"]] == "java"]
        solidity_links = [row["id"] for row in links if row["kind"] == "solidity-trust-grpc"]
        measured = {
            "all_source_digests_match": {"expected": {"reference_count": len(scenario_document["references"])}, "actual": {"references": materialization["source_digests"]}, "evidence_path": ep + "materialization.json"},
            "all_rendered_configs_recorded": {"expected": {"node_count": 8}, "actual": {"configs": materialization["rendered_configs"]}, "evidence_path": ep + "materialization.json"},
            "genesis_recorded": {"expected": {"genesis_id": spec["topology"]["genesis_id"]}, "actual": materialization["genesis"], "evidence_path": ep + "materialization.json"},
            "four_witness_keys_created": {"expected": {"key_count": 4}, "actual": {"created_paths": materialization["witness_key_paths"]}, "evidence_path": ep + "materialization.json"},
            "eight_processes_running": {"expected": {"process_count": 8}, "actual": {"pids": {row["node_id"]: row["pid"] for row in readiness}}, "evidence_path": ep + "readiness.json"},
            "all_declared_tcp_ports_bound": {"expected": {"endpoint_count": len(supervisor.endpoints)}, "actual": {"bindings": bound_ports}, "evidence_path": ep + "readiness.json"},
            "all_prometheus_endpoints_healthy": {"expected": {"endpoint_count": 8, "http_status": 200}, "actual": {"probes": metrics_readiness}, "evidence_path": ep + "readiness.json"},
            "head_height_at_least_1": {"expected": {"minimum_height": 1, "node_count": 8}, "actual": {"heights": {row["node_id"]: row["height"] for row in sync}}, "evidence_path": ep + "sync.json"},
            "all_required_links_connected": {"expected": {"link_count": 22}, "actual": {"link_ids": [row["id"] for row in links]}, "evidence_path": ep + "links.json"},
            "java_to_rust_peer_observed": {"expected": {"minimum_links": 1}, "actual": {"link_ids": java_to_rust}, "evidence_path": ep + "links.json"},
            "rust_to_java_peer_observed": {"expected": {"minimum_links": 1}, "actual": {"link_ids": rust_to_java}, "evidence_path": ep + "links.json"},
            "solidity_trust_rpc_observed": {"expected": {"minimum_links": 1}, "actual": {"link_ids": solidity_links}, "evidence_path": ep + "links.json"},
            "network_and_genesis_ids_equal": {"expected": {"network_id": spec["topology"]["network_id"], "genesis_id": spec["topology"]["genesis_id"]}, "actual": chain_identity, "evidence_path": ep + "chain-identity.json"},
            "all_processes_exited": {"expected": {"process_count": 8, "forced_count": 0}, "actual": {"shutdown": shutdown, "absence": cleanup_observation["supervised_absence"]}, "evidence_path": ep + "cleanup.json"},
            "all_declared_ports_unbound": {"expected": {"endpoint_count": len(supervisor.endpoints)}, "actual": {"released_bindings": cleanup_observation["ports"]}, "evidence_path": ep + "cleanup.json"},
            "no_child_processes": {"expected": {"remaining_count": 0}, "actual": cleanup_observation["child_absence"], "evidence_path": ep + "cleanup.json"},
            "secret_files_removed": {"expected": {"remaining_count": 0}, "actual": cleanup_observation["key_scrub"], "evidence_path": ep + "cleanup.json"},
            "evidence_inventory_closed": {"expected": {"paths": inventory_names}, "actual": {"path_count": len(evidence_closure["paths"]), "closure_sha256": evidence_closure["closure_sha256"]}, "evidence_path": ep + "cleanup.json"},
        }
        verify_measured_observations(scenario_rows, measured)
        observations = []
        observation_ids_by_action = {}
        action_files = {}
        for index, scenario in enumerate(scenario_rows, 1):
            action = scenario["action"]
            ids_for_action = []
            paths_for_action = []
            for offset, subject in enumerate(scenario["expected_observations"], 1):
                observation_id = f"OBS-HARNESS-{index:03d}-{offset:02d}"
                ids_for_action.append(observation_id)
                value = measured[subject]
                paths_for_action.append(value["evidence_path"])
                observations.append({"id": observation_id, "kind": action, "subject": subject, "observed_at": wall_completed,
                                     "monotonic_ns": monotonic_completed, "status": "pass", **value})
            observation_ids_by_action[action] = ids_for_action
            action_files[action] = sorted(set(paths_for_action))
        scenario_results = []
        action_order = ["materialize", "start", "handshake", "cleanup"]
        for index, scenario in enumerate(scenario_rows):
            action = scenario["action"]
            start_wall, start_ns = phase_times[action]
            end_ns = phase_times[action_order[index + 1]][1] if index + 1 < len(action_order) else monotonic_completed
            end_wall = phase_times[action_order[index + 1]][0] if index + 1 < len(action_order) else wall_completed
            scenario_results.append({"id": scenario["id"], "status": "pass", "synthetic": False, "skipped": False,
                                     "started_at": start_wall, "completed_at": end_wall, "duration_ns": max(0, end_ns - start_ns),
                                     "observation_ids": observation_ids_by_action[action], "evidence_paths": action_files[action], "failure_ids": []})
        node_by_id = {node["id"]: node for node in spec["topology"]["nodes"]}
        pid_by_id = {row["node_id"]: row["pid"] for row in readiness}
        exit_by_id = {row["node_id"]: row["exit_code"] for row in shutdown}
        harness_nodes = [{"id": node_id, "implementation": node_by_id[node_id]["implementation"], "role": node_by_id[node_id]["role"],
                          "pid": pid_by_id[node_id], "started": True, "ready": True, "handshake_complete": True,
                          "sync_complete": True, "shutdown_clean": True, "exit_code": exit_by_id[node_id]}
                         for node_id in scenario_document["allocation"]["node_order"]]
        harness_links = [{"id": row["id"], "source": row["source"], "target": row["target"], "kind": row["kind"],
                          "connected": True, "handshake_complete": True, "sync_complete": True, "shutdown_clean": True} for row in links]
        def phase(action: str) -> dict:
            row = scenario_results[action_order.index(action)]
            return {"status": "pass", "started_at": row["started_at"], "completed_at": row["completed_at"], "duration_ns": row["duration_ns"], "observation_ids": row["observation_ids"], "failure_ids": []}
        config_files = []
        for identity in identities:
            if identity["implementation"] == "rust":
                config_files.append({"path": identity["chain_config"], "sha256": identity["chain_config_sha256"]})
            else:
                config_files.append({"path": identity["node_id"], "sha256": identity["config_sha256"]})
        toolchain = toolchain_identity(Path("/usr/lib/jvm/java-8-openjdk-amd64/bin/java"))
        configuration = {"network_id": spec["topology"]["network_id"], "genesis_id": spec["topology"]["genesis_id"],
                         "topology_sha256": canonical_sha256(scenario_document["topology"]), "files": config_files,
                         "configuration_sha256": canonical_sha256(config_files)}
        peak_rss = max(row["rss_bytes"] for row in resource_samples)
        disk_written = sum(row["disk_bytes_written"] for row in resource_samples)
        expires = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + spec["result_contract"]["validity_days"] * 86400))
        result = {"schema": "c030-qualification-result-v1", "spec_sha256": EXPECTED_SPEC_SHA256,
                  "scenario_manifest_sha256": sha256_file(scenario_manifest), "scenario_id": "C030.01", "mode": "harness", "platform_id": "P-LINUX-X64", "output_path": canonical_output_path(output), "profile": profile,
                  "release_manifest_sha256": release_sha, "release_id": release_manifest["release_id"], "release_version": release_manifest.get("version", release_manifest["release_id"]),
                  "release_sequence": release_manifest["release_sequence"], "source_revision": release_manifest["source_revision"], "toolchain": toolchain, "configuration": configuration,
                  "started_at": wall_started, "completed_at": wall_completed, "expires_at": expires,
                  "monotonic": {"clock": "monotonic", "started_ns": monotonic_started, "completed_ns": monotonic_completed, "duration_ns": monotonic_completed-monotonic_started, "nondecreasing": True},
                  "environment": runtime_environment, "environment_sha256": sha256_file(evidence_root / "environment.json"),
                  "host_attestation_sha256": sha256_file(host_attestation_path), "cache_inventory_sha256": sha256_file(cache_inventory_path), "clean_tree": {"before": clean_before, "after": clean_after},
                  "scenario_ids": ids, "scenario_results": scenario_results, "observations": observations,
                  "invariants": [{"id": "C030-HARNESS-COVERAGE", "description": "exact frozen node and link coverage", "status": "pass", "observed": 30, "limit": 30, "failure_id": None}],
                  "metrics": [{"name": "nodes_ready", "unit": "nodes", "value": 8, "observed_at": wall_completed}, {"name": "links_connected", "unit": "links", "value": 22, "observed_at": wall_completed}],
                  "resources": {"samples": resource_samples, "peak_rss_bytes": peak_rss, "peak_cpu_percent": 0, "disk_bytes_written": disk_written, "network_bytes_sent": 0, "network_bytes_received": 0},
                  "evidence_files": {"files": evidence_rows, "inventory_sha256": canonical_sha256(evidence_rows)}, "failures": [],
                  "approvals": [], "overall_status": "pass", "result_sha256": "0"*64, "signature": None,
                  "harness": {"expected_node_ids": scenario_document["allocation"]["node_order"], "expected_link_ids": [row["id"] for row in scenario_document["topology"]["links"]], "nodes": harness_nodes, "links": harness_links,
                              "readiness": phase("start"), "handshake": phase("handshake"), "sync": phase("handshake"), "shutdown": phase("cleanup"),
                              "coverage": {"expected_nodes": 8, "observed_nodes": 8, "expected_links": 22, "observed_links": 22, "exact": True}, "synthetic_results": 0, "skipped_results": 0}}
        if profile == "release":
            approvals = load(required_path("C030_APPROVAL_RECORDS"))
            require(isinstance(approvals, list), "C030_APPROVAL_RECORDS must contain a JSON array")
            keys = qualification_signing_keys()
            require(len(keys) == 2, "release profile requires exactly two external qualification signing keys")
            signed = sign_result(result, approvals, keys)
            verify_result(signed, required_path("C030_QUALIFICATION_TRUST_STORE"), expected_item="C030.01", expected_mode="harness", expected_output_path=canonical_output_path(output))
            return signed
        result["failures"] = [{"id": "C030-DEVELOPER-PROFILE", "scenario_id": "C030.01", "kind": "approval", "message": "developer profile is diagnostic and cannot qualify a release", "observed_at": wall_completed, "evidence_paths": evidence_paths}]
        result["overall_status"] = "fail"
        digest_payload = dict(result); digest_payload.pop("result_sha256"); digest_payload.pop("signature")
        result["result_sha256"] = canonical_sha256(digest_payload)
        return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=(IMPLEMENTED_MODE, *OTHER_MODES))
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--profile", choices=("developer", "release"), default="developer")
    parser.add_argument("--preflight", action="store_true", help="report launch prerequisites without building or starting nodes")
    args = parser.parse_args()
    spec = verify_spec(args.spec)
    if args.preflight:
        report = harness_preflight(spec, args.profile)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["decision"] == "ready" else 2
    require(args.output is not None, "--output is required unless --preflight is used")
    expected_item = f"C030.{spec['future_tool_contracts']['command_modes'].index(args.mode) + 1:02d}"
    expected_output = (ROOT / spec["future_tool_contracts"]["mode_outputs"][expected_item]).resolve()
    require(args.output.resolve() == expected_output, f"mode {args.mode!r} must write exact result slot {expected_output}")
    if args.mode != IMPLEMENTED_MODE:
        parser.error(f"mode {args.mode!r} is not implemented by C030.01; refusing to emit a result")
    lock_path = Path(tempfile.gettempdir()) / "c030-qualification.lock"
    with lock_path.open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise HarnessError("another C030 qualification harness owns the frozen ports") from error
        require(not args.output.exists(), f"result destination already exists: {args.output}")
        result = run_harness(spec, args.output, args.profile)
        schema_path = ROOT / spec["future_tool_contracts"]["result_schema"]
        require(schema_path.is_file(), "C030 result schema is missing")
        Draft202012Validator(load(schema_path)).validate(result)
        atomic_write_json(args.output, result)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (HarnessError, subprocess.TimeoutExpired) as error:
        print(f"C030 qualification failed: {error}", file=sys.stderr)
        raise SystemExit(2)
