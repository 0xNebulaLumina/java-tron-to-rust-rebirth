"""Executable C028 platform, Sapling, and offline-release policy cases."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Callable

PLATFORM_ID = "C028-R14-PLATFORM"
SAPLING_ID = "C028-R15-SAPLING-EXCLUSION"
OFFLINE_ID = "C028-R17-OFFLINE-RELEASE"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tree(root: Path | None) -> str:
    digest = hashlib.sha256()
    if root is None or not root.exists():
        digest.update(b"missing\0")
        return digest.hexdigest()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix().encode()
        digest.update(relative + b"\0")
        if path.is_symlink():
            digest.update(b"L" + os.readlink(path).encode() + b"\0")
        elif path.is_file():
            digest.update(b"F" + path.read_bytes())
        else:
            digest.update(b"D")
    return digest.hexdigest()


def _tool(context: dict[str, object], name: str) -> Path:
    tools = context.get("required_tools")
    candidate = tools.get(name) if isinstance(tools, dict) else None
    if candidate:
        path = Path(str(candidate))
    else:
        path = Path(context["rust_root"]) / "target" / "debug" / name
    if not path.is_file():
        raise RuntimeError(f"required actual executable is unavailable: {name}")
    return path


def _run(argv: list[str], context: dict[str, object], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        argv,
        cwd=Path(context["repo_root"]),
        env=env if env is not None else dict(context.get("env", os.environ)),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=int(context.get("timeout_seconds", 300)),
        check=False,
    )


def _result(case_id: str, before: str, after: str, stdout: bytes, stderr: bytes, details: dict[str, object]) -> dict[str, object]:
    if before != after:
        raise AssertionError(f"{case_id} mutated the protected install tree")
    return {
        "id": case_id,
        "decision": "reject_before_mutation",
        "mutation": False,
        "exit_code": 0,
        "stdout_sha256": _sha(stdout),
        "stderr_sha256": _sha(stderr),
        "before_tree_sha256": before,
        "after_tree_sha256": after,
        "details": details,
    }


def _node_error(run: subprocess.CompletedProcess[bytes], category: str, fragment: str) -> dict[str, object]:
    if run.returncode != 2:
        raise AssertionError(f"node preflight returned {run.returncode}, expected 2: {run.stderr.decode(errors='replace')}")
    try:
        error = json.loads(run.stderr)
    except Exception as exc:
        raise AssertionError("node preflight did not emit its canonical JSON error") from exc
    if error.get("schema") != "tron-node-error-v1" or error.get("category") != category or fragment not in error.get("message", ""):
        raise AssertionError(f"unexpected node preflight error: {error!r}")
    return error


def _base_deployment(context: dict[str, object], node: Path) -> tuple[dict[str, object], dict[str, object]]:
    version = _run([str(node), "--version"], context)
    if version.returncode != 0:
        raise AssertionError(version.stderr.decode(errors="replace"))
    identity = json.loads(version.stdout)
    source = Path(context["rust_root"]) / "packaging" / "config" / "fullnode.deployment.json"
    deployment = json.loads(source.read_text())
    deployment["expected_release"] = {
        "release_id": identity["release_id"],
        "minimum_release_sequence": identity["release_sequence"],
    }
    deployment["platform"] = {
        "schema_version": 1,
        "id": identity["platform_id"],
        "os": "linux",
        "architecture": "x86_64",
        "target": identity["target"],
        "backend": identity["backend"],
        "backend_format": identity["backend_format"],
        "features": list(identity["features"]),
    }
    deployment["paths"]["chain_config"] = str((Path(context["rust_root"]) / "packaging" / "config" / "fullnode.conf").resolve())
    return deployment, identity


def platform_policy(context: dict[str, object]) -> dict[str, object]:
    protected = Path(context["installed_prefix"]) if context.get("installed_prefix") else None
    before = _tree(protected)
    work = Path(context["work_dir"]) / "platform"
    work.mkdir()
    node = _tool(context, "tron-fullnode")
    toolkit = _tool(context, "tron-toolkit")

    capabilities = _run([str(toolkit), "db", "capabilities", "--json"], context)
    if capabilities.returncode != 0:
        raise AssertionError(capabilities.stderr.decode(errors="replace"))
    matrix = json.loads(capabilities.stdout)
    backends = {item["backend"]: item for item in matrix["backends"]}
    if matrix.get("platform") != "P-LINUX-X64" or matrix.get("state") != "enabled":
        raise AssertionError(f"qualified platform capability drift: {matrix!r}")
    for java_backend in ("LEVELDB", "ROCKSDB"):
        item = backends.get(java_backend)
        if not item or item.get("state") != "referenceonly" or item.get("readable") or item.get("writable"):
            raise AssertionError(f"Java backend is not reference-only: {item!r}")

    destination = work / "must-not-exist"
    backend = _run([str(toolkit), "db", "cp", str(work / "absent-source"), str(destination), "--backend", "java-leveldb", "--network", "mainnet", "--genesis", "c028"], context)
    if backend.returncode == 0 or b"unsupported_backend" not in backend.stderr or destination.exists():
        raise AssertionError(f"toolkit did not reject Java backend before destination mutation: {backend.stderr!r}")

    deployment, _ = _base_deployment(context, node)
    observations: dict[str, object] = {}
    platform = json.loads(json.dumps(deployment)); platform["platform"]["target"] = "aarch64-unknown-linux-gnu"
    platform_path = work / "platform.json"; platform_path.write_text(json.dumps(platform))
    observations["platform"] = _node_error(_run([str(node), "preflight", "--deployment-config", str(platform_path), "--json"], context), "platform", "unsupported toolkit platform")

    limits = json.loads(json.dumps(deployment)); limits["runtime_limits"]["startup_timeout_seconds"] = 0
    limits_path = work / "limits.json"; limits_path.write_text(json.dumps(limits))
    observations["limits"] = _node_error(_run([str(node), "preflight", "--deployment-config", str(limits_path), "--json"], context), "resource_limit", "positive")

    bind = json.loads(json.dumps(deployment)); bind["listeners"]["http"]["bind"] = "0.0.0.0:8090"; bind["listeners"]["http"]["public"] = True
    bind_path = work / "bind.json"; bind_path.write_text(json.dumps(bind))
    observations["bind"] = _node_error(_run([str(node), "preflight", "--deployment-config", str(bind_path), "--json"], context), "plaintext_exposure", "must bind loopback")

    stdout = capabilities.stdout
    stderr = backend.stderr + b"\n" + b"\n".join(json.dumps(value, sort_keys=True).encode() for value in observations.values())
    after = _tree(protected)
    return _result(PLATFORM_ID, before, after, stdout, stderr, {"capabilities": matrix, "backend_exit": backend.returncode, "preflight_errors": observations})


def _release_module(context: dict[str, object]):
    path = Path(context["repo_root"]) / "tools" / "release" / "c028_release.py"
    spec = importlib.util.spec_from_file_location("c028_release_platform_cases", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load C028 release tooling")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sapling_exclusion(context: dict[str, object]) -> dict[str, object]:
    protected = Path(context["installed_prefix"]) if context.get("installed_prefix") else None
    before = _tree(protected)
    work = Path(context["work_dir"]) / "sapling"
    work.mkdir()
    release = _release_module(context)
    expected = {
        "sapling-spend": (48013340, "25fd9a0d1c1be0526c14662947ae95b758fe9f3d7fb7f55e9b4437830dcc6215a7ce3ea465914b157715b7a4d681389ea4aa84438190e185d5e4c93574d3a19a"),
        "sapling-output": (3647804, "a1cb23b93256adce5bce2cb09cefbc96a1d16572675ceb691e9a3626ec15b5b546926ff1c536cfe3a9df07d796b32fdfc3e5d99d65567257bf286cd2858d71a6"),
    }
    observed = {item["kind"]: (item["size"], item["blake2b_512"]) for item in release.SAPLING_POLICY}
    if observed != expected or any(item.get("included") is not False or item.get("redistribution_rights") != "not_asserted" for item in release.SAPLING_POLICY):
        raise AssertionError(f"Sapling policy drift: {release.SAPLING_POLICY!r}")
    errors = []
    named = work / "sapling-spend.params"; named.write_bytes(b"not-parameter-bytes")
    try: release.scan_forbidden_sapling(work)
    except RuntimeError as exc: errors.append(str(exc))
    else: raise AssertionError("release scan accepted a named Sapling parameter")
    named.unlink()
    sized = work / "opaque.bin"; sized.touch(); os.truncate(sized, expected["sapling-output"][0])
    try: release.scan_forbidden_sapling(work)
    except RuntimeError as exc: errors.append(str(exc))
    else: raise AssertionError("release scan accepted an exact-size possible Sapling parameter")
    manifest = release.generate_snapshot_manifest({"release_id": "c028-platform-drill"})
    if manifest["operator_input_policy"] != list(release.SAPLING_POLICY) or manifest["snapshots"]:
        raise AssertionError("snapshot manifest did not preserve external-only Sapling policy")
    after = _tree(protected)
    output = json.dumps(manifest, sort_keys=True).encode()
    return _result(SAPLING_ID, before, after, output, "\n".join(errors).encode(), {"operator_input_policy": manifest["operator_input_policy"], "rejections": errors})


def offline_release(context: dict[str, object]) -> dict[str, object]:
    protected = Path(context["installed_prefix"]) if context.get("installed_prefix") else None
    before = _tree(protected)
    work = Path(context["work_dir"]) / "offline"
    work.mkdir()
    release = _release_module(context)
    shim_dir = work / "bin"; shim_dir.mkdir(); record = work / "cargo-observation.json"
    cargo = shim_dir / "cargo"
    cargo.write_text("#!/usr/bin/env python3\nimport json,os,sys\nfrom pathlib import Path\nPath(os.environ['C028_CARGO_RECORD']).write_text(json.dumps({'argv':sys.argv[1:],'offline':os.environ.get('CARGO_NET_OFFLINE'),'target':os.environ.get('CARGO_TARGET_DIR')}))\nsys.exit(73)\n")
    cargo.chmod(0o755)
    env_before = os.environ.copy()
    os.environ.update(dict(context.get("env", {})))
    os.environ["PATH"] = str(shim_dir) + os.pathsep + env_before.get("PATH", "")
    os.environ["C028_CARGO_RECORD"] = str(record)
    identity = {"release_id":"c028-offline-drill","version":"0","release_sequence":1,"channel":"candidate","source_revision":"00" * 20,"source_date_epoch":0}
    try:
        try: release.build_one(Path(context["repo_root"]), work / "build", identity, False)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 73: raise
        else: raise AssertionError("controlled Cargo seam was not invoked")
    finally:
        os.environ.clear(); os.environ.update(env_before)
    observation = json.loads(record.read_text())
    argv = observation["argv"]
    if "--offline" not in argv or "--locked" not in argv or observation["offline"] != "true":
        raise AssertionError(f"release build permitted online dependency resolution: {observation!r}")
    checkout = work / "build" / "checkout"
    if (checkout / "java-tron").exists():
        raise AssertionError("release checkout included java-tron")
    after = _tree(protected)
    stdout = json.dumps(observation, sort_keys=True).encode()
    return _result(OFFLINE_ID, before, after, stdout, b"cargo seam exit 73", {"cargo": observation, "java_tron_excluded": True, "network_allowed": False})


CASES: dict[str, Callable[[dict[str, object]], dict[str, object]]] = {
    PLATFORM_ID: platform_policy,
    SAPLING_ID: sapling_exclusion,
    OFFLINE_ID: offline_release,
}
