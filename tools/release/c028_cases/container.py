"""Executable C028 container, Compose, and service artifact proof."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import sys
import tempfile
from pathlib import Path
from typing import Callable

VERIFICATION_TIME = "2026-09-08T12:00:00Z"

CASE_ID = "C028-R21-CONTAINER-SERVICE"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tree(root: Path) -> str:
    rows = []
    if root.exists():
        for path in sorted(root.rglob("*")):
            rel = path.relative_to(root).as_posix()
            if path.is_symlink():
                rows.append((rel, "l", os.readlink(path)))
            elif path.is_file():
                rows.append((rel, "f", _sha(path.read_bytes())))
            elif path.is_dir():
                rows.append((rel, "d", ""))
    return _sha(json.dumps(rows, separators=(",", ":")).encode())


def _run(argv: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(argv, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(argv)}\n{result.stdout}\n{result.stderr}")
    return result


def _blob(layout: Path, descriptor: dict[str, object], kind: str) -> bytes:
    digest = descriptor.get("digest")
    size = descriptor.get("size")
    if not isinstance(digest, str) or not digest.startswith("sha256:") or len(digest) != 71:
        raise RuntimeError(f"invalid OCI {kind} digest")
    data = (layout / "blobs" / "sha256" / digest[7:]).read_bytes()
    if len(data) != size or _sha(data) != digest[7:]:
        raise RuntimeError(f"OCI {kind} descriptor does not authenticate its blob")
    return data


def _load_oci(layout: Path, rootfs: Path) -> tuple[dict[str, object], dict[str, object], str]:
    marker = json.loads((layout / "oci-layout").read_text())
    if marker != {"imageLayoutVersion": "1.0.0"}:
        raise RuntimeError("invalid OCI layout marker")
    index = json.loads((layout / "index.json").read_text())
    manifests = index.get("manifests", [])
    if index.get("schemaVersion") != 2 or len(manifests) != 1:
        raise RuntimeError("OCI index must select one manifest")
    manifest = json.loads(_blob(layout, manifests[0], "manifest"))
    layers = manifest.get("layers", [])
    if manifest.get("schemaVersion") != 2 or len(layers) != 1:
        raise RuntimeError("OCI manifest must contain one layer")
    config = json.loads(_blob(layout, manifest["config"], "config"))
    compressed = _blob(layout, layers[0], "layer")
    raw = gzip.decompress(compressed)
    if config.get("rootfs", {}).get("diff_ids") != ["sha256:" + _sha(raw)]:
        raise RuntimeError("OCI diffID does not authenticate the uncompressed rootfs")
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        members = {member.name.rstrip("/"): member for member in archive.getmembers()}
    for volume_root in ("opt/tron", "etc/tron", "var/lib/tron"):
        member = members.get(volume_root)
        if member is None or not member.isdir() or (member.uid, member.gid) != (65532, 65532):
            raise RuntimeError(f"OCI writable volume root is not owned by runtime UID: {volume_root}")
    rootfs.mkdir()
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        archive.extractall(rootfs, filter="data")
    required = ["usr/local/bin/entrypoint.sh", "usr/local/bin/tron-release-verify", "bin/sh"]
    if any(not (rootfs / name).is_file() for name in required):
        raise RuntimeError("OCI rootfs is missing a required executable")
    image_config = config.get("config", {})
    if image_config.get("User") != "65532:65532" or image_config.get("Entrypoint") != ["/usr/local/bin/entrypoint.sh"]:
        raise RuntimeError("OCI nonroot user or entrypoint drift")
    return index, config, manifests[0]["digest"]


def _packaging(repo: Path, work: Path, digest: str) -> dict[str, object]:
    packaging = repo / "rust-tron" / "packaging"
    compose = packaging / "container" / "compose.yaml"
    dockerfile = packaging / "container" / "Dockerfile"
    if not compose.is_file() or not dockerfile.is_file():
        raise RuntimeError("packaged Dockerfile or Compose file is missing")
    docker = shutil.which("docker")
    systemd = shutil.which("systemd-analyze")
    if not docker or not systemd:
        raise RuntimeError("docker with Compose and systemd-analyze are required for the CI container acceptance case")
    env = dict(os.environ, TRON_IMAGE_DIGEST=digest.removeprefix("sha256:"), TRON_VERIFICATION_TIME=VERIFICATION_TIME)
    expected_ports = {"fullnode": {18888, 10001, 8090, 50051, 8545, 5555, 9527, 9080}, "solidity": {8091, 50061, 5555, 9527, 9080}}
    profile_models: dict[str, dict[str, object]] = {}
    for profile, selected in (("full", "fullnode"), ("solidity", "solidity")):
        result = _run([docker, "compose", "--profile", profile, "-f", str(compose), "config", "--format", "json"], cwd=compose.parent, env=env)
        model = json.loads(result.stdout)
        services = model.get("services", {})
        if set(services) != {selected}:
            raise RuntimeError(f"Compose {profile} profile must select only {selected}")
        service = services[selected]
        if service.get("profiles") != [profile]:
            raise RuntimeError(f"{selected} profile metadata drift")
        if service.get("user") != "65532:65532" or service.get("read_only") is not True:
            raise RuntimeError(f"{selected} is not nonroot/read-only")
        if service.get("environment", {}).get("TRON_VERIFICATION_TIME") != VERIFICATION_TIME:
            raise RuntimeError(f"{selected} lacks explicit trusted verification time")
        mounts = service.get("volumes", [])
        mandatory = {"/run/tron/candidate", "/run/tron/release-trust-store.json", "/etc/tron/snapshot-trust-store.json", "/etc/tron/backup-keyring.txt", "/var/lib/tron/parameters/sapling-spend.params", "/var/lib/tron/parameters/sapling-output.params"}
        readonly = {item.get("target") for item in mounts if item.get("read_only") is True}
        if not mandatory <= readonly:
            raise RuntimeError(f"{selected} lacks mandatory read-only mounts")
        published = {int(item["published"]) for item in service.get("ports", [])}
        if published != expected_ports[selected]:
            raise RuntimeError(f"{selected} published port contract drift")
        profile_models[profile] = {"service": selected, "sha256": _sha(result.stdout.encode())}
    default_result = _run([docker, "compose", "-f", str(compose), "config", "--format", "json"], cwd=compose.parent, env=env)
    if json.loads(default_result.stdout).get("services"):
        raise RuntimeError("Compose without a profile must select no node service")
    text = dockerfile.read_text()
    for token in ("FROM scratch AS verified-staging", "USER 65532:65532", "ENTRYPOINT [\"/usr/local/bin/entrypoint.sh\"]", "EXPOSE 18888/tcp 18888/udp"):
        if token not in text:
            raise RuntimeError(f"Dockerfile contract missing {token}")
    verify_root = work / "systemd-root"
    unit_dir = verify_root / "etc/systemd/system"
    bin_dir = verify_root / "opt/tron/current/bin"
    unit_dir.mkdir(parents=True)
    bin_dir.mkdir(parents=True)
    for unit in ("tron-fullnode.service", "tron-solidity.service"):
        shutil.copy2(packaging / "systemd" / unit, unit_dir / unit)
    for binary in ("tron-fullnode", "tron-solidity"):
        (bin_dir / binary).write_text("#!/bin/sh\nexit 0\n")
        (bin_dir / binary).chmod(0o755)
    root_bin = verify_root / "bin"
    root_bin.mkdir()
    for command in ("sh", "kill"):
        shutil.copy2(Path("/bin") / command, root_bin / command)
    for target in ("sysinit.target", "basic.target", "network-online.target", "multi-user.target"):
        (unit_dir / target).write_text("[Unit]\nDescription=C028 verification target\n")
    systemd_result = _run([systemd, "verify", f"--root={verify_root}", str(unit_dir / "tron-fullnode.service"), str(unit_dir / "tron-solidity.service")])
    return {"compose_profiles": profile_models, "default_services": [], "systemd_stderr_sha256": _sha(systemd_result.stderr.encode())}


def _compose_runtime(repo: Path, work: Path, candidate_source: Path, image: str, timeout: int) -> dict[str, object]:
    import importlib.util

    candidate = work / "compose" / "candidate"
    candidate.parent.mkdir()
    shutil.copytree(candidate_source, candidate)
    spec = importlib.util.spec_from_file_location("c028_drills_for_container", repo / "tools" / "release" / "c028_drills.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load C028 signing fixture")
    drills = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(drills)
    trust = candidate.parent / "trust"
    parameters = candidate.parent / "parameters"
    trust.mkdir(); parameters.mkdir()
    release_trust = trust / "release-trust-store.json"
    drills.sign_release(candidate, release_trust, Path("/opt/tron"), Path("/etc/tron"), Path("/var/lib/tron/install-receipt.json"))
    shutil.copy2(release_trust, trust / "snapshot-trust-store.json")
    (trust / "backup-keyring.txt").write_text("127.0.0.2 127.0.0.2:10001 " + "11" * 32 + "\n")
    for path in (release_trust, trust / "snapshot-trust-store.json", trust / "backup-keyring.txt"):
        os.chown(path, 65532, 65532)
        path.chmod(0o600)
    java_params = repo / "java-tron" / "framework" / "src" / "main" / "resources" / "params"
    for name in ("sapling-spend.params", "sapling-output.params"):
        source = java_params / name
        if not source.is_file():
            raise RuntimeError(f"fresh-runner Sapling material is missing: {source}")
        os.symlink(source, parameters / name)
    writable = candidate.parent / "writable"
    for name in ("install", "config", "data"):
        directory = writable / name
        directory.mkdir(parents=True)
        os.chown(directory, 65532, 65532)
        directory.chmod(0o700)
    compose = candidate.parent / "compose.yaml"
    shutil.copy2(repo / "rust-tron" / "packaging" / "container" / "compose.yaml", compose)
    override = candidate.parent / "runtime-image.yaml"
    volume_rows = "\n".join(f"      - type: bind\n        source: {writable / source}\n        target: {target}" for source, target in (("install", "/opt/tron"), ("config", "/etc/tron"), ("data", "/var/lib/tron")))
    override.write_text(f"services:\n  fullnode:\n    image: {image}\n    volumes:\n{volume_rows}\n  solidity:\n    image: {image}\n    volumes:\n{volume_rows}\n")
    env = dict(os.environ, TRON_IMAGE_DIGEST="0" * 64, TRON_VERIFICATION_TIME=VERIFICATION_TIME, TRON_RELEASE_CHANNEL="fixture", COMPOSE_FILE=f"{compose}:{override}")
    env.pop("COMPOSE_PROFILES", None)
    docker = shutil.which("docker") or "docker"
    launcher = repo / "tools" / "release" / "c028_compose.py"
    probes: dict[str, object] = {}
    default_base = [docker, "compose", "-f", str(compose), "-f", str(override)]
    for name, arguments, injected in (("zero", [], None), ("unknown", ["archive"], None), ("dual", ["full", "solidity"], None), ("dual_injection", ["full"], "full,solidity")):
        rejected_env = dict(env)
        if injected is not None:
            rejected_env["COMPOSE_PROFILES"] = injected
        result = subprocess.run([sys.executable, str(launcher), *arguments], cwd=compose.parent, env=rejected_env, text=True, capture_output=True, timeout=timeout)
        if result.returncode != 64:
            raise RuntimeError(f"Compose launcher accepted {name} mode selection: {result.returncode}")
        if _run([*default_base, "ps", "--services"], cwd=compose.parent, env=env).stdout.split():
            raise RuntimeError(f"Compose launcher {name} rejection created a service")
        probes[name] = {"decision": "reject_before_docker", "services": []}
    for mode, profile, binary, forbidden, expected_surfaces in (("fullnode", "full", "tron-fullnode", "solidity", {"18888/tcp", "18888/udp", "10001/udp", "8090/tcp", "50051/tcp", "8545/tcp", "5555/tcp", "9527/tcp", "9080/tcp"}), ("solidity", "solidity", "tron-solidity", "fullnode", {"8091/tcp", "50061/tcp", "5555/tcp", "9527/tcp", "9080/tcp"})):
        base = [docker, "compose", "--profile", profile, "-f", str(compose), "-f", str(override)]
        _run([sys.executable, str(launcher), profile], cwd=compose.parent, env=env, timeout=timeout)
        try:
            running_services = _run([*base, "ps", "--services", "--status", "running"], cwd=compose.parent, env=env).stdout.split()
            if running_services != [mode]:
                raise RuntimeError(f"Compose {profile} profile started unexpected services: {running_services}")
            if _run([*base, "ps", "--quiet", forbidden], cwd=compose.parent, env=env).stdout.strip():
                raise RuntimeError(f"Compose {profile} profile created forbidden service {forbidden}")
            container_id = _run([*base, "ps", "--quiet", mode], cwd=compose.parent, env=env).stdout.strip()
            if not container_id:
                raise RuntimeError(f"Compose did not create {mode}")
            live_surfaces = set(json.loads(_run([docker, "inspect", "--format", "{{json .NetworkSettings.Ports}}", container_id]).stdout))
            if live_surfaces != expected_surfaces:
                raise RuntimeError(f"{mode} live listener exposure drift: {sorted(live_surfaces)}")
            deadline = __import__("time").monotonic() + timeout
            probe = None
            while __import__("time").monotonic() < deadline:
                probe = subprocess.run([docker, "exec", container_id, f"/opt/tron/current/bin/{binary}", "probe", "--deployment-config", f"/etc/tron/current/{mode}.deployment.json", "--kind", "ready"], text=True, capture_output=True)
                if probe.returncode == 0:
                    break
                running = subprocess.run([docker, "inspect", "--format", "{{.State.Running}}", container_id], text=True, capture_output=True)
                if running.returncode or running.stdout.strip() != "true":
                    break
                __import__("time").sleep(0.2)
            if probe is None or probe.returncode:
                logs = subprocess.run([*base, "logs", mode], cwd=compose.parent, env=env, text=True, capture_output=True)
                raise RuntimeError(f"{mode} did not reach semantic readiness: {logs.stdout}\n{logs.stderr}")
            probes[mode] = {"authentication": "accepted", "install_receipt": True, "preflight": "accepted", "semantic_startup": "ready", "profile": profile, "services": running_services, "forbidden_service": forbidden, "published_surfaces": sorted(live_surfaces)}
        finally:
            _run([*base, "down", "--volumes", "--remove-orphans"], cwd=compose.parent, env=env, timeout=timeout)
    return probes


def _negative_time_probes(docker: str, image: str, work: Path) -> dict[str, object]:
    probes = {}
    for name, value in (("missing", None), ("malformed", "2026-09-08 12:00:00"), ("invalid_calendar", "2026-99-08T12:00:00Z")):
        state = work / f"negative-{name}"
        for directory in (state / "install", state / "config", state / "data"):
            directory.mkdir(parents=True, exist_ok=True)
        before = _tree(state)
        command = [docker, "run", "--rm", "--user", "65532:65532", "--read-only", "--mount", f"type=bind,src={state / 'install'},dst=/opt/tron", "--mount", f"type=bind,src={state / 'config'},dst=/etc/tron", "--mount", f"type=bind,src={state / 'data'},dst=/var/lib/tron"]
        if value is not None:
            command.extend(["--env", f"TRON_VERIFICATION_TIME={value}"])
        command.extend([image, "fullnode"])
        result = subprocess.run(command, text=True, capture_output=True, timeout=60)
        if result.returncode != 64 or "TRON_VERIFICATION_TIME" not in result.stderr or _tree(state) != before:
            raise RuntimeError(f"{name} verification time was not rejected before mutation: {result.returncode} {result.stderr!r}")
        probes[name] = {"decision": "reject_before_mutation", "exit_code": 64}
    return probes


def container_service(context: dict[str, object]) -> dict[str, object]:
    if context.get("mode") in {"metadata", "local-metadata"}:
        raise RuntimeError("local metadata mode is diagnostic only and cannot satisfy C028 container acceptance")
    repo = Path(str(context.get("repo") or context.get("root") or Path(__file__).resolve().parents[3])).resolve()
    workspace = Path(str(context.get("workspace") or tempfile.mkdtemp(prefix="c028-container-"))).resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    candidate = Path(str(context.get("candidate") or context.get("candidate_dir") or context.get("release") or context.get("release_dir") or workspace / "candidate")).resolve()
    layout = Path(str(context.get("oci_layout") or (candidate / "bundle" if (candidate / "bundle" / "index.json").is_file() else candidate)))
    before = _tree(workspace)
    stdout = bytearray()
    stderr = bytearray()
    with tempfile.TemporaryDirectory(prefix="c028-container-proof-", dir=workspace) as temporary:
        work = Path(temporary)
        rootfs = work / "rootfs"
        index, config, digest = _load_oci(layout, rootfs)
        metadata = _packaging(repo, work, digest)
        docker = shutil.which("docker")
        if not docker:
            raise RuntimeError("docker runtime is required for container acceptance")
        daemon = _run([docker, "info", "--format", "{{json .ServerVersion}}"])
        stdout.extend(daemon.stdout.encode()); stderr.extend(daemon.stderr.encode())
        image = "c028-container-proof:local"
        tar_path = work / "rootfs.tar"
        with tarfile.open(tar_path, "w") as archive:
            archive.add(rootfs, arcname=".")
        load = subprocess.run([docker, "import", "--change", 'USER 65532:65532', "--change", 'ENTRYPOINT [\"/usr/local/bin/entrypoint.sh\"]', "--change", 'ENV PATH=/usr/local/bin:/usr/bin:/bin', str(tar_path), image], text=True, capture_output=True, timeout=180)
        stdout.extend(load.stdout.encode()); stderr.extend(load.stderr.encode())
        if load.returncode:
            raise RuntimeError(f"authenticated OCI rootfs import failed: {load.stderr}")
        try:
            negative_probes = _negative_time_probes(docker, image, work)
            probes = _compose_runtime(repo, work, candidate, image, int(context.get("timeout_seconds", 180)))
        finally:
            subprocess.run([docker, "image", "rm", "-f", image], capture_output=True, text=True)
    after = _tree(workspace)
    details = {"oci_manifest": digest, "oci_diff_ids": config["rootfs"]["diff_ids"], "oci_entrypoint": config["config"]["Entrypoint"], "oci_user": config["config"]["User"], "index_schema": index["schemaVersion"], "protocol_probes": probes, "verification_time_probes": negative_probes, "all_material_compose": True, **metadata}
    return {"id": CASE_ID, "decision": "accept", "mutation": "temporary-runtime-image-only", "exit_code": 0, "stdout_sha256": _sha(bytes(stdout)), "stderr_sha256": _sha(bytes(stderr)), "before_tree_sha256": before, "after_tree_sha256": after, "details": details}


CASES: dict[str, Callable[[dict[str, object]], dict[str, object]]] = {CASE_ID: container_service}
