#!/usr/bin/env python3
"""C001 protobuf inventory, drift, lint, descriptor, and wire-fixture gate."""
from __future__ import annotations

import argparse
import hashlib
import json

import subprocess
import sys
import tomllib
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CRATE = ROOT / "rust-tron/crates/tron-protocol"
PROTO = CRATE / "proto"
JAVA = ROOT / "java-tron/protocol/src/main/protos"
DESCRIPTOR = CRATE / "descriptors/protocol.v1.pb"
INVENTORY = ROOT / "docs/oracles/protocol-conformance.v1.json"
FIXTURE_MANIFEST = ROOT / "docs/oracles/protocol-fixtures.v1.json"
EXTENSION_MANIFEST = ROOT / "docs/oracles/dr004-extension-fixtures.v1.json"
FIXTURES = CRATE / "tests/fixtures/protocol"
EXTENSION_FIXTURES = CRATE / "tests/fixtures/extensions"
LOCKFILE = ROOT / "rust-tron/Cargo.lock"
JAVA_ORACLE = ROOT / "tools/protocol/java/MapSerializationOracle.java"
JAVA_VERIFICATION = ROOT / "java-tron/gradle/verification-metadata.xml"
JAVA_PROTOBUF_VERSION = "3.25.8"
JAVA_PROTOBUF_SHA256 = "72bdb32eb38cafb7dcd288262c29a34d57cba2e19101af9685155ba8c0a56008"
VENDORED_PROTOC = [
    "cargo", "run", "--locked", "--quiet", "-p", "tron-protocol",
    "--bin", "protoc_vendored", "--",
]
EXPECTED_PROTOC_VERSION = "libprotoc 28.2"
EXTENSION_DESCRIPTORS = {
    "alternate_actuator.pb": ("alternate_actuator.proto", False),
    "builtin_name_collision.pb": ("builtin_name_collision.proto", False),
    "cross_collision_one.pb": ("cross_collision_one.proto", False),
    "cross_collision_two.pb": ("cross_collision_two.proto", False),
    "example_actuator.pb": ("example_actuator.proto", False),
    "unique_selected_builtin_collision.pb": ("unique_selected_builtin_collision.proto", True),
}
EXTENSION_CLASSES = {
    "alternate_actuator.pb": "independent_descriptor",
    "alternate_actuator.proto": "independent_descriptor_source",
    "builtin_name_collision.pb": "built_in_identity_collision",
    "builtin_name_collision.proto": "built_in_identity_collision_source",
    "cross_collision_one.pb": "cross_extension_collision_descriptor",
    "cross_collision_one.proto": "cross_extension_collision_source",
    "cross_collision_two.pb": "cross_extension_collision_descriptor",
    "cross_collision_two.proto": "cross_extension_collision_source",
    "example_actuator.pb": "descriptor",
    "example_actuator.proto": "descriptor_source",
    "example_any.bin": "any",
    "example_contract.bin": "message",
    "example_transaction_contract.bin": "transaction_contract",
    "malformed_descriptor.bin": "malformed_descriptor",
    "unique_selected_builtin_collision.pb": "secondary_built_in_collision",
    "unique_selected_builtin_collision.proto": "secondary_built_in_collision_source",
}
EXTENSION_GENERATOR = (
    "protoc-bin-vendored 3.1.0 (libprotoc 28.2; Cargo.lock checksum "
    "dd89a830d0eab2502c81a9b8226d446a52998bb78e5e33cb2637c0cdd6068d99) "
    "via protoc_vendored helper"
)


def vendored_protoc_info():
    result = subprocess.run(
        VENDORED_PROTOC[:-1], cwd=ROOT / "rust-tron", check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return json.loads(result.stdout)


def run_protoc(args, *, cwd=PROTO, **kwargs):
    return subprocess.run(VENDORED_PROTOC + list(args), cwd=cwd, **kwargs)

def locked_package(name: str):
    packages = tomllib.loads(LOCKFILE.read_text())["package"]
    return next(package for package in packages if package["name"] == name)

PROTOS = [
    "api/api.proto", "api/zksnark.proto", "core/Discover.proto", "core/Tron.proto",
    "core/TronInventoryItems.proto", "core/contract/account_contract.proto",
    "core/contract/asset_issue_contract.proto", "core/contract/balance_contract.proto",
    "core/contract/common.proto", "core/contract/exchange_contract.proto",
    "core/contract/market_contract.proto", "core/contract/proposal_contract.proto",
    "core/contract/shield_contract.proto", "core/contract/smart_contract.proto",
    "core/contract/storage_contract.proto", "core/contract/vote_asset_contract.proto",
    "core/contract/witness_contract.proto",
]
LEGACY_ENUMS = {
    "core/contract/common.proto:ResourceCode",
    "core/contract/smart_contract.proto:SmartContract.ABI.Entry.EntryType",
    "core/contract/smart_contract.proto:SmartContract.ABI.Entry.StateMutabilityType",
    "core/Tron.proto:AccountType", "core/Tron.proto:ReasonCode", "core/Tron.proto:Proposal.State",
    "core/Tron.proto:MarketOrder.State", "core/Tron.proto:Permission.PermissionType",
    "core/Tron.proto:Transaction.Contract.ContractType", "core/Tron.proto:Transaction.Result.code",
    "core/Tron.proto:Transaction.Result.contractResult", "core/Tron.proto:TransactionInfo.code",
    "core/Tron.proto:BlockInventory.Type", "core/Tron.proto:Inventory.InventoryType",
    "core/Tron.proto:Items.ItemType", "core/Tron.proto:PBFTMessage.MsgType",
    "core/Tron.proto:PBFTMessage.DataType", "api/api.proto:Return.response_code",
    "api/api.proto:TransactionSignWeight.Result.response_code",
    "api/api.proto:TransactionApprovedList.Result.response_code", "api/zksnark.proto:ZksnarkResponse.Code",
}
CASES = ("encode", "decode", "malformed", "unknown_field", "any", "map_order", "presence", "size")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

PROVENANCE_CATEGORIES = {"copied", "mechanically_derived", "clean_room", "newly_authored"}
FIXTURE_PROVENANCE_FIELDS = {
    "path", "sha256", "kind", "category", "origin", "origin_revision", "source_inputs",
    "generator", "generator_version", "command", "license_and_notices", "distribution",
}


def safe_in_tree_path(value: object) -> Path | None:
    if not isinstance(value, str) or not value or "\\" in value:
        return None
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts or relative.as_posix() != value:
        return None
    candidate = (ROOT / relative).resolve()
    try:
        candidate.relative_to(ROOT.resolve())
    except ValueError:
        return None
    return candidate


def check_fixture_provenance(manifest: dict) -> list[str]:
    errors = []
    rows = manifest.get("provenance")
    if not isinstance(rows, list):
        return ["fixture provenance must be a list"]
    actual_paths = {
        path.relative_to(ROOT).as_posix()
        for path in FIXTURES.rglob("*") if path.is_file()
    }
    recorded_paths = set()
    for index, row in enumerate(rows):
        label = f"fixture provenance row {index}"
        if not isinstance(row, dict):
            errors.append(f"{label} must be an object")
            continue
        missing = FIXTURE_PROVENANCE_FIELDS - row.keys()
        extra = row.keys() - FIXTURE_PROVENANCE_FIELDS
        if missing: errors.append(f"{label} missing fields: {sorted(missing)}")
        if extra: errors.append(f"{label} has extra fields: {sorted(extra)}")
        path = safe_in_tree_path(row.get("path"))
        if path is None:
            errors.append(f"{label} has unsafe path: {row.get('path')!r}")
            continue
        relative = path.relative_to(ROOT).as_posix()
        digest = row.get("sha256")
        if not isinstance(digest, str) or len(digest) != 64 or (path.is_file() and sha(path.read_bytes()) != digest):
            errors.append(f"fixture provenance digest mismatch: {relative}")
        if relative in recorded_paths: errors.append(f"duplicate fixture provenance path: {relative}")
        recorded_paths.add(relative)
        if path.parent != FIXTURES.resolve(): errors.append(f"fixture provenance path outside protocol fixture directory: {relative}")
        if not path.is_file(): errors.append(f"fixture provenance path is not a file: {relative}")
        expected_kind = "textproto" if path.suffix == ".textproto" else "binary" if path.suffix == ".bin" else None
        if row.get("kind") != expected_kind: errors.append(f"fixture provenance kind mismatch: {relative}")
        category = row.get("category")
        if category not in PROVENANCE_CATEGORIES: errors.append(f"invalid fixture provenance category: {relative}")
        for field in FIXTURE_PROVENANCE_FIELDS - {"path", "sha256", "kind", "category", "source_inputs"}:
            if not isinstance(row.get(field), str) or not row[field].strip():
                errors.append(f"fixture provenance {field} must be non-empty: {relative}")
        inputs = row.get("source_inputs")
        if not isinstance(inputs, list):
            errors.append(f"fixture provenance source_inputs must be a list: {relative}")
            continue
        if category in {"copied", "mechanically_derived", "clean_room"} and not inputs:
            errors.append(f"fixture provenance category requires source inputs: {relative}")
        if category == "mechanically_derived" and row.get("generator") in {"none", "manual-authorship"}:
            errors.append(f"mechanically derived fixture lacks generator: {relative}")
        if category == "mechanically_derived" and (not isinstance(row.get("command"), str) or "no generator" in row["command"]):
            errors.append(f"mechanically derived fixture lacks a mutation/generation command: {relative}")
        for source_index, source in enumerate(inputs):
            source_label = f"{relative} source input {source_index}"
            if not isinstance(source, dict) or set(source) != {"path", "sha256"}:
                errors.append(f"{source_label} must contain exactly path and sha256")
                continue
            source_path = safe_in_tree_path(source.get("path"))
            source_digest = source.get("sha256")
            if source_path is None or not source_path.is_file():
                errors.append(f"{source_label} is not a safe in-tree file")
            elif not isinstance(source_digest, str) or len(source_digest) != 64 or sha(source_path.read_bytes()) != source_digest:
                errors.append(f"{source_label} digest mismatch")
    if recorded_paths != actual_paths:
        errors.append(
            f"fixture provenance directory coverage mismatch: missing={sorted(actual_paths-recorded_paths)} "
            f"extras={sorted(recorded_paths-actual_paths)}"
        )
    fixture_paths = {
        row.get("path") for row in manifest.get("fixtures", [])
        if isinstance(row, dict) and isinstance(row.get("path"), str) and row["path"].startswith(FIXTURES.relative_to(ROOT).as_posix() + "/")
    }
    binary_paths = {path for path in actual_paths if path.endswith(".bin")}
    if fixture_paths != binary_paths:
        errors.append(f"fixture manifest binary coverage mismatch: missing={sorted(binary_paths-fixture_paths)} extras={sorted(fixture_paths-binary_paths)}")
    source_paths = {
        row.get("source") for row in manifest.get("fixtures", [])
        if isinstance(row, dict) and row.get("expect") == "encode_exact"
    }
    textproto_paths = {path for path in actual_paths if path.endswith(".textproto")}
    if source_paths != textproto_paths:
        errors.append(f"fixture manifest textproto coverage mismatch: missing={sorted(textproto_paths-source_paths)} extras={sorted(source_paths-textproto_paths)}")
    return errors



def varint(value: int) -> bytes:
    out = bytearray()
    while value > 0x7f:
        out.append((value & 0x7f) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def fields(data: bytes):
    pos = 0
    while pos < len(data):
        key, pos = read_varint(data, pos)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, pos = read_varint(data, pos)
            yield number, wire, value
        elif wire == 1:
            end = pos + 8; yield number, wire, data[pos:end]; pos = end
        elif wire == 2:
            length, pos = read_varint(data, pos); end = pos + length
            if end > len(data): raise ValueError("truncated length-delimited field")
            yield number, wire, data[pos:end]; pos = end
        elif wire == 5:
            end = pos + 4; yield number, wire, data[pos:end]; pos = end
        else:
            raise ValueError(f"unsupported protobuf wire type {wire}")


def read_varint(data: bytes, pos: int):
    value = shift = 0
    while pos < len(data) and shift < 70:
        byte = data[pos]; pos += 1; value |= (byte & 0x7f) << shift
        if byte < 0x80: return value, pos
        shift += 7
    raise ValueError("truncated or oversized varint")


def text(data: bytes) -> str:
    return data.decode("utf-8")


def field_values(data: bytes, number: int, wire: int | None = None):
    return [v for n, w, v in fields(data) if n == number and (wire is None or w == wire)]


def descriptor_inventory(data: bytes):
    files = []
    for file_data in field_values(data, 1, 2):
        name = text(field_values(file_data, 1, 2)[0])
        package_values = field_values(file_data, 2, 2)
        package = text(package_values[0]) if package_values else ""
        row = {"path": name, "package": package, "messages": [], "enums": [], "services": []}
        for message_data in field_values(file_data, 4, 2):
            parse_message(message_data, "", row)
        for enum_data in field_values(file_data, 5, 2):
            row["enums"].append(parse_enum(enum_data, ""))
        for service_data in field_values(file_data, 6, 2):
            methods = []
            for method_data in field_values(service_data, 2, 2):
                methods.append({
                    "name": text(field_values(method_data, 1, 2)[0]),
                    "input": text(field_values(method_data, 2, 2)[0]).lstrip("."),
                    "output": text(field_values(method_data, 3, 2)[0]).lstrip("."),
                    "client_streaming": bool((field_values(method_data, 5, 0) or [0])[0]),
                    "server_streaming": bool((field_values(method_data, 6, 0) or [0])[0]),
                })
            row["services"].append({"name": text(field_values(service_data, 1, 2)[0]), "methods": methods})
        files.append(row)
    return sorted(files, key=lambda item: item["path"])


def parse_message(data: bytes, prefix: str, file_row: dict):
    name = text(field_values(data, 1, 2)[0]); relative = f"{prefix}.{name}" if prefix else name
    message_fields = []
    for field_data in field_values(data, 2, 2):
        type_names = field_values(field_data, 6, 2)
        message_fields.append({
            "name": text(field_values(field_data, 1, 2)[0]),
            "number": field_values(field_data, 3, 0)[0],
            "label": (field_values(field_data, 4, 0) or [1])[0],
            "type": (field_values(field_data, 5, 0) or [0])[0],
            "type_name": text(type_names[0]).lstrip(".") if type_names else None,
            "proto3_optional": bool((field_values(field_data, 17, 0) or [0])[0]),
        })
    options = field_values(data, 7, 2)
    map_entry = bool(options and (field_values(options[0], 7, 0) or [0])[0])
    file_row["messages"].append({"name": relative, "fields": message_fields, "map_entry": map_entry})
    for enum_data in field_values(data, 4, 2):
        file_row["enums"].append(parse_enum(enum_data, relative))
    for nested_data in field_values(data, 3, 2):
        parse_message(nested_data, relative, file_row)


def parse_enum(data: bytes, prefix: str):
    name = text(field_values(data, 1, 2)[0]); relative = f"{prefix}.{name}" if prefix else name
    values = [{"name": text(field_values(v, 1, 2)[0]), "number": field_values(v, 2, 0)[0]} for v in field_values(data, 2, 2)]
    return {"name": relative, "values": values}


def normalized_descriptor() -> bytes:
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "descriptor.pb"
        command = [f"--proto_path={PROTO}", "--include_imports", f"--descriptor_set_out={output}", *PROTOS]
        run_protoc(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        file_blobs = field_values(output.read_bytes(), 1, 2)
        file_blobs.sort(key=lambda blob: field_values(blob, 1, 2)[0])
        return b"".join(varint((1 << 3) | 2) + varint(len(blob)) + blob for blob in file_blobs)


def descriptor_metadata(descriptor: bytes, protoc_info: dict) -> dict:
    build_rs = (CRATE / "build.rs").read_bytes()
    build_text = build_rs.decode()
    required_build_rules = [
        'prost.btree_map(["."])',
        "prost.file_descriptor_set_path(&generated_descriptor)",
        ".build_client(true)",
        ".build_server(true)",
        ".compile_well_known_types(true)",
        'compile_protos_with_config(prost, PROTOS, &["proto"])',
        "descriptor.file.sort_by(|left, right| left.name.cmp(&right.name))",
        "file.source_code_info = None",
        "descriptor.encode_to_vec()",
    ]
    missing = [rule for rule in required_build_rules if rule not in build_text]
    if missing:
        raise ValueError(f"build.rs descriptor contract drift: missing={missing}")

    files = descriptor_inventory(descriptor)
    services = sorted(
        f"{file['package']}.{service['name']}"
        for file in files for service in file["services"]
    )
    inputs = [
        {"path": f"proto/{path}", "sha256": sha((PROTO / path).read_bytes())}
        for path in PROTOS
    ]
    inputs.append({"path": "proto/google/protobuf/any.proto", "sha256": sha((PROTO / "google/protobuf/any.proto").read_bytes())})
    packages = {}
    for name in ("prost", "prost-build", "prost-types", "tonic", "tonic-build", "protoc-bin-vendored"):
        package = locked_package(name)
        packages[name] = {"version": package["version"], "checksum": package["checksum"]}
    toolchain = tomllib.loads((ROOT / "rust-tron/rust-toolchain.toml").read_text())["toolchain"]
    any_path = CRATE / "proto/google/protobuf/any.proto"
    any_license = CRATE / "proto/google/LICENSE"
    return {
        "schema_version": 1,
        "artifact": "descriptors/protocol.v1.pb",
        "artifact_sha256": sha(descriptor),
        "java_tron_revision": "4a21592f95e37908b21bc3f611c6e7a1a67f09f3",
        "rust_toolchain": {
            "channel": toolchain["channel"],
            "profile": toolchain["profile"],
            "components": toolchain["components"],
            "targets": toolchain["targets"],
        },
        "build_rs_sha256": sha(build_rs),
        "generator": {"packages": packages, "protoc_source": "protoc-bin-vendored", "protoc_version": protoc_info["version"]},
        "options": {
            "root_input_count": len(PROTOS),
            "include_root": "proto",
            "include_imports": True,
            "include_source_info_during_generation": True,
            "compile_well_known_types": True,
            "well_known_input": "google/protobuf/any.proto",
            "map_representation": "BTreeMap for every generated map field",
            "build_client": True,
            "build_server": True,
        },
        "service_surfaces": services,
        "normalization": [
            "sort FileDescriptorProto entries lexicographically by name",
            "clear every source_code_info field",
            f"encode the FileDescriptorSet with prost {packages['prost']['version']}",
        ],
        "inputs": inputs,
        "google_any_provenance": {
            "source": "https://github.com/protocolbuffers/protobuf/blob/v3.25.8/src/google/protobuf/any.proto",
            "revision": "v3.25.8",
            "license": "BSD-3-Clause",
            "license_file": "proto/google/LICENSE",
            "license_sha256": sha(any_license.read_bytes()),
            "sha256": sha(any_path.read_bytes()),
        },
    }


def java_map_oracles() -> list[dict]:
    verification = JAVA_VERIFICATION.read_text()
    component = f'<component group="com.google.protobuf" name="protobuf-java" version="{JAVA_PROTOBUF_VERSION}">'
    component_metadata = verification.split(component, 1)[1].split("</component>", 1)[0] if component in verification else ""
    if f'<sha256 value="{JAVA_PROTOBUF_SHA256}"' not in component_metadata:
        raise ValueError("protobuf-java 3.25.8 is not authenticated by java-tron Gradle metadata")
    resolver = subprocess.run(
        [str(ROOT / "java-tron/gradlew"), "-p", str(JAVA_ORACLE.parent), "printProtobufJavaJar", "--quiet", "--no-daemon"],
        cwd=ROOT, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    jar = Path(resolver.stdout.strip().splitlines()[-1])
    if sha(jar.read_bytes()) != JAVA_PROTOBUF_SHA256:
        raise ValueError("resolved protobuf-java jar digest differs from authenticated Gradle metadata")
    with tempfile.TemporaryDirectory() as directory:
        subprocess.run(
            ["javac", "-cp", str(jar), "-d", directory, str(JAVA_ORACLE)],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        result = subprocess.run(
            ["java", "-cp", f"{directory}:{jar}", "MapSerializationOracle", str(DESCRIPTOR)],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
    return json.loads(result.stdout)


def source_drift_errors():
    errors = []
    for relative in PROTOS:
        rust = (PROTO / relative).read_bytes(); java = (JAVA / relative).read_bytes()
        if rust != java: errors.append(f"schema drift: {relative} rust={sha(rust)} java={sha(java)}")
    expected = set(PROTOS)
    actual = {str(path.relative_to(JAVA)) for path in JAVA.rglob("*.proto")}
    if actual != expected:
        errors.append(f"Java schema inventory differs: missing={sorted(expected-actual)} extra={sorted(actual-expected)}")
    return errors


def cases_for(message: dict, map_entries: set[str]):
    fields_ = message["fields"]
    applicable = {"encode", "decode", "malformed", "unknown_field", "presence", "size"}
    if any(field["type_name"] == "google.protobuf.Any" for field in fields_): applicable.add("any")
    if any(field["type_name"] in map_entries for field in fields_): applicable.add("map_order")
    return {case: case in applicable for case in CASES}


def make_inventory():
    descriptor = DESCRIPTOR.read_bytes(); files = descriptor_inventory(descriptor)
    rows = []
    for file in files:
        if file["path"].startswith("google/"): continue
        package = file["package"]
        map_entries = {f"{package}.{message['name']}" for message in file["messages"] if message["map_entry"]}
        rows.append({"kind": "schema", "id": file["path"], "owner_item": "C001.07", "gate": "C001.V"})
        for message in file["messages"]:
            rows.append({"kind": "message", "id": f"{package}.{message['name']}", "schema": file["path"], "cases": cases_for(message, map_entries), "owner_item": "C001.07", "gate": "C001.V"})
        for enum in file["enums"]:
            rows.append({"kind": "enum", "id": f"{package}.{enum['name']}", "schema": file["path"], "owner_item": "C001.07", "gate": "C001.V"})
        for service in file["services"]:
            service_id = f"{package}.{service['name']}"
            rows.append({"kind": "service", "id": service_id, "schema": file["path"], "owner_item": "C001.07", "gate": "C001.V"})
            for method in service["methods"]:
                rows.append({"kind": "method", "id": f"{service_id}/{method['name']}", "schema": file["path"], "input": method["input"], "output": method["output"], "client_streaming": method["client_streaming"], "server_streaming": method["server_streaming"], "owner_item": "C001.07", "gate": "C001.V"})
    counts = {kind: sum(row["kind"] == kind for row in rows) for kind in ("schema", "message", "enum", "service", "method")}
    return {
        "schema_version": 1,
        "java_tron_revision": "4a21592f95e37908b21bc3f611c6e7a1a67f09f3",
        "descriptor": "../../rust-tron/crates/tron-protocol/descriptors/protocol.v1.pb",
        "descriptor_sha256": sha(descriptor),
        "normalization": ["protoc --include_imports without source info", "sort FileDescriptorProto by name", "preserve each FileDescriptorProto byte encoding"],
        "case_definitions": {
            "encode": "canonical source-derived message encodes to expected bytes",
            "decode": "expected bytes decode with the declared message type",
            "malformed": "truncated or invalid wire input is rejected",
            "unknown_field": "well-formed unknown fields are accepted and do not alter known values",
            "any": "Any type URL is type.googleapis.com/<fully-qualified-name> and value bytes are canonical",
            "map_order": "logical map equality is independent of encoded entry order; canonical fixture order is explicit",
            "presence": "absent versus explicitly encoded default is covered where wire presence is observable",
            "size": "encoded byte count is asserted before size-sensitive hashing or transport",
        },
        "counts": counts,
        "unmapped_rows": 0,
        "rows": rows,
    }

def lint_enums(inventory):
    files = descriptor_inventory(DESCRIPTOR.read_bytes()); seen = set(); violations = []
    for file in files:
        if file["path"].startswith("google/"): continue
        for enum in file["enums"]:
            identifier = f"{file['path']}:{enum['name']}"
            zero = next((value["name"] for value in enum["values"] if value["number"] == 0), None)
            if identifier in LEGACY_ENUMS: seen.add(identifier)
            elif zero is not None and not zero.startswith("UNKNOWN_"): violations.append(f"{identifier}={zero}")
    if seen != LEGACY_ENUMS: violations.append(f"stale legacy enum allowlist: missing={sorted(LEGACY_ENUMS-seen)} extra={sorted(seen-LEGACY_ENUMS)}")
    return violations


def protoc_codec(mode: str, message: str, payload: bytes):
    return run_protoc(
        [f"--proto_path={PROTO}", f"--{mode}={message}", *PROTOS],
        input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )


def check_fixtures(manifest):
    errors = []
    payloads = {}
    errors.extend(check_fixture_provenance(manifest))
    coverage = {family: set() for family in manifest["families"]}
    for case in manifest["fixtures"]:
        path = safe_in_tree_path(case.get("path"))
        if path is None or not path.is_file():
            errors.append(f"fixture path missing or unsafe: {case.get('case_id')}")
            continue
        payload = path.read_bytes()
        payloads[case["case_id"]] = payload
        if case["family"] in coverage: coverage[case["family"]].add(case["class"])
        if len(payload) != case["size"] or sha(payload) != case["sha256"]:
            errors.append(f"fixture drift: {case['case_id']}"); continue
        if case["expect"] == "decode_ok":
            result = protoc_codec("decode", case["message"], payload)
            if result.returncode: errors.append(f"decode rejected {case['case_id']}: {result.stderr.decode().strip()}")
        elif case["expect"] == "decode_error":
            result = protoc_codec("decode", case["message"], payload)
            if result.returncode == 0: errors.append(f"malformed fixture accepted: {case['case_id']}")
        elif case["expect"] == "encode_exact":
            source_path = safe_in_tree_path(case.get("source"))
            if source_path is None or not source_path.is_file():
                errors.append(f"fixture source missing or unsafe: {case['case_id']}")
                continue
            source = source_path.read_bytes(); result = protoc_codec("encode", case["message"], source)
            if result.returncode or result.stdout != payload: errors.append(f"encode mismatch: {case['case_id']}")
    required = {"canonical", "unknown_field", "malformed"}
    for family, classes in coverage.items():
        if not required <= classes: errors.append(f"incomplete fixture family {family}: missing={sorted(required-classes)}")
    for family in manifest["families"]:
        canonical = payloads.get(f"{family}-canonical")
        unknown = payloads.get(f"{family}-unknown")
        if canonical is None or unknown is None:
            continue
        if not unknown.startswith(canonical) or unknown == canonical:
            errors.append(f"unknown-field fixture does not preserve canonical known bytes: {family}")
    def account_map(payload):
        entries = {}
        for entry in field_values(payload, 6, 2):
            keys = field_values(entry, 1, 2); values = field_values(entry, 2, 0)
            if keys and values: entries[text(keys[0])] = values[0]
        return entries
    account_canonical = payloads.get("account-canonical")
    account_reversed = payloads.get("account-map-reversed")
    if account_canonical is not None and account_reversed is not None:
        if account_map(account_canonical) != account_map(account_reversed):
            errors.append("map-order fixtures are not logically equivalent")
        if account_canonical == account_reversed:
            errors.append("map-order fixtures do not exercise distinct encodings")
    presence_absent = payloads.get("presence-absent")
    presence_default = payloads.get("presence-default")
    if presence_absent is not None and presence_default is not None and presence_absent == presence_default:
        errors.append("presence fixtures do not distinguish absent and explicit default")
    any_payload = payloads.get("extension-any-canonical")
    if any_payload is not None:
        any_urls = field_values(any_payload, 1, 2)
        if not any_urls or text(any_urls[0]) != "type.googleapis.com/org.tron.example.actuator.ExampleContract":
            errors.append("Any fixture type URL drift")
    return errors


def check_extension_fixtures(manifest, protoc_info, locked_protoc):
    errors = []
    expected_generator = manifest.get("generator")
    actual_generator = {
        "helper": "rust-tron/crates/tron-protocol/src/bin/protoc_vendored.rs",
        "cargo_package": "protoc-bin-vendored",
        "cargo_version": locked_protoc["version"],
        "cargo_checksum": locked_protoc["checksum"],
        "protoc_version": protoc_info["version"],
    }
    if expected_generator != actual_generator:
        errors.append("extension fixture generator provenance drift")

    rows = manifest.get("fixtures", [])
    declared_paths = [row.get("path") for row in rows]
    if len(declared_paths) != len(set(declared_paths)):
        errors.append("duplicate extension fixture manifest path")
    actual_names = {path.name for path in EXTENSION_FIXTURES.iterdir() if path.is_file()}
    declared_names = {Path(path).name for path in declared_paths if isinstance(path, str)}
    if declared_names != actual_names:
        errors.append(
            f"extension fixture manifest coverage drift: missing={sorted(actual_names-declared_names)} "
            f"unexpected={sorted(declared_names-actual_names)}"
        )

    required_provenance = {
        "category", "origin", "generator", "inputs", "modification_method",
        "license_and_notices", "distribution",
    }
    rows_by_name = {}
    for row in rows:
        relative = row.get("path")
        if not isinstance(relative, str):
            errors.append("extension fixture path is not a string")
            continue
        path = (EXTENSION_MANIFEST.parent / relative).resolve()
        name = path.name
        rows_by_name[name] = row
        if path.parent != EXTENSION_FIXTURES.resolve():
            errors.append(f"extension fixture path escapes fixture directory: {relative}")
        if row.get("class") != EXTENSION_CLASSES.get(name):
            errors.append(
                f"extension fixture class drift: {name}: "
                f"actual={row.get('class')} expected={EXTENSION_CLASSES.get(name)}"
            )
        provenance = row.get("provenance")
        if not isinstance(provenance, dict) or set(provenance) != required_provenance:
            errors.append(f"invalid extension fixture provenance fields: {name}")
            provenance = {}
        elif (not all(provenance[key] for key in required_provenance - {"inputs"})
              or not isinstance(provenance["inputs"], list)):
            errors.append(f"incomplete extension fixture provenance: {name}")
        if name.endswith(".pb") and provenance.get("generator") != EXTENSION_GENERATOR:
            errors.append(f"extension descriptor generator provenance drift: {name}")
        if name.endswith(".proto") and provenance.get("category") != "newly_authored":
            errors.append(f"extension source provenance category drift: {name}")
        if not path.is_file():
            errors.append(f"missing extension fixture: {name}")
            continue
        payload = path.read_bytes()
        if row.get("size") != len(payload) or row.get("sha256") != sha(payload):
            errors.append(f"extension fixture size/digest drift: {name}")

    for name, row in rows_by_name.items():
        provenance = row.get("provenance", {})
        for input_ref in provenance.get("inputs", []):
            if "@sha256:" not in input_ref:
                continue
            input_name, expected_digest = input_ref.split("@sha256:", 1)
            input_row = rows_by_name.get(input_name)
            if input_row is None or input_row.get("sha256") != expected_digest:
                errors.append(f"extension fixture input provenance drift: {name}: {input_name}")

    with tempfile.TemporaryDirectory() as directory:
        output_dir = Path(directory)
        for output_name, (source_name, include_imports) in EXTENSION_DESCRIPTORS.items():
            args = [f"--proto_path={EXTENSION_FIXTURES}"]
            if include_imports:
                args.append("--include_imports")
            generated = output_dir / output_name
            args.extend([f"--descriptor_set_out={generated}", source_name])
            result = run_protoc(args, cwd=EXTENSION_FIXTURES, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode:
                errors.append(f"extension descriptor generation failed: {output_name}: {result.stderr.decode().strip()}")
            elif generated.read_bytes() != (EXTENSION_FIXTURES / output_name).read_bytes():
                errors.append(f"extension descriptor drift: {output_name}")
    return errors


def check():
    errors = source_drift_errors()
    generated = normalized_descriptor(); canonical = DESCRIPTOR.read_bytes()
    if generated != canonical: errors.append(f"descriptor drift: generated={sha(generated)} canonical={sha(canonical)}")
    metadata = json.loads((CRATE / "descriptors/protocol.v1.json").read_text())
    protoc_info = vendored_protoc_info()
    try:
        expected_metadata = descriptor_metadata(canonical, protoc_info)
    except ValueError as error:
        errors.append(str(error))
        expected_metadata = None
    if metadata != expected_metadata:
        errors.append("complete descriptor metadata object drift")
    locked_protoc = locked_package("protoc-bin-vendored")
    if protoc_info["version"] != EXPECTED_PROTOC_VERSION:
        errors.append(f"vendored protoc version drift: resolved={protoc_info['version']} expected={EXPECTED_PROTOC_VERSION}")
    inventory = make_inventory()
    if json.loads(INVENTORY.read_text()) != inventory: errors.append("protocol conformance inventory drift; run --write")
    errors.extend(lint_enums(inventory))
    manifest = json.loads(FIXTURE_MANIFEST.read_text())
    errors.extend(check_fixtures(manifest))
    try:
        actual_java_maps = java_map_oracles()
        if manifest.get("java_map_serialization", {}).get("rows") != actual_java_maps:
            errors.append("protobuf-java DynamicMessage map serialization oracle drift")
    except (OSError, subprocess.CalledProcessError, ValueError, json.JSONDecodeError) as error:
        errors.append(f"protobuf-java map oracle failed: {error}")
    extension_manifest = json.loads(EXTENSION_MANIFEST.read_text())
    errors.extend(check_extension_fixtures(extension_manifest, protoc_info, locked_protoc))
    if errors:
        print("\n".join(errors), file=sys.stderr); return 1
    print(
        f"C001 protocol gate passed: {inventory['counts']}, {len(manifest['fixtures'])} protocol fixtures, "
        f"{len(extension_manifest['fixtures'])} extension fixtures"
    )
    return 0


def write_inventory():
    INVENTORY.write_text(json.dumps(make_inventory(), indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="regenerate the conformance inventory only")
    args = parser.parse_args()
    if args.write: write_inventory(); return 0
    return check()


if __name__ == "__main__":
    raise SystemExit(main())
