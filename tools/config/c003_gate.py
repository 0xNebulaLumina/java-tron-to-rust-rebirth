#!/usr/bin/env python3
"""Generate and verify the C003 Java-derived config/CLI/lifecycle inventory."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
JAVA_REVISION = "4a21592f95e37908b21bc3f611c6e7a1a67f09f3"
REFERENCE = ROOT / "java-tron/common/src/main/resources/reference.conf"
PACKAGED = ROOT / "java-tron/framework/src/main/resources/config.conf"
CLI = ROOT / "java-tron/framework/src/main/java/org/tron/core/config/args/CLIParameter.java"
ARGS = ROOT / "java-tron/framework/src/main/java/org/tron/core/config/args/Args.java"
DYNAMIC = ROOT / "java-tron/framework/src/main/java/org/tron/core/config/args/DynamicArgs.java"
RUST_CONFIG = ROOT / "rust-tron/crates/tron-config/src/lib.rs"
RUST_NODE = ROOT / "rust-tron/crates/tron-node/src/lib.rs"
INVENTORY = ROOT / "docs/oracles/c003-config-source-inventory.v1.json"
FIXTURES = ROOT / "docs/oracles/c003-config-differential-fixtures.v1.json"
RUST_CONFIG_TEST = ROOT / "rust-tron/crates/tron-config/tests/c003_config_differentials.rs"
RUST_NODE_TEST = ROOT / "rust-tron/crates/tron-node/tests/c003_lifecycle_differentials.rs"

CONFIG_ROOT_TARGETS = {
    "storage": "Config.storage", "node": "Config.node", "vm": "Config.vm", "block": "Config.block",
    "committee": "Config.committee", "event": "Config.event", "rate": "Config.rate", "genesis": "Config.genesis",
    "crypto": "Config.crypto", "enery": "Config.enery", "trx": "Config.trx", "seed": "Config.seed",
    "localwitness": "Config.localwitness", "localWitnessAccountAddress": "Config.local_witness_account_address",
    "localwitnesskeystore": "Config.localwitnesskeystore", "net": "ConfigLoader::known_schema",
    "address": "GenesisAsset.address", "enable": "EventTopic.enable", "filter": "EventConfig.filter",
    "parentHash": "GenesisConfig.parent_hash", "redundancy": "EventTopic.redundancy", "timestamp": "GenesisConfig.timestamp",
    "topic": "EventTopic.topic", "triggerName": "EventTopic.trigger_name", "url": "GenesisWitness.url", "voteCount": "GenesisWitness.vote_count",
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"(?m)//.*$|#.*$", "", text)
def config_keys(path: Path) -> list[dict]:
    text = strip_comments(path.read_text(encoding="utf-8"))
    stack: list[tuple[str, list[str]]] = []
    rows: dict[str, int] = {}

    def prefix() -> list[str]:
        return [part for _, parts in stack for part in parts]

    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip().lstrip(",").strip()
        if not line:
            continue
        while line and line[0] in "}]":
            closer = line[0]
            expected = "object" if closer == "}" else "array"
            if stack and stack[-1][0] == expected:
                stack.pop()
            line = line[1:].lstrip(",").strip()
        if not line:
            continue
        object_match = re.match(r'^([A-Za-z0-9_.-]+|"[^"]+")\s*(?:=|:)?\s*\{\s*$', line)
        if object_match:
            stack.append(("object", object_match.group(1).strip('"').split(".")))
            continue
        if line == "{":
            stack.append(("object", []))
            continue
        match = re.match(r'^([A-Za-z0-9_.-]+|"[^"]+")\s*(?:=|:)\s*(.*)$', line)
        if not match:
            continue
        key, value = match.groups()
        parts = key.strip('"').split(".")
        full = ".".join(prefix() + parts)
        if value.startswith("{"):
            stack.append(("object", parts))
            if "}" in value:
                stack.pop()
        elif value.startswith("["):
            rows.setdefault(full, number)
            if "]" not in value:
                stack.append(("array", parts))
        else:
            rows.setdefault(full, number)
    return [{"key": key, "source": {"path": path.relative_to(ROOT).as_posix(), "line": line}}
            for key, line in sorted(rows.items())]


def rust_field(name: str) -> str:
    name = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return name.replace("-", "_").lower()


def camel_case(name: str) -> str:
    head, *tail = name.split("_")
    return head + "".join(part[:1].upper() + part[1:] for part in tail)


def exact_config_mapping(key: str, rust: str) -> dict:
    parts = key.split(".")
    leaf = parts[-1]
    field = rust_field(leaf)
    explicit_fields = {
        match.group("key"): match.group("field")
        for match in re.finditer(
            r'#\[serde\(rename\s*=\s*"(?P<key>[^"]+)"[^]]*\)\]\s*(?:pub\s+)?(?P<field>[a-zA-Z0-9_]+)\s*:',
            rust,
        )
    }
    approved = {
        "node.activeConnectFactor": "Java transport tuning key is accepted but has no retained Rust runtime consumer",
        "node.connectFactor": "Java transport tuning key is accepted but has no retained Rust runtime consumer",
    }
    if key in approved:
        return {"kind": "approved-decision", "decision": approved[key]}
    if key.startswith("committee.") and not re.search(rf"\b{re.escape(field)}\s*:", rust):
        return {"kind": "manual", "rustTarget": f'Config.committee.remaining["{leaf}"]', "evidence": "CommitteeConfig #[serde(flatten)] remaining"}
    explicit_field = explicit_fields.get(leaf)
    if explicit_field:
        field = explicit_field
        evidence = f'#[serde(rename="{leaf}")]'
    elif camel_case(field) == leaf:
        evidence = "#[serde(rename_all=\"camelCase\")]"
    else:
        raise ValueError(f"no exact serde/manual/approved mapping for {key} (candidate field {field})")
    if not re.search(rf"\b{re.escape(field)}\s*:", rust):
        raise ValueError(f"mapped Rust field is absent for {key}: {field}")
    target = ".".join(["Config"] + [rust_field(part) for part in parts])
    target = target.rsplit(".", 1)[0] + "." + field
    return {"kind": "serde", "rustTarget": target, "serdeKey": leaf, "evidence": evidence}


def cli_options() -> list[dict]:
    text = CLI.read_text(encoding="utf-8")
    rows = []
    pattern = re.compile(r"(?P<deprecated>@Deprecated\s+)?@Parameter\((?P<body>.*?)\)\s+public\s+(?P<type>[\w<>]+)\s+(?P<field>\w+)", re.S)
    for match in pattern.finditer(text):
        body = match.group("body")
        names = re.search(r"names\s*=\s*\{([^}]*)\}", body)
        aliases = re.findall(r'"([^"]+)"', names.group(1)) if names else []
        positional = not aliases
        line = text.count("\n", 0, match.start()) + 1
        rows.append({
            "field": match.group("field"), "javaType": match.group("type"),
            "names": aliases, "positional": positional,
            "deprecated": bool(match.group("deprecated")),
            "arity": int(re.search(r"arity\s*=\s*(\d+)", body).group(1)) if re.search(r"arity\s*=\s*(\d+)", body) else None,
            "source": {"path": CLI.relative_to(ROOT).as_posix(), "line": line},
            "mode": "mode-selector" if match.group("field") in {"solidityNode", "keystoreFactory"} else "all",
            "rustParserBranches": aliases or ["<seed-nodes-positional>"],
        })
    return rows


def make_inventory() -> dict:
    reference = config_keys(REFERENCE)
    packaged = config_keys(PACKAGED)
    rust_config = RUST_CONFIG.read_text(encoding="utf-8")
    keys = {}
    for source, rows in (("reference", reference), ("packaged", packaged)):
        for row in rows:
            root = row["key"].split(".", 1)[0]
            entry = keys.setdefault(row["key"], {"key": row["key"], "sources": [], "domain": root})
            entry["sources"].append({"id": source, **row["source"]})
    for entry in keys.values():
        entry["mapping"] = exact_config_mapping(entry["key"], rust_config)
    options = cli_options()
    rust_cli = rust_config
    unmapped_keys = sorted(row["key"] for row in keys.values() if not row["mapping"])
    unmapped_options = sorted(branch for row in options for branch in row["rustParserBranches"] if branch != "<seed-nodes-positional>" and f'"{branch}"' not in rust_cli)
    if "seed_nodes.push" not in rust_cli:
        unmapped_options.append("<seed-nodes-positional>")
    return {
        "schemaVersion": 2,
        "id": "c003-config-sources-v2",
        "javaRevision": JAVA_REVISION,
        "sourceHashes": {p.relative_to(ROOT).as_posix(): sha(p) for p in (REFERENCE, PACKAGED, CLI, ARGS, DYNAMIC)},
        "bundles": [
            {"id": "reference", "java": REFERENCE.relative_to(ROOT).as_posix(), "rust": "rust-tron/crates/tron-config/src/reference.conf", "sha256": sha(REFERENCE)},
            {"id": "packaged", "java": PACKAGED.relative_to(ROOT).as_posix(), "rust": "rust-tron/crates/tron-config/src/config.conf", "sha256": sha(PACKAGED)},
        ],
        "configKeys": list(keys.values()),
        "cliOptions": options,
        "aliases": [{"accepted": a, "canonical": row["names"][-1], "field": row["field"]} for row in options for a in row["names"][:-1]],
        "modes": ["full", "solidity", "keystore-factory", "witness", "p2p-disabled", "pbft"],
        "precedenceLowToHigh": ["reference", "packaged-or-external", "assigned-cli", "event-stage", "platform-stage", "witness-stage"],
        "dynamicReload": {"mutable": ["node.active", "node.passive", "derived node.trust"], "immutableAllOtherKeys": True, "javaSource": DYNAMIC.relative_to(ROOT).as_posix()},
        "counts": {"configKeys": len(keys), "cliFields": len(options), "cliNames": sum(len(row["names"]) for row in options), "unmappedKeys": len(unmapped_keys), "unmappedOptions": len(unmapped_options)},
        "unmappedKeys": unmapped_keys, "unmappedOptions": unmapped_options,
    }


def check() -> int:
    errors = []
    generated = make_inventory()
    try:
        stored = json.loads(INVENTORY.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        stored = None; errors.append(f"inventory: {error}")
    if stored != generated:
        errors.append("C003 inventory drift; run python3 tools/config/c003_gate.py --write")
    for bundle in generated["bundles"]:
        rust = ROOT / bundle["rust"]
        if not rust.is_file() or sha(rust) != bundle["sha256"]:
            errors.append(f"bundled config differs from pinned Java source: {bundle['rust']}")
    if generated["unmappedKeys"] or generated["unmappedOptions"]:
        errors.append(f"unmapped Java surface: keys={generated['unmappedKeys']} options={generated['unmappedOptions']}")
    for row in generated["configKeys"]:
        mapping = row.get("mapping", {})
        if mapping.get("kind") not in {"serde", "manual", "approved-decision"}:
            errors.append(f"missing exact Rust config mapping for {row['key']}: {mapping}")
        if mapping.get("kind") == "serde" and mapping.get("serdeKey") != row["key"].split(".")[-1]:
            errors.append(f"inexact serde key mapping for {row['key']}: {mapping}")
        if mapping.get("kind") == "manual" and not mapping.get("evidence"):
            errors.append(f"manual mapping lacks evidence for {row['key']}: {mapping}")
        if mapping.get("kind") == "approved-decision" and not mapping.get("decision"):
            errors.append(f"approved decision lacks rationale for {row['key']}: {mapping}")
    node_symbols = RUST_NODE.read_text(encoding="utf-8")
    pbft_projection = [
        "config.node.jsonrpc.http_pbft_enable && pbft",
        "config.node.jsonrpc.http_pbft_port",
    ]
    if any(symbol not in node_symbols for symbol in pbft_projection):
        errors.append("enabled_api_ports lacks exact JsonRpc PBFT enable/port projection")
    config_tests = RUST_CONFIG_TEST.read_text(encoding="utf-8")
    for symbol in ("node.jsonrpc.httpPBFTEnable = true", "node.jsonrpc.httpPBFTPort = 18565", "http_pbft_enable", "http_pbft_port, 18565"):
        if symbol not in config_tests:
            errors.append(f"JsonRpc PBFT differential lacks non-default coverage: {symbol}")
    for symbol in ('node.openHistoryQueryWhenLiteFN = true', 'open_history_query_when_lite_fn', 'compatibility_bridge().open_history_query_when_lite_fn'):
        if symbol not in config_tests:
            errors.append(f"openHistoryQueryWhenLiteFN differential lacks non-default typed/bridge coverage: {symbol}")
    try:
        fixtures = json.loads(FIXTURES.read_text(encoding="utf-8"))
        required = {"reference", "bundled", "external", "cli", "witness", "mode", "dynamic-reload", "errors", "lifecycle-transition", "precedence", "defaults", "limits", "schema"}
        actual = {case["category"] for case in fixtures["cases"]}
        missing = sorted(required - actual)
        if missing: errors.append(f"missing differential fixture categories: {missing}")
        if fixtures.get("sourceHashes") != generated["sourceHashes"]: errors.append("fixture source hashes drift")
        if any(not case.get("rustCase") or not case.get("javaEvidence") for case in fixtures["cases"]): errors.append("every fixture requires rustCase and javaEvidence")
        executable_tests = RUST_CONFIG_TEST.read_text(encoding="utf-8") + RUST_NODE_TEST.read_text(encoding="utf-8")
        missing_cases = sorted(case["rustCase"] for case in fixtures["cases"] if f"fn {case['rustCase']}" not in executable_tests)
        if missing_cases: errors.append(f"fixture cases lack executable Rust tests: {missing_cases}")
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as error:
        errors.append(f"fixtures: {error}")
    if errors:
        print("\n".join(errors)); return 1
    print(f"C003 config gate passed: {generated['counts']}, {len(fixtures['cases'])} differential fixtures, zero unmapped keys/options")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    if args.write:
        document = make_inventory()
        INVENTORY.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {INVENTORY.relative_to(ROOT)}")
        return 0
    return check()

if __name__ == "__main__":
    raise SystemExit(main())
