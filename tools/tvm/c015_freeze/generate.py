#!/usr/bin/env python3
"""Generate the independently authored C015 Freeze replacement fixture.

This file contains no Solidity source or bytecode from java-tron. The programs below
were written directly from the public EVM/TVM opcode stack contracts documented in
the behavior-only record emitted with the fixture.
"""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUTPUT = ROOT / "docs/oracles/c015-freeze-cleanroom.v1.json"
REVISION = "4a21592f95e37908b21bc3f611c6e7a1a67f09f3"
OWNER = bytes([0x21]) * 20
RECEIVER = bytes([0x22]) * 20


def push20(value: bytes) -> bytes:
    assert len(value) == 20
    return bytes([0x73]) + value


def program_rows():
    # Programs intentionally use direct opcodes rather than a Solidity compiler.
    freeze_self = push20(OWNER) + bytes.fromhex("621e84806000d500")
    expire_self = push20(OWNER) + bytes.fromhex("6000d700")
    unfreeze_self = push20(OWNER) + bytes.fromhex("6000d600")
    freeze_delegated_energy = push20(RECEIVER) + bytes.fromhex("622dc6c06001d500")
    create2_empty = bytes.fromhex("6009600060006000f500")
    rows = [
        ("freeze-self-bandwidth", freeze_self, "FREEZE(receiver=self, amount=2_000_000, resource=bandwidth) returns one"),
        ("freeze-expiry-seconds", expire_self, "FREEZEEXPIRETIME(self, bandwidth) returns the millisecond expiry divided by 1000"),
        ("unfreeze-self-bandwidth", unfreeze_self, "UNFREEZE(self, bandwidth) returns zero before expiry and one at expiry"),
        ("freeze-delegated-energy", freeze_delegated_energy, "FREEZE(receiver, 3_000_000, energy) updates owner, receiver, delegation row, and total energy weight atomically"),
        ("create2-empty-init", create2_empty, "CREATE2(value=0, offset=0, size=0, salt=9) creates an empty-runtime contract at the public CREATE2-derived address"),
    ]
    return [{"id": name, "program_hex": code.hex(), "sha256": hashlib.sha256(code).hexdigest(), "observable_contract": contract} for name, code, contract in rows]


def document():
    return {
        "schema": "c015-freeze-cleanroom.v1",
        "version": 1,
        "classification": "clean_room",
        "replacement_license": "Apache-2.0",
        "authorship": "0xNebulaLumina java-tron-to-rust-rebirth project contributors",
        "reference_revision": REVISION,
        "scope": ["legacy FREEZE", "legacy UNFREEZE", "FREEZEEXPIRETIME", "CREATE2", "bandwidth and energy resource accounting"],
        "separation": {
            "permitted_inputs": [
                "public EVM CREATE2 semantics and address formula",
                "public TVM opcode registry stack arities and activation names",
                "behavioral assertions and numeric outcomes in pinned java-tron tests"
            ],
            "forbidden_inputs": [
                "UNLICENSED FreezeTest.sol source text",
                "compiled FreezeTest.sol creation or runtime bytecode",
                "decompilation, disassembly, or mechanical translation of that fixture"
            ],
            "procedure": "The implementer specified observable state transitions first, then hand-authored short direct-opcode programs with a structure independent of Solidity compiler output. No observer retained or supplied expressive fixture content.",
            "retained_results": "Only program bytes, their hashes, public numeric expectations, and behavior-only provenance are retained."
        },
        "legal_review": {
            "record": "C015.07 technical/legal provenance review",
            "decision": "independent technical/legal provenance review approved the technically separated, newly authored Apache-2.0 clean-room replacement; the original UNLICENSED artifact remains prohibited",
            "status": "approved",
            "reviewed_controls": ["input allowlist", "explicit source/bytecode denylist", "authorship", "replacement license", "content hashes", "test-only distribution"]
        },
        "initial_state": {"timestamp_ms": 1700000000000, "minimum_frozen_days": 3, "owner_balance": 10000000, "total_net_weight": 0, "total_energy_weight": 0},
        "expected_resource_contracts": {
            "self_bandwidth": {"balance": 8000000, "frozen": 2000000, "expiry_ms": 1700259200000, "total_net_weight": 2},
            "delegated_energy_after_self_freeze": {"owner_balance": 5000000, "owner_delegated": 3000000, "receiver_acquired": 3000000, "expiry_ms": 1700259200000, "total_energy_weight": 3},
            "pre_expiry_unfreeze_result": 0,
            "at_expiry_final_owner_balance": 10000000,
            "invalid_overspend_result": 0,
            "v2_queues": []
        },
        "programs": program_rows()
    }


def encoded(value):
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = encoded(document())
    if args.check:
        assert OUTPUT.read_text() == expected, "clean-room oracle drift"
        print(f"c015-freeze: {len(program_rows())} independently authored programs verified")
    else:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(expected)
        print(OUTPUT)


if __name__ == "__main__":
    main()
