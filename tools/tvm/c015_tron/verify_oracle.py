#!/usr/bin/env python3
import json, pathlib, re, sys
root = pathlib.Path(__file__).resolve().parents[3]
oracle = json.loads((root/'docs/oracles/c015-tron.v1.json').read_text())
source = (root/'java-tron/actuator/src/main/java/org/tron/core/vm/PrecompiledContracts.java').read_text()
found = {m.group(2)[-8:] for m in re.finditer(r'private static final DataWord (\w+)Addr = new DataWord\(\s*"([0-9a-f]{64})"\)', source)}
expected = {row['address'] for row in oracle['contracts']}
if len(expected) != 19 or expected - found:
    raise SystemExit(f'inventory mismatch: missing={sorted(expected-found)} count={len(expected)}')
for row in oracle['contracts']:
    if row['activation'] not in {'ALLOW_TVM_SOLIDITY_059','ALLOW_TVM_VOTE','ALLOW_TVM_FREEZE_V2'}:
        raise SystemExit(f"bad activation {row}")
if {x['id'] for x in oracle['scenarios']} != {'vote-malformed','freeze-malformed','batch-osaka-malformed-revert','chain-invalid-code','expire-negative'}:
    raise SystemExit('scenario inventory mismatch')
print('c015-tron oracle verified: 19 contracts, 5 boundary scenarios')
