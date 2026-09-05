# DR-005: TRON-specific TVM interpreter

## Decision

`tron-tvm` uses a custom, table-driven interpreter. It does not depend on REVM, `revm-interpreter`, Alloy primitives, or an Ethereum state database. Fixed-width arithmetic uses exactly `ruint` 1.17.0 with default features disabled, behind the public `Word` type; no `ruint` type appears in the crate API.

Opcode activation and adjustment are resolved from an immutable `TvmRules` snapshot for each top-level execution. Ordered variants use last-matching-wins resolution, preserving Java registry adjustment order without mutable global tables: higher memory pricing, fair-energy adjustments, selfdestruct restriction, then Osaka vote cost.

State execution uses an in-memory layered repository journal over a C009 `Session` child or immutable `ReadView`. Nested CALL/CREATE work uses journal checkpoints, not nested durable engines. Persistent writes, transient storage, and new-contract markers commit or revoke together; transient values and markers never flush. A zero storage write deletes the row while an absent row remains distinguishable from a present zero value before mutation.

The opcode-family integration contract is `OperationSpec` plus ordered `OperationVariant` rows supplied by `opcodes_a::operation_specs`, `opcodes_b::operation_specs`, and `opcodes_c::operation_specs`. `required_before` and `resulting_window` are Java stack-window values; projected size is `len - required_before + resulting_window`. The integration registry rejects duplicates and resolves one allocation-free 256-slot table per execution.

## Rationale

TVM differs from Ethereum in persisted address width, CREATE/CREATE2 derivation, memory and call-depth limits, dynamic-property activation, energy and CPU ordering, TRON-specific operations, repository behavior, and result mapping. Adapting an Ethereum runtime would retain little of its execution model and obscure consensus behavior. A small fixed-width arithmetic dependency is reviewable and avoids hot-path big-integer allocation while preserving ownership of every TVM semantic.

## Consequences

C014 opcode families implement rows against the stable operation interfaces without exposing their internals to sibling modules. C015 precompiles share the same repository checkpoint and energy meter. C016 may receive a committable state child only after successful execution; revert and fault paths revoke it before returning.
