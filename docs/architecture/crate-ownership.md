# Rust workspace ownership and gate map

## Boundary rule

The workspace is a directed acyclic graph. A crate may depend only on crates in an earlier dependency layer shown below. Reverse dependencies and peer cycles are prohibited. `tron-node` is the composition root; libraries never obtain services from it. `tron-toolkit` is a separate composition root for operational commands and never depends on `tron-node`.

No crate created by C000 contains node behavior. The manifests reserve ownership boundaries for later checklist items and gates.

## Dependency layers

```text
L0  tron-protocol   tron-primitives
L1  tron-config     tron-crypto
L2  tron-shielded   tron-storage
L3  tron-state
L4  tron-tvm
L5  tron-execution
L6  tron-consensus
L7  tron-network
L8  tron-apis       tron-events-metrics
L9  tron-node       tron-toolkit
```

Allowed edges are declared in each crate manifest. Adding an edge requires updating this map, retaining the layer order, pinning the dependency in the applicable manifests and lockfiles, and passing the consuming item's review and gate.

## Owning crate and acceptance gate

| Crate | Owns | Primary implementation chunks | Acceptance gates |
|---|---|---|---|
| `tron-protocol` | Canonical protobuf descriptors, generated wire types, service surfaces | C001 | G-WIRE |
| `tron-primitives` | Fixed-width identifiers, byte ordering, deterministic arithmetic/time primitives | C002 | G-WIRE, G-CRYPTO, G-STATE |
| `tron-config` | Typed configuration, CLI model, lifecycle declarations | C003 | G-OPS, G-ARCH |
| `tron-crypto` | Hash engines, keys, signatures, addresses, keystore core | C004-C005 | G-CRYPTO, G-SEC, G-LICENSE |
| `tron-shielded` | Sapling primitives, parameters, native/FFI adapter boundary | C006 | G-CRYPTO, G-SEC, G-LICENSE, G-ARCH |
| `tron-storage` | Rust disk format, KV backend, migrations, snapshots; initial pure-Rust `rustlog-v1` WAL/snapshot format and backend-independent market ordering | C007 | G-FORMAT, G-STATE, G-ARCH |
| `tron-state` | Canonical protobuf/raw capsules; account, asset, block, transaction, result, index, contract, ABI, code, state and storage-row logical codecs; collision-free named-store namespaces and the atomic cross-store batch seam; revoking sessions, cursors, genesis, fork graph | C008-C011 (C008.01-C008.04 codecs and storage seam implemented here) | G-STATE, G-FORMAT |
| `tron-tvm` | TVM repository, interpreter, opcodes, precompiles | C014-C015 | G-TVM, G-CRYPTO |
| `tron-execution` | Actuators, admission, trace, billing, pending state, block processing | C012-C013, C016, C019 | G-STATE, G-TVM, G-CONSENSUS |
| `tron-consensus` | DPoS scheduling and PBFT sidecar | C017-C018 | G-CONSENSUS |
| `tron-network` | External transport, discovery, application protocol, sync and relay | C020-C021 | G-P2P, G-SEC |
| `tron-apis` | gRPC, HTTP protobuf-JSON, JSON-RPC and filters | C022-C024, C026 | G-API, G-OPS |
| `tron-events-metrics` | Events, plugins, metrics and operational services | C025 | G-OPS, G-API |
| `tron-node` | Full-node and Solidity-node composition roots and process lifecycle | C003, C019-C026, C028 | G-OPS, G-P2P, G-API, G-ARCH |
| `tron-toolkit` | Rust-format operational and keystore command composition | C027 | G-OPS, G-FORMAT, G-ARCH |

C000.01 owns this initial graph. Later crate additions or third-party dependencies do not inherit approval from C000; each dependency must be pinned in the applicable manifests and lockfiles and reviewed and accepted through its consuming tracker item's gate.
