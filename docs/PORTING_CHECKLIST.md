# java-tron Rust Porting Checklist

This tracker implements `docs/PORTING_PLAN.md`. Execution status is `[ ]` not started, `[-]` in progress, `[x]` complete, or `[D]` externally blocked; dependency readiness is separately derived as `blocked` or `ready`. The checked-in machine tracker is authoritative and every substantive item and `.V` record must contain an explicit `dependencies[]` array of stable item IDs: `Cddd.dd`, bounded family IDs `Cddd.ddA` through `Cddd.ddZ`, or verification IDs `Cddd.V`. `ready` means every dependency is `[x]` with valid, non-stale evidence and approvals and no active rerun/reopen trigger; otherwise it is `blocked`. Empty arrays are roots only. CI rejects unknown, duplicate, self and cyclic edges, recomputes readiness/parents, and requires this checklist's dependency projection to round-trip exactly. Parent status is derived from substantive children and `.V`, never edited. Records also contain owner, branch/PR, blocker/unblock/decision/adoption fields, last-updated, and immutable `evidence[]`: schema version, command, run ID, environment/tool identity, stable case/scenario IDs and per-case pass/fail/skip disposition, start/end timestamps, observed exit/status, expected and observed result/hash, stdout/stderr artifact hashes, and all artifact paths/SHA-256s. Any covered source/config/schema/fixture/dependency/toolchain/generator/command/expectation/normalization change invalidates evidence and approvals until required reruns and re-review pass. `[-]`, `[x]`, and `[D]` requirements and recurring adoption/review rules are defined in the plan; C000 supplies executable schemas and validators.

## C000 — Repository, architecture, and oracle contract

**Status:** `[ ]`
**Derived prerequisite gates (non-executable):** `[]`  
**Commit boundary:** architecture and governance artifacts only: workspace/crate graph; canonical fixture/tracker schemas; source-derived production/test ownership ledgers; dependency, security, license, and extension decisions; Java-reference-runner skeleton. No node behavior.
**Active revision:** `65d7291`  
**Current validation:** **FAIL** — committed C000 reviews invalidate all prior C000 EV evidence and RV approvals. The artifact runner aborts after the validator signature change; tracker validation reports stale evidence, digest/revision drift, incomplete platform coverage, stale ledgers, and ineffective completion records. RV-0002/RV-0003 are stale/pending, DD-005/adoption license bindings are not current, the independent-review schema digest is inconsistent, and DR-004/C000.12 is missing from finite provenance/license-review scope.


- [ ] **C000.01** Define workspace crates for protocol, primitives, config, crypto, shielded, storage, state, TVM, execution, consensus, network, APIs, events/metrics, node, and toolkit; prohibit dependency cycles; publish the owning-crate/gate map.
  **dependencies[]:** `[]`
- [ ] **C000.02** Pin Rust and Java toolchains, source revision, the initial supported Linux x86_64 GNU platform/backend/feature row, unsafe policy, and reproducible artifact provenance. Reserve Linux aarch64 and macOS x86_64/aarch64 stable row IDs for explicit later enablement with native executors and evidence; this platform staging must not narrow protocol behavior or migration scope.
  **dependencies[]:** `["C000.01"]`
- [ ] **C000.03** Define explicit dependency injection, typed HEAD/SOLIDITY/PBFT cursors, clock/randomness abstractions, cancellation, and startup/shutdown graph.
  **dependencies[]:** `["C000.02"]`
- [ ] **C000.04** Check in a versioned machine-readable fixture/result schema: canonical bytes, presence/null/absent rules, ordered logical state and deltas, error taxonomy, events/logs, revision/tool identities, and centrally reviewed closed normalization allowlist.
  **dependencies[]:** `["C000.03"]`
- [ ] **C000.05** Define Java/Rust runner CLI/stdin/stdout protocol, deterministic environment, artifact versioning, mismatch reports, positive/negative cases, and deliberate mismatch tests for output/state/error/forbidden normalization.
  **dependencies[]:** `["C000.04"]`
- [ ] **C000.06** Record DR-001 physical Java disk incompatibility, Rust manifest/version/migration/resync contract, and no-write rejection rule.
  **dependencies[]:** `["C000.05"]`
- [ ] **C000.07** Establish the threat model, security severity/closure/exception policy, and license/provenance schemas for source, schemas, generated code, crates, native/FFI, parameters, fixtures, binaries, plaintext interfaces and resource exhaustion. Define critical/high/medium/low classification, blockers, authorized residual-risk acceptance, rationale/evidence, expiry, and rerun/reopen triggers. This task establishes policy only; it cannot attest to later adoptions.
  **dependencies[]:** `["C000.06"]`
- [ ] **C000.08** Generate source-derived production ledgers with stable IDs and source locations for modules/packages/classes, schemas/messages/services, contract types/actuators, extension points, stores/codecs/dynamic properties, opcodes/precompiles, P2P messages/handlers, RPC/HTTP/JSON-RPC surfaces, config/CLI, metrics/events/services, resources/scripts, and toolkit commands; every row must own a task and gate before that task starts.
  **dependencies[]:** `["C000.07"]`
- [ ] **C000.09** Generate the early case-level Java test/resource ledger bound to the pinned revision, including methods, parameter sets, nested/inherited/generated cases, ignores and assumptions; provisionally map every row to an owning chunk. C029 performs final reconciliation, not first discovery.
  **dependencies[]:** `["C000.08"]`
- [ ] **C000.10** Check in the machine tracker schema and dependency projection. Require explicit `dependencies[]` on every substantive and `.V` record; define `ready` exactly as all dependencies `[x]` with current evidence/approval; reject unknown/duplicate/self/cyclic edges; enforce checklist↔tracker round-trip, legal transitions, required metadata, evidence comparison/staleness, invalid deferrals and parent derivation.
  **dependencies[]:** `["C000.09"]`
- [ ] **C000.11** Establish the `DD-###` and dependency/adoption inventory schemas: exact version/features, alternatives, semantic gaps/adapters, determinism/serialization, unsafe/FFI, platforms, maintenance/security/license/provenance and replacement/rollback path. Each later integration is a separate inventory instance owned by and prerequisite to its consuming item; CI rejects unregistered or unapproved dependencies.
  **dependencies[]:** `["C000.10"]`
- [ ] **C000.12** Record DR-004 for custom-actuator compatibility: support Java-equivalent discovery/registration, custom protobuf contract type and owner extraction, dispatch/state/API integration; assign C001/C012/C016/C022 rows and define an end-to-end fixture derived from `example/actuator-example`.
  **dependencies[]:** `["C000.11"]`
- [ ] **C000.13** Publish immutable finite manifest, evidence and independent-review schemas. Evidence includes observed exit/result, stdout/stderr hashes, timestamps, schema/case outcomes and invalidation edges. Reviews include scope/seam rows, exact revisions/hashes, named independent reviewers/recusals, finding IDs/severity/disposition, fix revision, required rerun links, closure approval, retention/expiry and invalidation triggers.
  **dependencies[]:** `["C000.12"]`
- [ ] **C000.14** Publish the continuously enforced platform manifest for the C000.02 initially supported Linux x86_64 GNU row, marking native versus cross-built/emulated execution and the applicable compile, differential/unit, native-resource, FFI, packaging and smoke commands. Record reserved later rows and their explicit enablement conditions without treating them as C000 blockers.
  **dependencies[]:** `["C000.02","C000.13"]`
- [ ] **C000.15** Generate the recurring dependency/adoption inventory from manifests/lockfiles/tool inputs, bind every instance to a consuming item and local gate, and require current `DD-###`, security and license approval before that item becomes ready or checked.
  **dependencies[]:** `["C000.14"]`
- [ ] **C000.V** Architecture/security/license review approves C000 policy artifacts; ledger, tracker, dependency/adoption and platform validators report zero gaps; every applicable cell on the initially supported Linux x86_64 GNU row has current native evidence or reviewed non-applicability; both runners pass positive and negative protobuf-free fixtures and intentional mismatch detection. Reserved later platform rows neither satisfy nor block C000.V until explicitly enabled.
  **dependencies[]:** `["C000.01","C000.02","C000.03","C000.04","C000.05","C000.06","C000.07","C000.08","C000.09","C000.10","C000.11","C000.12","C000.13","C000.14","C000.15"]`

**First dependency-ready implementation item:** `C000.01`. C000.01 is ready because it is the sole dependency root. C000.02-C000.15, C000.V, and all later implementation items are blocked by unchecked prerequisites; reserved later platform rows remain non-blocking until explicitly enabled.

## C001 — Canonical protobuf and generated APIs

**Status:** `[ ]`  
**Derived prerequisite gates (non-executable):** `["C000.V"]`  
**Commit boundary:** all canonical schemas, reproducible generation, descriptors, generated Rust API, proto compatibility gates.

- [ ] **C001.01** Synchronize all 17 canonical schemas under protocol core/contracts/api, including Google imports and licenses.  
  **dependencies[]:** `["C000.V"]`
- [ ] **C001.02** Pin protobuf/gRPC generator/runtime and generate a deterministic descriptor set.  
  **dependencies[]:** `["C000.V"]`
- [ ] **C001.03** Preserve packages, field tags, enum numbers/names, gaps, maps, nested types, `Any` type URLs, deprecated methods, and misspellings.  
  **dependencies[]:** `["C000.V"]`
- [ ] **C001.04** Generate Wallet, WalletSolidity, WalletExtension, Database, Monitor, Network, and TronZksnark client/server surfaces.  
  **dependencies[]:** `["C000.V"]`
- [ ] **C001.05** Port enum-zero lint with the 21 legacy allowlist and schema synchronization checks.  
  **dependencies[]:** `["C000.V"]`
- [ ] **C001.06** Add encode/decode/unknown-field/malformed golden fixtures for high-risk transaction, block, account, shielded, PBFT, inventory, and API messages.  
  **dependencies[]:** `["C000.V"]`
- [ ] **C001.07** Generate the versioned protocol conformance manifest for every schema/message/enum/service/method, defining descriptor normalization plus applicable encode/decode/malformed/unknown-field/`Any`/map-order/presence/size cases; zero unmapped rows.  
  **dependencies[]:** `["C000.V"]`
- [ ] **C001.08** Own the DR-004 extension protobuf boundary: define checked descriptor/schema registration or runtime loading, deterministic registration order, full-name and `Any` type URL formation, numeric `ContractType` allocation/encoding, built-in/extension and extension/extension collision errors, and example-derived canonical descriptor/`Any`/transaction-contract/malformed/collision byte fixtures.  
  **dependencies[]:** `["C000.V"]`
- [ ] **C001.V** Canonical and extension descriptor/byte-level Java comparisons pass; every C001.08 type-URL/`ContractType`/collision fixture passes; no unreviewed schema delta, and C012/C016/C022 remain blocked until this gate is `[x]`.  
  **dependencies[]:** `["C001.01","C001.02","C001.03","C001.04","C001.05","C001.06","C001.07","C001.08"]`

## C002 — Deterministic primitives and byte semantics

**Status:** `[ ]`  
**Derived prerequisite gates (non-executable):** `["C001.V"]`  
**Commit boundary:** canonical byte/hash/address/ID/math/Merkle primitives and differential vectors.

- [ ] **C002.01** Fixed-width address/hash/block-ID/transaction-ID types with validated conversions.  
  **dependencies[]:** `["C001.V"]`
- [ ] **C002.02** Big/little-endian, Java byte/string/locale ordering, fixed-width concatenation, and slice helpers.  
  **dependencies[]:** `["C001.V"]`
- [ ] **C002.03** Strict and legacy arithmetic/overflow/floor behavior; forbid consensus use of nondeterministic floating-point APIs.  
  **dependencies[]:** `["C001.V"]`
- [ ] **C002.04** Transaction raw/full hash boundaries and block raw-header ID with height overwrite/equality semantics.  
  **dependencies[]:** `["C001.V"]`
- [ ] **C002.05** Merkle pair hashing, odd-leaf promotion, and empty zero root.  
  **dependencies[]:** `["C001.V"]`
- [ ] **C002.06** Tapos low-two-byte key and middle-eight-byte hash helpers.  
  **dependencies[]:** `["C001.V"]`
- [ ] **C002.07** Market comparator and rational cross-multiplication ordering.  
  **dependencies[]:** `["C001.V"]`
- [ ] **C002.V** Java vectors pass in all boundary, ordering, and overflow cases.  
  **dependencies[]:** `["C002.01","C002.02","C002.03","C002.04","C002.05","C002.06","C002.07"]`

## C003 — Configuration, CLI, and lifecycle

**Status:** `[ ]`  
**Derived prerequisite gates (non-executable):** `["C001.V","C002.V"]`  
**Commit boundary:** complete typed configuration/CLI and explicit lifecycle graph.

- [ ] **C003.01** Port canonical defaults from `reference.conf` and packaged runtime config.  
  **dependencies[]:** `["C001.V","C002.V"]`
- [ ] **C003.02** Port Node/VM/Storage/Genesis/Block/Committee/Misc/Event/RateLimiter/Metrics models.  
  **dependencies[]:** `["C001.V","C002.V"]`
- [ ] **C003.03** Preserve key casing, aliases, typos, object-list parsing, clamps, sentinels, and platform constraints.  
  **dependencies[]:** `["C001.V","C002.V"]`
- [ ] **C003.04** Implement precedence: CLI parse → config → CLI override → event → platform → witness post-processing.  
  **dependencies[]:** `["C001.V","C002.V"]`
- [ ] **C003.05** Implement all FullNode/Solidity/witness/p2p-disabled/keystore-factory CLI options and seed operands.  
  **dependencies[]:** `["C001.V","C002.V"]`
- [ ] **C003.06** Port config parity, comments, depth, naming, and unique-port gates.  
  **dependencies[]:** `["C001.V","C002.V"]`
- [ ] **C003.08** Generate the stable config/CLI inventory with source locations, domains, aliases, modes and precedence edges; map defaults, invalid values, clamps, sentinels, duplicate ports, exit/stdout/stderr and side effects to executable Java/Rust cases with zero gaps.  
  **dependencies[]:** `["C001.V","C002.V"]`
- [ ] **C003.07** Define explicit service construction/start/stop order and failure propagation with no static mutable singleton.  
  **dependencies[]:** `["C001.V","C002.V"]`
- [ ] **C003.V** Every Java key and option is matched or covered by an approved decision; defaults/error/precedence differentials pass.  
  **dependencies[]:** `["C003.01","C003.02","C003.03","C003.04","C003.05","C003.06","C003.08","C003.07"]`

## C004 — Core crypto and addresses

**Status:** `[ ]`  
**Derived prerequisite gates (non-executable):** `["C002.V"]`  
**Commit boundary:** complete non-shielded crypto/address/signature compatibility.

- [ ] **C004.01** secp256k1 key generation, sign, recover, verify, low-S, and `[r,s,v-27]` encoding.  
  **dependencies[]:** `["C002.V"]`
- [ ] **C004.02** SM2/SM3 key/signature engine and engine selection.  
  **dependencies[]:** `["C002.V","C003.02","C003.04"]`
- [ ] **C004.03** SHA-256/SM3 typed hash API distinct from Keccak/RIPEMD/Blake2 primitives.  
  **dependencies[]:** `["C002.V"]`
- [ ] **C004.04** TRON 0x41 address and Base58Check derivation/validation.  
  **dependencies[]:** `["C002.V"]`
- [ ] **C004.05** Historical padded signature acceptance, unique signer recovery, and malformed boundaries.  
  **dependencies[]:** `["C002.V"]`
- [ ] **C004.06** Normal contract, CREATE, and CREATE2 address formulas.  
  **dependencies[]:** `["C002.V"]`
- [ ] **C004.V** Fixed Java vectors match byte-for-byte in both engines.  
  **dependencies[]:** `["C004.01","C004.02","C004.03","C004.04","C004.05","C004.06"]`

## C005 — Keystore core

**Status:** `[ ]`  
**Derived prerequisite gates (non-executable):** `["C004.V"]`  
**Commit boundary:** keystore format and secure file operations, excluding CLI presentation.

- [ ] **C005.01** JSON schema, KDF/cipher/MAC, address, version, and SM2 selection compatibility.  
  **dependencies[]:** `["C004.V"]`
- [ ] **C005.02** Password text/file rules including whitespace, BOM, multiline, empty, and malformed input.  
  **dependencies[]:** `["C004.V"]`
- [ ] **C005.03** New/import/list/update core operations.  
  **dependencies[]:** `["C004.V"]`
- [ ] **C005.04** Atomic replace, cleanup, overwrite/force, symlink refusal, ownership and POSIX 0600.  
  **dependencies[]:** `["C004.V"]`
- [ ] **C005.V** Cross-open Java/Rust fixtures and all corrupt/password/filesystem cases pass.  
  **dependencies[]:** `["C005.01","C005.02","C005.03","C005.04"]`

## C006 — Sapling and shielded crypto

**Status:** `[ ]`  
**Derived prerequisite gates (non-executable):** `["C001.V","C004.V","C005.V"]`  
**Commit boundary:** complete shielded primitives, parameter initialization, and semantic adapter.

- [ ] **C006.01** Map all JLibrustzcash/JLibsodium methods and parameter structs to reviewed Rust implementations/FFI.  
  **dependencies[]:** `["C001.V","C004.V","C005.V"]`
- [ ] **C006.02** Parameter packaging, integrity validation, initialization, temp-resource lifecycle, and `ZCASH_INIT` errors.  
  **dependencies[]:** `["C001.V","C004.V","C005.V"]`
- [ ] **C006.03** Spending/viewing keys, addresses, notes, nullifiers, commitments, encryption/decryption.  
  **dependencies[]:** `["C001.V","C004.V","C005.V"]`
- [ ] **C006.04** Incremental Merkle tree, path, voucher, endian reversal, depth and full-tree errors.  
  **dependencies[]:** `["C001.V","C004.V","C005.V"]`
- [ ] **C006.05** Proving/verification contexts, spend/output/final checks, free paths, concurrency.  
  **dependencies[]:** `["C001.V","C004.V","C005.V"]`
- [ ] **C006.06** External localhost ZK gRPC service compatibility boundary.  
  **dependencies[]:** `["C001.V","C004.V","C005.V"]`
- [ ] **C006.V** All tracked Sapling/Merkle/shielded fixtures and failure vectors pass; ignored coverage is consciously replaced, not omitted.  
  **dependencies[]:** `["C006.01","C006.02","C006.03","C006.04","C006.05","C006.06"]`

## C007 — Rust storage format and backend

**Status:** `[ ]`  
**Derived prerequisite gates (non-executable):** `["C002.V","C003.V"]`  
**Commit boundary:** Rust-owned storage backend, manifest, migrations, snapshots, and Java-format rejection.

- [ ] **C007.01** KV backend API: get/put/delete, atomic batches, ordered iterators, range/prefix, flush, checkpoint.  
  **dependencies[]:** `["C002.V","C003.V"]`
- [ ] **C007.02** Logical market ordering independent of backend comparator quirks.  
  **dependencies[]:** `["C002.V","C003.V"]`
- [ ] **C007.03** Rust manifest with format/schema/network/genesis/backend/features identity.  
  **dependencies[]:** `["C002.V","C003.V"]`
- [ ] **C007.04** Detect and reject Java LevelDB/RocksDB directories without writes.  
  **dependencies[]:** `["C002.V","C003.V"]`
- [ ] **C007.05** Atomic Rust-version migration framework with preflight, backup, crash recovery, rollback, and resumability rules.  
  **dependencies[]:** `["C002.V","C003.V"]`
- [ ] **C007.06** Fresh initialization, clean resync marker/state, verified snapshot import boundary.  
  **dependencies[]:** `["C002.V","C003.V"]`
- [ ] **C007.07** Corruption, disk-full, lock, permissions, concurrent-open, unknown/newer-version errors.  
  **dependencies[]:** `["C002.V","C003.V"]`
- [ ] **C007.V** Reopen/crash/migrate/rollback/reject/order/atomicity matrix passes on every applicable C000.14 OS/architecture/backend/feature row, including native-resource and FFI checks where present.  
  **dependencies[]:** `["C007.01","C007.02","C007.03","C007.04","C007.05","C007.06","C007.07"]`

## C008 — Capsules and logical store schemas

**Status:** `[ ]`  
**Derived prerequisite gates (non-executable):** `["C001.V","C002.V","C004.V","C007.V"]`  
**Commit boundary:** all capsule codecs and exact logical store schemas.

- [ ] **C008.01** Account/permission/resource/asset capsule codecs and address keys.  
  **dependencies[]:** `["C001.V","C002.V","C004.V","C007.V"]`
- [ ] **C008.02** Block/transaction/result/info capsules and index values.  
  **dependencies[]:** `["C001.V","C002.V","C004.V","C007.V"]`
- [ ] **C008.03** Exact account-name/id, asset legacy/V2, recent Tapos, and history keys.  
  **dependencies[]:** `["C001.V","C002.V","C004.V","C007.V"]`
- [ ] **C008.04** Contract/ABI/code/state/storage-row split and key composition.  
  **dependencies[]:** `["C001.V","C002.V","C004.V","C007.V"]`
- [ ] **C008.05** Witness/schedule/votes/proposal/exchange schemas.  
  **dependencies[]:** `["C001.V","C002.V","C004.V","C007.V"]`
- [ ] **C008.06** Market pair/price/order keys, padding, normalized quantities, linked records.  
  **dependencies[]:** `["C001.V","C002.V","C004.V","C007.V"]`
- [ ] **C008.07** Legacy/V2 delegated resource and account-index prefixes.  
  **dependencies[]:** `["C001.V","C002.V","C004.V","C007.V"]`
- [ ] **C008.08** Shielded, bloom, trace, common, PBFT, and all remaining stores.  
  **dependencies[]:** `["C001.V","C002.V","C004.V","C007.V"]`
- [ ] **C008.09** Dynamic properties keys/defaults, including leading-space ` ALLOW_SAME_TOKEN_NAME`.  
  **dependencies[]:** `["C001.V","C002.V","C004.V","C007.V"]`
- [ ] **C008.10** Account-asset optimization representation and external 8-byte balances.  
  **dependencies[]:** `["C001.V","C002.V","C004.V","C007.V"]`
- [ ] **C008.11** Generate store/DB/key/value/dynamic-property inventories and the state coverage matrix for absent/present/delete, every session transition, nested commit/merge/revoke/pop/close, persistence crash points, reopen, and every relevant fork-flag boundary.  
  **dependencies[]:** `["C001.V","C002.V","C004.V","C007.V"]`
- [ ] **C008.V** Every Java DB name/key/value fixture compares exactly at the logical layer.  
  **dependencies[]:** `["C008.01","C008.02","C008.03","C008.04","C008.05","C008.06","C008.07","C008.08","C008.09","C008.10","C008.11"]`

## C009 — Revoking state and cursors

**Status:** `[ ]`  
**Derived prerequisite gates (non-executable):** `["C007.V","C008.V"]`  
**Commit boundary:** complete transactional overlay/session/checkpoint/cursor behavior.

- [ ] **C009.01** Overlay value operators and current-to-root reads.  
  **dependencies[]:** `["C007.V","C008.V"]`
- [ ] **C009.02** Nested build/merge/commit/revoke/pop/destroy/close semantics across every store.  
  **dependencies[]:** `["C007.V","C008.V"]`
- [ ] **C009.03** Rust checkpoint encoding, atomic persistence, recovery, stack/flush limits.  
  **dependencies[]:** `["C007.V","C008.V"]`
- [ ] **C009.04** Held speculative pending session behavior.  
  **dependencies[]:** `["C007.V","C008.V"]`
- [ ] **C009.05** Separate typed HEAD/SOLIDITY/PBFT cursors and PBFT offset.  
  **dependencies[]:** `["C007.V","C008.V"]`
- [ ] **C009.06** Concurrency/read isolation and shutdown flushing.  
  **dependencies[]:** `["C007.V","C008.V"]`
- [ ] **C009.V** Transition matrix, complete revoke, crash recovery, and cursor isolation pass.  
  **dependencies[]:** `["C009.01","C009.02","C009.03","C009.04","C009.05","C009.06"]`

## C010 — Genesis, dynamic state, resources, and account trie

**Status:** `[ ]`  
**Derived prerequisite gates (non-executable):** `["C003.V","C006.V","C009.V"]`  
**Commit boundary:** deterministic genesis/state initialization, resource models, optimization, trie, and Rust logical migrations.

- [ ] **C010.01** Genesis accounts/witnesses/assets/block and network identity validation.  
  **dependencies[]:** `["C003.V","C006.V","C009.V"]`
- [ ] **C010.02** Dynamic counters/fees/flags/fork stats/maintenance defaults and migration initialization.  
  **dependencies[]:** `["C003.V","C006.V","C009.V"]`
- [ ] **C010.03** Bandwidth/energy/TRON power windows, scaling, weights, and fee pool/burn behavior.  
  **dependencies[]:** `["C003.V","C006.V","C009.V"]`
- [ ] **C010.04** Legacy/V2 asset and account-asset optimization transitions/dual writes.  
  **dependencies[]:** `["C003.V","C006.V","C009.V"]`
- [ ] **C010.05** Account-state trie RLP key, reduced value, Keccak MPT, child inlining, forced root hash, duplicate-leaf fix.  
  **dependencies[]:** `["C003.V","C006.V","C009.V"]`
- [ ] **C010.06** Rust schema migrations preserve logical state and recomputed roots.  
  **dependencies[]:** `["C003.V","C006.V","C009.V"]`
- [ ] **C010.V** Genesis bytes, roots, counters, resources, optimization, and rejection differentials pass.  
  **dependencies[]:** `["C010.01","C010.02","C010.03","C010.04","C010.05","C010.06"]`

## C011 — Fork graph and activation

**Status:** `[ ]`  
**Derived prerequisite gates (non-executable):** `["C008.V","C009.V","C010.V"]`  
**Commit boundary:** in-memory fork graph and fork-version controller.

- [ ] **C011.01** Linked mini-store, unlinked store, weak parent links, size/eviction, lookup/removal.  
  **dependencies[]:** `["C008.V","C009.V","C010.V"]`
- [ ] **C011.02** Main/fork branch path and common-ancestor calculation.  
  **dependencies[]:** `["C008.V","C009.V","C010.V"]`
- [ ] **C011.03** Fork version witness statistics, downgrade/upgrade, special heights, maintenance-rounded activation.  
  **dependencies[]:** `["C008.V","C009.V","C010.V"]`
- [ ] **C011.V** Linked/orphan/replacement/eviction/branch/activation fixtures match Java.  
  **dependencies[]:** `["C011.01","C011.02","C011.03"]`

## C012 — Account, asset, witness, and permission actuators

**Status:** `[ ]`  
**Derived prerequisite gates (non-executable):** `["C004.V","C010.V","C011.V","C001.V"]`  
**Commit boundary:** complete first actuator family with validation, execution, errors, and differential state fixtures.

- [ ] **C012.01** AccountCreate, AccountUpdate, SetAccountId, AccountPermissionUpdate.  
  **dependencies[]:** `["C004.V","C010.V","C011.V"]`
- [ ] **C012.02** Transfer and account auto-creation/system fee behavior.  
  **dependencies[]:** `["C004.V","C010.V","C011.V"]`
- [ ] **C012.03** AssetIssue, UpdateAsset, TransferAsset, ParticipateAssetIssue, UnfreezeAsset.  
  **dependencies[]:** `["C004.V","C010.V","C011.V"]`
- [ ] **C012.04** WitnessCreate, WitnessUpdate, VoteWitness and permission defaults.  
  **dependencies[]:** `["C004.V","C010.V","C011.V"]`
- [ ] **C012.05** ContractType-to-protobuf/actuator registration and owner extraction.  
  **dependencies[]:** `["C004.V","C010.V","C011.V"]`
- [ ] **C012.06** Implement DR-004 custom-actuator registry/discovery and owner extraction against the approved extension descriptor/adoption inventory; preserve built-in and extension collision/error behavior.  
  **dependencies[]:** `["C004.V","C010.V","C011.V","C001.V","C000.12","C000.15"]`
- [ ] **C012.V** Every contract success/failure/boundary produces Java-identical deltas/results and full revoke.  
  **dependencies[]:** `["C012.01","C012.02","C012.03","C012.04","C012.05","C012.06"]`

## C013 — Resource, governance, exchange, and market actuators

**Status:** `[ ]`  
**Derived prerequisite gates (non-executable):** `["C012.V"]`  
**Commit boundary:** all remaining non-VM actuators.

- [ ] **C013.01** Legacy Freeze/Unfreeze/Withdraw and resource weight/account/vote effects.  
  **dependencies[]:** `["C012.V"]`
- [ ] **C013.02** FreezeV2/UnfreezeV2/WithdrawExpire/CancelAll with 32-entry and delay rules.  
  **dependencies[]:** `["C012.V"]`
- [ ] **C013.03** Delegate/Undelegate locked/unlocked records and usage migration.  
  **dependencies[]:** `["C012.V"]`
- [ ] **C013.04** Proposal create/approve/delete and complete parameter validation IDs/gaps/dependencies.  
  **dependencies[]:** `["C012.V"]`
- [ ] **C013.05** Exchange create/inject/withdraw/trade and legacy/V2 dual stores.  
  **dependencies[]:** `["C012.V"]`
- [ ] **C013.06** Market sell/match/cancel, Keccak IDs, normalized prices, max 20 matches, linked lists.  
  **dependencies[]:** `["C012.V"]`
- [ ] **C013.07** Brokerage/storage/update-setting/energy-limit/clear-ABI and miscellaneous contract types.  
  **dependencies[]:** `["C012.V"]`
- [ ] **C013.V** Contract/fork-flag matrix and arithmetic/error/state oracles pass.  
  **dependencies[]:** `["C013.01","C013.02","C013.03","C013.04","C013.05","C013.06","C013.07"]`

## C014 — TVM interpreter and repository

**Status:** `[ ]`  
**Derived prerequisite gates (non-executable):** `["C002.V","C004.V","C010.V","C013.V"]`  
**Commit boundary:** TVM repository/interpreter/opcodes/gas without precompile completion.

- [ ] **C014.01** Repository overlays, child commit/revoke, account/code/ABI/storage access.  
  **dependencies[]:** `["C002.V","C004.V","C010.V","C013.V"]`
- [ ] **C014.02** Stack, memory, data words, program counter, jumps, return/revert, logs, internal txs.  
  **dependencies[]:** `["C002.V","C004.V","C010.V","C013.V"]`
- [ ] **C014.03A** From the versioned TVM manifest, implement arithmetic/bitwise/comparison/environment opcode families and their fork/flag states; local differential gate for every owned row.  
  **dependencies[]:** `["C002.V","C004.V","C010.V","C013.V"]`
- [ ] **C014.03B** Implement memory/storage/control-flow/log opcode families and activation states; local differential gate for every owned row.  
  **dependencies[]:** `["C002.V","C004.V","C010.V","C013.V"]`
- [ ] **C014.03C** Implement call/create/system/TRON opcode families and activation states; local differential gate for every owned row.  
  **dependencies[]:** `["C002.V","C004.V","C010.V","C013.V"]`
- [ ] **C014.04** CALL/CREATE/CREATE2/delegate/static behavior, depth, value, selfdestruct.  
  **dependencies[]:** `["C002.V","C004.V","C010.V","C013.V"]`
- [ ] **C014.05** Energy/gas schedules, penalties, CPU/time limits, strict math.  
  **dependencies[]:** `["C002.V","C004.V","C010.V","C013.V"]`
- [ ] **C014.06** Exact exception to `contractResult` mapping, including misspellings/legacy values.  
  **dependencies[]:** `["C002.V","C004.V","C010.V","C013.V"]`
- [ ] **C014.07** Generate the TVM conformance manifest listing each opcode, fork interval, input boundaries, energy formula, state effect and exception/result mapping; all registry rows must be owned by C014.03A-C.  
  **dependencies[]:** `["C002.V","C004.V","C010.V","C013.V"]`
- [ ] **C014.V** Runtime/repository behavior and every opcode-manifest row, fork/address/storage boundary pass deterministically; inventory difference is empty.  
  **dependencies[]:** `["C014.01","C014.02","C014.03A","C014.03B","C014.03C","C014.04","C014.05","C014.06","C014.07"]`

## C015 — TVM precompiles and shielded execution

**Status:** `[ ]`  
**Derived prerequisite gates (non-executable):** `["C006.V","C014.V"]`  
**Commit boundary:** complete precompile/native-contract surface and conformance vectors.

- [ ] **C015.01** ECRecover/hash/identity/modexp/BN128/Blake2f and all standard precompiles.  
  **dependencies[]:** `["C006.V","C014.V"]`
- [ ] **C015.02** P256 verify with exact input/output and 6900 energy.  
  **dependencies[]:** `["C006.V","C014.V"]`
- [ ] **C015.03** TRON-specific staking/voting/resource/batch/native precompiles and flags.  
  **dependencies[]:** `["C006.V","C014.V"]`
- [ ] **C015.04** Shielded transfer/TRC20 verification, stores, proofs, energy, failure mapping.  
  **dependencies[]:** `["C006.V","C014.V"]`
- [ ] **C015.05** Independently recreate or license-compatible replace the UNLICENSED Freeze fixture.  
  **dependencies[]:** `["C006.V","C014.V","C015.07"]`
- [ ] **C015.06** Extend the TVM manifest to every standard/TRON/shielded precompile and native contract with activation, input domains, energy, effects and result mapping; require one differential vector per row and boundary class.  
  **dependencies[]:** `["C006.V","C014.V"]`
- [ ] **C015.07** Before fixture work, approve legal guidance and a clean-room procedure for the UNLICENSED Freeze behavior: permissible observations, observer/implementer separation if required, retained evidence, authorship and replacement license.  
  **dependencies[]:** `["C006.V","C014.V"]`
- [ ] **C015.V** 782 P256 vectors and complete malformed/boundary/success/failure precompile matrix pass.  
  **dependencies[]:** `["C015.01","C015.02","C015.03","C015.04","C015.05","C015.06","C015.07"]`

## C016 — Transaction pipeline and pending pool

**Status:** `[ ]`  
**Derived prerequisite gates (non-executable):** `["C009.V","C013.V","C015.V","C001.V","C012.V"]`  
**Commit boundary:** complete transaction admission, execution, billing, tracing, persistence, and pending semantics.

- [ ] **C016.01** One-contract, size, expiration, Tapos, duplicate/cache, and unknown-field rules.  
  **dependencies[]:** `["C009.V","C013.V","C015.V"]`
- [ ] **C016.02** Permission/operations/signature-count/weight/fee and ownerless shielded validation.  
  **dependencies[]:** `["C009.V","C013.V","C015.V"]`
- [ ] **C016.03** Bandwidth, multisig, memo, energy origin/caller split, fee pool/burn/blackhole.  
  **dependencies[]:** `["C009.V","C013.V","C015.V"]`
- [ ] **C016.04** Runtime dispatch, constant policy, OUT_OF_TIME retry, witness result comparison.  
  **dependencies[]:** `["C009.V","C013.V","C015.V"]`
- [ ] **C016.05** ProgramResult, receipt, TransactionInfo/Ret, logs/internal/orders and packing fee.  
  **dependencies[]:** `["C009.V","C013.V","C015.V"]`
- [ ] **C016.06** Pending held session, capacity, requeue/revoke, smart-contract queue, ID cache.  
  **dependencies[]:** `["C009.V","C013.V","C015.V"]`
- [ ] **C016.07** Dispatch custom actuators through the normal admission, permission, execution, receipt, revoke/requeue and failure pipeline; produce the DR-004 differential state/result fixture.  
  **dependencies[]:** `["C009.V","C013.V","C015.V","C001.V","C012.V"]`
- [ ] **C016.V** End-to-end Java differential state/result and leak-free revoke/requeue gates pass.  
  **dependencies[]:** `["C016.01","C016.02","C016.03","C016.04","C016.05","C016.06","C016.07"]`

## C017 — DPoS consensus

**Status:** `[ ]`  
**Derived prerequisite gates (non-executable):** `["C011.V","C013.V","C016.V"]`  
**Commit boundary:** complete DPoS scheduling, maintenance, rewards, proposals, forks, and solidification.

- [ ] **C017.01** 3-second slot arithmetic, timestamp optimization, eligibility, witness selection/shuffle/sort quirks.  
  **dependencies[]:** `["C011.V","C013.V","C016.V"]`
- [ ] **C017.02** Production, missed slots, participation, duplicate/equivocation/timing guards.  
  **dependencies[]:** `["C011.V","C013.V","C016.V"]`
- [ ] **C017.03** Maintenance boundaries, vote deltas, active/current schedules, cycle transitions.  
  **dependencies[]:** `["C011.V","C013.V","C016.V"]`
- [ ] **C017.04** Witness/standby/fee-pool rewards and legacy allowance.  
  **dependencies[]:** `["C011.V","C013.V","C016.V"]`
- [ ] **C017.05** Proposal 70% application, one-shot/dependency rules, dynamic writes.  
  **dependencies[]:** `["C011.V","C013.V","C016.V"]`
- [ ] **C017.06** 70% solidity position and fork activation updates.  
  **dependencies[]:** `["C011.V","C013.V","C016.V"]`
- [ ] **C017.07** Publish deterministic consensus scenario manifests with seeds, complete genesis/config, slots, maintenance/fork schedules, witness changes, threshold−1/at/+1, misses/equivocation, rewards/proposals and per-step Java schedules/state/roots/cursors/events.  
  **dependencies[]:** `["C011.V","C013.V","C016.V"]`
- [ ] **C017.V** Fixed-clock 27-witness simulations match Java across maintenance and fork boundaries.  
  **dependencies[]:** `["C017.01","C017.02","C017.03","C017.04","C017.05","C017.06","C017.07"]`

## C018 — PBFT sidecar and backup election

**Status:** `[ ]`  
**Derived prerequisite gates (non-executable):** `["C004.V","C017.V"]`  
**Commit boundary:** auxiliary PBFT and witness backup UDP behavior.

- [ ] **C018.01** PBFT raw/message signing, recovery, dedup, expiry, forwarding and action dispatch.  
  **dependencies[]:** `["C004.V","C017.V"]`
- [ ] **C018.02** Commit/SRL quorum validation and sign-data persistence/retrieval.  
  **dependencies[]:** `["C004.V","C017.V"]`
- [ ] **C018.03** Preserve PBFT as auxiliary sidecar, not block-selection consensus.  
  **dependencies[]:** `["C004.V","C017.V"]`
- [ ] **C018.04** Backup UDP `0x05` envelope, allowlist, 3s keepalive, six-interval timeout.  
  **dependencies[]:** `["C004.V","C017.V"]`
- [ ] **C018.05** Priority then IP tie-break MASTER/SLAVER election and service lifecycle.  
  **dependencies[]:** `["C004.V","C017.V"]`
- [ ] **C018.06** Extend consensus manifests with PBFT quorum−1/at/+1, expiry, dedup, invalid signatures, backup election and timeout scenarios.  
  **dependencies[]:** `["C004.V","C017.V"]`
- [ ] **C018.V** Message/store/quorum/election/timeouts match Java, including real UDP behavior.  
  **dependencies[]:** `["C018.01","C018.02","C018.03","C018.04","C018.05","C018.06"]`

## C019 — Block manager and fork switching

**Status:** `[ ]`  
**Derived prerequisite gates (non-executable):** `["C016.V","C017.V","C018.V"]`  
**Commit boundary:** block production/validation/application, fork replay, roots, indexes, and rollback hooks.

- [ ] **C019.01** Block timestamp/parent/size/signature/witness/version validation and construction.  
  **dependencies[]:** `["C016.V","C017.V","C018.V"]`
- [ ] **C019.02** Ordered transaction execution/result comparison, Merkle/account roots and block ID.  
  **dependencies[]:** `["C016.V","C017.V","C018.V"]`
- [ ] **C019.03** Rewards, maintenance, recent/history/index persistence and receive metadata.  
  **dependencies[]:** `["C016.V","C017.V","C018.V"]`
- [ ] **C019.04** Fork switch rewind/replay, signature-cache clearing, failure restoration.  
  **dependencies[]:** `["C016.V","C017.V","C018.V"]`
- [ ] **C019.05** Pending suspension/requeue and HEAD/SOLIDITY/PBFT advancement.  
  **dependencies[]:** `["C016.V","C017.V","C018.V"]`
- [ ] **C019.06** Event/filter removed/reapply hooks and state-consistent ordering.  
  **dependencies[]:** `["C016.V","C017.V","C018.V"]`
- [ ] **C019.07** Extend consensus manifests with explicit branch graphs, minimum reorg depths, injected replay failures, restoration, pending requeue, cursor and event assertions.  
  **dependencies[]:** `["C016.V","C017.V","C018.V"]`
- [ ] **C019.V** Multi-branch Java differential state/root/event/view fixtures pass atomically.  
  **dependencies[]:** `["C019.01","C019.02","C019.03","C019.04","C019.05","C019.06","C019.07"]`

## C020 — External transport and discovery

**Status:** `[ ]`  
**Derived prerequisite gates (non-executable):** `["C001.V","C003.V","C004.V","C007.V"]`  
**Commit boundary:** libp2p-2.2.9-compatible external TCP/UDP/DNS transport layer.

- [ ] **C020.01** TCP varint frame codec, 5,242,880-byte maximum, traffic accounting, read timeout.  
  **dependencies[]:** `["C001.V","C003.V","C004.V"]`
- [ ] **C020.02** Negative control bytes and exact external Connect protobuf schemas.  
  **dependencies[]:** `["C001.V","C003.V","C004.V"]`
- [ ] **C020.03** Active/passive handshake, network/version asymmetry, admission, duplicate/self/capacity/trust rules.  
  **dependencies[]:** `["C001.V","C003.V","C004.V"]`
- [ ] **C020.04** Compression negotiation, snappy envelope, 5 MiB uncompressed protection.  
  **dependencies[]:** `["C001.V","C003.V","C004.V"]`
- [ ] **C020.05** External keepalive, disconnect, temporary IP ban and reconnect behavior.  
  **dependencies[]:** `["C001.V","C003.V","C004.V"]`
- [ ] **C020.06** Kademlia UDP raw envelope, limits, buckets/table/XOR/lookup/timeouts/eviction.  
  **dependencies[]:** `["C001.V","C003.V","C004.V"]`
- [ ] **C020.07** DNS tree signed root/leaf validation and candidate production.  
  **dependencies[]:** `["C001.V","C003.V","C004.V"]`
- [ ] **C020.08** Connection pool, node detection/status probe, candidate ranking, persisted peers.  
  **dependencies[]:** `["C001.V","C003.V","C004.V","C007.V"]`
- [ ] **C020.09** Publish the P2P harness manifest: pinned Java artifact/config, topology, deterministic chain, capture hashes, directions/roles, payload boundaries, compression matrix, malformed corpus, timing tolerances, disconnect/ban expectations, discovery/DNS datasets and minimum sync/reorg depths.  
  **dependencies[]:** `["C001.V","C003.V","C004.V"]`
- [ ] **C020.V** Captured and live Java↔Rust bidirectional TCP, compression, malformed, UDP, DNS and ban tests pass; UDP ambiguity is evidence-resolved.  
  **dependencies[]:** `["C020.01","C020.02","C020.03","C020.04","C020.05","C020.06","C020.07","C020.08","C020.09"]`

## C021 — Application P2P, sync, gossip, and relay

**Status:** `[ ]`  
**Derived prerequisite gates (non-executable):** `["C019.V","C020.V"]`  
**Commit boundary:** complete application network protocol and mixed-node synchronization.

- [ ] **C021.01** Exact positive type-byte factory; reject reserved/unsupported types as Java does.  
  **dependencies[]:** `["C019.V","C020.V"]`
- [ ] **C021.02** Application Hello construction/validation/policy and fixed-byte ping/pong.  
  **dependencies[]:** `["C019.V","C020.V"]`
- [ ] **C021.03** Peer state, inventory/request caches, rate limits, latency ordering, cleanup and one-hour bad bans.  
  **dependencies[]:** `["C019.V","C020.V"]`
- [ ] **C021.04** Sparse summary, chain inventory validation, batch/remain rules, ordered fetch/process.  
  **dependencies[]:** `["C019.V","C020.V"]`
- [ ] **C021.05** Advertisement inventory/fetch/spread, bounded caches and stale suppression.  
  **dependencies[]:** `["C019.V","C020.V"]`
- [ ] **C021.06** Transaction/block/PBFT handlers, request correlation, size/time/signature/Merkle/errors.  
  **dependencies[]:** `["C019.V","C020.V"]`
- [ ] **C021.07** Fast-forward witness Hello signing/trust and successor full-block relay.  
  **dependencies[]:** `["C019.V","C020.V"]`
- [ ] **C021.08** Watchdog/effective/resilience/fetch/statistics services and disconnect mapping.  
  **dependencies[]:** `["C019.V","C020.V"]`
- [ ] **C021.09** Execute and individually report every P2P manifest scenario, including active/passive and bidirectional handshakes, ordinary and fast-forward propagation, convergence and terminal peer/cache state.  
  **dependencies[]:** `["C019.V","C020.V"]`
- [ ] **C021.V** Two-way Java↔Rust genesis-to-head sync, tx/block propagation, reorg, ordinary/fast-forward, timeout/disconnect gates pass.  
  **dependencies[]:** `["C021.01","C021.02","C021.03","C021.04","C021.05","C021.06","C021.07","C021.08","C021.09"]`

## C022 — Wallet and gRPC

**Status:** `[ ]`  
**Derived prerequisite gates (non-executable):** `["C019.V","C021.V","C001.V","C016.V"]`  
**Commit boundary:** complete domain service and protobuf gRPC surfaces.

- [ ] **C022.01A** Generate the descriptor-derived RPC inventory and implement bounded account/asset/witness/governance query families; local method/status/bytes gate.  
  **dependencies[]:** `["C019.V","C021.V"]`
- [ ] **C022.01B** Implement transaction construction/broadcast/execution and shielded RPC families; local gate.  
  **dependencies[]:** `["C019.V","C021.V"]`
- [ ] **C022.01C** Implement chain/block/resource/market/exchange/node query families and deprecated aliases; local gate.  
  **dependencies[]:** `["C019.V","C021.V"]`
- [ ] **C022.02** WalletSolidity, WalletExtension, Database, Monitor, Network and TronZksnark services.  
  **dependencies[]:** `["C019.V","C021.V"]`
- [ ] **C022.03** Deprecated and `*2` constructors, exact Return/TransactionExtention behavior.  
  **dependencies[]:** `["C019.V","C021.V"]`
- [ ] **C022.04** Full/Solidity/PBFT cursor wrappers and standalone replication Database calls.  
  **dependencies[]:** `["C019.V","C021.V"]`
- [ ] **C022.05** Plaintext server limits, reflection, max streams/messages/headers/connections.  
  **dependencies[]:** `["C019.V","C021.V"]`
- [ ] **C022.06** Per-method/global/IP rate limits, blocking/nonblocking overload, disabled/lite/metrics interceptors.  
  **dependencies[]:** `["C019.V","C021.V"]`
- [ ] **C022.07** Add custom-actuator API construction/exposure and run the DR-004 end-to-end fixture through registration, owner extraction, execution, state delta, broadcast and query.  
  **dependencies[]:** `["C019.V","C021.V","C001.V","C016.V"]`
- [ ] **C022.V** Zero-unmapped RPC inventory; each executable case records request bytes, state/cursor checkpoint, exact status/message/error bytes, limit schedule and evidence run ID.  
  **dependencies[]:** `["C022.01A","C022.01B","C022.01C","C022.02","C022.03","C022.04","C022.05","C022.06","C022.07"]`

## C023 — HTTP protobuf-JSON

**Status:** `[ ]`  
**Derived prerequisite gates (non-executable):** `["C022.V"]`  
**Commit boundary:** every HTTP route, serializer, filter, limit, and error surface.

- [ ] **C023.01A** Generate the servlet-derived HTTP route inventory; implement bounded `/wallet` account/asset/witness/governance families with local route gates.  
  **dependencies[]:** `["C022.V"]`
- [ ] **C023.01B** Implement transaction/contract/shielded and chain/resource/market route families with local gates.  
  **dependencies[]:** `["C022.V"]`
- [ ] **C023.02** Implement bounded `/walletsolidity`, `/walletpbft`, `/net`, and `/monitor` families with local gates.  
  **dependencies[]:** `["C022.V"]`
- [ ] **C023.03** JSON/form request parsing, `visible`, `Any`, Permission_id, extra_data, broadcasthex.  
  **dependencies[]:** `["C022.V"]`
- [ ] **C023.04** Hex/Base58/name protobuf JSON, escaping, defaults, and GET-only `int64_as_string` scope.  
  **dependencies[]:** `["C022.V"]`
- [ ] **C023.05** HTTP 404 disabled, lite gates, `{"Error":"class : message"}`, size 413, connection/rate behavior.  
  **dependencies[]:** `["C022.V"]`
- [ ] **C023.06** Define comparison policy: included/excluded headers, byte/status/error rules, controlled clock, concurrency/rate schedules and state/cursor checkpoints.  
  **dependencies[]:** `["C022.V"]`
- [ ] **C023.V** Zero-unmapped route inventory and all per-family/boundary cases pass with run IDs.  
  **dependencies[]:** `["C023.01A","C023.01B","C023.02","C023.03","C023.04","C023.05","C023.06"]`

## C024 — JSON-RPC and filters

**Status:** `[ ]`  
**Derived prerequisite gates (non-executable):** `["C019.V","C022.V"]`  
**Commit boundary:** observed TRON JSON-RPC subset on all cursor ports.

- [ ] **C024.01** Servlet parse/batch/nesting/token/request/response constraints and HTTP-200 JSON-RPC errors.  
  **dependencies[]:** `["C019.V","C022.V"]`
- [ ] **C024.02A** Generate the interface-derived method inventory; implement bounded web3/net/chain/block/account/state families with local gates.  
  **dependencies[]:** `["C019.V","C022.V"]`
- [ ] **C024.02B** Implement call/gas/transaction/receipt/buildTransaction families with local gates.  
  **dependencies[]:** `["C019.V","C022.V"]`
- [ ] **C024.02C** Implement sync/mining/filter/log families and deliberate unsupported/null/zero behavior with local gates.  
  **dependencies[]:** `["C019.V","C022.V"]`
- [ ] **C024.03** Tron address/hash/quantity/tag conversions and genesis-derived chain ID.  
  **dependencies[]:** `["C019.V","C022.V"]`
- [ ] **C024.04** buildTransaction supported contract families and exact unsupported method-not-found/null/zero behavior.  
  **dependencies[]:** `["C019.V","C022.V"]`
- [ ] **C024.05** Log bloom/exact topics/addresses/ranges and full/Solidity filter maps.  
  **dependencies[]:** `["C019.V","C022.V"]`
- [ ] **C024.06** New/block/uninstall/changes/logs/filterLogs, five-minute expiry, caps, reorg removed/reapply.  
  **dependencies[]:** `["C019.V","C022.V"]`
- [ ] **C024.07** Full/Solidity/PBFT ports and cursor routing; preserve absence on standalone Solidity where observed.  
  **dependencies[]:** `["C019.V","C022.V"]`
- [ ] **C024.08** Define request/state checkpoint, exact result/error comparison, batch/limit/concurrency schedules and controlled-clock expiry cases.  
  **dependencies[]:** `["C019.V","C022.V"]`
- [ ] **C024.V** Zero-unmapped method inventory; all family/error/limit/filter/reorg cases pass with run IDs.  
  **dependencies[]:** `["C024.01","C024.02A","C024.02B","C024.02C","C024.03","C024.04","C024.05","C024.06","C024.07","C024.08"]`

## C025 — Events, plugins, metrics, and operations

**Status:** `[ ]`  
**Derived prerequisite gates (non-executable):** `["C019.V","C021.V","C022.V","C023.V","C024.V"]`  
**Commit boundary:** event pipelines, plugin adapter, ZeroMQ, metrics, node info and service lifecycle.

- [ ] **C025.01** Block/transaction/contract event/log and solidity trigger schemas/modes.  
  **dependencies[]:** `["C019.V","C021.V","C022.V","C023.V","C024.V"]`
- [ ] **C025.02** Async history/realtime/solid queues, redundant/ETH/solidified modes and reorg ordering.  
  **dependencies[]:** `["C019.V","C021.V","C022.V","C023.V","C024.V"]`
- [ ] **C025.03** PF4J-compatible plugin boundary or approved equivalent with explicit compatibility adapter.  
  **dependencies[]:** `["C019.V","C021.V","C022.V","C023.V","C024.V"]`
- [ ] **C025.04** ZeroMQ PUB topic frame + JSON frame, bind/HWM/failure/shutdown behavior.  
  **dependencies[]:** `["C019.V","C021.V","C022.V","C023.V","C024.V"]`
- [ ] **C025.05** Monitor metrics and Prometheus names/labels/latencies/traffic/disconnect/block detail.  
  **dependencies[]:** `["C019.V","C021.V","C022.V","C023.V","C024.V"]`
- [ ] **C025.06** NodeInfo observed fields/quirks, health/readiness and metrics enablement.  
  **dependencies[]:** `["C019.V","C021.V","C022.V","C023.V","C024.V"]`
- [ ] **C025.07** Service startup, reverse shutdown, signals, stop conditions and surfaced failures.  
  **dependencies[]:** `["C019.V","C021.V","C022.V","C023.V","C024.V"]`
- [ ] **C025.08** Generate metric/event/service inventories; define scrape windows, float/counter tolerances, labels, API-specific interceptors, event order and standalone checkpoint comparisons; require zero unmapped rows.  
  **dependencies[]:** `["C019.V","C021.V","C022.V","C023.V","C024.V"]`
- [ ] **C025.V** Live subscriber, metric parity, event reorg, lifecycle and failure-propagation gates pass.  
  **dependencies[]:** `["C025.01","C025.02","C025.03","C025.04","C025.05","C025.06","C025.07","C025.08"]`

## C026 — Standalone Solidity node

**Status:** `[ ]`  
**Derived prerequisite gates (non-executable):** `["C019.V","C022.V","C023.V"]`  
**Commit boundary:** complete non-P2P remote replication topology.

- [ ] **C026.01** Require/parse trust-node and reject invalid/missing configuration.  
  **dependencies[]:** `["C019.V","C022.V","C023.V"]`
- [ ] **C026.02** Database gRPC polling for dynamic solidity height and sequential blocks.  
  **dependencies[]:** `["C019.V","C022.V","C023.V"]`
- [ ] **C026.03** Verify/apply blocks, retry/backoff/failure/cancellation and restart persistence.  
  **dependencies[]:** `["C019.V","C022.V","C023.V"]`
- [ ] **C026.04** Generate a versioned standalone-Solidity exposure manifest with stable service/method/route/port row IDs. For every general API inventory row record required, forbidden or not-applicable exposure plus cursor routing; implement exactly that subset, with no P2P or full-cursor JSON-RPC.  
  **dependencies[]:** `["C019.V","C022.V","C023.V"]`
- [ ] **C026.05** Generate and validate the exposure manifest from source/config descriptors with zero added, missing or changed rows; bind every row to executable endpoint/absence/cursor evidence.  
  **dependencies[]:** `["C019.V","C022.V","C023.V"]`
- [ ] **C026.V** Cross-language full→Solidity replication and API-state parity pass; standalone exposure manifest has zero difference and every required/forbidden/cursor row has passing evidence.  
  **dependencies[]:** `["C026.01","C026.02","C026.03","C026.04","C026.05"]`

## C027 — Toolkit and data workflows

**Status:** `[ ]`  
**Derived prerequisite gates (non-executable):** `["C005.V","C007.V","C008.V","C009.V","C025.V"]`  
**Commit boundary:** pinned Java toolkit reference matrix plus Rust-format DB and compatible keystore CLI tools.

- [ ] **C027.01** Generate the Java toolkit command/option/error inventory for `db convert/archive/cp/lite/mv/root` and related commands, bound to Java revision and architecture/backend restrictions.  
  **dependencies[]:** `["C005.V","C007.V","C008.V","C009.V","C025.V"]`
- [ ] **C027.02** Execute the pinned Java reference matrix on non-destructive fixtures; record command, expected/actual exit/stdout/stderr/filesystem hashes and retained evidence.  
  **dependencies[]:** `["C005.V","C007.V","C008.V","C009.V","C025.V"]`
- [ ] **C027.03** Map each Java command to retained-reference-only behavior, Rust equivalent, or reviewed non-applicability under DR-001; no silent omission.  
  **dependencies[]:** `["C005.V","C007.V","C008.V","C009.V","C025.V"]`
- [ ] **C027.04** Rust command tree/help/options and DB inspect/copy/move/root/checkpoint with path, lock, symlink and partial-failure safety.  
  **dependencies[]:** `["C005.V","C007.V","C008.V","C009.V","C025.V"]`
- [ ] **C027.05** Rust-format lite split/merge, archive, migration, backup and rollback commands.  
  **dependencies[]:** `["C005.V","C007.V","C008.V","C009.V","C025.V"]`
- [ ] **C027.06** Explicit non-destructive Java-format rejection/resync guidance and keystore new/import/list/update CLI.  
  **dependencies[]:** `["C005.V","C007.V","C008.V","C009.V","C025.V"]`
- [ ] **C027.07** Architecture/backend capability reporting; no silent engine substitution.  
  **dependencies[]:** `["C005.V","C007.V","C008.V","C009.V","C025.V"]`
- [ ] **C027.08** Publish the command/drill manifest with platform/backend, fixture sizes, fault points, exact outputs, manifest/state hashes and filesystem/no-write assertions.  
  **dependencies[]:** `["C005.V","C007.V","C008.V","C009.V","C025.V"]`
- [ ] **C027.V** Java reference matrix and Rust command manifest both pass with per-command run IDs; Rust workflows round-trip.  
  **dependencies[]:** `["C027.01","C027.02","C027.03","C027.04","C027.05","C027.06","C027.07","C027.08"]`

## C028 — Packaging, deployment, and resync

**Status:** `[ ]`  
**Derived prerequisite gates (non-executable):** `["C006.V","C021.V","C024.V","C025.V","C026.V","C027.V"]`  
**Commit boundary:** reproducible distribution and complete operational lifecycle after every advertised API is gated.

- [ ] **C028.01** Reproducible FullNode/Solidity/Toolkit binaries and parameter/config packaging.  
  **dependencies[]:** `["C006.V","C021.V","C024.V","C025.V","C026.V","C027.V"]`
- [ ] **C028.02** Consume C000.14 supported OS/architecture/backend/feature matrix and startup preflight; no undeclared platform row.  
  **dependencies[]:** `["C006.V","C021.V","C024.V","C025.V","C026.V","C027.V"]`
- [ ] **C028.03** Service/container examples, health/readiness, logs, signals and numeric resource limits.  
  **dependencies[]:** `["C006.V","C021.V","C024.V","C025.V","C026.V","C027.V"]`
- [ ] **C028.04** Plaintext API/P2P/event/ZK exposure and key-management security guidance.  
  **dependencies[]:** `["C006.V","C021.V","C024.V","C025.V","C026.V","C027.V"]`
- [ ] **C028.05** End-to-end upgrade/rollback matrix: retained binaries/tools/config, preflight, quiescence, point of no return, downgrade eligibility after writes, network safety and clean-resync fallback.  
  **dependencies[]:** `["C006.V","C021.V","C024.V","C025.V","C026.V","C027.V"]`
- [ ] **C028.06** Snapshot format and trust-store policy: out-of-band anchor provisioning; signer scope; rotation/revocation; signature algorithm/version agility; offline verification; network checkpoint and operator-selected minimum acceptable height independent of snapshot metadata; clock/freshness failures; authenticated provenance; network/genesis/version/height and trusted block/state-root binding; completeness/replay/anti-rollback; atomic staging, cleanup and resync fallback.  
  **dependencies[]:** `["C006.V","C021.V","C024.V","C025.V","C026.V","C027.V"]`
- [ ] **C028.07** Genesis resync, snapshot, disk-full, corruption, wrong identity, newer format and partial migration drills at declared fault points, including revoked key, rotated key, stale-but-valid signature, rollback height, compromised metadata and offline verification cases.  
  **dependencies[]:** `["C006.V","C021.V","C024.V","C025.V","C026.V","C027.V"]`
- [ ] **C028.08** Package every HTTP/gRPC/JSON-RPC/event/metric integration and prove advertised endpoints/ports/configs from a clean install.  
  **dependencies[]:** `["C006.V","C021.V","C024.V","C025.V","C026.V","C027.V"]`
- [ ] **C028.09** Publish the release-artifact trust contract and signed release manifest binding the release identity/version to every binary, container image digest, configuration bundle, native library/resource and parameter package digest; attach SBOM and build-provenance attestations; define out-of-band trust-anchor provisioning, signer scope, threshold if used, rotation/revocation, algorithm/version agility and offline verification.  
  **dependencies[]:** `["C006.V","C021.V","C024.V","C025.V","C026.V","C027.V","C000.02","C000.07","C000.14","C028.01"]`
- [ ] **C028.10** Execute clean-install artifact-authentication drills on every supported C000.14 platform row: accept the authentic signed manifest and exact artifacts; reject missing, malformed, mismatched, unknown-key, expired-policy and revoked-key signatures, substituted mirror bytes, detached SBOM/provenance, and mixed-release bundles before execution or installation mutation.  
  **dependencies[]:** `["C006.V","C021.V","C024.V","C025.V","C026.V","C027.V","C028.09"]`
- [ ] **C028.V** Command/drill manifest passes on every C000.14 supported matrix row with artifact/run hashes, final roots, rollback target, snapshot trust-store/signature/freshness/anti-rollback and resync assertions, plus release-manifest signature, artifact digest, SBOM/provenance and clean-install authentication evidence.  
  **dependencies[]:** `["C028.01","C028.02","C028.03","C028.04","C028.05","C028.06","C028.07","C028.08","C028.09","C028.10"]`

## C029 — Java test-surface mapping and regression closure

**Status:** `[ ]`  
**Derived prerequisite gates (non-executable):** `["C001.V","C002.V","C003.V","C004.V","C005.V","C006.V","C007.V","C008.V","C009.V","C010.V","C011.V","C012.V","C013.V","C014.V","C015.V","C016.V","C017.V","C018.V","C019.V","C020.V","C021.V","C022.V","C023.V","C024.V","C025.V","C026.V","C027.V","C028.V"]`  
**Commit boundary:** auditable mapping of every Java test source/fixture/ignored case and complete Rust regression corpus.

- [ ] **C029.01** Regenerate the C000 case-level Java test/resource ledger at the release revision and reject source/count drift.  
  **dependencies[]:** `["C001.V","C002.V","C003.V","C004.V","C005.V","C006.V","C007.V","C008.V","C009.V","C010.V","C011.V","C012.V","C013.V","C014.V","C015.V","C016.V","C017.V","C018.V","C019.V","C020.V","C021.V","C022.V","C023.V","C024.V","C025.V","C026.V","C027.V","C028.V"]`
- [ ] **C029.02** Reconcile each stable case ID to behavior claim, applicability decision, Rust test/fixture IDs and execution evidence; many-to-one mappings require explicit behavior decomposition.  
  **dependencies[]:** `["C001.V","C002.V","C003.V","C004.V","C005.V","C006.V","C007.V","C008.V","C009.V","C010.V","C011.V","C012.V","C013.V","C014.V","C015.V","C016.V","C017.V","C018.V","C019.V","C020.V","C021.V","C022.V","C023.V","C024.V","C025.V","C026.V","C027.V","C028.V"]`
- [ ] **C029.03** Re-home protocol/crypto/chainbase/consensus behavior currently tested from framework.  
  **dependencies[]:** `["C001.V","C002.V","C003.V","C004.V","C005.V","C006.V","C007.V","C008.V","C009.V","C010.V","C011.V","C012.V","C013.V","C014.V","C015.V","C016.V","C017.V","C018.V","C019.V","C020.V","C021.V","C022.V","C023.V","C024.V","C025.V","C026.V","C027.V","C028.V"]`
- [ ] **C029.04** Make ignored shielded/VM/benchmark cases explicit covered, benchmark-only, or blocker-owned; never silently drop.  
  **dependencies[]:** `["C001.V","C002.V","C003.V","C004.V","C005.V","C006.V","C007.V","C008.V","C009.V","C010.V","C011.V","C012.V","C013.V","C014.V","C015.V","C016.V","C017.V","C018.V","C019.V","C020.V","C021.V","C022.V","C023.V","C024.V","C025.V","C026.V","C027.V","C028.V"]`
- [ ] **C029.05** Add minimal fixture for every compatibility defect found during porting.  
  **dependencies[]:** `["C001.V","C002.V","C003.V","C004.V","C005.V","C006.V","C007.V","C008.V","C009.V","C010.V","C011.V","C012.V","C013.V","C014.V","C015.V","C016.V","C017.V","C018.V","C019.V","C020.V","C021.V","C022.V","C023.V","C024.V","C025.V","C026.V","C027.V","C028.V"]`
- [ ] **C029.06** Enforce determinism/isolation and remove flaky sleeps/fixed ports/mutable images.  
  **dependencies[]:** `["C001.V","C002.V","C003.V","C004.V","C005.V","C006.V","C007.V","C008.V","C009.V","C010.V","C011.V","C012.V","C013.V","C014.V","C015.V","C016.V","C017.V","C018.V","C019.V","C020.V","C021.V","C022.V","C023.V","C024.V","C025.V","C026.V","C027.V","C028.V"]`
- [ ] **C029.V** Regeneration is clean and the case-level mapping has zero unexplained or evidence-free rows.  
  **dependencies[]:** `["C029.01","C029.02","C029.03","C029.04","C029.05","C029.06"]`

## C030 — Mixed-network qualification, security, and performance

**Status:** `[ ]`  
**Derived prerequisite gates (non-executable):** `["C028.V","C029.V"]`  
**Commit boundary:** qualification evidence and fixes for endurance/security/performance findings.

- [ ] **C030.01** Reproducible mixed Java/Rust multi-node harness with full, witness, fast-forward and Solidity roles.  
  **dependencies[]:** `["C030.09"]`
- [ ] **C030.02** Genesis sync, snapshot bootstrap, restart, rolling upgrade, fork/reorg, maintenance and witness rotation scenarios.  
  **dependencies[]:** `["C030.09"]`
- [ ] **C030.03** Congestion, pending pressure, slow/malformed peers, disconnect/ban/reconnect and discovery/DNS failures.  
  **dependencies[]:** `["C030.09"]`
- [ ] **C030.04** gRPC/HTTP/JSON-RPC/event load and size/rate/resource exhaustion scenarios.  
  **dependencies[]:** `["C030.09"]`
- [ ] **C030.05** State/root/head/solid/PBFT/API/event convergence monitor throughout soak.  
  **dependencies[]:** `["C030.09"]`
- [ ] **C030.06** Parser, crypto/key, unsafe/FFI, plaintext deployment, dependency and release-artifact supply-chain security review using C000.07 severity, closure, exception, expiry and reopen policy; verify signed release-manifest trust anchors, rotation/revocation, offline verification and substitution rejection evidence.  
  **dependencies[]:** `["C030.09"]`
- [ ] **C030.07** License/provenance approval for source, schemas, generated code, crates, parameters, fixtures, binaries, containers, configuration bundles and native resources; reconcile every shipped digest to the signed release manifest, SBOM and build-provenance attestations.  
  **dependencies[]:** `["C030.09"]`
- [ ] **C030.08** Performance parity budget for sync, execution, block processing, API latency, memory, disk and startup; optimize only with unchanged oracle output.  
  **dependencies[]:** `["C030.09"]`
- [ ] **C030.09** Before qualification, freeze the release-gate specification: exact versions/config/topology/workloads, numeric duration/block/maintenance/fork minima, sampling frequency, zero/tolerance invariants, performance budgets, C000.07 policy/approvers, clean-environment definition, evidence hashes/retention/expiry and rerun triggers.  
  **dependencies[]:** `["C000.07","C000.13","C028.V","C029.V"]`
- [ ] **C030.V** Sustained soak has no divergence, limits hold and budget is approved; no unresolved critical/high finding exists and every medium/low finding has a recorded approved unexpired disposition.  
  **dependencies[]:** `["C030.01","C030.02","C030.03","C030.04","C030.05","C030.06","C030.07","C030.08","C030.09"]`

## C031 — Split final review and release compatibility

**Status:** `[ ]`  
**Derived prerequisite gates (non-executable):** `["C030.V"]`  
**Commit boundary:** final review fixes, complete release evidence, and readiness declaration.

- [ ] **C031.01** Complete the finite protocol/protobuf/crypto review manifest with named independent reviewers, scope rows, findings, fixes, reruns and closure.  
  **dependencies[]:** `["C030.V"]`
- [ ] **C031.02** Complete the finite storage/state/snapshot/trie review manifest, including snapshot trust-store and storage↔fork rollback seams.  
  **dependencies[]:** `["C030.V"]`
- [ ] **C031.03** Complete the finite TVM/actuator/transaction-pipeline review manifest, including DR-004 descriptor→registry→pipeline seams.  
  **dependencies[]:** `["C030.V"]`
- [ ] **C031.04** Complete the finite DPoS/PBFT/block/fork review manifest, including network→consensus dispatch seams.  
  **dependencies[]:** `["C030.V"]`
- [ ] **C031.05** Complete the finite P2P/discovery/sync/relay review manifest, including transport→application and network→consensus seams.  
  **dependencies[]:** `["C030.V"]`
- [ ] **C031.06** Complete the finite gRPC/HTTP/JSON-RPC/events/metrics/ops/toolkit review manifest, including API→cursor and snapshot→packaging seams.  
  **dependencies[]:** `["C030.V"]`
- [ ] **C031.07** Complete the finite security/unsafe/FFI/license/distribution review manifest and secondary review of every cross-domain seam.  
  **dependencies[]:** `["C030.V"]`
- [ ] **C031.08** Final G-WIRE, G-CRYPTO, G-STATE, G-TVM and G-CONSENSUS records cite exact current evidence runs with complete case outcomes.  
  **dependencies[]:** `["C030.V"]`
- [ ] **C031.09** Final G-P2P and mixed Java/Rust full-sync/propagation/reorg records cite exact current scenario runs.  
  **dependencies[]:** `["C030.V"]`
- [ ] **C031.10** Final G-API and HEAD/SOLIDITY/PBFT cursor records cite RPC/HTTP/JSON-RPC and standalone-Solidity exposure manifest rows and current run IDs.  
  **dependencies[]:** `["C030.V"]`
- [ ] **C031.11** Final G-FORMAT records cite current migration/rollback/Java-rejection/resync/snapshot trust-store, revoked/rotated-key, stale-signature and rollback-height drill IDs.  
  **dependencies[]:** `["C030.V"]`
- [ ] **C031.12** Final G-OPS, G-ARCH, G-SEC, G-LICENSE and G-ENDURANCE records cite clean-environment run IDs and immutable evidence hashes, including signed release-manifest verification, exact artifact/SBOM/provenance binding, trust-anchor rotation/revocation, offline verification and substituted-channel rejection on every supported platform row.  
  **dependencies[]:** `["C030.V"]`
- [ ] **C031.13** Phase-one terminal-closure validation: freshly derive parents and validate every record except the explicitly fixed terminal set `{C031.13, C031.V}`; require zero `[ ]`, `[-]`, invalid `[D]`, stale evidence/approval, open review finding, unapproved lower-severity disposition, dependency/adoption/custom-extension/scope/ledger gap in the validated set. Record command, run ID, immutable result/stdout/stderr hashes and the exact exclusion set; completion of this item is authorized only by that passing artifact.  
  **dependencies[]:** `["C031.01","C031.02","C031.03","C031.04","C031.05","C031.06","C031.07","C031.08","C031.09","C031.10","C031.11","C031.12"]`
- [ ] **C031.V** Depend on C031.13 and every C031 substantive child. After C031.13 is valid, deterministically produce a canonical candidate snapshot with every ordinary record and C031.13 valid and C031.V proposed `[x]`, but with no C031.V evidence edge to the validating run or terminal receipt. An authenticated compare-and-swap committer outside the tracker record graph must verify and atomically commit that exact candidate, then emit an externally stored receipt binding the candidate digest, repository revision, committed C031.V state, signer/tool identity, validation/commit timestamps, and final tracker digest. Final validity derives only from verifying that receipt against the checked-in revision and tracker; mismatch or stale-base failure invalidates closure.  
  **dependencies[]:** `["C031.01","C031.02","C031.03","C031.04","C031.05","C031.06","C031.07","C031.08","C031.09","C031.10","C031.11","C031.12","C031.13"]`
