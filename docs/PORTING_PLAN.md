# Complete java-tron to Rust Porting Plan

## 1. Mission and compatibility target

Build a production-grade Rust implementation of java-tron that can participate in the TRON network and replace a Java full node without changing externally observable behavior, except for the explicitly documented initial disk-format boundary below. This is a complete port, not an MVP. Completion requires compatibility in:

- protobuf and one-byte network wire formats;
- transaction, block, state-transition, hashing, signature, resource, governance, fork, DPoS, PBFT-sidecar, TVM, and error semantics;
- full/head, Solidity, and PBFT state views;
- P2P transport, discovery, admission, synchronization, propagation, timeouts, bans, relay, and backup election;
- gRPC, HTTP protobuf-JSON, JSON-RPC, events, metrics, configuration, command-line, lifecycle, and operational behavior;
- DB tooling, keystore tooling, lite/history workflows, and supported plugin/event interfaces.

The Java implementation remains the executable behavioral specification until every compatibility gate in this plan passes. Rust may use idiomatic ownership, explicit dependency injection, async I/O, and mature crates internally, but these choices must not alter observable contracts.

## 2. Explicit disk-format decision

**DR-001 — Initial Rust releases do not open or modify java-tron LevelDB/RocksDB directories.**

The Rust node will use a Rust-owned, versioned storage format. It must:

1. write a manifest containing format version, network/genesis identity, schema version, engine/backend identity, and required feature flags;
2. refuse unknown, newer, corrupted, wrong-network, or partially migrated formats with actionable errors;
3. provide atomic migrations between supported Rust format versions, with backup/rollback semantics;
4. support clean resynchronization from genesis or an independently verified Rust snapshot;
5. never silently interpret a Java directory as Rust state;
6. expose an explicit future import boundary, but not claim Java disk compatibility until a separately reviewed importer passes byte/state-root differential validation.

This decision concerns physical files only. Logical store keys, values, ordering, snapshots, rollback, state roots, transaction results, and all network/API-visible behavior must still match Java. Java DB conversion/archive behavior is specified and tested for the Java toolchain, but the initial Rust toolkit operates on Rust formats and clearly rejects Java formats.

## 3. Non-negotiable engineering rules

- Preserve every protobuf tag, enum number, misspelling, legacy alias, type URL, field presence rule, and supported unknown-field behavior.
- Preserve distinct hashes: transaction ID hashes `raw_data`; transaction Merkle leaves hash the complete serialized transaction; block IDs hash raw headers and overwrite bytes 0..7 with height; Keccak uses TRON-specific address rules; the configured SHA-256/SM3 engine must never be conflated with Keccak.
- Preserve Java-observed integer boundaries, overflow/hardening switches, floor division, ordering, time windows, and deterministic math. Do not replace compatibility behavior with “safer” semantics without a decision record.
- Model HEAD, SOLIDITY, and PBFT as separate cursors/views over state. Do not collapse them.
- Preserve speculative pending-state sessions and block/fork commit, merge, revoke, and replay behavior.
- Replace implicit Spring/static initialization with an explicit dependency graph and deterministic startup/shutdown order.
- Every chunk must be independently reviewable, verifiable, and committable. A chunk cannot merge with failing acceptance gates or undocumented compatibility differences.
- No actionable item may be marked deferred. Deferral is reserved for genuinely external blockers and must include an owner, reason, unblock condition, and decision record.

## 4. Tracker and execution model

`docs/PORTING_TRACKER.json` is the sole checked-in progress source. It contains ordered chunks C000 through C031; each chunk contains its stable substantive items, its preserved `.V` gate, ordinary review findings, and an optional external blocker. Status views are generated on demand with `python3 tools/tracker/validate.py --status` and `--next`; no checked-in checklist duplicates tracker state.

Chunks execute strictly in order. Completed chunks form a contiguous prefix, at most the first unfinished chunk may be active, under review, or externally blocked, and every later chunk remains `todo`. C001-C031 retain every approved item ID, gate ID, title, task boundary, chunk boundary, and commit boundary. Earlier chunk completion replaces the old item-level dependency graph.

Items are `todo`, `doing`, or `done`. Chunk states are `todo`, `active`, `review`, `blocked`, and `done`. A blocker is used only for a genuinely external dependency and records a reason and observable unblock condition. Active, review, and blocked chunks name an owner and a concrete resume action.

Each gate is an ordered list of ordinary commands stored as argument arrays with repository-relative working directories and bounded timeouts. `python3 tools/tracker/validate.py --gate Cnnn` validates tracker structure, runs the commands in order, fails fast, and never updates status. Commands are frozen before implementation begins. Changing gate commands, fixtures, normalization rules, or acceptance text resets the gate and review state.

After all items are implemented, run the complete gate and move the chunk to review. Reviewers record concise findings with stable IDs in the chunk. An open finding requests changes; beginning a fix resets the gate; after the fix, rerun the complete gate and have the reviewer close the finding. A chunk is done only when every item is done, the gate passes, review is approved, every finding is closed, and no blocker remains. Required CI reruns the gate on the final checked-in tree; stored gate status is a resumability marker, not a separate proof system.

Implementation, finding fixes, and the final tracker-only completion update use ordinary commits. Protected-branch review and required CI provide final-tree assurance. Dependencies are pinned in manifests and lockfiles and accepted through the owning item's review and gate; no separate dependency-selection ledger is maintained. Tracker-specific evidence envelopes, independent-review manifests, governance signatures, candidate snapshots, CAS receipts, and external completion receipts are likewise not part of this process.
## 5. Differential-oracle strategy

### 5.1 Oracle harness

Create version-pinned Java and Rust runners using one versioned machine-readable fixture/result schema. The schema defines canonical byte encoding; ordering; null/absent/presence rules; logical initial state and deltas; errors; logs/events; source/toolchain identity; expected outputs; and a centrally reviewed, closed normalization allowlist. Normalize only listed nondeterministic metadata such as ephemeral ports, process IDs, or logging prefixes; consensus, state, API and protocol fields can never be fixture-local normalization choices. C000 must prove positive and negative execution plus deliberate mismatch detection for output, state, error and forbidden normalization.

### 5.2 Required oracle classes

1. **Wire oracle:** byte-for-byte protobuf and P2P envelopes, enum values, `Any` type URLs, maps, unknown fields, malformed input, max sizes.
2. **Crypto oracle:** keys, 0x41 addresses, Base58Check, secp256k1 and SM2 signatures/recovery, SHA-256/SM3, Keccak, contract addresses, keystore files.
3. **State oracle:** initial state plus one operation, raw logical key/value deltas, receipt/result bytes, dynamic counters, commit and full revoke.
4. **TVM oracle:** return bytes, logs, internal transactions, created/deleted accounts, storage, energy used/penalty, exception/result mapping.
5. **Block oracle:** transaction admission/order, result comparison, Merkle root, account root, block ID/signature, rewards, maintenance, fork replay.
6. **Consensus oracle:** exact slot/witness schedule, missed slots, participation, maintenance rounding, proposal threshold, rewards, solidification, PBFT sidecar.
7. **Network oracle:** captured and live Java↔Rust external control handshake, compression, application handshake, discovery, sync, gossip, disconnect reason, timeout/ban.
8. **API oracle:** identical gRPC status/message bytes, HTTP status/body/headers, protobuf-JSON rendering, JSON-RPC result/error, cursor view, rate/size/disabled behavior.
9. **Operations oracle:** configuration precedence, CLI parsing and exit codes, startup/shutdown order, manifests/migrations, resync, metrics/events, signal handling.

Fixtures discovered during implementation are durable regression assets. Each compatibility bug adds the smallest reproducer before the fix merges.

## 6. Dependency-ordered implementation chunks

### C000 — Repository, architecture, governance artifacts, and compatibility harness contract

Before behavioral implementation, establish workspace/crate boundaries, the initial Linux x86_64 GNU build target, pinned Rust and Java toolchains and Java source revision, explicit lifecycle and cursor architecture, the fixture/result contract, Java/Rust runner protocol, DR-001, DR-004, the security and license/provenance policies, and source-derived production and case-level Java test ownership ledgers. Production ledgers cover modules/classes, protocols, actuators/extensions, stores, TVM, networking, APIs, config, resources/scripts, metrics/events/services, and toolkit commands. The test ledger includes parameterized, inherited, ignored, and assumption-gated cases. Every row retains its stable owner and acceptance gate.

C000 uses the single-source v2 tracker and establishes the ordinary review-fix loop. It retains the initial Linux x86_64 GNU platform target and reserves later platform expansion without narrowing Java protocol behavior or migration scope. Dependency versions remain in manifests and lockfiles; semantic risk is handled through design review and compatibility tests, while security, license, SBOM, provenance, and release qualification remain explicit C030 requirements.

Record DR-004 for Java custom-actuator extensibility and assign protobuf registration, owner extraction, dispatch/state, and API integration to C001/C012/C016/C022. C001 owns extension-provided descriptor/schema registration or runtime loading, full-name/type-URL and numeric `ContractType` encoding, deterministic registration order, built-in/extension and extension/extension collision rejection, and example-derived canonical bytes. The checked-in actuator example becomes an end-to-end registration→construction→broadcast→execution→state/query fixture.

The canonical C000 gate runs, in order: read-only ownership-ledger regeneration comparison; retained-artifact coherence audit; `cargo check --locked --workspace` in `rust-tron`; oracle schema/result/mismatch unit checks; the eight positive, negative, and deliberate mismatch differential cases; harness subprocess/resource checks; and Java/Rust launcher smoke checks. These are behavior-neutral harness and architecture checks, not protocol implementation.

**Gate:** retained C000 artifacts are coherent; both ownership ledgers regenerate exactly; the workspace compiles; all harness validation, differential mismatch, resource, and smoke commands pass; ordinary review is approved; every finding is closed; and no blocker remains.

### C001 — Canonical protobuf source and generated Rust surface

Vendor/synchronize all tracked canonical schemas, Google includes, generation tooling, descriptor set and services. Generate a source-revision-bound conformance manifest for every schema/message/enum/service/method, including descriptor normalization and applicable encode/decode/malformed/unknown-field/`Any`/map-order/presence/size cases. A separate DR-004 extension row defines descriptor/schema registration or runtime loading, full-name/type-URL formation, numeric `ContractType` allocation/encoding, deterministic order, duplicate/collision behavior, and canonical example-derived descriptor, `Any`, transaction-contract and malformed/collision byte fixtures.

**Gate:** normalized canonical and extension descriptor comparison and every applicable manifest case pass; generated/runtime-loaded surfaces are complete; all collision/type-URL/`ContractType` fixtures pass; inventory difference and unmapped-row counts are zero before C012/C016/C022 consume the extension.

### C002 — Deterministic primitives and canonical byte types

Implement fixed-width hashes/addresses/IDs, endian utilities, Java-compatible byte/string ordering, integer conversion, deterministic clocks, strict/legacy math helpers, Merkle algorithm, block/transaction ID primitives, and market comparator.

**Gate:** differential vectors cover empty/odd Merkle trees, BlockId height overlay/equality, Tapos slices, overflow boundaries, string/byte ordering, and both math modes.

### C003 — Configuration model, defaults, CLI, and lifecycle graph

Generate a stable source-derived inventory of every key/option, source location, domain, alias, mode and precedence edge. Port defaults, parsing, platform constraints, post-processing and lifecycle, with executable cases for defaults, invalids, clamps, sentinels, duplicate ports, precedence, exit/stdout/stderr and side effects.

**Gate:** the inventory has zero unmapped rows; every comparison case passes; lifecycle has no hidden globals or cycles.

### C004 — Core cryptography and addresses

Implement secp256k1, SM2, SHA-256/SM3 engine selection, Keccak, RIPEMD/Base58Check, recoverable signatures, low-S signing, padded historical signatures, permission signer recovery, and normal/CREATE/CREATE2 address formulas using reviewed crates.

**Gate:** fixed Java vectors match byte-for-byte in both engine modes; malformed signatures and address boundaries return equivalent categories.

### C005 — Keystore core and secure filesystem behavior

Implement Java-compatible keystore JSON/KDF/cipher/address behavior, password parsing, import/update/list/new primitives, atomic replacement, cleanup, symlink policy, and POSIX permissions.

**Gate:** Java-generated files open in Rust and Rust-generated compatible files open in Java where format is shared; malformed/corrupt/password/BOM/multiline/symlink/0600 vectors pass.

### C006 — Sapling, shielded cryptography, and parameter initialization

Replace JNI boundaries with reviewed Rust crates/FFI for the complete JLibrustzcash/JLibsodium semantic surface, parameter integrity, contexts, notes, keys, encryption, Merkle tree/path/voucher, proof verification, and external ZK service boundary.

**Gate:** all tracked Merkle fixtures and shielded vectors match; parameter hashes and failure codes match; context lifetime/concurrency/error cases are proven; ignored Java cases are either enabled or replaced by equivalent explicit coverage.

### C007 — Rust storage backend and format/version manager

Implement Rust-owned KV backend abstractions, batches, iterators, prefix/range order, checkpoints, durability, corruption handling, manifest/version/network checks, atomic migrations, backups, and clean-resync initialization. Implement exact market key comparator semantics at the logical layer.

**Gate:** DR-001 rejection behavior is tested; fresh/reopen/crash/migrate/rollback/wrong-network/corruption cases pass; ordering and batch atomicity match Java logical behavior; x86_64 and aarch64 supported backends pass.

### C008 — Protobuf capsules and logical store schemas

Implement immutable/mutable wrappers and exact logical key/value codecs for every store: accounts/assets, indexes, blocks/transactions/results, dynamic properties, witnesses/votes/proposals/exchanges/markets, contracts/ABI/code/storage, delegation, shielded, trace/bloom, common, and PBFT data. Preserve leading-space and prefix quirks.

**Gate:** Java fixtures produce identical logical keys and serialized values; IDs, optimized account assets, ABI split, Tapos indexes, market/delegation keys, dynamic defaults, and all DB names are covered.

### C009 — Revoking snapshots, sessions, checkpoints, and state cursors

Implement overlay reads/writes/deletes, nested sessions, merge/commit/revoke/pop, checkpoint encoding in Rust format, recovery, flush limits, and independent HEAD/SOLIDITY/PBFT cursors.

**Gate:** exhaustive transition matrix and crash recovery pass; one operation followed by revoke restores every logical store; concurrent read cursors never observe speculative writes.

### C010 — Genesis, dynamic properties, resources, account trie, and migrations

Implement genesis creation/validation, dynamic property initialization and governance flags, resource processors/windows, asset optimization transitions, account-state MPT with TRON RLP/inlining/root rules, and Rust schema migrations that preserve logical state.

**Gate:** Java-vs-Rust genesis state, roots, counters, resource arithmetic, optimization transitions, and supplied-root rejection match across representative fork configurations.

### C011 — Fork graph and chain selection foundation

Implement Khaos-style in-memory linked/unlinked fork graph, main-chain indexing, branch discovery, removal, limits, parent handling, and fork controller version activation/statistics.

**Gate:** fork graph tests cover linked/unlinked/orphan/replacement/eviction; Java differential fixtures match branch paths and activation decisions.

### C012 — Non-VM transaction actuators: accounts, permissions, assets, witnesses

Implement validation/execution/result behavior for account create/update/id/permission, TRX transfer, asset issue/update/transfer/participation/unfreeze, witness create/update/vote, fees, auto-account creation, indexes, and permissions.

**Gate:** per-contract state-delta/revoke/error-boundary oracle passes for every contract type in scope.

### C013 — Non-VM transaction actuators: resources, governance, exchange, and market

Implement legacy/V2 freeze/unfreeze/withdraw/cancel, delegation/undelegation, proposals, exchanges, brokerage, and market orders/matching/cancel with feature switches and historical arithmetic.

**Gate:** every contract type and fork flag matrix has Java differential state/result fixtures; market max-20 matching, linked lists, normalized prices, and overflow modes match.

### C014 — TVM repository, interpreter, opcodes, and gas/energy

Generate a versioned TVM conformance manifest listing every registry opcode with family, fork/flag interval, input boundaries, energy formula, state effects and exception/result mapping. Implement it as bounded arithmetic/environment, memory/storage/control/log, and call/create/system/TRON family commits, each with a local differential gate.

**Gate:** every manifest row and activation/boundary class passes Java comparison; no registry or manifest difference remains and no wall-clock nondeterminism enters results.

### C015 — TVM precompiles, native contracts, and shielded execution

Implement all precompiles (including BN128, Blake2f, P256), TRON native system contracts, shielded verification, energy schedules, and activation flags.

**Gate:** 782 P256 records pass with exact 6900 gas; every precompile has malformed/boundary/success/failure vectors; independently licensed replacement covers Freeze fixture behavior.

### C016 — Transaction admission, trace, billing, and pending pool

Implement Tapos, expiration/size/duplicate checks, signature/permission checks, one-contract rule, unknown-field sanitization, bandwidth/multisig/memo fees, runtime dispatch, energy billing, `TransactionInfo`, pending speculative session, requeue, and broadcast admission results.

**Gate:** full pipeline differential oracle compares result bytes and every logical state delta; retry-on-out-of-time and witness-result mismatch match; pending revoke/requeue leaves no leaked state.

### C017 — DPoS scheduling, maintenance, rewards, proposals, and solidification

Implement 3-second slots, witness scheduling/shuffle/order quirks, production eligibility, participation, missed slots, maintenance, vote updates, rewards, proposal application, hard-fork activation, 70% solidification, and block production interfaces.

**Gate:** fixed-clock 27-witness simulations match Java over maintenance/fork boundaries; reward and dynamic-property deltas are byte-identical.

### C018 — PBFT auxiliary protocol and backup election

Implement PBFT message construction/signature/quorum/expiry/dedup/forward/persistence/SRL behavior without changing DPoS selection, plus witness-backup UDP allowlist, keepalive, priority/IP election, MASTER/SLAVER behavior.

**Gate:** Java differential fixtures and real UDP tests match message bytes, quorum, stores, timeouts, and election transitions.

### C019 — Block manager, processing, fork switch, and event rollback hooks

Implement block validation/production/application, transaction ordering/results, Merkle/account roots, rewards, recent indexes, fork switch/replay with signature-cache invalidation, pending suspension/requeue, and reorg removed/reapply hooks.

**Gate:** multi-branch differential scenarios match final logical state, roots, events, and head/solid/PBFT views; failed fork replay atomically restores the old branch.

### C020 — External P2P transport and discovery compatibility

Reproduce libp2p 2.2.9-observed TCP varint framing, 5 MiB limit, negative control bytes, external Connect schemas/handshake/admission, snappy envelope, keepalive/read timeout, bans, connection pool, node detection, UDP Kademlia raw envelope, DNS trees, and persistence. Treat the binary dependency as a black-box oracle.

**Gate:** packet captures and live Java↔Rust tests prove active/passive handshakes, compressed/uncompressed exchange, malformed limits, UDP discovery, DNS resolution, admission, reconnect bans, and shutdown. Ambiguous UDP framing is resolved by captured behavior, not assumption.

### C021 — Application P2P handshake, peers, sync, gossip, relay, and handlers

Implement positive application message bytes, Hello policy, fixed `0xC0` ping/pong, peer state/caches/rate limits, sparse chain summary, inventory/fetch/sync ordering, advertisement, transaction/block handlers, fast-forward relay, timeouts, disconnect mapping, and PBFT wire input.

**Gate:** deterministic handler tests plus two-way Java↔Rust full sync and propagation pass; ordinary and fast-forward paths are separate gates; disconnect reasons and timeout/ban layering match.

### C022 — Wallet/domain service and gRPC APIs

Use the descriptor-derived RPC inventory and bounded account/asset/witness/governance, transaction/contract/shielded, and chain/resource/market/node families. Each case specifies request bytes, state/cursor checkpoint, status/message/error comparison and limit schedule. Include DR-004 custom-actuator construction/exposure.

**Gate:** every RPC inventory row and boundary case passes its named command or scenario; no unmapped method remains.

### C023 — HTTP protobuf-JSON APIs

Generate the servlet route inventory and implement bounded wallet query, transaction/contract/shielded, chain/resource/market, Solidity/PBFT/net/monitor families. Define included/excluded headers, exact body/status/error comparison, controlled clock and concurrency/rate schedules.

**Gate:** every route row and boundary case passes its named command or scenario; no unmapped route remains.

### C024 — JSON-RPC and filters

Generate the interface-derived method inventory and implement bounded web3/net/chain/state, call/transaction/receipt, and filter/log families, including deliberate unsupported/null/zero behavior. Cases define request, checkpoint, exact result/error, batch/limit/concurrency and controlled expiry.

**Gate:** every method/error/activation row passes; no accidental Ethereum surface or unmapped row remains; reorg behavior passes.

### C025 — Events, plugins, metrics, node info, and operational services

Implement event/plugin/ZeroMQ/lifecycle behavior after gRPC, HTTP and JSON-RPC are available. Generate metric/event/service inventories and define sample windows, label sets, float/counter tolerances, API-specific interceptors, event ordering and standalone state checkpoints.

**Gate:** zero inventory gaps; live event, metric, API-integration, lifecycle, and failure scenarios pass.

### C026 — Standalone Solidity node and remote replication

Implement trust-node-required no-P2P replication with explicit checkpoint heights and matching service inventory.

**Gate:** cross-language replication reaches declared heights/roots and the exact service/API inventory matches.

### C027 — Toolkit and operational data workflows

Preserve a pinned Java-toolkit reference obligation separately from Rust-format tooling. Inventory and execute Java `db convert/archive/cp/lite/mv/root` command/options/errors on non-destructive fixtures, including architecture/backend restrictions, and map each row to retained-reference behavior, Rust equivalent, or reviewed non-applicability under DR-001. The Rust command manifest records inputs, exit/stdout/stderr, filesystem mutations/hashes, fault points and Java-directory no-write assertions.

**Gate:** the Java reference matrix and Rust command/drill manifest pass per command and platform.

### C028 — Packaging, deployment, observability, rollback, snapshot, resync, and release-artifact authentication

Package only after every advertised API and operational integration is gated. Define the supported OS/architecture/backend matrix, numeric resource limits and exact clean-install command/drill manifest. The snapshot trust contract includes an out-of-band trust store: anchor provisioning, signer authorization scope, key rotation/revocation, signature algorithm/version agility, offline verification, network checkpoint and operator-selected minimum acceptable height independent of snapshot metadata, and explicit clock/freshness failure behavior. It also requires authenticated provenance, identity/version/height, trusted block/state-root binding, completeness/replay/anti-rollback checks, atomic staging/interruption cleanup and resync fallback.

Separately, the release-artifact trust contract authenticates what operators install. A signed release manifest binds release identity/version to every binary, container image digest, configuration bundle, native library/resource and parameter package digest, with attached SBOM and build-provenance attestations. Trust anchors are provisioned out of band and support scoped authorization, rotation/revocation, algorithm/version agility and offline verification. Clean-install drills on every supported platform accept only the authentic complete bundle and reject missing/invalid/revoked signatures, unknown keys, digest substitution, mirror tampering, detached or mismatched SBOM/provenance, and mixed-release artifacts before execution or installation mutation.

**Gate:** install, endpoint exposure, sync/snapshot/migrate/rollback/resync, snapshot trust-store lifecycle, signature/freshness/rollback failures, release-manifest authentication, artifact/SBOM/provenance binding, release trust-anchor rotation/revocation/offline verification, substituted-channel rejection, signal, disk/corruption, and restart drills pass on every matrix row with expected hashes and roots.
### C029 — Complete Java-suite mapping and differential regression closure

Regenerate the C000 case-level test/resource ledger at the release revision and reject drift. Reconcile each stable case ID to its behavior claim, applicability decision, Rust fixture/test IDs, and passing regression command; many-to-one mappings require explicit decomposition. This is final zero-gap reconciliation, not first discovery.

**Gate:** regeneration is clean and no case is unexplained, untested, or silently omitted.

### C030 — Multi-node endurance, security, supply-chain, and performance qualification

Before execution, freeze the release-gate specification with exact versions/config/topology/workloads, numeric duration/block/maintenance/fork minima, sampling frequency, zero/tolerance invariants, performance baselines/budgets, security severity and closure policy, license authorities, and clean-environment definition. `C030.09` owns this specification and must be completed before the governed C030.01-C030.08 qualification scenarios run.

Security and license/provenance qualification includes release-artifact supply-chain review: signed release-manifest trust anchors and lifecycle, exact shipped-digest reconciliation, SBOM/provenance attachment, offline verification, compromised-channel substitution rejection, and clean-install checks for every supported platform row.

**Gate:** every specified scenario passes; release artifacts authenticate and reconcile on every supported platform; no high-severity security or unresolved license finding remains.
### C031 — Final review and release compatibility gate

Perform ordinary domain and cross-boundary review on the current tree, covering protocol/crypto, storage/state/rollback, TVM/execution, consensus/forks/PBFT, networking, APIs/operations, packaging/snapshots/release authentication, and the seams between them. Findings are recorded directly in `C031.review.findings`, fixed with ordinary commits, and closed only after the complete affected gate is rerun.

Run the final current-tree regression and qualification commands for every compatibility domain, operational workflow, supported platform, security/license requirement, supply-chain control, and product authentication contract. `C031.13` is the full release check over all C000-C031 items, gates, inventories, fixtures, and cross-domain seams.

C031 deliberately retains all substantive domain and release reviews, security and license qualification, and product-authentication requirements. It intentionally discards tracker-specific evidence envelopes and CAS receipt machinery as redundant with ordinary review, gates, and required CI; ordinary signed release artifacts and the C028-C030 authentication controls remain required.

**Gate:** the full current-tree release check passes, ordinary domain and seam review is approved, every finding is closed, every prior chunk remains done on the current tree, and no blocker remains. C031 completes through the same tracker-only completion commit and required CI gate rerun as every other chunk; there is no special tracker candidate, evidence-envelope, or CAS receipt protocol, while ordinary signed release artifacts remain required.
## 7. Acceptance gate catalog

- **G-WIRE:** descriptor and byte-level protobuf/P2P compatibility.
- **G-CRYPTO:** deterministic fixed vectors in secp/SHA-256 and SM2/SM3 modes.
- **G-STATE:** raw logical key/value deltas, roots, sessions, rollback, and reopen.
- **G-TVM:** opcode/precompile/runtime/result/energy conformance.
- **G-CONSENSUS:** slots, schedules, maintenance, rewards, solidification, forks, PBFT sidecar.
- **G-P2P:** live bidirectional Java↔Rust handshake, discovery, sync, gossip, relay, disconnect.
- **G-API:** gRPC/HTTP/JSON-RPC route and behavior matrix including limits/errors/cursors.
- **G-OPS:** config/CLI/lifecycle/events/metrics/Solidity/toolkit/packaging.
- **G-FORMAT:** Rust manifest, migrations, rollback, snapshots, rejection of Java formats, clean resync.
- **G-ARCH:** builds and runtime drills on every currently supported platform row; later x86_64/aarch64 or OS expansion requires explicit enablement and native evidence.
- **G-SEC:** parser/resource/key/deployment security review.
- **G-LICENSE:** source, fixtures, generated code, crates, parameters, and distribution approval.
- **G-ENDURANCE:** mixed-version/mixed-language multi-node soak with no state divergence.

## 8. Decision and risk register

| ID | Decision/risk | Required treatment |
|---|---|---|
| DR-001 | Java physical DB format initially unsupported | Rust manifest/versioning/migrations/resync; reject Java directories unchanged. |
| DR-002 | Java behavior is oracle, including quirks | Preserve observed behavior unless a reviewed compatibility-break record proves network safety. |
| DR-003 | Mature crates may replace plumbing | Review exact version/features, alternatives, semantic gaps/adapters, determinism/serialization, unsafe/FFI, platforms, maintenance/security/license/provenance, and replacement/rollback path in the consuming change. Reject candidates unable to meet exact observable semantics or supported targets. |
| DR-004 | Custom-actuator extensions are a supported compatibility surface | Preserve discovery/registration, custom protobuf type, owner extraction, dispatch/state/API integration; prove with the checked-in example-derived end-to-end fixture. |
| R-001 | Protobuf reserialization changes hashes | Complete protocol manifest and golden bytes for raw/full transactions, headers, maps, `Any`, unknown fields. |
| R-002 | Binary-only libp2p behavior | Pinned black-box captures and scenario-manifested live mixed-node tests. |
| R-003 | Static globals/implicit Spring order | Explicit dependency graph, immutable config snapshots, deterministic lifecycle tests. |
| R-004 | HEAD/SOLIDITY/PBFT collapse | Separate typed cursors and concurrency tests. |
| R-005 | Pending/fork state leaks | Complete session-transition and branch-failure manifests. |
| R-006 | Math/overflow/time divergence | Java differential boundary vectors and fixed clocks. |
| R-007 | SHA-256/SM3/Keccak confusion | Distinct types/APIs and dual-engine vectors. |
| R-008 | Mature EVM/MPT/crypto/storage/API crates differ from TRON | Normal design review, pinned manifests/lockfiles, conformance wrappers, rollback ownership, and zero-gap gates. |
| R-009 | Shielded ABI, native resources, parameters and licenses | Threat model, integrity/provenance approval, bounded FFI and no silent disablement. |
| R-010 | Fast-forward bypass changes security | Separate ordinary/fast-forward scenarios and minimum-depth gates. |
| R-011 | API error/limit/metric differences | Closed inventories, exact comparison policies and numeric concurrency/sample schedules. |
| R-012 | Event/filter reorg semantics lost | Removed/reapply fixtures, ordering, and checkpoint assertions. |
| R-013 | GPL/LGPL/Apache/UNLICENSED conflicts | Early and final provenance review; legal-guided clean-room procedure for Freeze replacement. |
| R-014 | Mutable CI/external artifacts | Pin toolchains, Java binary, images, captures, and retained release inputs needed to reproduce qualification. |
| R-015 | Migration corruption or unusable operational rollback | Atomic migration plus executable/config retention, point-of-no-return, downgrade safety and clean-resync fallback. |
| R-016 | Untrusted/stale snapshots | Authenticated provenance, trusted root/height, completeness, freshness/anti-rollback and atomic import. |
| R-017 | Resource exhaustion/plaintext exposure discovered late | C000 threat model, per-parser/API numeric limits, deployment guidance and adversarial qualification. |
| R-018 | Packaging omits API, native resource, or authentic release binding | Explicit C024/C025 dependency, package inventory, signed release manifest binding all shipped digests plus SBOM/provenance, out-of-band trust-anchor lifecycle, and clean-install endpoint/resource/authentication drills. |

New compatibility decisions use the next `DR-###`, and risks use the next `R-###`. Decisions state context, options, selected behavior, and compatibility impact. Dependency selections are reviewed in the normal design and compatibility-test flow and pinned in manifests or lockfiles.

## 9. Commit and review policy

Commit boundaries are sequential and clean. C000 architecture and harness artifacts land before behavioral work. Each later chunk is one logical commit series, and each stable item remains independently reviewable and committable within its existing boundary. Generated source may share a commit only with reproducible generation. Never combine unrelated protocol, storage, consensus, networking, or API changes.

For each chunk: implement its items in tracker order; run the stored gate commands; enter ordinary review; record findings in the tracker; fix findings in focused commits; reset and rerun the complete gate after fixes; close every finding; obtain approval; then make an ordinary tracker-only commit marking the chunk done. Any later change that affects a completed chunk's behavior or gate must reopen the affected gate and review before dependent work continues.

## 10. Definition of complete

The Rust port is complete only when every C000-C031 item is done in the preserved sequence, every chunk gate passes on the final checked-in tree, every chunk review is approved with all findings closed, all ownership inventories and differential fixtures are reconciled, all supported-platform and operational drills pass, and no blocker remains. C028-C030 snapshot and release-artifact authentication, SBOM/provenance, trust-anchor lifecycle, offline verification, substituted-channel rejection, endurance, security, license, and performance requirements remain product acceptance requirements. Required CI reruns the C031 gate on the final completion commit.
