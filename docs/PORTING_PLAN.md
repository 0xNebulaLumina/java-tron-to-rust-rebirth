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

## 4. Tracker semantics and durable evidence

The checklist is a human-reviewed projection of the versioned machine-readable `docs/PORTING_TRACKER.json`. Every substantive item and every `.V` gate is a record with stable `id`, literal explicit `dependencies[]`, `status`, derived `readiness`, owner, branch/PR, evidence, blocker fields, decision/adoption records, and `last_updated`. The checked-in checklist dependency projection and tracker must round-trip with no added, missing, or changed record or edge. `dependencies[]` contains stable substantive or `.V` item IDs only—never prose, bare chunk IDs, ranges, or partial “includes” annotations. Parent/chunk prerequisites and status are derived metadata, not executable dependencies. `ready` means, exactly, that every referenced record is `[x]`, its required evidence and approvals are valid and non-stale, and no rerun/reopen trigger is active; otherwise readiness is `blocked`. Empty `dependencies[]` is allowed only for graph roots. CI rejects unknown, duplicate, self, and cyclic edges, verifies every `.V` directly depends on every substantive child it closes, and checks mandatory governed-work edges such as `C015.07→C015.05` and `C030.09→C030.01` through `C030.08`.

Execution states are `[ ]` not started, `[-]` in progress, `[x]` complete, and `[D]` externally blocked. `[-]` requires active ownership, branch/PR, timestamp, and current evidence. `[x]` requires all dependencies ready, passing evidence, required adoption approvals, and review. `[D]` requires a genuinely external blocker, owner, immutable blocker evidence, unblock condition, decision record, and validity review; an invalid or now-doable deferral is a release failure. Parent chunk state is freshly derived from every substantive child and its `.V` gate and is never independently edited.

Each evidence record is immutable and contains: evidence-schema version; command and normalized environment/toolchain identity; run ID; stable case/scenario IDs; start/end timestamps; observed exit code and status; declared expected result/hash; observed result or result hash; stdout and stderr artifact paths and SHA-256 hashes; all other artifact paths/hashes; and a per-case `pass|fail|skip` outcome with any approved skip disposition. CI reruns the declared comparison, rejects absent cases, unapproved skips, failures, expectation mismatches, unreachable/hash-mismatched artifacts, and prevents `[x]` from citing a different run. Source, fixture, schema, config, dependency, toolchain, generator, normalization-policy, expected-output, or command changes invalidate affected evidence through declared coverage and rerun-trigger edges until an exact replacement run is recorded.

Checked-in manifests and ledgers are finite, versioned artifacts bound to exact source and tool revisions. Rows use stable IDs and include source location, owning item, acceptance case IDs, disposition, and dependency/adoption references. Generation commands and zero-difference checks are part of the owning gate. Recurring dependency/security/license adoption is represented by inventory instances owned by consuming items; completing the C000 policy tasks cannot pre-approve later integrations.

Independent-review manifests are also finite records: domain/scope-row IDs (including cross-domain seams), covered source/config/schema/toolchain revisions and artifact hashes, named reviewer identity, author/reviewer separation and conflict/recusal statement, stable finding IDs, severity, disposition, fix revision, required rerun IDs, closure reviewer/date, and approval. Any covered change or rerun/reopen trigger invalidates the affected approval and evidence. Approval requires zero open findings, post-fix reruns and re-review, no unresolved critical/high finding, and an approved, reasoned, expiring disposition for every lower-severity finding.
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

Before behavioral implementation, establish workspace/crate boundaries, supported targets, pinned Rust/Java toolchains and source revision, tracker/fixture/evidence/review schemas, early security threat model and license/provenance policy, dependency/adoption records, and source-derived production/test ledgers. Production ledgers cover modules/classes, protocols, actuators/extensions, stores, TVM, networking, APIs, config, resources/scripts, metrics/events/services and toolkit commands. The test ledger is case-level, including parameterized/inherited/ignored/assumption-gated cases. Every row receives an owner and gate before its implementation starts.

The threat/review policy defines critical/high/medium/low classification, release-blocking rules, remediation expectations, authorized residual-risk acceptors, mandatory rationale/evidence, expiry, and rerun/reopen triggers. C000 establishes policy and schemas only. A generated dependency/adoption inventory registers each later crate, tool, native/FFI component, schema source, fixture, and parameter against its consuming item; that item's explicit dependencies and local gate require its `DD-###` plus security/license approval, and CI rejects unregistered adoption.

Record DR-004 for Java custom-actuator extensibility and assign protobuf registration, owner extraction, dispatch/state and API integration to C001/C012/C016/C022. C001 owns extension-provided descriptor/schema registration or runtime loading, full-name/type-URL and numeric `ContractType` encoding, deterministic registration order, built-in/extension and extension/extension collision rejection, and example-derived canonical bytes. The checked-in actuator example becomes an end-to-end registration→construction→broadcast→execution→state/query fixture.

The machine tracker contains an explicit `dependencies[]` array for every item. Chunk order remains sequential at each `.V` boundary, but tracker-declared family items may proceed after their exact prerequisite contracts rather than unrelated siblings; such exceptions are finite and enumerated, never inferred from prose. The early platform manifest enumerates every supported OS/architecture/backend/feature row, marks native versus cross-built/emulated execution, and continuously runs applicable compile, differential/unit, native-resource, FFI and smoke checks.

**Gate:** validators report zero unowned production/test/adoption rows; checklist and tracker dependencies round-trip exactly with no unknown/self/cycle; architecture, threat/review policy, license/provenance policy and all currently introduced adoption instances are approved; every platform row has current evidence; both runners pass canonical positive/negative fixtures and intentional mismatch detection.

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

**Gate:** packet captures and live Java↔Rust tests prove active/passive handshakes, compressed/uncompressed exchange, malformed limits, UDP discovery, DNS resolution, admission, reconnect bans, and shutdown. Ambiguous UDP framing is resolved by recorded evidence, not assumption.

### C021 — Application P2P handshake, peers, sync, gossip, relay, and handlers

Implement positive application message bytes, Hello policy, fixed `0xC0` ping/pong, peer state/caches/rate limits, sparse chain summary, inventory/fetch/sync ordering, advertisement, transaction/block handlers, fast-forward relay, timeouts, disconnect mapping, and PBFT wire input.

**Gate:** deterministic handler tests plus two-way Java↔Rust full sync and propagation pass; ordinary and fast-forward paths are separate gates; disconnect reasons and timeout/ban layering match.

### C022 — Wallet/domain service and gRPC APIs

Use the descriptor-derived RPC inventory and bounded account/asset/witness/governance, transaction/contract/shielded, and chain/resource/market/node families. Each case specifies request bytes, state/cursor checkpoint, status/message/error comparison and limit schedule. Include DR-004 custom-actuator construction/exposure.

**Gate:** every RPC inventory row and boundary case has a passing run ID; no unmapped method remains.

### C023 — HTTP protobuf-JSON APIs

Generate the servlet route inventory and implement bounded wallet query, transaction/contract/shielded, chain/resource/market, Solidity/PBFT/net/monitor families. Define included/excluded headers, exact body/status/error comparison, controlled clock and concurrency/rate schedules.

**Gate:** every route row and boundary case passes with a run ID; no unmapped route remains.

### C024 — JSON-RPC and filters

Generate the interface-derived method inventory and implement bounded web3/net/chain/state, call/transaction/receipt, and filter/log families, including deliberate unsupported/null/zero behavior. Cases define request, checkpoint, exact result/error, batch/limit/concurrency and controlled expiry.

**Gate:** every method/error/activation row passes; no accidental Ethereum surface or unmapped row remains; reorg behavior passes.

### C025 — Events, plugins, metrics, node info, and operational services

Implement event/plugin/ZeroMQ/lifecycle behavior after gRPC, HTTP and JSON-RPC are available. Generate metric/event/service inventories and define sample windows, label sets, float/counter tolerances, API-specific interceptors, event ordering and standalone state checkpoints.

**Gate:** zero inventory gaps; live event, metric, API-integration, lifecycle and failure cases pass with run IDs.

### C026 — Standalone Solidity node and remote replication

Implement trust-node-required no-P2P replication with explicit checkpoint heights and matching service inventory.

**Gate:** cross-language replication reaches declared heights/roots and the exact service/API inventory matches.

### C027 — Toolkit and operational data workflows

Preserve a pinned Java-toolkit reference obligation separately from Rust-format tooling. Inventory and execute Java `db convert/archive/cp/lite/mv/root` command/options/errors on non-destructive fixtures, including architecture/backend restrictions, and map each row to retained-reference behavior, Rust equivalent, or reviewed non-applicability under DR-001. The Rust command manifest records inputs, exit/stdout/stderr, filesystem mutations/hashes, fault points and Java-directory no-write assertions.

**Gate:** the Java reference matrix and Rust command/drill manifest pass per command and platform with immutable run evidence.

### C028 — Packaging, deployment, observability, rollback, snapshot, resync, and release-artifact authentication

Package only after every advertised API and operational integration is gated. Define the supported OS/architecture/backend matrix, numeric resource limits and exact clean-install command/drill manifest. The snapshot trust contract includes an out-of-band trust store: anchor provisioning, signer authorization scope, key rotation/revocation, signature algorithm/version agility, offline verification, network checkpoint and operator-selected minimum acceptable height independent of snapshot metadata, and explicit clock/freshness failure behavior. It also requires authenticated provenance, identity/version/height, trusted block/state-root binding, completeness/replay/anti-rollback checks, atomic staging/interruption cleanup and resync fallback.

Separately, the release-artifact trust contract authenticates what operators install. A signed release manifest binds release identity/version to every binary, container image digest, configuration bundle, native library/resource and parameter package digest, with attached SBOM and build-provenance attestations. Trust anchors are provisioned out of band and support scoped authorization, rotation/revocation, algorithm/version agility and offline verification. Clean-install drills on every supported platform accept only the authentic complete bundle and reject missing/invalid/revoked signatures, unknown keys, digest substitution, mirror tampering, detached or mismatched SBOM/provenance, and mixed-release artifacts before execution or installation mutation.

**Gate:** install, endpoint exposure, sync/snapshot/migrate/rollback/resync, snapshot trust-store lifecycle, signature/freshness/rollback failures, release-manifest authentication, artifact/SBOM/provenance binding, release trust-anchor rotation/revocation/offline verification, substituted-channel rejection, signal, disk/corruption and restart drills pass on every matrix row with expected hashes, roots and run IDs.
### C029 — Complete Java-suite mapping and differential regression closure

Regenerate the C000 case-level test/resource ledger at the release revision and reject drift. Reconcile each stable case ID to behavior claim, applicability decision, Rust fixture/test IDs and execution evidence; many-to-one mappings require explicit decomposition. This is final zero-gap reconciliation, not first discovery.

**Gate:** regeneration is clean and no case is unexplained, evidence-free or silently omitted.

### C030 — Multi-node endurance, security, supply-chain, and performance qualification

Before execution, freeze an immutable release-gate specification with exact versions/config/topology/workloads, numeric duration/block/maintenance/fork minima, sampling frequency, zero/tolerance invariants, performance baselines/budgets, security severity and closure policy, license authorities, clean-environment definition, evidence retention/expiry and rerun triggers. C000/per-chunk reviews are the early approvals; C030 is independent requalification. `C030.09` owns this frozen specification and is an explicit dependency of every governed execution/review item `C030.01` through `C030.08`; it depends on the approved policy, packaging/authentication inputs and release-revision regression closure needed to freeze criteria before results exist.

Security and license/provenance qualification includes release-artifact supply-chain review: signed release-manifest trust anchors and lifecycle, exact shipped-digest reconciliation, SBOM/provenance attachment, offline verification, compromised-channel substitution rejection, and clean-install evidence for every supported platform row.

**Gate:** every specified scenario produces a passing run ID and immutable evidence hash; release artifacts authenticate and reconcile on every supported platform; no high-severity security or unresolved license finding remains.
### C031 — Split final review and release compatibility gates

Finite domain and cross-boundary review manifests assign every scope row and seam—including storage↔fork rollback, API↔cursor routing, snapshot↔packaging, release-manifest↔installed-artifact, and network↔consensus dispatch—to a primary and secondary independent reviewer. Reviewers approve exact revisions, artifacts and run IDs, not prose; author/reviewer separation, conflicts/recusals, finding disposition, fix revision, rerun linkage and post-fix closure are validated. Covered changes and declared rerun triggers invalidate approval and affected evidence.

Terminal closure is non-circular and uses a canonical candidate plus an authenticated external commit receipt. After `C031.13` is complete from its fixed-exclusion validation run, the terminal validator deterministically produces a canonical candidate snapshot in which every ordinary substantive and `.V` record is valid and `C031.13` is valid, and in which `C031.V` is proposed as `[x]` with no evidence edge to the terminal run or receipt. The validator hashes the complete candidate but does not authenticate or finalize it. A trusted compare-and-swap committer outside the tracker record graph then verifies the candidate and unchanged base, atomically commits that exact candidate, and emits an externally stored authenticated receipt binding the candidate digest, repository revision, committed `C031.V` state, signer and tool identity, validation/commit timestamps, and final checked-in tracker digest. Any mismatch, stale base, failed signature/trust check, or non-identical final digest aborts or invalidates closure. Final validity derives only from verification of that external receipt against the checked-in revision and tracker; `C031.V` never cites or authenticates its own validating run.

**Gate:** all split and seam reviews have complete scope coverage, independent approval, zero open findings and current post-fix reruns; no unresolved critical/high issue exists and every lower-severity issue has an approved unexpired disposition. The canonical candidate validation freshly derives parents and reports zero `[ ]`, `[-]`, invalid `[D]`, stale evidence/approval, dependency/adoption gap, or ledger gap across every ordinary substantive and `.V` record, with `C031.13` valid and `C031.V` proposed `[x]`; completion additionally requires a valid external authenticated compare-and-swap receipt whose bound revision and final tracker digest exactly match the repository.
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
- **G-ARCH:** supported x86_64/aarch64 builds and runtime drills.
- **G-SEC:** parser/resource/key/deployment security review.
- **G-LICENSE:** source, fixtures, generated code, crates, parameters, and distribution approval.
- **G-ENDURANCE:** mixed-version/mixed-language multi-node soak with no state divergence.

## 8. Decision and risk register

| ID | Decision/risk | Required treatment |
|---|---|---|
| DR-001 | Java physical DB format initially unsupported | Rust manifest/versioning/migrations/resync; reject Java directories unchanged. |
| DR-002 | Java behavior is oracle, including quirks | Preserve observed behavior unless a reviewed compatibility-break record proves network safety. |
| DR-003 | Mature crates may replace plumbing | Before implementation, create `DD-###` with exact version/features, alternatives, semantic gaps/adapters, determinism/serialization, unsafe/FFI, platforms, maintenance/security/license/provenance and replacement/rollback path. Reject candidates unable to meet exact observable semantics or supported targets. |
| DR-004 | Custom-actuator extensions are a supported compatibility surface | Preserve discovery/registration, custom protobuf type, owner extraction, dispatch/state/API integration; prove with the checked-in example-derived end-to-end fixture. |
| R-001 | Protobuf reserialization changes hashes | Complete protocol manifest and golden bytes for raw/full transactions, headers, maps, `Any`, unknown fields. |
| R-002 | Binary-only libp2p behavior | Pinned black-box captures and scenario-manifested live mixed-node tests. |
| R-003 | Static globals/implicit Spring order | Explicit dependency graph, immutable config snapshots, deterministic lifecycle tests. |
| R-004 | HEAD/SOLIDITY/PBFT collapse | Separate typed cursors and concurrency tests. |
| R-005 | Pending/fork state leaks | Complete session-transition and branch-failure manifests. |
| R-006 | Math/overflow/time divergence | Java differential boundary vectors and fixed clocks. |
| R-007 | SHA-256/SM3/Keccak confusion | Distinct types/APIs and dual-engine vectors. |
| R-008 | Mature EVM/MPT/crypto/storage/API crates differ from TRON | Pre-adoption `DD-###`, conformance wrappers, rollback owner and zero-gap manifest gates. |
| R-009 | Shielded ABI, native resources, parameters and licenses | Threat model, integrity/provenance approval, bounded FFI and no silent disablement. |
| R-010 | Fast-forward bypass changes security | Separate ordinary/fast-forward scenarios and minimum-depth gates. |
| R-011 | API error/limit/metric differences | Closed inventories, exact comparison policies and numeric concurrency/sample schedules. |
| R-012 | Event/filter reorg semantics lost | Removed/reapply fixtures, ordering and checkpoint assertions. |
| R-013 | GPL/LGPL/Apache/UNLICENSED conflicts | Early and final provenance review; legal-guided clean-room procedure for Freeze replacement. |
| R-014 | Mutable CI/external artifacts | Pin toolchains, Java binary, images and captures; hash and retain all release evidence. |
| R-015 | Migration corruption or unusable operational rollback | Atomic migration plus executable/config retention, point-of-no-return, downgrade safety and clean-resync fallback. |
| R-016 | Untrusted/stale snapshots | Authenticated provenance, trusted root/height, completeness, freshness/anti-rollback and atomic import. |
| R-017 | Resource exhaustion/plaintext exposure discovered late | C000 threat model, per-parser/API numeric limits, deployment guidance and adversarial qualification. |
| R-018 | Packaging omits API, native resource, or authentic release binding | Explicit C024/C025 dependency, package inventory, signed release manifest binding all shipped digests plus SBOM/provenance, out-of-band trust-anchor lifecycle, and clean-install endpoint/resource/authentication drills. |

New decisions use the next `DR-###`, dependency selections use `DD-###`, and risks use `R-###`. Every record states context, options, decision, compatibility impact, evidence, owner and revisit trigger.

## 9. Commit and review policy

Commit boundaries are sequential and clean. C000 governance artifacts land first as ordered behavior-neutral commits. Each later chunk is one logical commit series; bounded family subtasks may land as ordered commits only when their manifest rows and prerequisite contracts are checked, and each commit carries its local executable gate. A behavior-neutral prerequisite must prove no observable change. Generated source may share a commit only with reproducible generation. Never combine unrelated protocol, storage, consensus, network or API changes, and never close a broad parent using evidence from unfinished families.

## 9.1 Reviewer finding disposition register

No finding was discarded. The durable dispositions are:

| Finding | Disposition |
|---|---|
| Custom actuator extension omitted | Resolved by DR-004 and C000.12/C022.07 plus C001/C012/C016 ownership and an end-to-end example-derived fixture. |
| Java toolkit promise unenforced | Resolved by the pinned C027 Java command/option/error reference matrix and explicit mapping to Rust/non-applicability. |
| Metrics/packaging dependencies incomplete | Resolved by C025 depending on C023/C024 and C028 depending explicitly on C024/C025. |
| Opcode/RPC/HTTP/JSON-RPC chunks unbounded | Resolved by source-derived manifests, bounded family IDs and local gates. |
| No early production ownership ledger | Resolved by C000.08 zero-gap source-derived ledgers. |
| Tracker lacks fields/readiness/derivation | Resolved by the tracker schema, separate readiness, evidence fields, transition validator and derived parents. |
| Oracle schema/normalization underspecified | Resolved by canonical C000.04/C000.05 schema and deliberate mismatch tests. |
| Protobuf/config/state/TVM inventories absent | Resolved by C001.07, C003.08, C008.11, C014.07 and C015.06 manifests with zero-gap gates. |
| Consensus/P2P/API/ops scenarios non-reproducible | Resolved by C017.07/C018.06/C019.07, C020.09/C021.09, API comparison tasks, C025.08 and command/drill manifests. |
| Test mapping late/file-granular | Resolved by early C000.09 case-level ownership and C029 release-revision regeneration/reconciliation. |
| Final qualification terms undefined | Resolved by immutable C030.09 numeric release-gate specification and evidence-linked C031 gates. |
| Security/license review too late | Resolved by C000 threat/provenance approval, per-chunk adoption decisions and independent C030 requalification. |
| Mature-crate choices implicit | Resolved by mandatory pre-implementation `DD-###` records and rejection/rollback criteria. |
| Chunk dependencies overly serial | Resolved with item/family-level prerequisites and ordered bounded commits; whole-chunk dependencies remain only where the complete contract is required. |
| Snapshot trust contract missing | Resolved by C028.06 authenticated trust, root, freshness, atomicity and fallback requirements. |
| Rollback only covers storage | Resolved by C028.05 binary/tool/config retention, write/quiescence and downgrade-safety matrix. |
| UNLICENSED fixture clean-room ambiguity | Resolved by C015.07 legal guidance and retained clean-room provenance evidence before implementation. |
| Release artifacts lack operator authentication | Resolved by C028 signed release-manifest/SBOM/provenance trust contract and per-platform substitution/revocation/offline-verification drills, independently requalified in C030.06/C030.07 and cited by C031.12. |
| Terminal validator is circular | Resolved by a canonical candidate containing valid ordinary records and C031.13 plus a proposed `[x]` C031.V, followed by an authenticated external compare-and-swap receipt that binds the committed revision and final tracker digest; C031.V contains no self-citation. |
| Dependency projection uses chunk/range/prose shorthand | Resolved by authoritative `docs/PORTING_TRACKER.json` plus literal per-record checklist `dependencies[]`, exact round-trip validation, and mandatory edge checks. |

Because every reviewer finding is actionable and accepted, there are no discarded findings requiring an exception rationale.
## 10. Definition of complete

The Rust port is complete only when the canonical terminal candidate validates every ordinary C000–C031 substantive and `.V` record, validates `C031.13`, proposes `C031.V` `[x]` without any self-authenticating evidence edge, and an external authenticated compare-and-swap receipt verifies against the exact committed repository revision and final tracker digest. The receipt must bind the candidate digest, committed `C031.V` state, signer/tool identity, validation and commit timestamps, repository revision, and final tracker digest; it—not a run cited by C031.V—is the terminal completeness proof. Completion also requires zero unchecked, in-progress, invalid-deferred, stale-evidence, stale-approval, dependency/adoption, scope, or ledger gaps; all final split and cross-boundary reviews approve; a Rust node can clean-resync and operate in mixed Java/Rust networks without divergence; every released binary/container/config/native-resource/parameter bundle is authenticated against the signed release manifest and reconciled to its SBOM/provenance; and all public interfaces pass differential compatibility gates. Physical Java DB compatibility remains outside scope under DR-001, but logical state, migration, snapshot, resync, API, and network compatibility do not.
## 11. Second corrective-pass finding dispositions

| Finding | Disposition | Corrective ownership |
|---|---|---|
| REREVIEW-01 custom-actuator protobuf gap | Resolved | C001.08/C001.V now own extension descriptors or runtime loading, type URLs, numeric `ContractType`, collisions and example-derived byte fixtures before C012/C016/C022. |
| REREVIEW-02 over-serialized chunk dependencies | Resolved | Tracker requires explicit item edges; C004 and C020 show narrowed cross-chunk contracts, while `.V` boundaries preserve sequential chunk completion and finite family exceptions. |
| REREVIEW-03 final unchecked/in-progress gap | Resolved | C031.13 validates the nonterminal graph; the canonical terminal candidate validates all ordinary records and C031.13 with C031.V proposed `[x]`; final validity comes from the external authenticated compare-and-swap receipt bound to the exact committed tracker digest. |
| REREVIEW-04 indeterminate readiness | Resolved | C000.10 requires item `dependencies[]`, exact ready truth semantics, round-trip validation and unknown/duplicate/self/cycle rejection. |
| REREVIEW-05 incomplete evidence | Resolved | Plan §4, C000.13 and C031 require observed exit/result, stdout/stderr hashes, timestamps, schema/case outcomes, exact-run comparison and stale-evidence invalidation. |
| REREVIEW-06 stale/finite review closure | Resolved | Finite review manifests now require finding IDs, dispositions, fix revisions, rerun linkage, post-fix closure and change-triggered approval invalidation. |
| REREVIEW-07 standalone Solidity inventory | Resolved | C026.04-.V define a source-derived required/forbidden/cursor exposure manifest with row evidence; C031.10 cites it. |
| REREVIEW-08 recurring adoption controls | Resolved | C000 policy/setup is separated from C000.15 recurring inventory instances; consuming-item readiness and gates require current DD/security/license approval. |
| REREVIEW-09 early platform enforcement | Resolved | C000.14 establishes continuous full platform rows; C007.V and C028 consume applicable rows. |
| REREVIEW-10 late security taxonomy | Resolved | C000.07 defines severity, blockers, exception authority/evidence/expiry and reopen triggers; C030/C031 apply it to every finding. |
| REREVIEW-11 snapshot trust-anchor lifecycle | Resolved | C028.06-.07 define provisioning, scope, rotation/revocation, algorithm agility, operator minimum height, freshness/offline verification and adversarial drills; C031.11 cites them. |
| REREVIEW-12 reviewer independence/seam gaps | Resolved | C031 manifests require named independent reviewers, recusal rules, exact scope hashes, primary/secondary seam ownership and complete coverage validation. |
