# Repository Agent Guidance

## Mission

This repository exists to produce a complete, faithful Rust port of the checked-in `java-tron` implementation. The Java tree is the executable behavioral specification until the compatibility gates in `docs/PORTING_PLAN.md` pass. Do not narrow the work to an MVP and do not “improve” observable quirks without a reviewed compatibility decision.

## Required planning and tracking

- Read `docs/PORTING_PLAN.md` before implementation work.
- `docs/PORTING_TRACKER.json` is the only checked-in progress tracker. Do not create or maintain a second checklist or status projection.
- Work strictly in chunk order from C000 through C031. Only the first non-done chunk may be active, in review, or externally blocked; every later chunk remains `todo`.
- Preserve every stable C001-C031 item ID, `.V` gate ID, chunk boundary, and commit boundary. Do not move, merge, split, or renumber porting work.
- Use `python3 tools/tracker/validate.py --status` for the current chunk summary and `python3 tools/tracker/validate.py --next` for the concrete next action. Run a chunk's stored commands with `python3 tools/tracker/validate.py --gate Cnnn`.
- A gate is an ordinary ordered command list. Commands fail fast and never mutate tracker state. A stored `passed` value is only a resumability marker; required CI reruns the gate on the final checked-in tree.
- After implementation, run the complete chunk gate and move the chunk to review. Reviewers record concise stable findings in the chunk's `review.findings`; fixes reset the gate, the complete gate is rerun, and findings are closed before approval.
- Mark a chunk `done` only when every item is done, its gate passes, review is approved, every finding is closed, and no blocker remains. Commit the tracker update as an ordinary tracker-only completion commit after implementation and finding-fix commits.
- Use a chunk blocker only for something genuinely external, with a concrete reason and observable unblock condition. Do not classify doable work as blocked.
- Any change to gate commands, fixtures, normalization, or acceptance text while a chunk is active resets the gate and review state. Protected-branch review and required CI provide final-tree assurance; do not add tracker evidence envelopes, review manifests, governance signatures, CAS receipts, or external completion receipts.
- Record compatibility decisions as `DR-###` and risks as `R-###`. Dependency versions belong in manifests and lockfiles, and each selection is accepted through its owning item's review and gate without a separate dependency-selection ledger. Semantic, security, and license risk is handled by normal design review, compatibility gates, and final qualification.
- C031 retains all substantive domain and release reviews, security and license qualification, and product-authentication requirements, but deliberately discards tracker-specific evidence envelopes and CAS receipt machinery as redundant. Ordinary signed release artifacts and all C028-C030 authentication, SBOM/provenance, offline-verification, trust-anchor, and substituted-channel protections remain required.

## Compatibility rules

- Preserve protobuf tags, enum numbers/names, misspellings, gaps, `Any` type URLs, unknown-field behavior, and one-byte P2P message prefixes.
- Preserve byte-level hash boundaries and serialization. Transaction ID hashes raw data; transaction Merkle leaves hash the full transaction; block ID hashes the raw header and embeds height.
- Keep SHA-256/SM3 engine hashing distinct from Keccak.
- Preserve Java arithmetic, overflow, ordering, timing, feature-flag, and error behavior where observable.
- Keep HEAD, SOLIDITY, and PBFT views separate.
- Pending transactions and fork processing must use atomic revoking sessions with complete rollback and replay.
- Use Java-vs-Rust differential fixtures for consensus, state, P2P, API, and operations behavior. Every compatibility bug gets a durable minimal fixture.

## Storage policy

Initial Rust releases use a Rust-owned versioned disk format. They do not open or modify Java LevelDB/RocksDB directories. Rust storage must provide manifest validation, atomic version migrations, backup/rollback, verified snapshots, and clean resynchronization. Java directories must be detected and rejected without writes. This physical-format exception does not relax logical state, key/value, root, API, or network compatibility.

## Engineering conventions

- Prefer explicit dependency injection and deterministic lifecycle ordering over Java-style static globals or implicit Spring construction.
- Use mature, pinned crates for cryptography, protobuf/gRPC, networking, storage, and HTTP where they can satisfy exact behavior; wrap and test compatibility differences rather than forking silently.
- Keep consensus-critical types narrow and explicit: addresses, hashes, block IDs, transaction IDs, slot/time values, energy, and state cursors should not be interchangeable raw byte vectors or integers.
- Do not combine unrelated protocol, storage, consensus, networking, and API changes in one commit.
- Generated code must be reproducible from checked-in schemas and pinned tools.
- Any unsafe or FFI boundary requires a narrow module, documented invariants, and direct failure/lifetime tests.
- Do not redistribute or translate `FreezeTest.sol` as a reusable fixture until its `UNLICENSED` status is resolved; independently recreate compatible behavior or obtain permission.

## Lessons

Reusable repository facts and conventions learned from the Java evidence:

- The Java project has ten Gradle subprojects. The effective dependency order is protocol/platform → common → crypto → chainbase → actuator/consensus → framework, with plugins consuming protocol/platform/common/crypto and framework test output.
- Canonical schemas are the 17 `.proto` files under `java-tron/protocol/src/main/protos`; generated Java is intentionally absent. Schemas are shared with wallet-cli/grpc-gateway and must remain synchronized.
- Public protobuf services include Wallet, WalletSolidity, WalletExtension, Database, Monitor, an empty Network service, and TronZksnark. Deprecated RPC names remain part of the compatibility surface.
- `Transaction.Result.code` spells success `SUCESS`; API return code spells `BANDWITH_ERROR`. Preserve wire names/numbers rather than correcting them.
- Transaction IDs hash `Transaction.raw_data`; transaction Merkle hashes include signatures/results; block signatures and IDs cover the raw block header. Empty block Merkle root is 32 zero bytes and an odd leaf is promoted unchanged.
- `Sha256Hash` may mean SHA-256 or SM3 depending on engine mode. Keccak remains Keccak. TRON addresses use prefix `0x41`; normal contract address derivation is Keccak(txid || owner), not Ethereum sender/nonce RLP.
- Recent-block/Tapos keys use only the low two bytes of height and values use bytes 8..16 of the block ID. These truncations are intentional compatibility behavior.
- Dynamic properties are consensus state. The exact key for same-token-name includes a leading space: ` ALLOW_SAME_TOKEN_NAME`.
- Account asset optimization clears asset maps in the persisted Account and stores balances externally as `address || asset-id/name -> big-endian i64`. Contract storage similarly splits ABI from the persisted contract.
- Revoking snapshots and sessions are consensus-critical. Pending transactions hold speculative state; fork replay must clear cached signature verification because permissions can differ by branch.
- HEAD, SOLIDITY, and PBFT are distinct cursors over revoking stores. PBFT is an auxiliary signed-data/quorum sidecar; DPoS remains block-selection consensus.
- DPoS uses 3-second slots, 27-witness scheduling assumptions in core tests, maintenance-rounded transitions, proposal approval at at least 70% of active witnesses, and 70% solidification positioning.
- java-tron delegates critical TCP/UDP P2P behavior to binary-only `io.github.tronprotocol:libp2p:2.2.9`. Compatibility must be established with packet captures and live Java↔Rust tests, not source assumptions.
- TCP carries two separate protocol layers: negative external control bytes (`0xFF`..`0xFB`) and nonnegative application bytes. Application ping/pong (`0x22`/`0x23`, payload `0xC0`) are unrelated to external timestamped keepalive messages.
- Application message codes include TRX `0x01`, BLOCK `0x02`, TRXS `0x03`, INVENTORY `0x06`, FETCH `0x07`, SYNC `0x08`, CHAIN_INVENTORY `0x09`, PBFT commit `0x14`, Hello `0x20`, disconnect `0x21`, ping/pong `0x22`/`0x23`, and PBFT wire input `0x34`.
- External TCP framing is protobuf varint length-delimited with a 5,242,880-byte payload limit; compression is negotiated and uses a protobuf snappy envelope. Discovery datagrams are effectively raw `[type][protobuf]` up to 2,047 bytes, but this must be confirmed against real peers.
- Ordinary and fast-forward propagation differ materially. Fast-forward bypasses normal request correlation and sends full blocks to scheduled successor witnesses; test it separately.
- API defaults include HTTP 8090/8091/8092, gRPC 50051/50061/50071, JSON-RPC 8545/8555/8565, P2P 18888, backup UDP 10001, ZeroMQ 5555, and Prometheus 9527.
- HTTP, gRPC, JSON-RPC, P2P, backup, event queue, and ZK service transports are plaintext by default. `disabledApi` protects HTTP/gRPC but not JSON-RPC.
- HTTP protobuf JSON has custom visible-mode address/name formatting and GET-scoped `int64_as_string`. JSON-RPC is a partial TRON-specific Ethereum emulation; unsupported methods and null/zero uncle behavior are intentional.
- Solidity nodes do not join P2P. They require a trust node and replicate verified blocks through Database gRPC.
- Events are asynchronous stateful pipelines with removed/reapply behavior on reorg, not simple post-commit logging.
- The tracked Java test tree contains 530 source files and ten test resources. Important protocol/crypto/chainbase/consensus behavior is often tested from the framework module rather than its owning module.
- The repository-level license is LGPLv3, but individual sources include GPLv3, Apache-2.0, ethereumJ LGPL text, and an UNLICENSED Solidity fixture. Crate/source/fixture/parameter distribution needs explicit provenance review.
- Python-based repository gates must keep the worktree clean; retain repository-level ignores for `__pycache__/` and `*.py[cod]`.
- Protocol inventory is descriptor-derived, not maintained by hand: `python3 tools/protocol/c001_gate.py --write` is the only regeneration command for `docs/oracles/protocol-conformance.v1.json`; normal verification uses the same command without `--write` and must leave the artifact byte-identical.
- Canonical protocol drift is checked at three boundaries: every Rust schema must byte-match its `java-tron/protocol/src/main/protos` source, the normalized descriptor must byte-match `descriptors/protocol.v1.pb`, and descriptor metadata/input digests must remain synchronized. Normalization sorts `FileDescriptorProto` records by path and strips source information without rewriting descriptor contents.
- The enum-zero exception is a closed, live 21-entry allowlist keyed as `<schema-path>:<nested-enum-name>`. New enums use an `UNKNOWN_` zero value; stale allowlist entries fail the gate rather than silently persisting.
- Golden protobuf fixtures retain the `.textproto` source where canonical encoding is asserted and record exact size plus SHA-256 for every binary. Unknown-field fixtures use a legal high-number field; malformed fixtures use a truncated length-delimited field; maps, explicit-default presence, and `Any` type URLs have separate positive fixtures.
- The exact C001 gate is `python3 tools/tracker/validate.py --gate C001`; its stored commands run the protocol drift/inventory/fixture checker, the canonical generated-surface test, and the DR-004 extension registry/byte test. Do not replace the stored command sequence with an ad hoc subset.
- Rust build output is repository-local and untracked: ignore only `rust-tron/target/` at the repository level so Cargo artifacts stay out of project changes without hiding source directories named `target` elsewhere.
- C002 primitive coverage is source-pinned in `docs/oracles/common-primitives-coverage.v1.json`; `python3 tools/primitives/c002_gate.py` checks all C002.01-C002.07 Java inputs, deterministic boundary-vector groups, and explicit C004/C006/C008 ownership seams without asserting later general crypto, shielded crypto, capsule, or logical store behavior.
- Locale.ROOT-compatible key casing uses Rust 1.85's pinned full-string `str::to_lowercase()`/`str::to_uppercase()` mappings with no normalization or dependency. Its domain is valid Unicode scalar values in `str`; unpaired Java UTF-16 surrogates are outside the Rust contract.
- Java `BlockId` has an intentional ordering inconsistency: equality compares all 32 overlaid bytes, while `compareTo(BlockId)` compares only height, so unequal IDs at the same height compare equal. Comparing to a plain `Sha256Hash` instead uses the inherited reverse-byte hash ordering.
- Primitive gates must distinguish exact hash inputs: transaction ID hashes preserved `Transaction.raw_data` bytes, transaction full hash/Merkle leaves hash preserved full transaction bytes, and block ID hashes preserved `BlockHeader.raw_data` bytes before overwriting digest bytes 0..8 with signed big-endian height.
- C003 configuration coverage is generated from the pinned Java `reference.conf`, packaged `config.conf`, `CLIParameter.java`, `Args.java`, and `DynamicArgs.java`. `python3 tools/config/c003_gate.py --write` is the only inventory regeneration command; ordinary verification omits `--write` and requires byte-identical bundled configs plus zero unmapped Java keys/options.
- Runtime configuration precedence is fixed: reference fallback → exactly one packaged-or-external overlay → explicitly assigned CLI fields → event OR-stage → platform rule → witness initialization. External `-c/--config` bypasses the packaged overlay, and ARM64 forces ROCKSDB after CLI application.
- Dynamic configuration reload is deliberately narrow: only active nodes, passive nodes, and the derived trust union change. Configuration parsing has no ambient argument/environment access, and lifecycle composition uses injected immutable configuration, cancellation, and monotonic time rather than Java static mutable singletons.
- C003 lifecycle services are declared in dependency order, start forward, cancel and unwind on startup failure, stop once in reverse order, and aggregate shutdown failures. Keystore-factory mode constructs no node services; enabled API ports are validated for nonzero `u16` range and uniqueness before startup.
- C004 core-crypto parity is source-pinned by `docs/oracles/c004-crypto-source-manifest.v1.json`; `python3 tools/crypto/c004_gate.py` authenticates the explicit Java whitelist and the generated 26-vector `docs/oracles/c004-crypto-fixture-manifest.v1.json`, requires all vectors to map to eight explicit Rust test dispatches, and treats that generated fixture manifest as the sole C004 vector artifact. Keystore belongs to C005/C005.V, zksnark/shielded crypto to C006/C006.V, and the Blake2 TVM precompile to C015/C015.V; these remain explicit ownership seams rather than implied C004 crypto coverage.
- C005 keystore parity is source-pinned by `docs/oracles/c005-keystore-source-manifest.v1.json`; `python3 tools/keystore/c005_gate.py` authenticates the pinned Java whitelist, regenerates the deterministic supplied private-key/salt/IV/UUID oracle for scrypt/PBKDF2 and EC/SM2, reconciles every filesystem policy ID, and requires all vectors to map to four explicit Rust test dispatches. C005 owns core keystore schema, crypto, password, and persistence behavior; C027 owns toolkit/CLI rendering, C003 owns node lifecycle/`KeystoreFactory` composition, and C025 owns operational logging, metrics, and failure propagation.
- C006 shielded parity is authenticated by `docs/oracles/c006-shielded-provenance.v1.json`: 31 `JLibrustzcash` plus 8 `JLibsodium` methods, the Maven native-reference checksums, exact TRON parameter sizes/SHA-256/BLAKE2b-512 values, and every checked-in Merkle fixture hash. The native SDK is a semantic reference only; runtime proof work is pure Rust with caller-supplied authenticated parameters.
- `python3 tools/shielded/c006_gate.py` authenticates the replacement ledger against the exact 162 `C006.V` rows in `java-test-ownership.v1.json` (146 active plus 16 ignored) and requires 11 named Rust proof rows, yielding the declared 157 active plus 16 ignored accounting. Every ignored row has a concrete owner chunk and an existing Rust test symbol with a canonical executable dispatch; generic replacement labels, ownership drift, missing symbols, or count drift fail the gate. The 14 ignored `ShieldedTRC20BuilderTest` cases are owned by C022.01B transaction construction, C016.02 ownerless shielded validation, or C015.04 shielded execution as applicable; the ignored external ZK call remains C006.06 and the ignored concurrent benchmark remains C006.05 with a named bounded-concurrency test. The gate and all C006 items/review remain `not_run` until every stored command executes.
- The C006.06 compatibility seam is the canonical `protocol.TronZksnark/CheckZksnarkProof` plaintext localhost gRPC boundary. Local tonic tests must preserve `transaction`, `sighash`, signed `value_balance`, and `tx_id` fields and must retain explicit unavailable-endpoint failure coverage without depending on port 60051 or an external process.
