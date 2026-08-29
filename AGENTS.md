# Repository Agent Guidance

## Mission

This repository exists to produce a complete, faithful Rust port of the checked-in `java-tron` implementation. The Java tree is the executable behavioral specification until the compatibility gates in `docs/PORTING_PLAN.md` pass. Do not narrow the work to an MVP and do not “improve” observable quirks without a reviewed compatibility decision.

## Required planning and tracking

- Read `docs/PORTING_PLAN.md` before implementation work.
- Treat `docs/PORTING_TRACKER.json` as the authoritative machine tracker and `docs/PORTING_CHECKLIST.md` as its reviewed human projection. Keep stable item IDs in commits and reviews, and preserve exact record/edge round-trip between both files.
- Respect literal item-level dependencies. Every substantive and `.V` record has an explicit `dependencies[]` containing only stable substantive or `.V` IDs—never chunk IDs, ranges, prose, or partial annotations. Every `.V` directly closes all substantive children it owns; reject unknown, duplicate, self, cyclic, or omitted mandatory edges before implementation.
- Tracker states are `[ ]` unchecked, `[-]` in progress, `[x]` checked, and `[D]` externally blocked. Never defer doable work. `[D]` requires an owner, evidence, unblock condition, and decision record.
- Record compatibility decisions as `DR-###` and risks as `R-###`; include evidence and revisit triggers.

- Machine tracker records must carry explicit item-level `dependencies[]`; readiness is derived only from checked dependencies with current evidence/approvals. Reject unknown, duplicate, self, and cyclic edges and stale evidence.
- Evidence must bind exact cases to one immutable run, including observed exit/result, stdout/stderr hashes, timestamps, and per-case outcomes. Covered source/config/schema/toolchain changes invalidate the evidence.
- Independent review records require named non-author reviewers, finite scope (including cross-domain seams), stable finding dispositions, fix-to-rerun linkage, and post-fix closure; covered changes invalidate approval.
- Dependency, security, and license approval is per adoption and owned by the consuming tracker item; completing the repository-level policy does not pre-approve future crates, tools, FFI, schemas, fixtures, or parameters.
- Qualification criteria must be frozen before governed execution: legal clean-room procedure precedes replacement fixture work, and the C030 release-gate specification precedes every governed qualification/review run.
- Released binaries, containers, configuration bundles, native resources, and parameter packages require operator-verifiable authentication through a signed release manifest, out-of-band trust anchors with rotation/revocation, exact digests, SBOM/provenance attachment, offline verification, and substituted-channel rejection drills.
- Terminal completion is non-self-authenticating: the validator produces a canonical candidate with every ordinary record and C031.13 valid and C031.V proposed `[x]` without citing its own run; an authenticated compare-and-swap committer outside the tracker graph atomically commits the exact candidate and issues an external receipt binding the candidate digest, repository revision, committed C031.V state, signer/tool identity, timestamps, and final tracker digest. Only receipt verification against the checked-in revision proves completion.

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
