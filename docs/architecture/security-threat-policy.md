# Threat model and security closure policy

C000 defines security constraints; it does not approve later dependencies, implementations, fixtures, parameters, binaries, or deployments.

## Assets, boundaries, and adversaries

Protected assets are consensus and state correctness; signing and shielded secrets; database and snapshot integrity and availability; protocol and API authenticity; operator credentials and configuration; build and release provenance; native/FFI memory safety; and bounded CPU, memory, disk, descriptors, tasks, connections, and queues.

Trust boundaries include P2P and discovery, gRPC/HTTP/JSON-RPC, events and plugins, CLI/config/filesystem inputs, snapshots/resync/migrations, Java oracle inputs/results, generated code and schemas, dependencies and build scripts, native libraries/FFI, Sapling parameters, packages, containers, and release channels. Plaintext interfaces are untrusted even on localhost; exposure, authentication, confidentiality, size limits, timeouts, concurrency, and backpressure must be explicit.

Adversaries include remote peers and clients, malicious contracts, blocks, snapshots, plugins and fixtures, compromised dependency or distribution channels, local unprivileged users, dishonest infrastructure, and accidental operators. Root, kernel, hardware, and provisioned trust anchors are outside the application boundary, with their assumptions stated.

The C005 keystore filesystem boundary treats other local UIDs and pathname redirection as adversarial. Every keystore-containing directory must be owned by the effective UID with mode 0700, and each operation holds an exclusive descriptor-backed advisory lock across discovery, validation, mutation, publication, and rollback. Parent components are traversed descriptor-relative without following symbolic links. Same-UID and root processes that ignore the advisory lock are explicitly outside this boundary: they already have authority to read, replace, or delete the user's keys. This exclusion does not permit pathname-based publication or weaken final-file ownership and 0600 checks.

## Severity and closure

- **critical:** practical consensus divergence, unauthorized secret extraction, remote code execution, release-authentication bypass, or irreversible widespread state corruption. Blocks merge and release.
- **high:** exploitable authorization bypass, persistent corruption, material privacy break, sandbox escape, or remotely sustained node unavailability. Blocks the owning gate and release.
- **medium:** bounded security impact requiring meaningful preconditions, or a plausible defense-in-depth failure. Blocks the owning gate unless explicitly accepted by the security and domain owners.
- **low:** limited hardening, documentation, or observability weakness. Requires a fix or explicit disposition before the owning gate.

Each finding records a stable ID, affected scope, threat scenario, severity rationale, reproduction, owner, remediation, and resolution. A fix is closed only after the complete owning gate passes and the ordinary review finding is closed. Critical and high findings cannot be waived for release. Medium and low exceptions must name their scope, rationale, compensating controls, owner, and expiry.

Reopen a finding when the affected behavior, dependency, toolchain, native component, exposure, platform, feature, or control changes, or when a new advisory or failed regression invalidates the prior conclusion. Resource-exhaustion analysis must define numeric input, allocation, recursion, queue, concurrency, timeout, disk, and rate limits and exercise adversarial cases. Silent fallback, disabled verification, fail-open parsing, and unbounded attacker-controlled work are blockers according to impact.

## C006 shielded proof and note boundary

`tron-shielded` owns Sapling proving and verification state; raw byte adapters never expose borrowed native pointers. Opaque handles are nonzero, monotonically allocated, wrong-kind and retired handles fail closed, and double-free is an error. The default table reserves at most 64 context slots. Its table state tracks `reserved_slots` across both addressable contexts and retired contexts that still have active operations; init checks and increments that count atomically under the table mutex, so removing a handle cannot open replacement capacity early. Each entry has a mutex-and-condition-variable admission state recording `retired` and `active`: a call clones the entry and must atomically increment `active` only while it is not retired before accessing the context, with RAII decrement and notification on every success, error, or panic exit. Free validates the kind, removes the handle, and marks it retired atomically while holding the table mutex, then releases the table and waits for `active == 0`; cloned but unadmitted calls fail `InvalidHandle`, while already admitted calls finish before free returns. A retirement RAII guard releases exactly one reserved slot after quiescence, including unwind paths. Each context has an independent mutex, so unrelated proofs continue concurrently and mutation of one transaction context remains serialized.

Raw wrapper validation is distinct from cryptographic rejection. Shape, signed-value, declared-length, and voucher-path marker violations return typed errors before any context or output mutation. Well-shaped invalid signatures, points, commitments, or proofs return `false`. Verification retains only the live typed Sapling context and bounded integer counters: each spend or output is parsed and cryptographically preverified against the prepared verifying key in a disposable context before the typed check commits it to the live context. Failed preverification leaves the live binding-commitment sum and counters unchanged; accepted items require constant work and memory independent of prior cardinality, with no proof retention, replay, or semantic spend/output cap. Proving output buffers are copied only after proof construction completes.

Pre-ZIP212 note encryption is explicit (`Zip212Enforcement::Off`), preserves the 512-byte memo, and supports recipient trial decryption and sender recovery. External ZIP32 key paths and the default diversifier/address are derived by the pinned Sapling implementation. Secret randomness comes from `OsRng`; deterministic production substitution is not exposed. Parameter files remain caller-supplied. Each file is read exactly once into an owned allocation of the expected size while size and BLAKE2b-512 are streamed; the digest is verified before deserialization parses an in-memory cursor over those immutable authenticated bytes. Parsing never seeks or rereads the writable source, so post-authentication in-place mutation or truncation cannot change the parsed parameters, while pre-snapshot mutation fails size or digest authentication before contexts can be created. The production `TronZksnark` client accepts only literal IPv4/IPv6 loopback endpoints (`127.0.0.1` or `::1`) over plaintext HTTP, defaults to `127.0.0.1:60051`, and rejects DNS names, non-loopback addresses, omitted ports, and alternate schemes before transport. Connect and request time are bounded, encoded requests above 4 MiB are rejected before transport, and a nonblocking one-per-client semaphore rejects a second in-flight request rather than queueing unbounded work. Connection/timeout/service failures are exposed as typed `Unavailable` or `Failed` errors and never converted to a successful proof response. Loopback remains an untrusted plaintext interface; operators must prevent untrusted local processes from binding or reaching the configured port.

JLibsodium compatibility uses a 1 MiB node message/AAD bound, a 1 MiB plus 16-byte authentication-tag ciphertext/output bound, and records libsodium's historical 274,877,906,880-byte IETF message ceiling only as an upstream limit rather than a node allowance. These numeric limits exceed observed Java production note payloads (at most 580 ciphertext bytes) and the 1,024-byte negative oracle. Declared lengths and caller capacities are validated before cryptographic allocation; overflow, undersized/oversized capacity, and authentication failure return typed or return-code failure with empty output, never an attacker-sized zero-filled vector. BLAKE2b maps the Java null/empty salt representation to libsodium's zero-filled 16-byte salt while rejecting every nonempty salt not exactly 16 bytes. Stateful updates accept only the Java note-derivation shapes of exactly 33 or 34 bytes; shape rejection occurs before acquiring the state-table lock and therefore cannot mutate or contend on a live hash state.

## C011 Khaos graph boundary

Khaos block IDs, heights, parent IDs, duplicate insertions, orphan arrival order, and heap-owned block payloads are network-controlled. Every accepted payload type must implement `RetainedSize`; byte slices, strings, vectors, primitives, and application payloads report their complete canonical or owned payload bytes rather than only their stack descriptor. Each linked and orphan store checks fixed block overhead plus that deep payload size for overflow and enforces insertion-list entry and accounted-byte limits derived from its configured capacity, independently of the height window and hash index. Duplicate replacements consume list and byte budget. This resource-pressure bound is an explicit security extension beyond Java: it scans insertion order, plans the exact oldest eligible `Rc` entries needed to admit the incoming block, skips only the exact pinned parent instance, and then evicts each victim with individual accounting and callbacks. Same-height siblings are not collateral victims, and insertion is rejected unless the post-admission entry and byte counts remain strictly within their configured limits. A single entry larger than the byte budget fails before any linked or orphan mutation with `KhaosError::ResourceLimit`. Separately, capacity-window expiry remains Java-compatible and evicts complete height buckets below the strict cutoff.

Modern and deprecated branch traversal treat retained parent graphs as untrusted even when assembled through accepted blocks. Both track visited parent IDs, require every resolved parent height to strictly decrease, and bound traversal steps by retained entries; they return typed cycle, malformed-chain, or traversal-limit errors instead of looping. Only the deprecated API's missing-initial-block behavior remains Java-compatible as an empty pair; a parent that disappears after traversal begins is an error. The inherited Java `isNotEmpty` surface remains explicitly unsupported and returns `KhaosError::UnsupportedOperation`.

## C007 storage format, migration, and snapshot boundary

Storage paths and snapshot inputs are untrusted local inputs. `tron-storage` validates the
checksummed canonical Rust manifest and exact network, genesis, schema, backend, backend-format,
feature, generation, state, and root identity before opening writable backend state. Its
pre-open classifier is read-only and rejects Java LevelDB/RocksDB markers, ambiguous nonempty
directories, corrupt or newer manifests, unsupported semantics, and partial migration without
creating locks or other filesystem entries. Initialization and snapshot import are empty-only;
there is no fallback from rejection to initialization.

Migration and import use separate staging generations, bounded reads, durable checksummed journals,
file-and-directory fsync, retained prior-manifest backups where a prior generation exists, and an
atomic manifest switch. Every untrusted storage-file read is capped at one byte beyond its numeric
policy limit, starts with a small fixed allocation, and fails with a typed error rather than growing
an allocation from attacker-controlled metadata. Snapshot import receives `max_source_bytes`
explicitly from its import policy/composition root, rejects oversized metadata before allocation,
then performs a capped fallible read so concurrent file growth cannot exceed the limit. The verifier
and materializer are never invoked for an oversized or over-limit growing source. Snapshot import
opens the source exactly once without following the final symbolic link and captures immutable bytes
plus the retained file identity; the verifier and materializer consume that same authenticated
snapshot, and any pathname replacement or size/identity change during capture or any pathname
replacement or symlink plant before materialization fails closed. Import holds the common retained
root lock from recovery and empty-destination validation through cleanup. Its identity/root-bound
verifier succeeds before a checksummed, fsynced journal becomes durable; only then may staging be
created and materialized.
The complete staging tree is synced before an atomic generation publish, root-directory fsync,
manifest install, and journal cleanup. Pre-generation failures remove staging and journal; every
subsequent open or retry rolls back a prepublish journal or completes a published generation and
manifest installation. Injected durable-phase faults and abrupt termination must permit a safe
retry at the same destination and preserve either the prior selected generation or a journaled,
resumable post-generation state. Snapshot authentication is mandatory and injected: C007 enforces
exact verifier identity and logical-root equality, while C028 owns trust anchors, signature policy,
freshness, and anti-rollback decisions. A clean-resync marker records operator intent only and
grants no trust. Disk-full, permission, lock/concurrent-open, corruption, integrity, unsupported,
and authentication failures are typed and fail closed.

The C007 storage filesystem boundary treats other local UIDs and pathname redirection as
adversarial. A writable storage root is owned by the effective UID with mode 0700. Opening
retains the verified directory descriptor; every manifest, WAL, snapshot, migration journal,
generation, staging directory, temporary file, rename, fsync, and removal is resolved relative
to that descriptor without following symbolic links. Temporary names are unpredictable and
created exclusively. The common storage lock retains its owner inode, and cleanup removes a
lock name only when it still denotes that inode. Writable open first securely retains or creates
the root, acquires the common kernel lock before initialization recovery, empty validation, or any
cleanup, then revalidates the root pathname and performs classification, recovery, manifest and
generation initialization descriptor-relative. The same retained lock remains held through manifest
validation and backend construction; a concurrent opener returns `Locked` and cannot clean another
opener's initialization journal. Checkpoint publication retains and revalidates the destination parent
before and after publication, atomically refuses an existing or symlinked final name, and removes a
just-published tree through the retained parent if post-publication identity validation fails.
Parent/final replacement and planted lock, temporary, manifest, WAL, journal, staging, checkpoint,
or snapshot symlinks fail closed and cannot redirect storage I/O outside the retained tree. Same-UID
and root processes that deliberately bypass the common advisory lock are outside this boundary; this
exclusion does not permit pathname-based publication or weaken ownership, mode, no-follow, or
inode-safe cleanup checks.

## C009 revoking state and cursor boundary

Speculative state is capability-scoped. `SessionManager::read_view` and
`SessionManager::session_view` capture the same immutable logical HEAD: the durable root plus every
committed, non-abandoned overlay, while excluding all active speculative overlays. Committed
overlays remain logically visible before physical flush; abandoned overlays never re-enter a read
view. Direct `DurableStore` reads are intentionally different and expose only the physical durable
root. Session mutation is serialized, while cloned immutable views permit unrelated readers to
proceed without observing later commits or speculative writes. Pending execution owns an outer
revocable layer, and child effects enter it only through explicit merge; reset, close, and drop
revoke the held speculative state.

Checkpoint stacks use a bounded Rust-owned canonical encoding with a SHA-256 checksum. Staging,
journaling, publication, retreat, and relink use the C007 atomic batch boundary; recovery accepts only
a staged image matching its durable journal checksum. Stack depth, encoded bytes, retreat count, and
flush count are policy-bounded. HEAD, SOLIDITY, and PBFT are distinct immutable cursor types carrying
checkpoint identity; PBFT offsets reject negative values, missing cursors fall back toward HEAD, and
cursor block numbers clamp to their validated parent root. Shutdown attempts both overlay disposition
and durable flush and returns all observed failures rather than hiding a later close error.

## C010 resources, asset migration, and account-root boundary

Resource arithmetic is consensus input. Usage decay rejects time reversal and non-positive
windows, uses widened signed intermediates for scaling and weighted windows, and converts back to
`i64` only with an overflow check. Negative consumption and fees fail closed. Global bandwidth,
energy, and TRON-power limits return zero for non-positive weights instead of dividing by zero;
adaptive energy remains bounded by the configured base and multiplier. Fee charging debits before
crediting exactly one explicit sink (transaction pool, burn counter, or black-hole balance), so a
caller cannot silently drop or duplicate value.

The asset name-to-ID proposal is an explicit trust boundary: reads never fall back across the
active gate, V2 issue rows are always written, legacy rows are written only while names are unique,
and account optimization externalizes balances in the same atomic batch that clears the inline map
and marks the account optimized. Missing or non-UTF-8 migration identifiers are typed failures.

Account-state roots are computed from Keccak address keys and reduced account values using canonical
RLP/MPT compact paths. Child nodes shorter than 32 bytes are inline and all others are referenced by
Keccak hash. TRON address bytes, reduced values, leaf count, aggregate value bytes, encoded node
bytes, and nibble depth are hard bounded with typed failures. Construction walks sorted borrowed
leaves in linear prefix groups, does not clone values or groups, and retains only hashed nodes rather
than transient subtree encodings. Duplicate keys replace the existing logical leaf atomically,
including byte accounting; sorted key ownership makes the root independent of insertion order, and
a forced/supplied block root never substitutes for validation: validation compares it with the
recomputed logical root and fails closed on mismatch.
