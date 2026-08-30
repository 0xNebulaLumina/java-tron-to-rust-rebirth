# Runtime dependency, cursor, determinism, and lifecycle contract

## Composition and dependency injection

`tron-node` and `tron-toolkit` are the only composition roots. They construct immutable configuration first, then explicit service values, and pass dependencies through constructors. Libraries must not read process environment, command-line arguments, global registries, wall time, operating-system randomness, or singleton service locators after composition. Static mutable state, hidden lazy construction, cyclic injection, and background work started by constructors are prohibited.

Construction and activation are separate phases:

```text
parse inputs -> validate config -> construct graph -> initialize resources
             -> start services -> signal ready -> run -> cancel
             -> quiesce ingress -> drain work -> flush/close state -> stop
```

A dependency is represented by the narrow owning trait or concrete value. Optional capabilities are explicit `Option`/enum configuration at the composition root, not nullable services. A service may depend only on an earlier crate layer and an earlier lifecycle phase.

## Typed state cursors

HEAD, SOLIDITY, and PBFT are distinct types, never enum values stored in one mutable thread-local cursor and never interchangeable integers.

```rust
pub struct HeadCursor { /* private checkpoint identity */ }
pub struct SolidityCursor { /* private solid checkpoint identity */ }
pub struct PbftCursor { /* private PBFT checkpoint identity and offset */ }
```

The eventual state API exposes read views parameterized by the concrete cursor type. Conversion is allowed only through an explicit, validated state service operation that records the checkpoint/height relationship. HEAD may include the latest accepted speculative/chain state; SOLIDITY resolves the independently tracked solidified checkpoint; PBFT resolves the independently tracked PBFT checkpoint and its Java-compatible offset. API adapters receive the required cursor from composition and cannot mutate a process-wide current cursor.

## Clock and randomness

All time enters through injected traits with units encoded in types. Consensus slot time, monotonic deadlines, and wall-clock timestamps are separate interfaces; monotonic values are never serialized and wall time never drives consensus calculations without an explicit compatibility rule.

Randomness enters through an injected, purpose-specific source. Consensus-visible shuffles and fixtures use specified deterministic algorithms and seeds. Secret-key generation uses an approved cryptographic source that cannot be substituted with deterministic test randomness in production. General-purpose library calls to ambient randomness are prohibited.

### Primitive digest, arithmetic, and clock boundaries

`tron-primitives` owns fixed-width addresses, hashes and IDs, but does not own a
digest engine. Hash construction accepts a narrow `DigestProvider`; concrete
SHA-256 and SM3 implementations are supplied by the later `tron-crypto` layer.
This preserves the L0 dependency direction and keeps serialized bytes as the
explicit input to every digest operation. Wire values do not keep provider-agnostic
digest caches: each ID/hash request consults its supplied provider, so sequential or
concurrent use of distinct algorithms cannot reuse or poison another provider's result.

Integer wrapper selection is explicit through `ArithmeticMode`, selected only by
`MathPolicy.disable_java_lang_math`. Both wrapper modes use exact checked add,
subtract, and multiply and report overflow; neither mode wraps. The independent
`MathPolicy.allow_strict_math` flag selects only the injected `PowProvider` path.
Host floating-point `pow` is not exposed to consensus; providers operate on raw
IEEE-754 bit patterns. Java floor division rounds toward negative infinity, and
BigInteger division truncates toward zero.

`BlockId` equality and hashing cover all 32 bytes and it deliberately implements no
`Ord`/`PartialOrd`: Java-compatible height-only comparison is `height_compare`, while
callers that truly require a total key order must opt into `total_bytes_compare`.

Locale.ROOT key casing uses Rust 1.85's pinned full-string `str::to_lowercase()` and
`str::to_uppercase()` mappings. This preserves contextual and expanding Unicode
casing without normalization or a runtime dependency. The accepted domain is valid
Unicode scalar values represented by Rust `str`; unpaired Java UTF-16 surrogates are
outside that contract.

Wall and monotonic clocks are separate injected traits. Consensus functions
receive a `ConsensusTime` value chosen by their caller and have no clock trait,
so they cannot consult ambient process time. Deterministic fixed/manual clocks
are available for composition tests; monotonic instants are duration values and
must never be serialized as wall timestamps.

## Cancellation and task ownership

The composition root owns one process cancellation source and creates child scopes for services and bounded operations. Cancellation propagates root-to-leaf; failures propagate leaf-to-root with typed cause and service identity. Dropping a future is not the shutdown protocol. Every spawned task is registered to exactly one service, has a bounded termination contract, and is joined before that service reports stopped. Detached tasks are prohibited.

Ingress cancellation stops new P2P/API/tool work before state-bearing work drains. A timeout escalates to a reported failed shutdown; it must not silently abandon state flushes or native resources.

## Lifecycle graph

```text
Configuration
  -> Clock / monotonic clock / randomness / cancellation root
  -> Protocol registry and primitive policies
  -> Crypto and shielded providers
  -> Storage backend and format manager
  -> State stores, revoking sessions, HEAD/SOLIDITY/PBFT cursors
  -> TVM and transaction execution
  -> DPoS and PBFT services
  -> Block/pending manager
  -> Network transport and application protocol
  -> API services
  -> Events/metrics services
  -> Node ready signal
```

Startup follows the arrows. A service starts only after every dependency reports initialized. Readiness is emitted only after all enabled ingress services are accepting work and state initialization is complete. Partial-start failure cancels the graph and stops only successfully initialized services in strict reverse order.

Shutdown is reverse dependency order with explicit phases:

1. revoke readiness and cancel new ingress;
2. stop block production, sync admission, API mutation, and transaction admission;
3. drain bounded handlers, event publication, and pending work according to compatibility rules;
4. settle/revoke speculative sessions and persist required checkpoints;
5. flush stores and close backend/native resources;
6. stop metrics/log exporters and join all tasks;
7. return a typed aggregate result preserving every stop failure.

Signals, operator requests, fatal service failures, and startup failures all enter the same cancellation path. No component may call process exit directly except the composition root after shutdown completes.

### C003 composition-root implementation

`tron-config` parses an explicit argument iterator; it never reads process arguments. Each
override is an `Option`, so a CLI default cannot overwrite a configured value merely because the
field exists. Short aliases (`-c`, `-d`, `-h`, `-v`, `-w`, and `-p`) and the Java long names map to
the same assigned field. Positional operands are seed nodes. Full node is the default mode;
Solidity and keystore-factory modes are explicit and mutually exclusive. Parsing reports unknown
options, missing values, invalid typed values, and conflicting modes as structured errors.

Runtime configuration is assembled in one fixed pipeline: parse CLI, load reference plus selected
config overlay, apply only assigned CLI fields (including `-w` witness enablement), apply the event
subscription OR-stage, apply the platform storage-engine rule, then initialize witness credentials.
Witness credential priority is CLI private key, configured `localwitness` private-key list, then
configured `localwitnesskeystore` list with the CLI password. `node.witness` is runtime-only state
set by CLI and has no HOCON key. The witness address follows the winning source: CLI address only
accompanies a CLI key; configured address accompanies configured keys or keystores. Keystore
decryption remains outside this chunk.

Dynamic configuration reload exposes a value containing only active, passive, and derived trust
node lists. It cannot replace storage, VM, genesis, committee, witness, API, or other immutable
runtime configuration. The caller owns scheduling and cancellation of reload attempts; the config
crate creates no watcher or background task.

`tron-node` receives an immutable `Arc<Config>`, cancellation token, monotonic clock, and already
constructed services through `NodeContext` and `ServiceGraph`. Constructors do not start work.
Services declare names, earlier dependencies, and Full/Solidity/PBFT/witness/P2P gates. Their start
and stop operations are externally cancellable async futures; the composition root bounds them with
the exactly pinned Tokio runtime and injected per-operation deadlines. It cancels a timed-out future,
waits for that owned operation to be dropped, and never detaches lifecycle work. Services own and
join any tasks they create before their stop future completes.

The graph rejects missing, duplicate, and forward dependencies before startup. Its explicit one-shot
state machine is `New -> Starting -> Running -> Stopping -> Stopped`, with `Failed` recording a
startup failure after a complete reverse unwind. `start` is accepted only from `New`; duplicate
starts and starts after terminal shutdown fail with a typed transition error before any service is
started. `shutdown` is accepted from `Running` and retried from `Stopping`; calls from `New` are
typed transition errors, while calls after `Stopped` or fully unwound `Failed` are idempotent.

The graph starts enabled services sequentially, cancels the shared root on timeout or failure, and
reverse-unwinds only the services that completed startup. Every accepted start therefore either
reaches `Running` or runs shutdown. A startup error whose unwind also fails returns both errors
without discarding either service failure or timeout detail and leaves the graph in `Stopping` for
retry. Shutdown continues in strict reverse order after failures or timeouts, but removes ownership
only for services whose stop completed successfully. Timed-out and failed services remain registered
for later shutdown retries; the graph becomes `Stopped` and subsequent shutdown calls become
idempotent only after every registered service has stopped. Never-completing start and stop futures
are bounded by the composition root. Restart is intentionally unsupported, so cancellation remains
the original graph-wide token for its full lifetime.

API selection is a composition plan, not an API implementation. Full and Solidity surfaces are
mode-gated, PBFT surfaces additionally require `committee.allowPBFT == 1`, and enabled ports must be
non-zero `u16` values unique across all selected HTTP, RPC, and JSON-RPC surfaces. P2P is a Full-mode
capability and is categorically absent in Solidity and keystore-factory modes regardless of config;
within Full mode it additionally requires P2P not to be disabled. Witness remains gated independently
by its finalized configuration flag. Keystore-factory mode enables no node API surface.

## C005 keystore persistence boundary

The keystore core exposes new, import, list, direct-load, and password-update operations without
owning CLI presentation. Creation and update always emit standard-scrypt V3 wallets. Cryptographic
randomness and UUID generation are injectable through `KeystoreRandom`; new-key tests inject the
`PrivateKey` itself, so deterministic fixtures do not consume process randomness.

Import has two independent policies. `force_duplicate` permits another file for an address already
present in the directory; `overwrite` permits replacing the requested destination. Neither implies
the other. Update requires exactly one strict-scan match and derives the replacement address from
the decrypted private key instead of copying the JSON declaration.

Directory discovery parses strict JSON, bounds each entry to 8 KiB, and opens entries relative to a retained directory descriptor without following links. Every keystore-containing directory is required to be owned by the effective UID with exact POSIX mode 0700; violations return typed `InsecureDirectory`. Each scan, mutation, publication, and update holds an exclusive descriptor-backed advisory lock for the whole operation. Corrupt, BOM-prefixed, unquoted-field, oversized, symlink, and non-regular entries are reported as typed skip warnings. File ownership or POSIX mode violations are typed security errors rather than silent skips.

A configured direct-load path uses descriptor-relative nofollow traversal for every parent component. Only the final component may be a symbolic link: it is resolved with `readlinkat`, its target parent is independently anchored and secured, and the target is opened nofollow from that same resolution. The resulting `DirectLoadFollowedSymlink` warning therefore cannot describe a different pathname observation than the file that was opened. Direct load uses the legacy parser that accepts unquoted field names. All opened keystore files require effective-UID ownership and exact mode 0600.

Sensitive JSON is written to a create-new 0600 temporary file in the locked destination directory and flushed with `fsync`. Overwrite first moves the stable original to a descriptor-relative backup, publishes the replacement through the retained descriptor, verifies the parent identity, and syncs the directory. Any failure after publication removes the replacement and restores the original backup before the lock is released; successful completion removes the backup. Existing regular files are replaced only when overwrite is explicit. Parent symbolic links are rejected. Same-UID or root processes that disregard the advisory lock are outside this threat boundary because they can already read, replace, and delete the user's keys. Non-POSIX persistence remains explicitly unsupported.

## C006 shielded context lifecycle

The composition root loads and integrity-checks the TRON Sapling spend/output parameter files once, then injects the resulting `Arc<TronParameters>` into `ShieldedRawAdapter`. The crate does not read environment variables, discover parameter paths, or start workers. It contacts the external `TronZksnark` service only when a caller explicitly constructs the production client; that client is restricted to literal loopback IP endpoints and performs no endpoint discovery. Proving and verification initialization creates owned handle-table entries; free atomically retires an entry and dropping the last in-flight `Arc` releases it after an operation already holding the handle completes.

The default live-context bound is 64 and may be replaced only by an explicit positive construction-time bound. Handle-table locking is short-lived; operations clone the selected entry and then lock only that context. This permits bounded work on independent contexts without a global proof mutex and serializes transaction-local accumulation. Shutdown must stop ingress, wait for owned proof operations, then free all handles before releasing the shared parameters. Double-free and post-retirement use are reported rather than ignored.

Proving contexts accumulate spend trapdoors minus output trapdoors only after successful proof creation and use that sum for the binding signature. Verification contexts record only accepted spends and outputs; every proposed mutation is replayed into a fresh context before commit. The stateless `new` verification APIs allocate no handles. Pre-ZIP212 note encryption/decryption/recovery is synchronous and owns all ciphertext, memo, and key bytes; it starts no task and retains no global state. The C006.06 gRPC client owns a reusable tonic channel and a one-per-client in-flight semaphore; request permits are released on every success, transport failure, service failure, and timeout. It applies fixed connect/request deadlines and does not retry, queue, discover, or silently downgrade failures.

## Protobuf wire compatibility boundary

Inbound protobuf messages that can be hashed, signed, relayed, or returned byte-for-byte retain
their original wire bytes. Decoding provides an immutable known-field view; it does not authorize
re-encoding because prost discards unknown fields and cannot reproduce duplicate fields, explicit
defaults, or original map-entry order.

Constructed or mutated messages with no map fields may use the explicit constructed-message
encoder. For every map-bearing message, direct `prost::Message::encode` is non-compatible and
forbidden at observable boundaries: generated Rust maps do not retain the insertion order emitted
by protobuf-java. Callers must instead supply insertion-ordered pairs to `tron-protocol`'s bounded
`OrderedMapEncoder`, selecting the method for the descriptor's key/value wire kinds. Forward and
reverse insertion are distinct compatibility cases and must reproduce the corresponding Java bytes.
Resource bounds are mandatory and a rejected entry must leave accumulated bytes unchanged.

This C000.03 document defines structure only. Concrete traits and behavior belong to their owning implementation chunks and remain subject to C000.V architecture review.
