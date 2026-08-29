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
