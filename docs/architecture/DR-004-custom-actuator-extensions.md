# DR-004 — custom-actuator extension compatibility

## Decision

Custom actuators are a supported Rust extension surface. The descriptor namespace introduced here is a newly authored Rust ABI, not a schema or numeric allocation derived from `java-tron/example/actuator-example`, and it is not claimed to be Java-compatible. Later domains must separately decide and prove owner extraction, dispatch, state mutation and revoke, transaction admission, broadcast/construction, and API query behavior. Unknown, malformed, duplicate, or colliding registrations fail closed at construction before any registry is returned or state mutation can occur.

## Stable extension contract

An extension declares a stable extension ID, descriptor-set digest, fully qualified protobuf message name, numeric `ContractType`, owner-extraction function, actuator factory, deterministic registration priority, supported network/fork interval, state access declaration, API construction/query surfaces, and lifecycle owner. The canonical `Any` type URL is derived solely as `type.googleapis.com/<fully-qualified-message-name>` and therefore is not a separately declared or independently colliding identity. Registration order sorts by `(priority, extension_id)` and never depends on filesystem or service-loader iteration order. Built-in/extension and extension/extension collisions in full name, numeric contract type, extension ID, or dispatch key are explicit errors.

C001 owns descriptor/schema registration or runtime loading, full-name and type-URL formation, numeric allocation/encoding, collision behavior, and canonical bytes. C012 owns owner extraction, validation/execution, state deltas, and full revoke. C016 owns admission, permission/signature checks, dispatch, billing/result, and pending-session behavior. C022 owns construction, broadcast, exposure, and query surfaces. No domain may silently absorb another domain's seam.

## C001 descriptor boundary

The descriptor-only registry consumes a complete batch and either returns one fully constructed
registry or an error; it has no mutable publication target and cannot expose a partially accepted
batch. Entries are ordered by `(priority, extension_id)`. Before descriptor decoding, the constructor
bounds the batch at 64 entries and each descriptor set at 1 MiB, then verifies the declared SHA-256
digest. During structural validation it bounds each set at 128 files, 8192 contributed symbols, and
32 nested-message levels. The declared fully qualified message must exist, and its canonical URL is
derived as `type.googleapis.com/<fully-qualified-message-name>`.

Registration inventories every contributed file name and symbol, not only the selected message.
Symbols include top-level and nested messages and enums, enum values in protobuf scope, fields,
extensions, services, and methods. Duplicate file names within one descriptor, against the canonical
pool, or across prior extensions fail closed. Duplicate symbols within one descriptor, against any
canonical symbol, or across prior extensions likewise fail closed, including when both selected
messages are otherwise unique. Resource excess, malformed or unnamed descriptor elements, and all
identity collisions are rejected before an immutable registration list is returned.

Canonical Java built-in numbers remain unchanged, including `CustomContract = 20`. A declaration
of any canonical built-in number is reported as `BuiltInContractTypeCollision` before extension
allocation-range validation. The closed interval `1000..=1999` is a newly authored Rust extension
namespace: it is neither present in Java's canonical `ContractType` enum nor claimed to be accepted
by Java nodes. The newly authored example identity is
`org.tron.example.actuator.ExampleContract`, with type URL
`type.googleapis.com/org.tron.example.actuator.ExampleContract` and Rust extension type number
`1000`. These are Rust byte-level ABI allocation rules, not Java compatibility or runtime dispatch
approval.

This is the explicit C001.08 compatibility decision: `java-tron/example/actuator-example`
defines Java actuator behavior but no protobuf message, descriptor, fully qualified protobuf name,
`Any` type URL, or numeric contract identity from which these bytes could be derived. C001 therefore
delivers the newly authored Rust descriptor namespace above and makes no example-derivation claim.
Whether a later integration adopts a distinct Java-compatible custom-actuator protobuf and numeric
identity is intentionally deferred to the downstream C012/C016/C022 integration decision and proof;
it is not a C001 compatibility property.

`docs/oracles/dr004-extension-fixtures.v1.json` inventories the canonical descriptor, message,
`Any`, transaction-contract, malformed-descriptor, and collision fixtures. C001 does not implement
owner extraction, actuator factories, validation/execution, state mutation/revoke, admission,
broadcast, construction, or query behavior.

## Newly authored extension fixture

The `DR004.ACTUATOR_EXAMPLE.E2E` seed schema and C001 bytes are newly authored for this Rust port.
They are not derived from `java-tron/example/actuator-example`, which supplies no matching protobuf
message or numeric contract identity. The eventual runtime fixture must additionally cover owner
extraction, admission, execution, state mutation and revoke, API construction/query, malformed
runtime inputs, and runtime collision handling. Per-file provenance and restricted test-only
distribution status are recorded in `docs/oracles/dr004-extension-fixtures.v1.json`; C001 does not
pre-implement or approve behavior owned by C012, C016, or C022.

## C012 execution registry

C012 composes the immutable C001 descriptor registry with an equally immutable batch of custom
actuator providers. Providers are trusted, statically linked, reviewed native node code; this
surface is never a sandbox and never accepts an untrusted or dynamically discovered plugin. The
composition root must bind each provider to an allowlisted provider identity and reviewed binary
or source SHA-256 digest. A provider absent from that exact identity-and-digest allowlist rejects
the whole construction.

Provider metadata is invoked exactly once, caught for unwind panics, validated, and retained as an
immutable snapshot. Provider order is normalized by `(priority, extension_id)`, and every provider
must exactly match one descriptor registration in extension ID, priority, protobuf full name, and
numeric contract type. Missing, extra, duplicate, colliding, or mismatched providers reject the
whole construction. Provider payload declarations are nonzero and bounded at 1 MiB. Raw state
access declarations are bounded at 64 entries before duplicate declarations are deduplicated, so
duplicates cannot evade the resource bound. Each entry separately declares read and write access;
writes do not imply reads. `Common`, `Checkpoint`, and `Temporary` are sensitive node-internal
stores and cannot be granted to an extension.

Canonical built-ins decode directly into their generated prost message type without descriptor
reflection. Owner extraction uses `owner_address`, except shielded transfer's canonical
`transparent_from_address`. `CustomContract` and `GetContract` have no corresponding generated
contract payload and fail explicitly. A canonical contract whose C012 actuator has not yet been
implemented decodes and exposes its owner but returns `UnsupportedBuiltInActuator` on dispatch.

Custom providers receive protobuf payload bytes through typed, provider-owned decoding functions;
the execution registry performs no reflection and grants no physical-store handle. Every generic
get/decode, dynamic-property read, account-asset read, account-asset write, put, and delete checks
the immutable read/write capability snapshot. These checks apply during validation and execution.
Providers construct the normal `Actuator` trait object, so execution validates and mutates a child
revoking session, merges state and publishes deltas only on success, and revokes the child while
recording a failed result on error. Registry calls catch Rust unwind panics and convert them into
node errors where unwinding permits. Process abort/exit and ambient native effects cannot be caught
or revoked and therefore remain part of the trusted-native-code boundary. The exact surface,
limits, errors, and test ownership are recorded by `docs/oracles/c012-registry-extension.v1.json`.

### C012 compatibility-oracle boundary

The C012 extension oracle is a `newly_authored_rust_contract`, not a pinned-Java observation.
Its twelve variants derive expected behavior only from the authenticated descriptor bytes, the
provider metadata that must exactly match that descriptor registration, and the provider's declared
state-access contract. The oracle freezes concrete protobuf payload bytes, provider limits, initial
store contents, result fields, ordered byte deltas, error identities, construction atomicity, and
child-session revoke outcomes. It covers owner/dispatch, a declared write, validation and execution
failure, an undeclared write, missing/mismatched/colliding providers, runtime type-URL mismatch, the
inclusive payload bound and its first rejected byte, and the declared-store resource bound.

`docs/oracles/c012-execution-fixtures.v1.json` keeps this extension evidence in the
`dr004_rust_extension` namespace. The `built_in_java_differential` namespace remains separate: Java
revision, method mapping, and Java execution hashes apply only there and cannot authenticate or
approve an extension expectation. C012 acceptance requires an independent Rust test to execute all
twelve extension IDs through the actual registry and, where execution is applicable, a real
revoking `Session`; constant-only comparisons are not evidence. A reviewer must record either
`approved` or `changes_requested` after confirming provenance, all twelve executions, namespace
separation, and the absence of a Java-compatibility claim.

## Rejection and compatibility rules

There is no runtime plugin loader. Only trusted, statically linked native providers selected at the
composition root by an exact allowlisted identity and reviewed code digest can be registered.
Extension code remains inside the node process and is not sandboxed: process exit/abort and ambient
native effects are outside session revoke. State access is restricted to declared read/write
capabilities and excludes sensitive internal stores. Changes to provider code or digest,
descriptors, type allocation, owner rules, dispatch, state schema, API exposure, platform support,
or dependencies require the affected integration scenario and owning gate to run again.
