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

## Rejection and compatibility rules

Runtime loading accepts only authenticated, version-compatible extension packages selected by explicit configuration. Extension code has no ambient global state, bypass around permission or resource accounting, direct physical storage access, or undeclared API. State writes use the same revoking session as built-ins. Changes to descriptors, type allocation, owner rules, dispatch, state schema, API exposure, platform support, or dependencies require the affected integration scenario and owning gate to run again.
