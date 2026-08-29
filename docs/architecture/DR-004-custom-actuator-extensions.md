# DR-004 — custom-actuator extension compatibility

## Decision

Custom actuators are a supported compatibility surface. Rust must preserve Java-equivalent deterministic discovery and registration, extension protobuf identity, owner extraction, dispatch, state mutation/revoke, transaction admission, broadcast/construction, and API query behavior. Unknown, malformed, duplicate, or colliding registrations fail closed before partial registration or state mutation.

## Stable extension contract

An extension declares a stable extension ID, descriptor-set digest, fully qualified protobuf message name, canonical `Any` type URL, numeric `ContractType`, owner-extraction function, actuator factory, deterministic registration priority, supported network/fork interval, state access declaration, API construction/query surfaces, and lifecycle owner. Registration order sorts by `(priority, extension_id)` and never filesystem/service-loader iteration order. Built-in/extension and extension/extension collisions in full name, type URL, numeric contract type, extension ID, or dispatch key are explicit errors.

C001 owns checked descriptor/schema registration or runtime loading, full-name/type-URL formation, numeric allocation/encoding, collision behavior, and canonical bytes. C012 owns owner extraction, validation/execution, state deltas and full revoke. C016 owns admission, permission/signature checks, dispatch, billing/result and pending-session behavior. C022 owns construction, broadcast, exposure and query surfaces. These ownership rows are mandatory and no domain may silently absorb another domain's seam.

## Example-derived end-to-end fixture

The pinned `java-tron/example/actuator-example` source yields fixture `DR004.ACTUATOR_EXAMPLE.E2E`: register descriptor and actuator; construct extension message; wrap canonical `Any`; construct and broadcast transaction contract; extract owner; admit and dispatch; compare result bytes and ordered logical state delta; query through API; revoke and prove exact initial state. Negative siblings cover malformed descriptor/message, unknown type URL/type number, every collision class, nondeterministic order, invalid owner, validation failure, execution rollback, API disabled/unregistered, and pending-session revoke. C001/C012/C016/C022 each own its case slice; C022.V owns final end-to-end closure after prerequisite gates.

## Rejection and compatibility rules

Runtime loading is allowed only from authenticated, version-compatible, approved adoption inventory instances. Extension code has no ambient global state, bypass around permission/resource accounting, direct physical storage access, or undeclared API. State writes use the same revoking session and evidence schema as built-ins. A descriptor, type allocation, owner rule, dispatch adapter, state schema, API exposure, platform, or dependency change invalidates all affected evidence and review.
