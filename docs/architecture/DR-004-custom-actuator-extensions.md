# DR-004 — custom-actuator extension compatibility

## Decision

Custom actuators are a supported compatibility surface. Rust must preserve Java-equivalent deterministic discovery and registration, extension protobuf identity, owner extraction, dispatch, state mutation and revoke, transaction admission, broadcast/construction, and API query behavior. Unknown, malformed, duplicate, or colliding registrations fail closed before partial registration or state mutation.

## Stable extension contract

An extension declares a stable extension ID, descriptor-set digest, fully qualified protobuf message name, canonical `Any` type URL, numeric `ContractType`, owner-extraction function, actuator factory, deterministic registration priority, supported network/fork interval, state access declaration, API construction/query surfaces, and lifecycle owner. Registration order sorts by `(priority, extension_id)` and never depends on filesystem or service-loader iteration order. Built-in/extension and extension/extension collisions in full name, type URL, numeric contract type, extension ID, or dispatch key are explicit errors.

C001 owns descriptor/schema registration or runtime loading, full-name and type-URL formation, numeric allocation/encoding, collision behavior, and canonical bytes. C012 owns owner extraction, validation/execution, state deltas, and full revoke. C016 owns admission, permission/signature checks, dispatch, billing/result, and pending-session behavior. C022 owns construction, broadcast, exposure, and query surfaces. No domain may silently absorb another domain's seam.

## Example-derived end-to-end fixture

The later `DR004.ACTUATOR_EXAMPLE.E2E` fixture is derived from the pinned `java-tron/example/actuator-example` behavior. It must cover descriptor and type registration, canonical `Any` and transaction bytes, owner extraction, admission, execution, state mutation and revoke, API construction/query, malformed inputs, and every collision class. Fixture content must follow `license-provenance-policy.md`; this decision does not pre-implement or approve that later protocol fixture.

## Rejection and compatibility rules

Runtime loading accepts only authenticated, version-compatible extension packages selected by explicit configuration. Extension code has no ambient global state, bypass around permission or resource accounting, direct physical storage access, or undeclared API. State writes use the same revoking session as built-ins. Changes to descriptors, type allocation, owner rules, dispatch, state schema, API exposure, platform support, or dependencies require the affected integration scenario and owning gate to run again.
