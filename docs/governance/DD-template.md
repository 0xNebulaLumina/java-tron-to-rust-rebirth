# DD-### — dependency decision

- **Schema:** `dependency-decision-v1.schema.json`
- **Name/kind:** exact crate, tool, native/FFI, schema, fixture, parameter, or runtime identity
- **Exact version and source digest:** no range, branch, floating tag, or mutable URL; runtime/toolchain archive digests are captured in execution evidence when they are not checked in
- **Cargo/tool features:** complete enabled and disabled feature set; defaults explicit; an empty Cargo.lock is still inventoried and does not approve future crates
- **Consuming item(s) and local gate(s):** one adoption instance per consumer; repository inputs and execution tools use explicit `repository_input`/`inventory_only` dispositions
- **Alternatives:** selected/rejected candidates and evidence-backed rationale
- **Observable semantic contract:** bytes, ordering, errors, timing, state, determinism, serialization, concurrency, resource limits
- **Semantic gaps and adapters:** every gap, adapter owner, fixture/case, and rejection threshold
- **Unsafe/FFI:** safety, ownership, lifetime, aliasing, threading, panic, cleanup, native-resource contract
- **Platforms/features:** every applicable `P-*` row and unsupported combination
- **Maintenance:** release cadence, bus factor, issue/advisory response, upstream status
- **Security:** threat review, advisory query/evidence, reviewer, status, expiry/reopen triggers
- **License/provenance:** origin, digest, SPDX/notice/linkage/distribution analysis, reviewer, status, expiry/reopen triggers
- **Replacement/rollback:** abstraction boundary, data/wire compatibility, migration, rollback trigger and procedure
- **Approval:** named independent reviewer, exact revision/digests, date, expiry, findings and required reruns; security and license approvals may close independently for the exact adoption/tooling scope without closing architecture gate `C000.V`
- **Inventory/tooling boundary:** classify each record as `approved_repository_input`, `approved_tooling_scope`, `partially_approved_tooling_scope`, or an explicitly pending/rejected disposition. State exactly which checked-in inputs and fixed tool versions are approved and which runtime implementations, fetched archives, production crates, native libraries, backends, feature sets, or substituted toolchains remain unapproved.

Approval applies only to the recorded version, features, use, platform, source, and digest. Security/license tooling closure does not imply architecture approval. Any change creates or regenerates the consuming adoption instance and reopens the applicable decision/review.
