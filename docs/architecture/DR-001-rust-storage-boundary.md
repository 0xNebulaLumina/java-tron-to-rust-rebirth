# DR-001: Rust storage boundary, migration, and resynchronization

**Status:** accepted architecture contract; implementation and verification remain C007/C028 obligations.  
**Decision owner:** C000.06.  

Initial Rust releases must not open as Rust state, mutate, repair, migrate, lock, compact, checkpoint, rename, delete, or add files to a java-tron LevelDB/RocksDB directory. Physical compatibility is rejected; logical keys, values, ordering, roots, results, and observable behavior remain compatibility requirements.

## Detection and no-write rule

Before obtaining a writable handle or lock, startup/tooling examines the requested path read-only. A recognized Java layout, an ambiguous non-empty directory without a valid Rust manifest, a corrupt manifest, unknown/newer format, wrong network/genesis, unsupported backend/features, or partial migration is rejected. Detection may read metadata and bytes only. Rejection must leave the complete directory tree byte-for-byte and metadata-neutral: no lock, log, temp, manifest, backup, marker, access-time-dependent rewrite, permission, ownership, rename, or deletion. Diagnostics identify the classification and safe operator choices. Tests snapshot paths, types, contents, sizes, permissions, ownership, and timestamps before and after rejection.

## Rust manifest

A Rust-owned directory begins with an atomically installed, checksummed manifest containing manifest/schema versions, network and genesis identities, backend and backend-format identity, required feature flags, creation/migration lineage, clean/dirty state, and integrity fields. Unknown fields are preserved only where the manifest version defines that behavior; unknown/newer required semantics are fatal. No backend opens before manifest validation.

## Migration contract

Only explicitly supported Rust-to-Rust version edges may migrate. Preflight validates identity, integrity, free space, exclusive access, executable/tool compatibility, backup destination, and rollback capability. Migration writes to a separate staging generation, journals each durable phase, fsyncs files and directories, validates logical state/root, then atomically switches the manifest generation. Failure before switch retains the old generation; failure after switch follows the journaled recovery rule. Backup retention, point of no return, executable/config retention, resumability, rollback, and downgrade safety are explicit per edge. Java-to-Rust import is a future, separately reviewed boundary and cannot be represented as a migration edge.

## Resynchronization

Operators may initialize an empty Rust directory and resynchronize from genesis, or import an independently authenticated Rust snapshot after network/genesis/checkpoint, completeness, freshness, anti-rollback, signature, and logical-root validation. Import stages outside the live generation and switches atomically. Failure leaves no partially usable database. A clean-resync marker records intent and origin without weakening validation.

## Errors and revisit trigger

Errors are stable categories: `java_format`, `ambiguous_nonempty`, `manifest_missing`, `manifest_corrupt`, `format_unknown`, `format_newer`, `wrong_network`, `wrong_genesis`, `backend_unsupported`, `features_unsupported`, `partial_migration`, `locked`, `permission`, and `integrity`. Each is actionable and never silently falls back to initialization.

Revisit only through a new decision record after a Java importer demonstrates read-only source handling, canonical logical-state extraction, state-root equality, crash safety, provenance, and byte/state differential validation. Until then, documentation, CLI, and tooling must say “resync/import verified Rust snapshot,” never “reuse Java database.”
