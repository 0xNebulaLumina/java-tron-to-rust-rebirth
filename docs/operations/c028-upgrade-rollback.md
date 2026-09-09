# C028 upgrade and rollback

1. Authenticate the candidate offline and enforce a release-sequence floor.
2. Run binary `preflight`; it is read-only and must reject Java/ambiguous/newer-format storage without creating a lock or marker.
3. Revoke readiness and ingress, stop with SIGTERM, and wait up to 120 seconds for reverse drain and durable storage close.
4. Create a checkpoint with `tron-toolkit db checkpoint` using the exact selector shown by `tron-toolkit db capabilities --json`. Retain the old immutable release/config slot and old storage generation.
5. Run `tron-toolkit db migrate`; after interruption use `db resume` or `db rollback`, never remove journals by hand. Switch slots only after migration and fsync complete.
6. Start, require `/healthz` then `/readyz`, verify target height/block/root, and retain or roll back according to the compatibility report.

Rollback is allowed only before an incompatible new writer crosses its declared point of no return. Do not start an old binary on newer-format storage. If downgrade is not declared compatible, preserve/quarantine the old tree and clean-resynchronize a fresh rustlog-v1 directory from genesis or import an authenticated snapshot. A rollback symlink is not evidence that storage is compatible.
