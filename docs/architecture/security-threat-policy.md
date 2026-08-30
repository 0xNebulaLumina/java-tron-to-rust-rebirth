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
