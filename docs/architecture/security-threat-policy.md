# Threat model and security closure policy

This C000.07 policy defines review obligations; it does not approve any later dependency, implementation, binary, fixture, parameter, or deployment.

## Assets, boundaries, and adversaries

Protected assets are consensus/state correctness; signing and shielded secrets; database/snapshot integrity and availability; protocol/API authenticity; operator credentials/configuration; build/release/fixture/schema provenance; native/FFI memory safety; and bounded CPU, memory, disk, descriptors, tasks, connections, and queues. Trust boundaries include P2P and discovery, gRPC/HTTP/JSON-RPC, event/plugin/plaintext interfaces, CLI/config/filesystem, snapshots/resync/migrations, Java oracle inputs/results, generated code and schemas, crates/build scripts, native libraries/FFI, Sapling parameters, containers/packages, and CI/release channels.

Adversaries include unauthenticated remote peers and clients, malicious contracts/blocks/snapshots/plugins/fixtures, compromised dependency or distribution channels, local unprivileged users, dishonest infrastructure, and accidental operators. Host root, kernel, hardware, and explicitly provisioned trust anchors are outside the application boundary but their assumptions must be stated. Plaintext interfaces are untrusted even on localhost; exposure, authentication, confidentiality, message limits, timeouts, concurrency and backpressure must be explicit.

## Severity and blockers

- **critical:** practical consensus divergence, unauthorized signing/secret extraction, remote arbitrary code execution, trust-anchor/release authentication bypass, or irreversible widespread state corruption. Blocks every merge/release; no residual-risk exception.
- **high:** exploitable authentication/authorization bypass, remotely induced persistent corruption, material shielded/privacy break, sandbox escape, or unauthenticated resource exhaustion causing sustained node unavailability. Blocks the owning gate and release; no release exception, though an authorized security lead may time-bound non-release research use.
- **medium:** bounded availability/confidentiality/integrity impact requiring meaningful preconditions, incomplete provenance/license controls, or defense-in-depth failure with a plausible exploit chain. Blocks the owning gate unless an authorized security lead and owning domain lead accept residual risk.
- **low:** limited hardening/documentation/observability weakness without a direct material exploit. Requires remediation or explicit disposition before the owning gate.

Every finding uses a stable ID, affected scope rows and revisions/digests, threat scenario, severity rationale, reproducibility/evidence, owner, remediation, fix revision, required reruns, and closure reviewer/date. Closure requires the fix, passing post-fix evidence, independent review, and no open linked findings.

## Exceptions and reopening

Only medium/low findings may receive residual-risk acceptance. The security lead plus owning domain lead must be named; license findings additionally require the authorized legal/provenance approver. Acceptance records rationale, compensating controls, evidence, affected releases/platforms/features, explicit expiry no later than 90 days or the next release (whichever is earlier), and a remediation owner/date. Missing, expired, widened, or unverifiable acceptance is open.

Reopen on covered source/schema/config/fixture/parameter/dependency/toolchain/native/binary change; new advisory/exploit; changed exposure or trust boundary; failed/absent/stale rerun; hash mismatch; expanded platform/feature; compensating-control failure; exception expiry; severity increase; or evidence/reviewer invalidation. Resource-exhaustion reviews must specify numeric input, allocation, recursion, queue, concurrency, timeout, disk and rate limits plus adversarial cases. Silent fallback, disabled verification, fail-open parsing, and unbounded attacker-controlled work are blockers according to impact.
