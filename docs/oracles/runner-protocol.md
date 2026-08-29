# Reference runner protocol v1

Both launchers are distinct executable adapters with distinct implementation and toolchain identities over the same behavior-neutral protocol core. They do not execute node behavior. A runner reads exactly one UTF-8 JSON fixture from `--fixture PATH` or, when omitted, stdin; it writes exactly one compact JSON result to stdout. Diagnostics go to stderr. The Java launcher identifies the pinned Java reference boundary; the Rust launcher identifies the future Rust implementation boundary. In C000 both use the deterministic harness operation embedded in the fixture solely to prove framing, negative handling, comparison, and mismatch detection; the shared core must not introduce Java- or Rust-specific behavior.

## Commands and exits

- `java-runner run [--fixture PATH]` and `rust-runner run [--fixture PATH]`: exit 0 for an `ok` case, 10 for a fixture-declared error result, 64 for malformed/unsupported input, and 70 for an internal runner failure.
- `compare --java-result PATH --rust-result PATH`: writes a mismatch report; exits 0 on equality and 20 on any mismatch, including forbidden normalization.
- `identify`: writes protocol, source revision, implementation, and tool identity JSON and exits 0.

Input and emitted result schema version 1 are mandatory and are validated against the checked-in schemas before execution or comparison. Unknown schema versions, properties, harness operations, and mutations are rejected, never guessed. Invalid fixture JSON and every fixture schema/invariant failure produce a schema-valid `invalid_fixture` result with exit 64 and a typed `fixture/INVALID_FIXTURE` error. stdout contains no banners. JSON is UTF-8, compact, newline-terminated, object keys sorted, integers decimal, and canonical bytes lowercase even-length hexadecimal. Duplicate JSON object keys, NaN/infinity, non-integer JSON numbers, invalid Unicode, trailing data, invalid presence wrappers, duplicate or non-contiguous sequences, and non-canonical initial-state order are errors. `ok` requires exit 0 and no error; `error` requires exit 10 and a typed error; `invalid_fixture` requires exit 64 and `INVALID_FIXTURE`.

## Resource safety

Protocol implementations fail closed before schema recursion or comparison when a numeric ceiling is exceeded: 1,048,576 input bytes per document, JSON depth 64, 20,000 JSON values, 262,144 UTF-8 bytes per string or object key, 2,097,152 emitted bytes, 1,000 schema errors, 1,000 reported mismatches, and 40,000 queued comparison nodes. The checked-in `fixture-v1.schema.json` and `result-v1.schema.json` also bound collections and strings. A run-limit violation emits the schema-valid typed `fixture/INVALID_FIXTURE` result and exits 64; a comparison-limit violation emits a structured protocol error and exits 64. Implementations must not continue recursive validation, normalization, digesting, or comparison after a limit trips.

Governed platform subprocesses run one at a time, with at most 10 seconds per focused-cell child and 30 seconds for the top-level cell. Each stdout and stderr stream is incrementally drained and capped at 2,097,152 bytes; overflow terminates and reaps the child instead of accumulating further output. Stdin is capped at 1,048,576 bytes, except the unit cell's deliberate one-byte-over-limit probe. The smoke cell permits at most 8 commands; the unit cell permits 64 fixture files and 16 child invocations; the differential cell permits 32 cases, 96 child invocations, 64 result files, and 134,217,728 total temporary result bytes; and the native-resource cell permits 40 child invocations, 32 result files, and 67,108,864 total temporary result bytes. All cells use private temporary storage, keep at most one child active, and close streams, descriptors, files, and temporary directories on success, malformed input, overflow, and timeout. `tools/platform/run c000-smoke` exercises both launcher entry points plus invalid command paths; `tools/platform/run c000-native-resource` asserts repeated descriptor cleanup, file and directory cleanup, stdout and stderr overflow termination/reaping, and timeout termination/reaping. FFI and packaging remain reviewed not-applicable cells only while C000 has no such runtime surface.

## Deterministic environment

The orchestrator clears inherited locale/timezone/proxy variables and sets `LC_ALL=C.UTF-8`, `LANG=C.UTF-8`, `TZ=UTC`, a fixed fixture clock, a 256-bit fixture seed, disabled networking unless loopback is declared, a private empty temporary directory, umask 077, and unsigned-byte lexical filesystem ordering. Environment reads, wall clock, entropy, DNS, external network, host home/config, and ambient credentials are forbidden unless explicitly modeled by a later oracle case.

Every result records the pinned java-tron revision `df50ce9676b94de0b10a605076adfd8728811384`, protocol version, implementation, and toolchain. Artifact names are `<case-id>.<runner>.result.v1.json` and `<case-id>.mismatch.v1.json`; content digests are SHA-256 over the exact emitted bytes.

## Comparison

Comparison is structural after applying only `normalization-policy-v1.json`. Arrays remain ordered. State deltas compare sequence/store/key/before/after. Errors compare domain/code/message/details/retryable. Events and logs compare sequence/kind/fields. Presence distinguishes absent, explicit null, and present values. The report classifies all differences by output, state, error, event, log, exit, identity, forbidden normalization, or schema and gives JSON pointers plus both values.

Every applied normalization records the original value and canonical before/after digests. The comparator enforces the central rule's allowed oracle classes, JSON-pointer patterns, replacement, and value constraint; it rejects unresolved pointers and digest mismatches. A requested rule not in the central policy, a rule used by a disallowed oracle class, or a normalized pointer outside that rule's allowed pointer patterns is a `forbidden_normalization` mismatch. A fixture cannot define or widen a rule.

## C000 deterministic fixtures

`positive.json` proves equal output/state/events/logs. `negative.json` proves a deterministic typed error. Fixtures deliberately detect output, state, error, an unknown normalization rule, an allowed rule in a forbidden oracle class, and an allowed rule at a forbidden pointer. These are harness-contract fixtures only and confer no Java/Rust node compatibility evidence. C000.V remains responsible for executing and approving both runners and all cases.
