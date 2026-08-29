# Toolchains and platforms policy

## Pinned identities

- Rust: 1.85.1, minimal rustup profile, edition 2024, as declared by `rust-tron/rust-toolchain.toml` and the workspace manifests.
- Java reference source: the `java-tron` gitlink at `4a21592f95e37908b21bc3f611c6e7a1a67f09f3` from `https://github.com/tronprotocol/java-tron.git`.
- Java reference build: the checked-in Gradle 7.6.4 wrapper and Java 8-compatible runtime selected by the Java project.

The repository and lockfiles are the machine-readable pins. Host-local executable hashes and transient installation paths are not architecture requirements.

## Supported platform staging

The initial supported row is Linux x86_64 GNU (`x86_64-unknown-linux-gnu`). This limits initial build and qualification platforms, not Java protocol behavior, compatibility surfaces, ledgers, fixtures, or migration scope.

Stable future row IDs are reserved for Linux aarch64 (`P-LINUX-ARM64`), macOS x86_64 (`P-MACOS-X64`), and macOS aarch64 (`P-MACOS-ARM64`). Enabling a row requires its native executor, pinned toolchains, backend and feature selection, packaging path, and applicable gate commands. Cross-building or emulation may supplement but cannot establish native support. Windows, musl, 32-bit, big-endian, mobile, and WebAssembly remain unsupported until a later tracker chunk explicitly enables them.

The physical Java LevelDB/RocksDB format remains outside the initial Rust compatibility boundary under DR-001.

## Backend and feature policy

C000 selects no third-party storage, crypto, protobuf, networking, async, or FFI implementation. Dependencies are selected by the chunk that needs them and pinned in manifests and lockfiles. Competing implementations behind features must share one compatibility contract and must not alter consensus-visible bytes, ordering, state, errors, or timing semantics.

Default features form the production configuration. Features select implementations or optional operational surfaces, never protocol rules, wire values, state schemas, hash boundaries, or error categories. Unsupported combinations fail at configuration or compile time. Test, fault-injection, benchmark, and tracing features are excluded from release artifacts.

## Unsafe and native boundaries

Workspace-owned Rust uses `unsafe_code = "forbid"` by default. Any exception requires a narrow dedicated boundary, documented safety and ownership invariants, explicit supported platforms, deterministic cleanup, and direct failure/lifetime tests in its owning gate. Safe crates may not disable the workspace lint locally. Process-global initialization belongs in the lifecycle graph.

## Reproducible artifacts

Generated and released artifacts record the repository revision; relevant lockfiles; toolchain, target, backend and feature identities; normalized environment; inputs and command; and output hashes. Release artifacts additionally use the authenticated manifest, SBOM, provenance, and substituted-channel protections defined by C028 and C030. Mutable network inputs, floating dependency ranges, unrecorded environment influence, and generated files without a reproducible command are prohibited.
