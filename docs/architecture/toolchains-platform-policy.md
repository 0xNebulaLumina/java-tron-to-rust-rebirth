# Toolchains, platforms, features, unsafe, and provenance policy

## Pinned reference identities

- Rust toolchain: `rustc`/Cargo 1.85.1, minimal rustup profile, as declared by `rust-tron/rust-toolchain.toml`.
- Rust edition and minimum version: edition 2024 and `rust-version = 1.85.1`.
- Java reference source: checked-in `java-tron` tree at repository revision `df50ce9676b94de0b10a605076adfd8728811384`.
- Java reference build: Gradle 7.6.4 from `java-tron/gradle/wrapper/gradle-wrapper.properties`.
- Java runtime: Eclipse Temurin `8u462-b08` for x86_64 and Eclipse Temurin `17.0.16+8` for aarch64, preserving the checked-in Java major-version selection. Platform evidence must record the distribution archive digest; substituting a vendor or patch release invalidates the affected evidence.

The repository revision pins the Java source and this Rust architecture together. Generated evidence must additionally identify the exact dirty/clean state; a dirty tree cannot claim released provenance.

## Supported platform/backend rows

These are architecture-policy rows, not passing evidence. Native versus cross-built/emulated execution and exact commands are deferred to C000.14.

| Row | OS | Architecture | Rust target | Java JDK | Rust storage backend policy | Native boundary policy |
|---|---|---|---|---|---|---|
| P-LINUX-X64 | Linux | x86_64 | `x86_64-unknown-linux-gnu` | Temurin `8u462-b08` | Rust-owned default backend; LevelDB/RocksDB candidates require later adoption approval | Native execution required for release qualification |
| P-LINUX-ARM64 | Linux | aarch64 | `aarch64-unknown-linux-gnu` | Temurin `17.0.16+8` | Rust-owned default backend; no assumed Java LevelDB support | Native execution required; cross-build may be supplemental only |
| P-MACOS-X64 | macOS | x86_64 | `x86_64-apple-darwin` | Temurin `8u462-b08` | Rust-owned default backend; backend availability must be proven | Native execution required for release qualification |
| P-MACOS-ARM64 | macOS | aarch64 | `aarch64-apple-darwin` | Temurin `17.0.16+8` | Rust-owned default backend; no assumed Java LevelDB support | Native execution required for release qualification |

Windows, musl, 32-bit, big-endian, iOS, Android, and WebAssembly are unsupported unless a later reviewed tracker change adds complete rows and gates. The physical Java LevelDB/RocksDB format is not supported by initial Rust releases (DR-001); no backend choice may silently relax that boundary.

## Backend policy

C000 selects no third-party storage, crypto, protobuf, networking, async, or FFI implementation. A backend enters the graph only through a consuming-item `DD-###` record covering exact version/features, supported rows, observable semantic gaps, determinism, maintenance, security, license, provenance, and replacement/rollback. Multiple implementations behind a feature must share one compatibility contract and may not change consensus-visible bytes, ordering, errors, or timing semantics.

## Feature policy

- Default features must form the production configuration and be identical across supported platforms except for reviewed platform adapters.
- Features select implementations or optional operational surfaces, never consensus rules, wire values, state schema, hash boundaries, or error categories.
- Feature combinations are closed and enumerated in the C000.14 manifest; undeclared combinations are unsupported and must fail at configuration or compile time.
- Development, test-oracle, fault-injection, benchmark, and tracing features must not be enabled in release artifacts.
- Cargo features are additive. Mutually exclusive backends require an explicit compile-time rejection rather than precedence by accident.

## Unsafe and FFI policy

Workspace-owned Rust is `unsafe_code = "forbid"` by default. An unsafe or FFI need requires all of the following before code lands: a consuming tracker item; approved dependency/adoption and security/license records; a narrow dedicated module or crate; documented safety, lifetime, aliasing, threading, panic, ownership, and cleanup invariants; explicit supported platform rows; and direct failure/lifetime tests at the owning gate. Safe crates may not disable the workspace lint locally. Native handles must use deterministic ownership and cleanup; process-global initialization must be explicit in the lifecycle graph.

## Reproducible artifact and provenance policy

Every generated or released artifact must bind:

1. repository revision and clean-tree state;
2. Rust, Cargo, rustup target, Java, Gradle, generator, linker, and native tool identities;
3. target triple, OS image, architecture, backend, complete feature set, and environment normalization;
4. dependency lockfile and approved adoption inventory digests;
5. source/schema/config/fixture/input digests and the exact command;
6. output paths, sizes, SHA-256 digests, timestamps, exit status, stdout/stderr artifact digests, and per-case outcome;
7. builder identity and, for release artifacts, authenticated provenance/SBOM bindings defined by later release gates.

Network-fetched mutable inputs, floating dependency ranges, unrecorded environment influence, and generated files without a reproducible command are prohibited. C000.02 establishes this policy only; platform evidence and approvals remain pending C000.14 and C000.V.
