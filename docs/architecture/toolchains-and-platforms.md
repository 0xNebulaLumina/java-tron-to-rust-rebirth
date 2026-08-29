# Toolchains and platforms policy

## Pinned reference identities

- Rust toolchain: `rustc`/Cargo 1.85.1, minimal rustup profile, as declared by `rust-tron/rust-toolchain.toml`.
- Rust edition and minimum version: edition 2024 and `rust-version = 1.85.1`.
- Java reference source: checked-in `java-tron` tree at repository revision `df50ce9676b94de0b10a605076adfd8728811384`.
- Java reference build: Gradle 7.6.4 from `java-tron/gradle/wrapper/gradle-wrapper.properties`.
- Java runtime: Eclipse Temurin `8u462-b08` for the initial Linux x86_64 GNU row, preserving the checked-in Java major-version selection. Every later platform-enablement task must pin and prove its own JDK identity. Platform evidence must record the distribution archive digest; substituting a vendor or patch release invalidates the affected evidence.

The repository revision pins the Java source and this Rust architecture together. Generated evidence must additionally identify the exact dirty/clean state; a dirty tree cannot claim released provenance.

## Initial supported platform/backend row

The first architecture chunk supports and verifies one conservative native row on the available host. This narrows only build and verification platform support; it does not narrow Java protocol behavior, compatibility surfaces, ledgers, fixtures, or migration scope.

| Row | OS | Architecture | Rust target | Java JDK | Rust storage backend policy | Native boundary policy |
|---|---|---|---|---|---|---|
| P-LINUX-X64 | Linux | x86_64 | `x86_64-unknown-linux-gnu` | Temurin `8u462-b08` | Rust-owned default backend; LevelDB/RocksDB candidates require later adoption approval | Native execution required for C000 and release qualification |

The following stable platform row IDs are reserved for explicit later enablement and are not supported rows or C000 blockers: `P-LINUX-ARM64` (`aarch64-unknown-linux-gnu`), `P-MACOS-X64` (`x86_64-apple-darwin`), and `P-MACOS-ARM64` (`aarch64-apple-darwin`). Enabling one requires a reviewed tracker change that pins its JDK/toolchain and native executor, adds it to the supported manifest, supplies every applicable command and current native evidence, and updates downstream packaging/release gates. Cross-build or emulation may provide supplemental evidence but cannot establish native support.

Windows, musl, 32-bit, big-endian, iOS, Android, and WebAssembly remain unsupported unless a later reviewed tracker change adds complete rows and gates. The physical Java LevelDB/RocksDB format is not supported by initial Rust releases (DR-001); no backend choice may silently relax that boundary.

## Backend policy

C000 selects no third-party storage, crypto, protobuf, networking, async, or FFI implementation. A backend enters the graph only through a consuming-item `DD-###` record covering exact version/features, supported rows, observable semantic gaps, determinism, maintenance, security, license, provenance, and replacement/rollback. Multiple implementations behind a feature must share one compatibility contract and may not change consensus-visible bytes, ordering, errors, or timing semantics.

## Feature policy

- Default features must form the production configuration and be identical across supported platforms except for reviewed platform adapters.
- Features select implementations or optional operational surfaces, never consensus rules, wire values, state schema, hash boundaries, or error categories.
- Feature combinations are closed and enumerated in the C000.14 manifest; undeclared combinations are unsupported and must fail at configuration or compile time. Later platform enablement must use the same protocol contract unless a separately reviewed compatibility decision says otherwise.
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

Network-fetched mutable inputs, floating dependency ranges, unrecorded environment influence, and generated files without a reproducible command are prohibited. C000.02 establishes the initial Linux x86_64 GNU support policy and records later platform enablement requirements only; platform evidence and approvals remain pending C000.14 and C000.V.
