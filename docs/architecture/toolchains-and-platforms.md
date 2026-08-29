# Toolchains and platforms policy

## Pinned reference identities

- Rust toolchain declaration: `rustc`/Cargo 1.85.1, minimal rustup profile, as declared by `rust-tron/rust-toolchain.toml`. On the current Linux x86_64 host the locally installed 1.85.1 binaries identify `rustc 1.85.1 (4eb161250 2025-03-15)` (`sha256:f8d033fd72e878ec60493788c8bffec2e6c154dcab6f0cb4c145af8ada26a7ed`) and `cargo 1.85.1 (d73d2caf9 2024-12-31)` (`sha256:87e9ff02f95ea17d877e7c4eeb0f365f50fe3827f5afec132131ff3b8031a57e`). The installed rustup is `rustup 1.29.0 (28d1352db 2026-03-05)`, `sha256:4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10`. These binary hashes prove only this host installation; rustup distribution archive origins/digests remain `review_required` until authenticated download metadata or retained archives are supplied.
- Rust edition and minimum version: edition 2024 and `rust-version = 1.85.1`.
- Java reference source: gitlink `java-tron` from `https://github.com/tronprotocol/java-tron.git` at revision `4a21592f95e37908b21bc3f611c6e7a1a67f09f3`.
- Java reference build: Gradle 7.6.4, revision `e0bb3fc8cefad8432c9033cdfb12dc14facc9dd9`, from checked-in wrapper origin `https://services.gradle.org/distributions/gradle-7.6.4-bin.zip`; the current host's retained distribution archive is `sha256:bed1da33cca0f557ab13691c77f38bb67388119e4794d113e051039b80af9bb1` and the checked-in wrapper JAR is `sha256:3dc39ad650d40f6c029bd8ff605c6d95865d657dbfdeacdb079db0ddfffedf9f`.
- Java runtime policy: Eclipse Temurin `8u462-b08` for the initial Linux x86_64 GNU row, preserving the checked-in Java major-version selection. No matching Temurin archive is retained on the current host, and the installed Ubuntu OpenJDK 17.0.20 runtime is not the policy JDK; therefore JDK origin/archive digest and reference-runtime approval remain `review_required`. Unblocking requires the authenticated Temurin release URL/signature metadata, retained archive SHA-256, extracted `java -version`, and a native reference run using that exact archive. Every later platform-enablement task must pin and prove its own JDK identity; substituting a vendor or patch release invalidates affected evidence.

The repository revision pins the Java source and this Rust architecture together. Generated evidence must additionally identify the exact dirty/clean state; a dirty tree cannot claim released provenance.

Current-host command runtimes used by C000 governance tooling are pinned independently of production support: `/usr/bin/python3.12` is Ubuntu package `python3.12 3.12.3-1ubuntu0.15`, reports Python 3.12.3, and is `sha256:1643dacd9feaedc58f3cc581e4d22577dfe25c09b10282936186ccf0f2e61118`; `/bin/sh` resolves to `/usr/bin/dash`, Ubuntu package `dash 0.5.12-6ubuntu5`, `sha256:86d31f6fb799e91fa21bad341484564510ca287703a16e9e46c53338776f4f42`. Those implementation identities remain `review_required` pending authenticated package-origin/license evidence; another executable, package build, symlink target, or digest is a substitution and invalidates the affected tool evidence.

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
