# License and provenance policy

C000 establishes the constraints; it does not approve later dependencies, generated code, native components, fixtures, binaries, containers, or distributions.

Every introduced or shipped artifact must have a traceable origin, version or revision, license, copyright notices, generation or modification method, and intended distribution form. Generated code records its generator and inputs. Native libraries and parameters require authenticated sources, integrity verification, redistribution terms, supported architectures, and explicit runtime loading paths. Release artifacts additionally require the SBOM, signed release provenance, and substituted-channel rejection defined by the release gates.

Fixtures use one provenance category: `copied`, `mechanically_derived`, `clean_room`, or `newly_authored`. Copied and mechanically derived material records its upstream source and applicable notices and source obligations. Clean-room work records the behavior-only specification and separation used to avoid copying expressive implementation content. Newly authored work records its origin. The eight C000 harness fixtures are newly authored protocol fixtures; the later DR-004 actuator fixture must classify its own content when implemented.

The pinned `java-tron` source is LGPL-3.0-covered reference material. Repository-local inspection does not automatically permit copying into Rust code or distributed fixtures. Any copied or derived material must preserve applicable notices, identify modifications, and satisfy source-availability and linking obligations for the actual distribution form.

License compatibility is evaluated for the intended use, linkage, modification, notices, source offers, patents, export constraints, and project policy. Missing or ambiguous terms, incompatible obligations, unexplained generated origin, or absent required notices block the consuming item. A content, origin, version, license, generator, input, linkage, or distribution change requires a fresh determination. Legal exceptions must be explicit, scoped, time-bounded, and cannot override law or unknown ownership.
