---
status: accepted
date: 2026-07-27
supersedes:
  - 0002
extends:
  - 0001
governs:
  - rust/Cargo.toml
  - rust/src/lib.rs
  - rust/src/evidence/**
  - rust/src/replay/**
  - rust/src/adapters/**
  - rust/tests/**
  - .github/workflows/**
  - justfile
  - CHANGELOG.md
  - README.md
why: Netbraid is one product with one release cadence; separate registry packages add ownership, bootstrap, publication-order, and compatibility work without independent releases or consumers that require those package boundaries.
rejected:
  - Publish four lockstep packages to preserve source-directory boundaries
  - Publish only the root package while retaining unpublished runtime path dependencies
  - Flatten evidence, replay, and TShark process semantics into one undifferentiated module
  - Make CLI and TShark dependencies unavoidable for evidence and replay consumers
confidence: high
review_trigger: Revisit only when a module has independent external consumers, a materially different release cadence, or a dependency or compatibility boundary that optional features cannot preserve.
---

# Publish one Netbraid package

## Context

ADR-0002 prepared four crates.io packages in dependency order. That topology
made each source boundary independently installable, but it also required four
initial ownership publications, four trusted-publisher registrations,
bottom-up release orchestration, and lockstep version compatibility for one
product.

The original boundaries protect real invariants: evidence records are
policy-neutral, replay is deterministic, and saved-capture normalization owns a
bounded TShark process boundary. Git history does not show that those
invariants require independent registry artifacts. Linktop needs library APIs
without invoking the Netbraid CLI, but it does not need an independently
versioned evidence or replay release. No prepared 0.3.0 package has been
published and no `netbraid-v0.3.0` tag exists, so the distribution topology can
still change without abandoning a registry identity.

Cargo cannot publish a package whose runtime dependencies exist only as
unpublished path dependencies. Publishing only the root package while keeping
the three private packages is therefore not a workable intermediate state.

## Decision

Publish one crates.io package named `netbraid`. It contains both a public Rust
library and the `netbraid` operator binary:

```text
netbraid
├── evidence
├── replay
├── adapters
│   └── tshark
└── bin: netbraid
```

The source modules preserve the prior responsibilities:

- `netbraid::evidence` owns versioned records and local invariants;
- `netbraid::replay` owns deterministic parsing, comparison, reduction, and
  finite scenario replay; and
- `netbraid::adapters::tshark` owns bounded offline Wireshark-tool invocation and
  normalization.

The `adapters::tshark` module is behind the `adapter-tshark` Cargo feature.
The default `cli` feature enables it plus CLI-only dependencies, and the binary
requires `cli`. Library consumers that need only evidence and replay use
`default-features = false`; scenario fixture feature names remain stable.
This keeps one registry identity without making Linktop compile the CLI and
TShark dependency surface.

Package topology does not rename durable data. Existing `netmon.*` schemas,
digest profiles, field registries, corpus identifiers, and the
`netbraid-adapter-tshark` producer identity remain unchanged.

The single Cargo source archive includes the capture-derived scenario that is
a supported non-default product fixture. Its aggregate license is therefore
`(MIT OR Unlicense) AND BSD-3-Clause`, and the exact BSD notice remains in the
closed scenario inventory. Test-only upstream adapter and CLI corpora remain
in the GitHub repository and CI but are excluded from the registry archive.

The release workflow verifies and publishes only `netbraid`. Initial crates.io
ownership requires one scoped-token publication, followed by one trusted
publisher registration and immediate token revocation. Later releases retain
current-main, green-CI, immutable version/tag, registry metadata, Cargo VCS,
native archive, checksum, and attestation gates.

Version 0.3.0 remains the first intended registry version. ADR-0002's earlier
candidate commit is superseded by this explicit decision before publication;
the new package inventory and candidate commit must pass the same immutable
release checks before a tag is created.

## Consequences

- Operators use the normal `cargo install netbraid` path and maintainers own
  one registry release.
- Rust consumers import `netbraid::evidence` and `netbraid::replay` from one
  semver dependency. Existing exact-Git consumers can migrate deliberately;
  their pinned commit remains buildable until then.
- Semantic API review remains necessary even though module versions no longer
  move independently.
- The source archive's aggregate license is broader than the authored code's
  dual license because supported fixture bytes ship in the same package.
- A future crate split must be earned by independent consumers, cadence, or a
  dependency/compatibility boundary. Source organization alone is not enough.
