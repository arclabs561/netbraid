---
status: accepted
date: 2026-07-26
extends:
  - 0001
governs:
  - rust/Cargo.toml
  - rust/crates/*/Cargo.toml
  - rust/crates/*/README.md
  - rust/crates/*/LICENSE-MIT
  - rust/crates/*/UNLICENSE
  - .github/workflows/**
  - CHANGELOG.md
  - README.md
why: Real registry packages give Linktop and operators a normal reproducible dependency and cargo-install path without sibling checkouts or floating Git dependencies.
rejected:
  - Reserve names with placeholder crates that do not ship useful behavior
  - Publish only libraries while keeping the operator CLI GitHub-only
  - Replace GitHub native archives with crates.io source installation
confidence: high
review_trigger: Revisit if a package has no independent consumer or its release cadence can no longer remain compatible with the workspace version.
---

# Publish the Netbraid CLI and libraries to crates.io

## Context

The initial Rust boundary used exact Git revisions and `publish = false`.
That was useful while the record and replay APIs were experimental, but it
makes every consumer fetch repository source and prevents
`cargo install netbraid`. Publishing only empty name reservations would create
registry ownership without a usable artifact.

## Decision

Publish the real 0.2 workspace packages to crates.io in dependency order:

1. `netbraid-evidence`
2. `netbraid-replay`
3. `netbraid-adapter-tshark`
4. `netbraid`

Every internal published edge carries both a local `path` and version `0.2.0`.
Package publication is restricted to the `crates-io` registry. Each package
ships its own focused README, both license texts, and any compile-time test
fixtures it needs, so extracted package tests do not depend on workspace
siblings.

The root `netbraid` package is the real operator CLI, not a placeholder, so
`cargo install netbraid` installs useful behavior. The three libraries remain
independently consumable.

GitHub native archives, checksums, and attestations remain a parallel
distribution channel. Crates.io publication does not create a daemon, hosted
service, store, fusion authority, or automatic collection behavior.

## Consequences

- Release order is bottom-up; a dependent package cannot complete registry
  verification until its dependency version is live.
- Package API and compatibility now require deliberate semver and changelog
  discipline.
- Native archive users retain the existing release path, while Rust consumers
  no longer need a sibling checkout.
