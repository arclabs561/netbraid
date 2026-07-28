---
status: superseded
date: 2026-07-26
superseded_by:
  - 0005
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

Publish the real workspace packages to crates.io in dependency order:

1. `netbraid-evidence`
2. `netbraid-replay`
3. `netbraid-adapter-tshark`
4. `netbraid`

Every internal published edge carries both a local `path` and the exact
workspace version. Package publication is restricted to the `crates-io`
registry. Each package ships its own focused README, both license texts, and
any compile-time test fixtures it needs, so extracted package tests do not
depend on workspace siblings.

A workspace version is one immutable release identity across crates.io, the
Git tag, and GitHub release. The release gate rejects publication when the
version's tag already points to another commit. In particular, the existing
`netbraid-v0.2.0` tag prevents a later `main` commit from becoming a different
registry artifact also called 0.2.0; the first registry publication must use
the next deliberately bumped release version.

After initial registry ownership is bootstrapped, the GitHub release workflow
uses crates.io Trusted Publishing rather than a long-lived registry secret. A
confirmed manual run is the only publication authority: it requires the
checked-out commit to equal current `main`, requires successful push CI for
that exact SHA, publishes bottom-up, and verifies registry name, version,
repository, yanked state, Cargo VCS SHA, and dirty state. The release tag path
is verification-only and creates the GitHub release only after all four
registry artifacts match.

Crates.io cannot configure a trusted publisher for a crate that does not yet
exist. Initial ownership therefore requires one scoped API-token publication
from a clean checkout of the intended release commit, followed immediately by
registering this repository's `release.yml` as trusted publisher for all four
crates and revoking the bootstrap token. This exception reserves no empty
placeholder and does not authorize reusing the 0.2.0 release identity.

The root `netbraid` package is the real operator CLI, not a placeholder, so
`cargo install netbraid` installs useful behavior. The three libraries remain
independently consumable.

GitHub native archives, checksums, and attestations remain a parallel
distribution channel. Crates.io publication does not create a daemon, hosted
service, store, fusion authority, or automatic collection behavior.

## Consequences

- Release order is bottom-up; a dependent package cannot complete registry
  verification until its dependency version is live.
- The first publication remains an explicit operator bootstrap; subsequent
  publication uses short-lived OIDC credentials and must precede tagging.
- Package API and compatibility now require deliberate semver and changelog
  discipline.
- Native archive users retain the existing release path, while Rust consumers
  no longer need a sibling checkout.

## Superseded

[ADR-0005](0005-publish-one-netbraid-package.md) replaces the four-package
publication topology before any of those packages reached crates.io. The
evidence, replay, and TShark boundaries remain public Rust modules, while one
`netbraid` package owns the library, operator binary, registry identity, and
release lifecycle.
