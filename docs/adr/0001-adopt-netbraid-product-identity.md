---
status: accepted
date: 2026-07-26
governs:
  - rust/Cargo.toml
  - rust/crates/*/Cargo.toml
  - rust/src/**
  - rust/crates/**
  - cmd/root.go
  - .github/**
  - README.md
  - docs/**
why: Netbraid describes a provenance-preserving evidence, replay, adapter, and operator family more accurately than the narrower Netmon name while leaving evidence compatibility explicit.
rejected:
  - Keep Netmon as the product name and continue explaining that it is broader than monitoring
  - Create Netbraid as a second umbrella repository above Netmon and Linktop
  - Rename established netmon.* wire identifiers together with the product
confidence: high
review_trigger: Revisit only if the product narrows back to live monitoring or the Netbraid name develops a concrete ecosystem collision.
---

# Adopt Netbraid as the product and package identity

## Context

The repository began as a live packet monitor. Its Rust direction now owns
policy-neutral evidence records, deterministic replay, bounded saved-artifact
adapters, and an operator CLI. “Netmon” describes only one acquisition-era
behavior and collides conceptually with unrelated monitoring tools. A separate
umbrella repository would add another release and dependency boundary without a
distinct owner or runtime.

The rename must not make old evidence unreadable. Product/package identity,
producer identity, and serialized protocol namespace are separate concerns.

## Decision

The product, repository, current CLI identity, Rust package family, release
artifacts, and source directories use `netbraid`:

- `netbraid`
- `netbraid-evidence`
- `netbraid-replay`
- `netbraid-adapter-tshark`

Netbraid 0.2 emits `netbraid-adapter-tshark` as its current producer identity.
Readers continue to accept historical `netmon-adapter-tshark` producer values.

Every existing versioned `netmon.*` schema, digest profile, digest preimage,
environment policy, field registry, corpus identifier, and output contract
remains byte-for-byte stable. These are established wire namespaces rather
than branding. New versions of those existing families stay in the same
namespace unless a later compatibility ADR defines a protocol migration.

The legacy Go module path remains `github.com/arclabs561/netwatch` until that
compatibility tree is removed. Its current command identity is `netbraid`; the
module path is not presented as the product name.

## Consequences

- Existing evidence remains readable and digest semantics do not silently
  fork across a brand change.
- Consumers must update Rust dependency names and CLI invocations at the 0.2
  boundary.
- The rename does not add a daemon, store, collection service, identity
  authority, or private fusion plane.
- Historical prose, the 0.1 tag, and legacy producer fixtures may still name
  Netmon where that history is the subject.
