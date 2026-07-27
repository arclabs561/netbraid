---
status: accepted
date: 2026-07-27
extends:
  - 0003
governs:
  - rust/crates/netbraid-replay/src/scenario.rs
  - rust/crates/netbraid-replay/tests/scenario_bundle_v1.rs
  - rust/crates/netbraid-replay/tests/fixtures/scenarios/saved-capture-prefix-boundary/**
  - rust/crates/netbraid-replay/Cargo.toml
  - rust/crates/netbraid-replay/README.md
  - rust/crates/netbraid-adapter-tshark/Cargo.toml
  - rust/crates/netbraid-adapter-tshark/README.md
  - rust/Cargo.toml
  - rust/src/scenario.rs
  - rust/tests/scenario_cli.rs
  - README.md
  - CHANGELOG.md
  - docs/design/evaluation-corpus.md
  - docs/design/derived-intelligence-boundary.md
  - .github/workflows/ci.yml
  - .github/workflows/release.yml
  - justfile
why: Capture-derived evaluation scenarios need disclosure review, exact upstream and license lineage, and prefix-scoped abstentions without weakening the closed public-synthetic v0 contract or treating derivation as a privacy class.
rejected:
  - Add capture-derived or observed variants to the v0 PUBLIC_SYNTHETIC privacy enum
  - Collapse disclosure sensitivity, source origin, derivation, and acquisition into one label
  - Embed capture-derived scenarios with the normal library or synthetic-fixture feature
  - Distribute raw packet payloads when normalized records are sufficient for the named oracle
  - Admit arbitrary viewport text under a capture-only disclosure review
  - Reuse the v0 replay receipt without carrying v1 sensitivity and disclosure metadata
confidence: high
review_trigger: Revisit if an extractor or field registry changes, an upstream coordinate, digest, or license changes, retained identifier classes or payload handling change, capture-derived fixtures become default or enter Linktop, private sources are proposed, or a larger corpus needs external packaging.
---

# Admit public-reviewed capture-derived scenarios

## Context

The `netbraid.scenario_bundle.v0` contract deliberately admits only
`PUBLIC_SYNTHETIC` fixtures. That makes its privacy meaning small and exact, but
synthetic host-path records cannot exercise every saved-capture boundary. In
particular, they cannot prove that a negative conclusion over a partial
normalized prefix remains prefix-scoped when the next source frame changes the
result.

Adding an “observed” or “capture-derived” member to the v0 privacy enum would
combine different questions. Public disclosure status concerns what may be
distributed. Source origin concerns whether source bytes were observed or
synthetic. Derivation concerns how scenario artifacts were produced.
Acquisition concerns where the source came from. None implies another.

Capture-derived distribution also needs more lineage than the v0 generator
description: exact corpus coordinates, immutable upstream identity, source
content digest and size, redistribution terms, a disclosure review, and a
digest-bound license notice.

## Decision

Keep `netbraid.scenario_bundle.v0`, its `PUBLIC_SYNTHETIC` privacy value, and its
four built-in scenarios byte- and API-stable.

Add the strict `netbraid.scenario_bundle.v1` contract for reviewed,
capture-derived scenario distribution. Version 1 records these independent
axes:

- sensitivity: `PUBLIC_REVIEWED`;
- source origin: `observed`;
- derivation: `normalized_saved_capture`; and
- acquisition: `third_party_upstream`.

The disclosure review enumerates every retained identifier class in ingestible
evidence. The first scenario retains public-upstream IEEE 802.11 link-layer
addresses, one network name, and packet timestamps. Raw packet payload bytes
are omitted from ingestible evidence artifacts. `PUBLIC_REVIEWED` means the
whole distributed closure, including its separately classified legal notice,
passed an explicit review; it is not a claim that observed identifiers are
anonymous, synthetic, harmless, or suitable for another purpose.

The v1 loader derives evidence identifier classes from all admitted typed
saved-capture records and requires exact equality with the disclosure
declaration. It rejects host-path artifacts and opaque quarantine rows:
host-path evidence has no capture-source lineage in this contract, while an
opaque row could retain identifiers or payload bytes that the typed validator
cannot classify.

Version 1 also does not admit viewport-text artifacts. Formatting validation
cannot establish that arbitrary rendered text contains no undeclared
identifier or payload. V0 retains its existing synthetic viewport contract; a
future reviewed presentation artifact requires its own disclosure boundary.

Each source entry closes over the admitted corpus schema and fixture ID,
upstream repository, immutable revision, source path and HTTPS URL, upstream
blob SHA-1, raw-content SHA-256, raw byte count, SPDX license expression, and a
declared `license_text` artifact. A license artifact is a digest-bound,
UTF-8 text member of the closed inventory, but it is neither ingestible source
evidence nor a valid evidence reference.

Structural validation does not authenticate the `PUBLIC_REVIEWED` assertion in
an arbitrary external directory. The maintainer-admitted built-in gains its
trust from the reviewed, content-addressed distribution and tests that compare
its source and legal coordinates with the admitted corpus and immutable
upstream. Consumers must establish an equivalent trust anchor before treating
another structurally valid v1 bundle as reviewed.

The first v1 scenario,
`saved-capture-prefix-boundary`, contains two deterministic `records-jsonl`
normalizations of the admitted libpcap Nokia capture. Packet limit 6 yields a
prefix-scoped “disconnect-management frame not observed” result. Packet limit
7 preserves the first six packet records and adds one IEEE 802.11
deauthentication frame. The oracle requires abstention from source-wide
absence or frame-count claims and from actor or access-point identity, attack
intent, disconnect causality, and radio-channel claims.

The committed normalized records include their reference TShark version,
field-registry identity, and effective-configuration fingerprint. Those values
are provenance for the exact reviewed bytes, not portable regeneration
constants that another host must reproduce. Regeneration is a deliberate
review operation: any byte, extractor, registry, environment fingerprint, or
lineage change produces a new manifest closure and must pass the admission
gates again.

The capture-derived built-in is available only through the separate,
non-default `scenario-fixtures-capture-derived` feature. Enabling
`scenario-fixtures` continues to expose exactly the four v0 synthetic bundles.
The ordinary library embeds neither fixture family.

Cargo features control compiled API and binary embedding, not source-package
inventory. The `netbraid-replay` crate archive contains the normalized
BSD-3-Clause-derived fixture and its notice even when the capture-derived
feature is disabled. Its package metadata therefore uses
`(MIT OR Unlicense) AND BSD-3-Clause`. The scenario's notice artifact preserves
the upstream attribution and terms, but the notice alone would not make
`MIT OR Unlicense` an accurate license declaration for the whole crate
archive. The `netbraid-evidence` source archive contains no third-party fixture
bytes and retains `MIT OR Unlicense`.

Applying that package-inventory rule also exposed a distribution-boundary
problem: the adapter and root CLI archives were carrying test-only upstream
corpora even though no runtime or public fixture feature exposes them. Those
corpora, notices, and workspace-only integration tests remain in the GitHub
repository and CI but are excluded from the published Cargo archives. The
adapter and root CLI therefore retain `MIT OR Unlicense`. If the corpus becomes
a supported distribution, it needs an explicit data-package or release
boundary with its own aggregate license rather than riding inside runtime
crates.

Both bundle versions reuse the same timeline, expected-conclusion, coverage,
and checkpoint projection types. Version 0 keeps its exact
`netbraid.scenario_replay.v0` receipt. Version 1 emits
`netbraid.scenario_replay.v1`: a detached receipt additionally carries the
bundle schema, declared `PUBLIC_REVIEWED` sensitivity, and declared disclosure
review. Reusing v0 would lose that manifest metadata precisely when observed
identifiers enter the receipt, even though the inner checkpoint projection
fields are unchanged.

## Consequences

- Tests can use real decoded packet structure without implying that an
  observed source is synthetic or that derivation determines sensitivity.
- Reviewers can reconstruct the exact upstream and license lineage from the
  bundle while raw capture payloads remain outside the scenario artifact.
- Disclosure declarations are checked against typed evidence rather than
  accepted as unaudited prose; opaque evidence fails closed.
- Partial normalization can support positive observations immediately while
  negative and total-count claims remain bounded to the normalized prefix.
- Downstream consumers do not acquire capture-derived identifiers by enabling
  the existing synthetic fixture feature.
- The replay crate has a broader aggregate package license than the root CLI
  and evidence crate because Cargo ships the reviewed fixture independently of
  feature activation.
- Repository-only corpora do not silently broaden runtime crate archives. A
  future supported corpus distribution must own its packaging and license
  surface explicitly.
- Another disclosure class, acquisition mode, derivation, source family, or
  payload policy requires an explicit v1 extension or a later schema version;
  unknown tokens fail closed.
