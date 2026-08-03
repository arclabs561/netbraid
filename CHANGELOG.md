# Changelog

All notable changes to Netbraid's versioned Rust package and binary release are
documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The public library and CLI share one `netbraid` package and release version;
GitHub native binary releases remain available independently.

## [Unreleased]

### Added

- An optional bounded Unix adapter for canonical full-metadata Zeek `conn.log`
  files that projects typed session evidence without retaining source-local
  identifiers or unselected columns.

### Changed

- Retired the unconsumed Go live-capture compatibility tree, its container,
  and its CI lane. Its final source remains available at the
  `netwatch-go-final` tag; the active repository now builds and tests the Rust
  package plus its data/evaluation tooling.

## [0.3.2] - 2026-08-03

### Added

- Identifier-free packet-shape and WLAN fingerprint candidates, conservative
  comparison results, and an explicitly promotion-gated same-event hypothesis
  reducer. Unsupported, partial, malformed, or incompatible evidence remains
  typed abstention rather than a relation claim.
- A public inference facade for finite counter-capture, packet-shape,
  same-event, and RSSI reference-frame hypothesis families, with content-bound
  references and explicit unknown states.
- Pinned fetchers and deterministic local evaluators for the public capture
  corpus, Sorbonne same-event oracle, OPERAnet, CAEZ, Data4Cyber, NetsLab,
  IoT-23 flow lineage, RUFF-UWB held-out locations, controlled jamming causes,
  counter-capture campaigns, and XRF55 archives. Raw corpus bytes and generated
  reports remain outside Git.
- Optional read-only KismetDB, NPY, and SigMF adapters with bounded packet,
  row, or IQ-window projections and source-mutation fences.
- A checked-in producer/recipe contract for ignored derived artifacts, with a
  content-blind audit that rejects unclassified outputs and untracked
  provenance.

### Changed

- Scenario artifact ingestion now retains typed host-path and saved-capture
  sources behind an internal family boundary. Replay, disclosure validation, and
  checkpoint input projection reuse the validated saved-capture stream instead
  of reparsing its bytes, without changing public schemas or APIs.
- Saved-capture request batches may carry independent packet and input bounds
  while sharing one opening/closing TShark configuration fence. Bounded
  parallel normalization preserves input order and sequential result semantics;
  the public-corpus evaluator co-schedules its deterministic replicas through
  the evaluated Netbraid binary.

### Fixed

- Count only schema-validated HDF5 windows toward controlled-cause payload
  receipts, including when a reader returns a malformed summary.
- Reconnected the saved-capture parser fuzz target to the unified `netbraid`
  package so its nightly smoke recipe builds and runs again.
- Kept the optional KismetDB adapter on the declared Rust 1.88 floor by using
  the preceding compatible rusqlite/libsqlite release line.

## [0.3.1] - 2026-07-28

### Changed

- Replaced the internal migration-oriented README and planning ledger with a
  concise public operator guide, contributor decisions, architecture, fixture,
  conversation, and IEEE 802.11 evidence documentation.
- Made maintainer ADRs and design working notes local-only while retaining
  their durable product constraints in public documentation.
- Replaced the legacy single-stage Docker image with an explicit multi-stage
  build whose runtime contains only the Go compatibility binary and runtime
  libraries; base manifests are digest-pinned and local image builds no longer
  imply a registry push.
- Expanded repository ignores for raw captures, local analysis, logs,
  databases, and credential-bearing files; reduced the container context to an
  allowlist of Go build inputs; and corrected the scenario fixture line-ending
  rule.
- Replaced author-specific compatibility-reader test values with documentation
  addresses and neutral fixture names.

### Fixed

- Brought the legacy Go compatibility tree through the current lint suite with
  checked integer conversions, portable platform boundaries, typed TOML tags,
  error-chain handling, and allocation-safe buffer pooling.

## [0.3.0] - 2026-07-27

### Added

- A strict `netbraid.scenario_bundle.v1` contract for disclosure-reviewed,
  capture-derived scenarios with independent sensitivity, source-origin,
  derivation, and acquisition axes; exact upstream and corpus coordinates;
  enumerated identifier classes retained in ingestible evidence; and
  non-ingestible, digest-bound license artifacts. Evidence-identifier
  declarations must exactly match the admitted typed saved-capture records;
  unprovenanced host-path artifacts and opaque quarantine rows fail closed.
  Viewport text remains v0-only until presentation bytes have an explicit
  disclosure contract.
- A non-default `scenario-fixtures-capture-derived` fixture whose deterministic
  six- and seven-packet normalized prefixes protect the boundary between a
  prefix-scoped negative WLAN result and an observed seventh-frame
  deauthentication.
- Versioned, deterministic scenario bundles for offline consumer QA, including
  Wi-Fi/hotspot recurrence, a same-SSID BSSID attachment transition followed by
  an incompatible reused-label boundary, VPN-overlay attribution abstention,
  and a passive neighbor-cache source gap. Bundles carry exact artifact
  inventories, hashes, named checkpoints, required abstentions,
  coverage/freshness expectations, bounded text viewports, and a receipt-bound
  accessor for the typed checkpoint evidence that downstream consumers
  independently reduce.
- Provenance-qualified trailing-interval analysis for saved captures. Positive
  observations remain useful immediately, while negative conclusions require
  complete normalization and corroborating occurrence-receipt packet bounds.
- A one-time scoped-token boundary for initial crate ownership and a manual,
  current-main-only Trusted Publishing gate for later
  releases, with registry metadata and Cargo VCS identity verification before
  a release tag can create a GitHub release.

### Changed

- Collapsed the unpublished four-package workspace into one publishable
  `netbraid` library-and-CLI package. The public API retains
  `netbraid::evidence`, `netbraid::replay`, and the feature-gated
  `netbraid::adapters::tshark` boundaries without four registry ownership and
  release lifecycles.
- CLI and TShark dependencies are gated behind default `cli` and
  `adapter-tshark` features, so evidence/replay consumers can disable default
  features. Existing schema, digest, corpus, and producer identifiers remain
  unchanged.
- The single source archive declares
  `(MIT OR Unlicense) AND BSD-3-Clause` because it contains the supported
  capture-derived scenario; repository-only adapter and CLI corpora remain
  excluded.
- The offline `scenario` CLI now validates and replays both v0 and v1 bundles.
  The four `PUBLIC_SYNTHETIC` v0 built-ins and their
  `netbraid.scenario_replay.v0` receipt remain unchanged. V1 replay emits
  `netbraid.scenario_replay.v1` so declared sensitivity and disclosure metadata
  survive detached receipt transport without implying authenticated review.
- Cargo source archives now distinguish product fixtures from repository-only
  evaluation data. The package includes the reviewed BSD-3-Clause-derived
  fixture while excluding test-only upstream corpora, notices, and
  repository-only integration tests.
- CI now exercises all package features and verifies that public scenario
  fixtures are present in the packaged `netbraid` crate.
- Saved-capture JSON triage is now `netmon.saved_pcap_triage.v1`, retaining the
  validated capture manifest, optional occurrence receipt, normalized-record
  digest, and optional trailing-window projection. The public v0 projection API
  remains available for compatibility.

## [0.2.0] - 2026-07-26

### Added

- Publishable `netbraid`, `netbraid-evidence`, `netbraid-replay`, and
  `netbraid-adapter-tshark` package inventories, including self-contained
  documentation, licenses, fixtures, and tests. Registry publication remains
  pending credential rotation.
- A provenance-checked public saved-capture corpus spanning radiotap/802.11,
  RARP PCAPNG, PPPoE discovery, snaplen truncation, NTP conversations, and
  big-endian PCAPNG. Exact upstream bytes are stored as diffable hex beside
  pinned source revisions, blob IDs, decoded digests, licenses, and real-tool
  expectations.
- Corpus smoke coverage against installed TShark and Capinfos in local and CI
  Rust gates.
- Typed optional IEEE 802.11 packet fields and normalized wireless-radio
  metadata in saved-capture records, with a bumped TShark field-registry
  contract.
- A bounded finite-text wireless evidence summary covering frame mix, field
  coverage, radio contexts, observed identifiers, and nonempty SSID elements.
- A sixth canonical v0 schema fixture exercising the additive wireless packet
  envelope.

### Changed

- Renamed the product, Rust packages, operator binary, source tree, GitHub
  release contract, and current Go CLI identity from Netmon to Netbraid.
- New saved-capture records identify their producer as
  `netbraid-adapter-tshark`; historical `netmon-adapter-tshark` records remain
  readable.
- Preserved every existing `netmon.*` schema, digest-profile,
  environment-policy, field-registry, and corpus identifier as a stable wire
  compatibility namespace.

## [0.1.0] - 2026-07-26

### Added

- The experimental Rust evidence, replay, and saved-PCAP normalization
  workspace.
- The offline `netmon` CLI with human, full JSONL receipt, and deterministic
  normalized-record JSONL projections.
- Canonical pretty-JSON fixtures for the five public v0 record schemas.
- Locked Linux and macOS GitHub release bundles with checksums and build
  provenance.

### Legacy compatibility

- The Go capture CLI and disconnected `swucb` experiment remain in the
  repository but are not included in Rust release bundles.
- The disconnected Go watcher now rejects legacy shell action and predicate
  triggers instead of interpolating packet-derived event data into a shell.
- The legacy Go compatibility floor is now Go 1.25.12 so CI scans against a
  supported, patched standard library.
- Raw PCAP, PCAPNG, and CAP artifacts are ignored recursively; reviewed
  synthetic fixtures remain readable source encodings.

[Unreleased]: https://github.com/arclabs561/netbraid/compare/netbraid-v0.3.2...HEAD
[0.3.2]: https://github.com/arclabs561/netbraid/compare/netbraid-v0.3.1...netbraid-v0.3.2
[0.3.1]: https://github.com/arclabs561/netbraid/compare/netbraid-v0.3.0...netbraid-v0.3.1
[0.3.0]: https://github.com/arclabs561/netbraid/compare/netbraid-v0.2.0...netbraid-v0.3.0
[0.2.0]: https://github.com/arclabs561/netbraid/releases/tag/netbraid-v0.2.0
[0.1.0]: https://github.com/arclabs561/netbraid/releases/tag/netmon-v0.1.0
