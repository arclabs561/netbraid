# Changelog

All notable changes to Netbraid's versioned Rust workspace and binary release are
documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Netbraid uses one workspace release version. The CLI and three reusable
libraries are prepared for crates.io publication in dependency order; GitHub
native binary releases remain available independently.

## [Unreleased]

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

[Unreleased]: https://github.com/arclabs561/netbraid/compare/netbraid-v0.2.0...HEAD
[0.2.0]: https://github.com/arclabs561/netbraid/releases/tag/netbraid-v0.2.0
[0.1.0]: https://github.com/arclabs561/netbraid/releases/tag/netmon-v0.1.0
