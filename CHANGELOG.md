# Changelog

All notable changes to Netmon's versioned Rust workspace and binary release are
documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Netmon uses a workspace release version but does not publish its private crates
to crates.io.

## [Unreleased]

### Added

- A provenance-checked public saved-capture corpus spanning radiotap/802.11,
  RARP PCAPNG, PPPoE discovery, snaplen truncation, NTP conversations, and
  big-endian PCAPNG. Exact upstream bytes are stored as diffable hex beside
  pinned source revisions, blob IDs, decoded digests, licenses, and real-tool
  expectations.
- Corpus smoke coverage against installed TShark and Capinfos in local and CI
  Rust gates.

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

[Unreleased]: https://github.com/arclabs561/netmon/compare/netmon-v0.1.0...HEAD
[0.1.0]: https://github.com/arclabs561/netmon/releases/tag/netmon-v0.1.0
