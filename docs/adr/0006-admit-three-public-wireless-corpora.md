---
status: accepted
date: 2026-07-30
extends:
  - 0005
governs:
  - scripts/fetch-public-eval-corpus.py
why: Three primary-source records provide small, bounded evidence for Wi-Fi management frames, Wi-Fi probe metadata, and heterogeneous BLE/Zigbee RF capture without committing raw data.
rejected:
  - Treat raw IQ as device or person identity evidence
  - Add a dataset to the allowlist from approximate size or agent-supplied metadata
  - Treat the Zigbee capture as WLAN evidence before a protocol-specific projection exists
  - Download the larger archives as part of ordinary tests
confidence: high
review_trigger: Revisit if a source record, checksum, license, retained fields, or protocol projection changes.
---

# Admit three public wireless corpora

## Context

The first public-corpus tranche established the fetcher and the V2I alignment
candidate. Parallel research found smaller sources that cover an anonymized
802.11 management capture, labeled probe-request metadata, and heterogeneous
BLE/Zigbee RF recordings. The source pages expose exact file metadata, but the
archives must remain local until a derived fixture has its own review.

## Decision

Add these primary-source files to the fetcher's explicit catalog:

- SDR4IoT BLE and Zigbee RF dataset, Zenodo DOI `10.5281/zenodo.4639390`,
  CC BY 4.0, 78,658,727 bytes, and its published MD5.
- 802.11 management frames from a public location, Zenodo DOI
  `10.5281/zenodo.8003772`, MIT, 4,126,124 bytes, and its published MD5.
- Labeled IEEE 802.11 probe requests, Zenodo DOI
  `10.5281/zenodo.7503594`, CC BY 4.0, 49,977,913 bytes, and its published
  MD5.

The fetcher may download these only when named explicitly. Selected local
slices remain under ignored `eval-data/`. Netbraid may project the Wi-Fi PCAP
through its existing WLAN path. A Zigbee or BLE result remains unsupported or
protocol-specific until a separate typed projection exists; no cross-protocol
identity join is inferred from co-presence in an archive.

## Consequences

- The catalog has exact, reviewable source coordinates rather than approximate
  file sizes.
- The small management capture is suitable for a first external WLAN parser
  projection, while the probe dataset is metadata/label evaluation material.
- SDR4IoT provides a bounded multi-receiver Zigbee scene without forcing raw IQ
  into the normal test path.
- A future committed fixture still needs disclosure, provenance, and license
  review beyond this fetch decision.
