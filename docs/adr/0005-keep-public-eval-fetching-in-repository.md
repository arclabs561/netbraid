---
status: accepted
date: 2026-07-30
extends:
  - 0004
governs:
  - scripts/fetch-public-eval-corpus.py
  - eval-data/
  - README.md
  - .gitignore
why: Maintainer evaluation downloads need a reviewable owner, reproducible source checks, and an ignored local data boundary rather than ad-hoc workspace scripts or committed archives.
rejected:
  - Keep fetch logic only in a workspace scratch directory
  - Download archives without an allowlist, byte bound, and digest check
  - Commit raw public archives or extracted evaluation data
  - Duplicate the corpus fetcher in Linktop when Netbraid owns capture admission and replay
confidence: high
review_trigger: Revisit when adding a source, changing source terms or coordinates, distributing a derived fixture, or making Linktop a direct raw-capture consumer.
---

# Keep public evaluation fetching in the repository

## Context

Netbraid needs repeatable access to public wireless data for parser, replay,
fusion, and abstention evaluation. A workspace-only script is easy to lose and
does not tell another developer which sources are approved. Raw archives are
also too large and too changeable to become repository fixtures by default.

## Decision

Keep the source catalog and fetch/extract implementation in the committed
`scripts/fetch-public-eval-corpus.py` maintainer tool. The tool records each
source URL, public terms, DOI, declared byte count, and MD5 digest; it refuses
unexpected sizes, changed archives, partial-download overwrite, unsafe ZIP
members, symlinks, and extraction over a bounded aggregate size.

Store archives, inventories, selected extracts, and receipts under the ignored
repository-local `eval-data/` directory. The normal test gate does not fetch
network data. A selected extract may become a committed fixture only after a
separate provenance, disclosure, and licensing review.

Netbraid owns this boundary because it owns saved-capture admission and replay.
Linktop consumes reviewed Netbraid evidence or fixtures; it does not duplicate
the raw public-corpus downloader.

## Consequences

- Another developer can discover and run the same maintainer workflow from the
  checkout.
- Local data remains out of Git while its source and integrity receipts remain
  reviewable.
- New sources require an explicit catalog and terms review.
- Large archives remain opt-in and do not slow ordinary local checks.
- A future committed fixture must carry a narrower admission decision than the
  fetcher alone provides.
