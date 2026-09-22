# Data

This directory separates tracked source descriptions from local corpus bytes.

- `catalog/` records public source metadata and admission notes.
- `fetch/` contains bounded, checksum-aware acquisition tools.
- `fetch/dataset-fetch.py` is the discoverable cross-fetcher entry point. Use
  `just dataset-fetch-sources`, then `just dataset-fetch-plan SOURCE SELECTION`
  and `just dataset-fetch-status SOURCE SELECTION`. Fetching requires the same
  explicit source and selection plus `confirm=yes`; the plan prints estimated
  bytes, terms, and the delegated receipt/integrity contract first. There is
  no all-sources default. OSU LoRa must be discovered before its byte total is
  known, and terms acknowledgements remain explicit.
- `tests/` exercises fetch and integrity contracts without network access.
- `raw/` is ignored and holds downloaded archives or captures.
- `derived/` is ignored and holds extracted, indexed, or evaluated products.
- `archive/` is ignored and preserves historical data that is not an active
  reproducibility output.
- `receipts/` is ignored and holds machine-local integrity receipts.

Raw, derived, archived, and receipt content is never committed. Reviewed
public-safe test fixtures belong under `eval/fixtures/` or
`rust/tests/fixtures/`, not here.

Catalog metadata does not grant permission to acquire or redistribute a
dataset. Fetchers require an explicit local acknowledgement before acquiring
sources with noncommercial, no-redistribution, incomplete, or unspecified
terms. That acknowledgement affects only ignored local storage.

Tracked evaluation fixtures are bounded project-authored policies, campaign
descriptions, and aggregate oracles; they do not contain publisher rows,
samples, captures, or extracted members. Exact third-party capture bytes used
for adapter regression tests have one reviewed location and an admission ledger
that pins their origin, license, digest, and purpose.

Every retained file under `derived/` is declared in
`eval/derived-artifact-contract-v0.json` with its checked-in producer and
canonical `just` recipe. `just derived-artifact-audit` verifies that contract
from bounded filesystem metadata without reading corpus or artifact contents.
