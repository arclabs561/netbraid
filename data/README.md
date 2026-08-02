# Data

This directory separates tracked source descriptions from local corpus bytes.

- `catalog/` records public source metadata and admission notes.
- `fetch/` contains bounded, checksum-aware acquisition tools.
- `tests/` exercises fetch and integrity contracts without network access.
- `raw/` is ignored and holds downloaded archives or captures.
- `derived/` is ignored and holds extracted, indexed, or evaluated products.
- `receipts/` is ignored and holds machine-local integrity receipts.

Raw, derived, and receipt content is never committed. Reviewed public-safe test
fixtures belong under `eval/fixtures/` or `rust/tests/fixtures/`, not here.
