# Dataset catalog

Catalog entries describe public sources without embedding source data. Each
entry should identify the publisher, canonical URL or DOI, version, license or
access terms, expected artifact size and digest when available, modality,
labels, and the evaluation role it can support. Discovery indexes do not grant
redistribution rights for the artifacts they link.

`research-leads-v1.json` preserves research leads before artifact admission.
It distinguishes datasets from specifications, tools, system-oracle references,
and secondary indexes. A `candidate` is not downloadable merely because it is
listed: acquisition requires a canonical artifact inventory, explicit access
terms, bounded size, and a publisher digest or a reviewed local pin.

`fetch-osu-lora.py` lists the seven Oregon State LoRa RFFI setup roots from the
publisher's release note without network access. Its explicit `discover` action
emits a deterministic, bounded Apache-index inventory; `fetch` stores bytes and
local SHA-256 receipts only under the ignored `data/raw/` and `data/receipts/`
trees. Fetching defaults to a 10 GiB aggregate cap because the full release is
larger than 1.2 TB.

`controlled-jamming-artifacts-v1.json` is the exact acquisition boundary for
two Zenodo controlled-jamming records. It pins 112 publisher artifacts, sizes,
and MD5 digests without admitting their scenario labels as malicious-intent or
tamper truth. `fetch-controlled-jamming.py` downloads complete selected records
with strict byte caps, resumable ranges, local SHA-256 receipts, and no payload
extraction.
