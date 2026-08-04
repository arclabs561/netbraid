# netbraid

Netbraid tests how network observations relate while keeping their sources
separate.

## Why Netbraid?

Kismet captures, tracks, stores, and replays wireless observations. Netbraid
does not collect or track devices. It treats selected fields from a closed
KismetDB as one evidence source alongside saved packet, log, and signal
artifacts. The resulting records retain their source, coverage, and limits.

The braid is the set of typed links between those records. It is not one merged
identity record.

The Rust library currently tests SHA-256 digest agreement, packet same-event,
saved-PCAP shape, counter/capture correspondence, and RSSI-shift hypotheses.
Each result is supported, contradicted, or underdetermined and remains linked
to its inputs. Broader cross-modal fusion is evaluation work, not a supported
claim yet.

The CLI reads saved artifacts. The record types can be used by live consumers,
but Netbraid does not acquire observations or run a service.

The repository has two implementation layers:

- `rust/` is the published library and CLI.
- `data/` and `eval/` contain Python dataset and evaluation tooling.

Downloaded data stays outside Git. Status: experimental.

## Install

The Rust package requires Rust 1.88 or newer:

```sh
cargo install netbraid --version 0.3.2 --locked
```

Prebuilt archives are available from the
[`netbraid-v0.3.2` release](https://github.com/arclabs561/netbraid/releases/tag/netbraid-v0.3.2).
The macOS archives are not signed or notarized.

Saved-PCAP commands also require compatible `tshark` and `capinfos` binaries.

From a checkout:

```sh
cargo build --locked --manifest-path rust/Cargo.toml
./rust/target/debug/netbraid --help
```

## Quick start

Summarize a saved capture:

```sh
netbraid pcap incident.pcapng
netbraid pcap incident.pcapng --json
netbraid pcap incident.pcapng --records-jsonl > records.jsonl
```

The command accepts only regular PCAP or PCAPNG files. Input size, packet
count, subprocess output, and runtime are bounded. Name resolution is disabled.

Validate and replay a finite scenario from a checkout:

```sh
netbraid scenario validate \
  rust/tests/fixtures/replay/scenarios/wifi-hotspot-wifi
netbraid scenario replay \
  rust/tests/fixtures/replay/scenarios/wifi-hotspot-wifi \
  --checkpoint wifi-returned
```

Output excerpt:

```text
scenario wifi-hotspot-wifi @ wifi-returned (120000 ms)
3 record reference(s) ingested
host path: 3 record(s), 2 exact context key(s), 2 confirmed transition(s)
declared oracle: 1 supported conclusion(s), 0 required abstention(s)
```

Scenario fixtures are public-synthetic unless explicitly documented otherwise.
They test specific invariants; they are not representative network samples.

Run `netbraid --help` for the saved evidence and compatibility commands, and
`netbraid pcap --help` for the complete output and resource-control options.

## Rust library

The library separates source evidence from derived, revisable hypotheses.
Consumers that do not need the CLI or Wireshark process boundary can disable
default features:

```toml
[dependencies]
netbraid = { version = "0.3", default-features = false }
```

The main modules are:

- `evidence`: versioned records and provenance;
- `replay`: strict JSONL parsing and deterministic reduction;
- `infer`: finite hypothesis and counter-capture reducers; and
- `adapters`: optional boundaries for TShark, KismetDB, NPY, SigMF, and Zeek.

Default builds include the CLI and TShark adapter. The current checkout also
has optional KismetDB, NPY, SigMF, and Zeek adapters and scenario fixtures.
Published 0.3.2 predates the Zeek adapter; `cargo info netbraid@0.3.2` shows that
release's exact features.

Some schema IDs retain the historical `netmon.*` namespace for wire
compatibility. Product names and Rust paths use `netbraid`.

## Data and evaluation

Dataset metadata and fetchers live in [`data/`](data/README.md). Evaluation
harnesses, fixtures, and experiment records live in [`eval/`](eval/README.md).
Raw corpora, derived artifacts, and local receipts are ignored by Git.

```sh
uv run --script data/fetch/fetch-public-eval-corpus.py list
just public-corpus-eval-check
```

Evaluations keep source lineage, split groups, limitations, and aggregate
metrics explicit. Dataset-derived measurements are on-demand and are not part
of the default test gate. See the
[evaluation protocol](docs/public-corpus-evaluation.md).

## Boundaries

- Netbraid preserves source coverage and provenance; it does not upgrade an
  address, protocol, network name, or recurrence into verified identity.
- Fingerprints and hypotheses are comparison candidates, not claims about a
  device, application, owner, person, intent, or place.
- Absence claims require relevant coverage, freshness, and a complete interval.
- Strict replay rejects unknown schemas, fields, unsafe paths, and known
  corruption. Recovery of an interrupted final JSONL record is explicit.
- Netbraid does not own collection, retention, credentials, telemetry,
  identity graphs, or active-discovery policy.

## Documentation

- [Architecture](docs/architecture.md)
- [Saved-PCAP normalization](docs/saved-pcap-normalization.md)
- [Capture conversations](docs/capture-conversations.md)
- [Scenario fixture policy](docs/fixture-policy.md)
- [Wireless evidence](docs/wlan-evidence.md)
- [Design decisions](DECISIONS.md)

## Development

```sh
just check
just pcap-smoke       # requires TShark and Capinfos
```

`just check` runs the Rust and Python test gates. Set
`PYTHON=/path/to/python` to choose the interpreter used by evaluation targets.

## License

Authored code is available under MIT or the Unlicense. The package expression
is `(MIT OR Unlicense) AND BSD-3-Clause` because one supported fixture carries
the BSD-3-Clause license.
