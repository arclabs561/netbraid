# netbraid

Netbraid normalizes network evidence and replays it deterministically.

The Rust package provides a library and operator CLI for strict evidence logs,
finite scenario bundles, bounded saved-PCAP normalization, and conservative
derived hypotheses. The repository also contains a legacy Go capture CLI; it is
maintained for compatibility, not used by the Rust package.

```text
scenario wifi-hotspot-wifi @ wifi-returned (120000 ms) — manifest sha256:0039c3aec486771112102010b07d873b276b71547d089886b13f3235bb2d0ba2
3 record reference(s) ingested
host path: 3 record(s), 2 exact context key(s), 2 confirmed transition(s), 0 compatible/incomplete transition(s), latest wifi-primary-2
declared oracle: 1 supported conclusion(s), 0 required abstention(s), 3 source-coverage row(s), 1 viewport assertion(s)
```

The example comes from a public-synthetic fixture. Netbraid preserves what a
source observed, the source's coverage, and the limits on each conclusion. It
does not turn an address, protocol, network name, or recurrence into verified
device, application, owner, person, intent, or place identity.

Status: experimental.

## Install

The Rust package requires Rust 1.88 or newer:

```sh
cargo install netbraid --version 0.3.1 --locked
```

Checksummed native archives for x86-64 Linux, Intel macOS, and Apple silicon
macOS are attached to the
[`netbraid-v0.3.1` release](https://github.com/arclabs561/netbraid/releases/tag/netbraid-v0.3.1):

```sh
gh release download netbraid-v0.3.1 \
  --repo arclabs561/netbraid \
  --dir netbraid-v0.3.1
(cd netbraid-v0.3.1 && shasum -a 256 --check SHA256SUMS)
```

The macOS archives are not code-signed or notarized. Cargo installation is the
most portable path.

From a checkout:

```sh
cargo build --locked --manifest-path rust/Cargo.toml
./rust/target/debug/netbraid --help
```

## Use

```sh
netbraid evidence ./host-path.jsonl
netbraid pcap ./incident.pcapng
netbraid pcap ./incident.pcapng --json
netbraid pcap ./incident.pcapng --records-jsonl
netbraid pcap ./incident.pcapng --fingerprint-json
netbraid pcap ./incident.pcapng --wlan-fingerprint-json
netbraid scenario validate ./scenario
netbraid scenario replay ./scenario --checkpoint CHECKPOINT
```

`evidence` and `scenario` are finite, offline operations. `pcap` accepts only a
regular saved PCAP or PCAPNG file; it does not open live interfaces.

Three compatibility commands read the last object in a saved controller audit
log and exit:

```sh
netbraid --file ~/.cache/netops/audit-history.jsonl net
netbraid --file ~/.cache/netops/audit-history.jsonl device QUERY
netbraid --file ~/.cache/netops/audit-history.jsonl here
```

They do not capture traffic or query a controller. A missing, empty, or
malformed file is an error rather than evidence about the current network.

## Saved captures

`netbraid pcap` stages and hashes one saved artifact, obtains file facts from
Capinfos, and invokes TShark with:

- name resolution disabled;
- an explicit first-occurrence field registry;
- a private personal-configuration directory;
- bounded input, output, packet count, and runtime;
- no shell interpolation; and
- tool, registry, environment, and effective-configuration fingerprints.

TShark and Capinfos must be installed and compatible with the capture. Personal
Wireshark plugins are refused unless `--allow-personal-plugins` is explicit.
System plugins and allowed personal plugins remain fingerprinted provenance;
Netbraid does not claim that a dissector process is a sandbox.

The output modes serve different consumers:

| Mode | Consumer | Contract |
| --- | --- | --- |
| default text | operator | finite evidence summary and limitations |
| `--json` | program or agent | one provenance-complete triage document |
| `--jsonl` | archival pipeline | manifest, run receipt, records, quarantines |
| `--records-jsonl` | deterministic replay | occurrence-independent normalized records |
| `--fingerprint-json` | evaluator | identifier-free packet-shape candidate |
| `--wlan-fingerprint-json` | evaluator | identifier-free WLAN candidate |

`--packet-limit`, `--max-input-mib`, `--max-output-mib`, and
`--timeout-seconds` bound work. `--tail-seconds` narrows analysis to an artifact
interval; negative conclusions remain qualified by normalization completeness
and capture coverage.

Normalizing an existing file is passive. That does not prove the original
acquisition was passive. Supply independently known provenance with
`--observer-id`, `--acquired-time-unix-ms`, `--acquisition-mode`, and repeated
`--active-action` values.

See
[Saved-PCAP normalization](https://github.com/arclabs561/netbraid/blob/main/docs/saved-pcap-normalization.md)
and
[Capture conversations](https://github.com/arclabs561/netbraid/blob/main/docs/capture-conversations.md).

## Scenario bundles

A scenario is a closed, finite directory with a strict `scenario.json`
manifest and a digest-bound inventory of evidence and optional viewport
artifacts. Validation checks:

- schema and exact artifact inventory;
- safe paths, sizes, and SHA-256 digests;
- strict typed evidence streams;
- monotonic checkpoint references;
- source coverage and freshness;
- supported conclusions and required abstentions; and
- bounded text viewport dimensions.

The normal package includes public-synthetic fixtures for:

- Wi-Fi to hotspot and back;
- same-SSID attachment change and label reuse;
- VPN overlay transitions; and
- a stale passive neighbor-cache gap.

The non-default `scenario-fixtures-capture-derived` feature adds one
disclosure-reviewed, licensed upstream-capture boundary case. Fixtures prove
specific invariants; they are not a representative sample of networks,
operators, devices, or incidents.

```sh
netbraid scenario validate \
  rust/tests/fixtures/replay/scenarios/wifi-hotspot-wifi
netbraid scenario replay \
  rust/tests/fixtures/replay/scenarios/wifi-hotspot-wifi \
  --checkpoint wifi-returned
```

See
[Fixture policy](https://github.com/arclabs561/netbraid/blob/main/docs/fixture-policy.md)
and
[IEEE 802.11 evidence](https://github.com/arclabs561/netbraid/blob/main/docs/wlan-evidence.md).

## Maintainer evaluation data

Tracked source metadata and fetchers live under `data/`. Public corpora stay in
ignored `data/raw/`, generated products stay in ignored `data/derived/`, and
local integrity receipts stay in ignored `data/receipts/`. The fetchers verify
publisher-declared sizes and checksums where available, resume completed work,
and never admit downloaded bytes into Git. Evaluation harnesses, fixtures, and
aggregate experiment ledgers live under `eval/`.

```sh
uv run --script data/fetch/fetch-public-eval-corpus.py list
uv run --script data/fetch/fetch-public-eval-corpus.py baseline
uv run --script data/fetch/fetch-public-eval-corpus.py motivating
uv run --script data/fetch/fetch-public-eval-corpus.py fusion
uv run --script data/fetch/fetch-public-eval-corpus.py all
just xrf55-fetch list
```

The on-demand evaluators cover bounded public-corpus slices, a cross-sniffer
same-event oracle, deterministic structural reduction, archive-layout and
cross-layer alignment profiles, IoT-23 flow lineage, and counter-capture
campaign output. Dataset-derived metrics are not part of the default test gate.

```sh
just public-corpus-eval-check
just public-corpus-eval
just sorbonne-same-event-audit
just sorbonne-structural-reducer-eval
just operanet-layout-profile
just caez-alignment-profile
just data4cyber-alignment-profile
just netslab-alignment-profile
just iot23-flow-lineage-check
just counter-capture-eval-check
just mmwave-jamming-oracles-check
just indoor-jamming-oracles-check
```

The
[evaluation protocol](https://github.com/arclabs561/netbraid/blob/main/docs/public-corpus-evaluation.md)
defines lineage, split groups, metrics, and the separate fixture-admission gate.
Review source terms and receipts before promoting any public slice into a
committed fixture.

## Library

The CLI and library share one package and release version. Policy-neutral
evidence and replay consumers can avoid the CLI and Wireshark-tool dependency
surface:

```toml
[dependencies]
netbraid = { version = "0.3", default-features = false }
```

| Feature | Default | Adds |
| --- | --- | --- |
| `cli` | yes | operator binary and TShark adapter |
| `adapter-kismetdb` | no | read-only KismetDB packet-metadata normalization |
| `adapter-kismetdb-bundled` | no | KismetDB adapter with bundled SQLite |
| `adapter-tshark` | via `cli` | bounded saved-capture process boundary |
| `scenario-fixtures` | no | public-synthetic scenario accessors |
| `scenario-fixtures-capture-derived` | no | reviewed capture-derived scenario |

The primary public modules are:

- `netbraid::evidence`: versioned, policy-neutral record types;
- `netbraid::replay`: strict JSONL, scenario, triage, and pure reduction;
- `netbraid::infer`: finite, versioned evidence and hypothesis reducers;
- `netbraid::adapters::kismetdb`: optional read-only KismetDB boundary;
- `netbraid::adapters::tshark`: optional offline normalization boundary.

Schema IDs retain the historical `netmon.*` namespace where changing them
would break wire compatibility. Product names and Rust API paths use
`netbraid`.

See
[Architecture](https://github.com/arclabs561/netbraid/blob/main/docs/architecture.md)
and
[Design decisions](https://github.com/arclabs561/netbraid/blob/main/DECISIONS.md).

## Legacy Go capture CLI

The root Go program is a separate live-acquisition compatibility surface. It
requires libpcap and may require elevated privileges. Invoking it without a
subcommand begins acquisition and writes artifacts, so use an explicit
interface, output directory, and terminal condition:

```sh
go build -o netbraid-go .
sudo ./netbraid-go -q -i en0 -o /tmp/netbraid-capture
```

Its output contains one PCAP per selected interface plus `events.jsonl`.
Do not install it beside the Rust binary under the same filename. New
evidence, replay, adapter, and CLI work belongs in Rust; the Go tree receives
compatibility, security, and build fixes while its remaining acquisition
contract is retired deliberately.

The Go module's historical `github.com/arclabs561/netwatch` path remains for
source compatibility.

## Evidence and safety boundaries

- Netbraid does not capture or contact the network in its Rust commands.
- Raw capture artifacts, logs, local notebooks, and credentials are ignored by
  the repository and excluded from package and container contexts.
- JSONL replay is strict. Unknown schemas, unknown fields, non-canonical
  records, unsafe paths, and known corruption fail closed.
- Interrupted final JSONL fragments can be recovered only through an explicit
  warning-bearing read path.
- Conversation direction is canonical endpoint order, not guessed initiator
  or client/server direction.
- Protocol and traffic fingerprints are evidence candidates, not verified
  application, actor, role, or intent labels.
- Hypotheses are derived, versioned, and revisable; source evidence remains
  immutable.
- Absence claims require source coverage, freshness, and a complete relevant
  interval.

Netbraid does not own a daemon, database, retention policy, controller,
credentials, identity graph, automatic telemetry, or active-discovery policy.
Consumers may combine its records, but they must preserve source evidence and
declare their own inference authority.

## Development

```sh
just rust-check
just scenario-check
just pcap-smoke       # requires TShark and Capinfos
just test             # legacy Go compatibility
```

The Rust checks cover no-default-feature consumers, all package features,
formatting, tests, clippy, rustdoc warnings, fixture inventory, and extracted
package contents. The saved-capture smoke lane runs separately because it
depends on installed Wireshark tools. Set `PYTHON=/path/to/python` to select
the interpreter used by `just` evaluation targets.

## License

Authored code is available under MIT or the Unlicense. The package expression
is `(MIT OR Unlicense) AND BSD-3-Clause` because the source archive includes a
supported capture-derived fixture under BSD-3-Clause. Its notice is distributed
with the fixture.
