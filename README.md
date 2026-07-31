# netbraid

Netbraid contains a Rust library for network evidence and an older Go capture CLI.
The Rust code reads host snapshots, normalizes saved captures through TShark, and
replays finite test fixtures. It does not run a collector, store, or fusion service.

The repository also contains:

- `netbraid-adapter-tshark`, which turns a bounded saved capture into manifests,
  packet records, and quarantines;
- `swucb/`, an unused legacy experiment kept until the Go capture path can be
  retired.

The Go and Rust commands both build a binary named `netbraid`, so the examples
below invoke them by build path. The old Go module path is kept for compatibility.

## Scope

| Surface | Lifecycle | Job |
| --- | --- | --- |
| Go capture CLI | Legacy compatibility | Acquire selected packet/RF observations as PCAP and JSONL |
| Rust snapshot CLI | Compatibility reader | Interpret the latest saved netops audit snapshot |
| Rust v0 libraries | Experimental | Read and replay evidence, compare host paths, validate fixtures, reduce saved-capture packets, and emit packet-shape candidates |
| Rust Wireshark-tool adapter | Experimental | Normalize bounded saved captures into manifests, packets, receipts, and quarantines |
| `swucb/` | Legacy, deletion-gated | Preserve no runtime behavior; remove after the Rust acquisition control proves receipt-bound attribution |
| Broader multi-modal evidence families | Gated future | Add cross-source and RF evidence only after representative fixtures and a concrete second consumer |
| Live deployment or fusion service | External | Consume released evidence/replay artifacts after its own parity and rollback gates |

The Rust core is experimental. Its host-path record is policy-neutral, and its
multi-modal work still needs representative fixtures and a second consumer. The
Go capture CLI remains for compatibility; new core work is Rust.

The repository does not own:

- host-path and link-quality diagnosis, which belongs to Linktop. Once Netbraid exposes
  a stable policy-neutral Rust API, Linktop may move from its exact-revision v0
  dependency to that release; local diagnosis already remains usable without a
  Netbraid executable, store, controller, or deployment;
- deployed collectors, operational stores, retention, topology, runtime health,
  notifications, compatibility projections, or the current Python fusion service;
- device aliases, assignments, enrolled anchors, consent, credentials, household
  identity, or person-presence authority;
- controller/Kismet integration, active LAN inventory, IDS behavior, arbitrary shell
  hooks, or a distributed capture/dataflow runtime for the future core.

The legacy capture and watcher code is not the foundation for the future core. New
production capture belongs to the deployed Kismet path or mature capture tools; new
Netbraid work must preserve source evidence rather than widening capture features.

## Build and run the Go capture CLI

Go 1.25.12 or newer is declared by `go.mod`; this compatibility floor tracks
standard-library security fixes rather than the future Rust architecture.

This is the legacy acquisition binary, not the passive Rust reader. Invoking it
without a subcommand begins live acquisition on selected/default interfaces and
writes into the current directory. Keep it build-path-qualified and supply an
explicit interface, output directory, and terminal condition; do not install it
beside the Rust binary.

```sh
go build -o netbraid .
./netbraid --help
```

Capture one interface until interrupted, writing artifacts to the selected directory:

```sh
sudo ./netbraid -q -i en0 -o /tmp/netbraid-capture
```

`-i` accepts a Go regular expression as written; it is not implicitly anchored. Use
`-I` for all active interfaces. Per-interface options follow the expression after a
colon:

```sh
sudo ./netbraid -q -i 'wlp.*:h=static,b=2.4ghz' -o /tmp/netbraid-capture
```

`h=static|uniform|thompson` selects the hopping strategy and
`b=2.4ghz|5ghz` limits the band. The default strategy is `uniform`, with a 200 ms
capture interval. Multiple selected interfaces capture concurrently; one interface
occupies one channel at a time.

The capture directory contains `<hopper>:<interface>.pcap` files and `events.jsonl`.
Without `-q`, packet records go to stdout. `-S` selects the dynamic summary instead.

## Build and run the Rust snapshot CLI

```sh
cargo build --manifest-path rust/Cargo.toml
./rust/target/debug/netbraid --version
./rust/target/debug/netbraid --help
./rust/target/debug/netbraid net
./rust/target/debug/netbraid device '<name, MAC, or IP substring>'
./rust/target/debug/netbraid here
./rust/target/debug/netbraid evidence ./host-path.jsonl
./rust/target/debug/netbraid pcap ./incident.pcap
./rust/target/debug/netbraid pcap ./incident.pcapng --json
./rust/target/debug/netbraid pcap ./incident.pcapng --jsonl
./rust/target/debug/netbraid pcap ./incident.pcapng --records-jsonl
./rust/target/debug/netbraid pcap ./incident.pcapng --wlan-fingerprint-json
./rust/target/debug/netbraid scenario validate ./scenario --json
./rust/target/debug/netbraid scenario replay ./scenario --checkpoint CHECKPOINT --json
```

The Rust workspace requires Rust 1.88 or newer. The CLI and its three
libraries are released together at one version; the first registry release
identity is 0.3.0 because the earlier 0.2.0 Git tag already names immutable
bytes. Check crates.io for registry availability. Before a version is visible
there, install from a source checkout or its tagged GitHub archive rather than
assuming `cargo install netbraid` is available.

Initial crates.io ownership is a one-time publication from a clean
current-`main` checkout with a scoped token. Later releases use the repository's
Trusted Publishing workflow. The bootstrap token is revoked immediately after
all four trusted publishers are registered, and a release tag is created only
after crates.io reports artifacts from the intended commit.

To install a source checkout into Cargo's binary directory:

```sh
cargo +1.88 install --locked --path rust
netbraid --version
```

Tagged releases use `netbraid-vVERSION` and contain native archives for Linux
x86-64, Intel macOS, and Apple silicon macOS. Each archive contains the Rust
`netbraid` binary, README, both license files, and the canonical
`netbraid-evidence` v0 fixture bundle. For example:

```sh
version=0.3.0
target=aarch64-apple-darwin
asset="netbraid-v${version}-${target}.tar.gz"
gh release download "netbraid-v${version}" --repo arclabs561/netbraid \
  --pattern "$asset" --pattern SHA256SUMS
grep "  ${asset}$" SHA256SUMS | shasum -a 256 --check
tar -xzf "$asset"
mkdir -p "$HOME/.local/bin"
install -m 0755 "netbraid-v${version}-${target}/netbraid" "$HOME/.local/bin/netbraid"
```

Use `x86_64-apple-darwin` on an Intel Mac and
`x86_64-unknown-linux-gnu` on x86-64 Linux. The checksum covers the
downloaded archive. GitHub build-provenance attestations cover all release
archives and `SHA256SUMS`.

The macOS archives are not Developer ID signed or notarized. If local policy
rejects a downloaded binary, build the verified tag from source with Cargo
instead of weakening Gatekeeper.

The default snapshot input is `~/.cache/netops/audit-history.jsonl`; pass `--file PATH`
to read another audit history. The snapshot commands read the last JSON object and
exit. The `evidence` command strictly reads the complete supplied log. A missing,
empty, or malformed input is an error rather than evidence about the live network.
Compatibility output identifies the saved source path, exact Unix timestamp,
relative age or future-clock warning, and controller-reported metric names. Device
queries prioritize exact values, refuse ambiguous substring matches, and never turn
a hostname-shaped roster match into verified device identity.

At the library boundary, `read_jsonl` remains strict.
`read_jsonl_recovering_tail` can instead return the valid replay prefix plus a typed
warning when only the final malformed fragment is unterminated; internal or
newline-terminated corruption still fails. `append_jsonl` strictly preflights existing
content, writes each canonical record and its newline from one buffer, and inserts one
separator before a valid final JSON record that lacked a newline. Appends are
fail-closed around known corruption but are not cross-process locking: one writer owns
each log.

The `scenario` command is a finite, offline maintainer surface over
`netbraid.scenario_bundle.v0` and `netbraid.scenario_bundle.v1`. `validate`
selects the strict loader named by `scenario.json` and checks the exact manifest
and artifact inventory, hashes, safe paths, strict host-path or saved-capture
streams, monotonic timeline references, coverage/freshness separation,
supported conclusions, required abstentions, and ASCII viewport bounds.
`replay` returns the source prefix and typed projection at one named checkpoint.
Version 0 continues to emit the byte-stable `netbraid.scenario_replay.v0`
receipt. A v1 bundle emits `netbraid.scenario_replay.v1`, preserving the bundle
schema, declared sensitivity, and declared disclosure review when the receipt
is detached while retaining the same checkpoint projection fields. Structural
replay does not authenticate that declaration. The reported manifest SHA-256
closes over the exact `scenario.json` bytes and is not stored inside the
manifest. Scenario expectations are authored test oracles, not
source evidence, identity claims, or live collection instructions. Validation
proves their references and structural preconditions; consumer tests must
independently derive conclusions and render views before treating an oracle as
passed.

The normal library does not embed fixtures. Maintainer tests enable
`netbraid-replay/scenario-fixtures` to expose four tiny `PUBLIC_SYNTHETIC`
bundles covering Wi-Fi/hotspot recurrence, a same-SSID BSSID attachment
transition followed by an incompatible reused-label boundary, overlay
attribution abstention, and a stale neighbor-cache gap.

The separate, non-default
`netbraid-replay/scenario-fixtures-capture-derived` feature exposes one
`PUBLIC_REVIEWED` v1 bundle without changing that v0 list. It contains
deterministic six- and seven-packet normalized prefixes of an admitted libpcap
IEEE 802.11 capture. The seventh frame adds one observed deauthentication
frame; the oracle keeps the earlier negative result prefix-scoped and requires
abstention from source-wide counts or absence, identity, intent, causality, and
radio-channel claims. The bundle records exact upstream revision, path, blob
and content digests, byte count, SPDX terms, and a non-ingestible
`license_text` artifact. Its disclosure review enumerates link-layer addresses,
the network name, and packet timestamps retained in ingestible evidence; raw
packet payload bytes are omitted from those evidence artifacts. Validation
derives identifier classes from every admitted typed saved-capture record and
requires the declaration to match exactly. Version 1 does not admit host-path
streams or opaque quarantine rows, because neither can satisfy this
capture-source disclosure closure. It also leaves viewport text in v0 until
presentation bytes have their own disclosure contract. The separately
classified legal notice remains verbatim for redistribution compliance.

Structural validation does not authenticate a `PUBLIC_REVIEWED` assertion in
an arbitrary external directory. The built-in is trusted because its exact
content, source, and legal coordinates are admitted and tested; another
structurally valid bundle needs its own trusted review and distribution path.

The normalized fixture's committed TShark version, field registry, and
effective-configuration fingerprint describe the exact reviewed reference
bytes. They are provenance, not portable constants that every host must
reproduce. Regeneration changes the bundle closure and requires review.

## Maintainer evaluation data

The repository includes a small fetcher for approved public capture archives.
It stores downloads and selected extracts under the ignored `eval-data/`
directory, checks the declared byte count and MD5 digest, and writes receipts
for downloaded and extracted files. It is not part of the normal test gate.

```sh
uv run --script scripts/fetch-public-eval-corpus.py list
uv run --script scripts/fetch-public-eval-corpus.py v2i-80211ad
uv run --script scripts/fetch-public-eval-corpus.py v2i-80211ad \
  --inspect --inspect-output eval-data/v2i-80211ad-members.json
```

Use repeated `--extract-member` options to select a bounded slice after
inspection. The larger Zigbee archive is opt-in and uses the same checks:

```sh
uv run --script scripts/fetch-public-eval-corpus.py v2i-80211ad \
  --extract-member v2i-80211ad-dataset/2020/pcap/trace-236/monitor.ad.1593946636.pcap \
  --extract-member v2i-80211ad-dataset/2020/gps.csv \
  --extract-member v2i-80211ad-dataset/2020/trghpt.csv
```

Do not commit the archive, extracted files, or generated inventories. Review
the source terms and the extraction receipt before using a public slice in a
committed fixture.

The admitted fixture corpus also has a local, offline evaluator. It runs the
debug binary twice per fixture and checks manifest hashes, expected WLAN
evidence, content-bound provenance, deterministic output, and identifier
non-disclosure. It writes only a metadata report under the ignored
`eval-data/` directory:

```sh
uv run --script scripts/evaluate-admitted-corpus.py
```

The `pcap` command is offline and non-interactive. Its text output leads with a
bounded triage projection: normalization completeness and quarantine, the
supported WLAN disconnect-management-frame observations when present,
the largest cumulative capture conversation by original frame octets, and
TShark candidate display-filter pivots. A candidate pivot can also select
packets excluded by the reducer's eligibility rules; the typed reduction
coverage remains authoritative. It then reports artifact identity, observer/acquisition unknowns,
Capinfos file type and declared extent, the normalized packet subset, protocol
stacks, directional capture-conversation frame/octet counts and observed TCP
flags, and the successful run identifier and emitted-record digest.
Conversation output is capture-wide only when normalization is complete. It
uses canonical endpoint A/B ordering and never claims an initiator, flow, or
session. The top conversation is cumulative across the named claim scope, not
a recent or time-local ranking; excluded packet-envelope coverage remains
explicit by typed reason.

`--tail-seconds SECONDS` adds an explicit source-artifact trailing-interval
analysis to text or `--json` triage while preserving that cumulative result.
Decimal seconds down to nanosecond precision are accepted. The requested
interval ends at the occurrence receipt's latest source-artifact packet time
when that extent is available, otherwise it falls back to the latest normalized
packet event time. Both boundaries are inclusive. Output distinguishes the
source-artifact packet extent, normalized packet artifact extent, requested
interval, selected packet extent, packet/exclusion counts, largest selected
conversation, and time-bounded TShark candidate pivot. Positive selection
remains useful immediately. A negative conclusion is qualified only when
normalization is complete and an occurrence receipt supplies file packet-time
bounds consistent with the normalized packet extrema and spanning the requested
interval; otherwise output abstains with typed reasons. Packet timestamps do
not prove continuous acquisition coverage. This interval does not sessionize
tuple reuse or infer an episode. The option is analysis-only and conflicts
with `--jsonl` and `--records-jsonl`, so normalized evidence output remains
unchanged.

When independently known, `--acquisition-mode passive-host-local` records that
the original artifact was acquired passively from the host. An
`active-bounded` acquisition may also repeat `--active-action ACTION`.
Omitting the mode preserves an unknown policy; offline normalization never
retroactively proves how the artifact was acquired.

For saved wireless captures, normalized packet records may also carry typed
IEEE 802.11 frame type/subtype, TA/RA/SA/DA/BSSID identifiers, nonempty SSID
element bytes, and normalized channel/frequency/signal metadata when TShark
supplies them. Finite text ranks frame mix, radio contexts, observed BSSIDs,
transmitter addresses, and SSID elements with explicit packet-field coverage.
These are artifact observations, not claims about complete channel coverage,
device identity, role, presence, or intent.

`--json` emits one finite `netmon.saved_pcap_triage.v1` JSON document with source
and normalization details. It is derived output, not a new evidence record or
an identity claim. The Rust API also has a separate
`netmon.saved_pcap_fingerprint_candidate.v0` projection. It describes packet
shape, leaves endpoint addresses and ports out of its digest, and reports
partial or unsupported input instead of guessing. It does not identify a
device, person, place, or intent. The opt-in `--fingerprint-json` command emits
that candidate directly; it does not change `--json` output.

The separate `netmon.saved_pcap_wlan_fingerprint_candidate.v0` projection
summarizes validated 802.11/radiotap frame mix, radio metadata coverage,
channels, frequencies, and signal ranges. It excludes MAC addresses, BSSIDs,
and SSID bytes from its digest. Missing radio metadata remains visible as a
coverage fact; this candidate does not identify a device, person, place, or
intent, and it does not join BLE, CSI, or spectrum evidence. The opt-in
`--wlan-fingerprint-json` command emits it directly.
Positive disconnect-frame and conversation observations are useful from the
first supporting normalized packet. Negative WLAN observations are scoped to
the complete capture or normalized packet subset; a partial subset with no
IEEE 802.11 or eligible conversation evidence is explicitly insufficient.

`--jsonl` emits the manifest, occurrence-specific successful-run receipt,
packet envelopes, and quarantines. Its receipt deliberately changes across
runs: it includes a run ID, wall-clock interval, elapsed time, and raw tool
output digests. `--records-jsonl` emits exactly the deterministic normalized-record
sequence bound by the receipt's
`normalized_records_sha256`: manifest, packet envelopes, then quarantines. It
omits the run receipt, and equivalent runs using the same artifact, fields,
tools, configuration, limits, and independently supplied provenance produce
byte-identical output. The three machine-output choices are mutually exclusive.

The manifest does not infer that a detached artifact was acquired passively or
that it covered a network, channel, or interval completely; observer,
acquisition time, acquisition policy, and acquisition coverage are absent
unless independently supplied. See
[`docs/saved-pcap-normalization.md`](docs/saved-pcap-normalization.md).
The conversation reducer remains deliberately non-sessionized and capture-wide.

Saved-PCAP normalization requires compatible `tshark` and `capinfos`
executables at runtime. They are not bundled in release archives. On macOS,
install the Homebrew `wireshark` formula; on Debian or Ubuntu, install the
`tshark` package. `net`, `device`, `here`, and host-path `evidence` replay do
not invoke Wireshark tools.

## Promotion gates

Netbraid is the home for policy-neutral evidence fusion: braiding admitted
source observations into deterministic alignments, episodes, candidate
relations, and explanations. This is distinct from private identity fusion,
which applies device, room, person, consent, and retention policy elsewhere.

The future reusable core is narrower than private identity fusion and live
deployment. Each promoted slice must normalize a named immutable source artifact,
preserve observer and coverage evidence, replay deterministically, and explain why
a conclusion was reached or why the evidence is insufficient.

The long-term boundary is:

- Netbraid: versioned evidence records, source/coverage provenance, canonical replay,
  policy-neutral fusion, reversible candidate mechanics, and explanations;
- deployment consumers: collectors, operational stores, retention, topology,
  runtime health, compatibility rendering, and live projections;
- policy owners: device aliases, assignments, enrolled anchors, consent references,
  and credentials.

### Intended operator value

The future core is justified only if it can answer questions that a single live host
view or raw packet table cannot answer reproducibly:

| Operator circumstance | Netbraid job | Linktop projection |
| --- | --- | --- |
| A failure recurs across days or network contexts | replay source records into comparable path- or site-scoped episodes and baselines | show the relevant prior episode or baseline as optional cited evidence |
| Sources disagree about an endpoint binding or role | retain every observation, coverage interval, conflict, and candidate lineage | show the contradiction without replacing the current host observation |
| Encrypted traffic still needs coarse attribution | derive versioned application, service, stack, or role candidates from flow and handshake features, with alternatives and abstention | show a candidate only in a focused evidence view with source and window |
| One host cannot distinguish local, controller, sensor, and remote symptoms | align event and acquisition time across observers and expose the earliest supported change | identify which vantage implicated a segment and what remains unseen |
| An operator needs to hand off an intermittent incident | emit a deterministic, private evidence capsule and an explicitly sanitized projection | link the current session context to that capsule without requiring Netbraid |

This is not a commitment to one daemon or dashboard. The first useful library slice
is immutable records plus deterministic replay and explanation. Temporal reducers,
source-scoped relations, episode construction, fingerprint candidates, and query
projections follow only when each has a second consumer or a costly invariant worth
centralizing. Private identity fusion and live durable storage remain deployment
responsibilities, not Netbraid library behavior.

Linktop remains the immediate terminal instrument:

- its default acquisition policy is passive host-local observation;
- its active path probes are explicit, bounded, and independently useful;
- switching a Linktop view never causes Netbraid or another source to collect more;
- Netbraid evidence is optional, versioned, and provenance-preserving; and
- multi-source durable fusion, cross-vantage baselines, identity policy, and
  advisory fingerprint mechanics do not move into Linktop. Its explicitly
  configured v0 host-path JSONL is a narrow consumer of Netbraid replay, not a
  second fusion plane.

New Netbraid-owned core implementation is Rust. The Go capture CLI remains
compatibility code rather than a base to port feature by feature. Functionality,
semantic correctness, and operator quality take precedence over language
composition: mature specialists may remain subprocess or source boundaries, and
a native Rust extractor earns promotion only against the same evidence and
failure-semantics gates.

No typed multi-modal observation implementation starts before representative replay
fixtures fix the minimum schema. A policy-neutral binding reducer moves here only if a
later promotion decision proves a second consumer or a costly invariant. A live
deployment remains authoritative until shadow replay and rollback prove a single
replacement writer.

Kismet, Zeek, TShark, controllers, flow exporters, DHCP, DNS-SD, and similar systems
remain acquisition or dissection owners. The saved-capture TShark adapter normalizes
one declared packet-envelope field registry; future adapters may normalize other
versioned artifacts or records, but must not quietly reimplement their capture stacks.
Every temporal projection must retain source, observer, coverage, event/acquisition
time, and extractor or rule version; distinguish `observed`, `advertised`, `inferred`,
and `verified` claims; and support an explicit unknown or abstained result. Absence is
evidence only when the relevant coverage and source completeness are recorded.

Traffic fingerprints are one future inferred-evidence family, not device facts. TCP/IP
traits, TLS or QUIC handshakes, DNS and certificate metadata, packet-size/direction
sequences, flow timing, and control-plane advertisements may support application,
stack, service, or device-role candidates. Each candidate must retain the source
feature reference, observation window, extractor/signature/model version, conflicts,
and an open-world unknown result. NAT, relays, VPNs, shared libraries, encrypted
protocol evolution, and concept drift prevent a fingerprint from proving device
identity, human presence, or intent.

Collection purpose, site, modality, retention, and export remain deployment policy.
Aliases, assignments, enrolled anchors, consent, and credentials remain outside
Netbraid. Netbraid does not automatically label people or maintain a global fingerprint
index over unknown devices.

The terminology, native-extractor migration, episode, assessment, binding,
retention, and cross-surface contracts remain future design work; the current
promotion gates above are the operative boundary.

## Limitations

- Wi-Fi monitor mode and channel changes depend on the interface, operating system,
  drivers, and privileges. macOS cannot set channels through the current adapter; the
  capture path degrades to the current channel when setup fails.
- The Go capture model and disconnected `watch/` package are legacy code. The old
  host/new-port hooks are not wired into the current CLI, and legacy shell action or
  predicate triggers fail closed if selected.
- The Rust CLI is a saved-snapshot and evidence-log reader, not a live controller or
  Kismet client. Saved-PCAP normalization additionally requires compatible `tshark`
  and `capinfos` executables at runtime.
- TShark plugins and defaults can affect dissection. The adapter isolates personal
  configuration, removes documented ambient TShark behavior/path overrides, refuses
  personal plugins by default, and fingerprints effective configuration reports.
  `--allow-personal-plugins` is an executable-code opt-in; the digest is provenance,
  not a hermetic plugin bundle.
- There is an experimental v0 host-path schema and deterministic replay contract,
  but no stable multi-modal schema, daemon, or production fusion writer in this
  repository today.

## Checks

```sh
go test ./...
cargo test --manifest-path rust/Cargo.toml
just rust-check
just pcap-smoke
just pcap-smoke-show
just rust-check-full
just fuzz-smoke
just mutation-check
(cd rust && RUSTUP_TOOLCHAIN=nightly cargo fuzz run parse_saved_capture_jsonl -- -runs=1000)
```

The root `just test` also runs the repository's Go lint configuration before tests.
`just pcap-smoke` is opt-in because it invokes the locally installed TShark and
Capinfos against both readable synthetic captures and a small curated public corpus:
radiotap/802.11, raw 802.11, 5 GHz WPA2 association/EAPOL/protected data,
RARP, PPPoE discovery, severe snaplen truncation, NTP conversations, and
big-endian PCAPNG. The upstream bytes remain text-reviewable hex; their manifest
pins source commits, blob IDs, decoded digests, licenses, and stable normalization
expectations. See the
[fixture corpus](rust/crates/netbraid-adapter-tshark/tests/fixtures/README.md).
`just pcap-smoke-show` prints the finite operator summary from the CLI fixture so
presentation changes can be reviewed without preparing a local capture.
`just rust-check-full` is the release-oriented Rust gate: build, tests, Clippy,
rustdoc, and both installed-tool smoke suites. It does not install or bundle
Wireshark.
The fuzz command is a local parser smoke for arbitrary saved-capture JSONL; its
generated corpus and artifacts stay under `rust/fuzz/` and are not published.
`just fuzz-smoke` is the same bounded fuzz run through the repository command.

## License

Netbraid-authored source is dual-licensed under the
[MIT License](LICENSE-MIT) or the [Unlicense](UNLICENSE). Published source
archives retain the terms of their bundled product fixtures:

- `netbraid-replay` includes one reviewed BSD-3-Clause capture-derived
  scenario and declares `(MIT OR Unlicense) AND BSD-3-Clause`.

The test-only upstream corpora and notices used by `netbraid-adapter-tshark`
and the root CLI remain in the GitHub repository and CI but are excluded from
their published Cargo archives. Those packages and `netbraid-evidence` retain
`MIT OR Unlicense`.
