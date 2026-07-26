# netmon

Netmon is a versioned network-evidence and deterministic-replay workspace. Its Rust
release normalizes immutable artifacts, preserves provenance, and replays typed
evidence; the repository also retains a legacy Go capture tool and a disconnected
acquisition-policy experiment while the dependency-ordered Rust cutover proceeds.

Netmon currently contains four separate, buildable surfaces:

- The root Go CLI captures from one or more interfaces, optionally hops Wi-Fi
  channels, writes one PCAP per interface plus `events.jsonl`, and can print packets or
  a live summary.
- `rust/` is a small reader for the latest `netops` audit JSONL. Its `net`, `device`,
  and `here` commands do not capture traffic or query a controller directly. Its
  experimental `evidence` command deterministically replays a supplied v0 host-path
  JSONL log and distinguishes anchored exact recurrence from unanchored exact key
  matches and compatible/incomplete observations. Its `pcap` command normalizes a
  bounded saved capture through TShark and prints an operator summary or versioned
  JSONL evidence.
- `netmon-adapter-tshark` is an experimental Rust process boundary for saved PCAP and
  PCAPNG artifacts. It stages a regular file, reads file-level facts through
  Capinfos, disables name resolution, selects an explicit first-occurrence TShark
  field registry, fingerprints effective TShark configuration, refuses personal
  plugins unless explicitly allowed, preserves invalid rows as quarantines, and
  emits a successful-run receipt.
- `swucb/` is an unused legacy sliding-window UCB experiment. It remains only
  until the Rust acquisition control proves the receipt and replay contract
  needed to delete the old Go acquisition tree.

These surfaces share a repository, not one runtime or data model. Both CLIs currently
build a binary named `netmon`; the commands below invoke them by build path rather than
claiming they can be installed side by side. The Go module path
`github.com/arclabs561/netwatch` is retained as a compatibility name, not as the
repository's current charter.

## Scope

| Surface | Lifecycle | Job |
| --- | --- | --- |
| Go capture CLI | Legacy compatibility | Acquire selected packet/RF observations as PCAP and JSONL |
| Rust snapshot CLI | Compatibility reader | Interpret the latest saved netops audit snapshot |
| Rust v0 libraries | Experimental | Record and replay evidence, compare host-path context, and reduce eligible packet envelopes into capture-wide conversations |
| Rust Wireshark-tool adapter | Experimental | Normalize bounded saved captures into manifests, successful-run receipts, packet envelopes, and quarantines without live capture |
| `swucb/` | Legacy, deletion-gated | Preserve no runtime behavior; remove after the Rust acquisition control proves receipt-bound attribution |
| Rust evidence/replay core | Gated future | Normalize immutable artifacts, replay evidence, and reduce temporal state deterministically |
| Live deployment or fusion service | External | Consume released evidence/replay artifacts after its own parity and rollback gates |

The narrow Rust evidence/replay core exists as an experimental v0 package boundary.
Its broader multi-modal contract remains gated on representative fixtures and a
concrete consumer. `HostPathObservationV0` is specified in
[`docs/design/rust-library-boundary.md`](docs/design/rust-library-boundary.md) so
Linktop can act as a real second consumer without claiming that the broader gate has
passed. The dependency-ordered removal of the Go capture CLI and eventual migration
of reusable live-plane logic are specified in
[`docs/design/rust-acquisition-cutover.md`](docs/design/rust-acquisition-cutover.md).
New core work is Rust; the Go tree receives only compatibility, security, and build
fixes until it can be retired. A future opt-in Rust acquisition policy may reuse
Muxer instead of porting `swucb`; Muxer does not enter evidence, replay, Linktop, or
the passive default path.

The repository does not own:

- host-path and link-quality diagnosis, which belongs to Linktop. Once netmon exposes
  a stable policy-neutral Rust API, Linktop may move from its exact-revision v0
  dependency to that release; local diagnosis already remains usable without a
  Netmon executable, store, controller, or deployment;
- deployed collectors, operational stores, retention, topology, runtime health,
  notifications, compatibility projections, or the current Python fusion service;
- device aliases, assignments, enrolled anchors, consent, credentials, household
  identity, or person-presence authority;
- controller/Kismet integration, active LAN inventory, IDS behavior, arbitrary shell
  hooks, or a distributed capture/dataflow runtime for the future core.

The legacy capture and watcher code is not the foundation for the future core. New
production capture belongs to the deployed Kismet path or mature capture tools; new
netmon work must preserve source evidence rather than widening capture features.

## Build and run the Go capture CLI

Go 1.25.12 or newer is declared by `go.mod`; this compatibility floor tracks
standard-library security fixes rather than the future Rust architecture.

```sh
go build -o netmon .
./netmon --help
```

Capture one interface until interrupted, writing artifacts to the selected directory:

```sh
sudo ./netmon -q -i en0 -o /tmp/netmon-capture
```

`-i` accepts a Go regular expression as written; it is not implicitly anchored. Use
`-I` for all active interfaces. Per-interface options follow the expression after a
colon:

```sh
sudo ./netmon -q -i 'wlp.*:h=static,b=2.4ghz' -o /tmp/netmon-capture
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
./rust/target/debug/netmon --version
./rust/target/debug/netmon --help
./rust/target/debug/netmon net
./rust/target/debug/netmon device '<name, MAC, or IP substring>'
./rust/target/debug/netmon here
./rust/target/debug/netmon evidence ./host-path.jsonl
./rust/target/debug/netmon pcap ./incident.pcap
./rust/target/debug/netmon pcap ./incident.pcapng --jsonl
./rust/target/debug/netmon pcap ./incident.pcapng --records-jsonl
```

The Rust workspace requires Rust 1.88 or newer. It is a versioned GitHub binary
release, not a crates.io package; every workspace package has `publish = false`.
To install a source checkout into Cargo's binary directory:

```sh
cargo +1.88 install --locked --path rust
netmon --version
```

Tagged releases use `netmon-vVERSION` and contain native archives for Linux
x86-64, Intel macOS, and Apple silicon macOS. Each archive contains the Rust
`netmon` binary, README, both license files, and the canonical
`schema-fixtures/v0` bundle. For example:

```sh
version=0.1.0
target=aarch64-apple-darwin
asset="netmon-v${version}-${target}.tar.gz"
gh release download "netmon-v${version}" --repo arclabs561/netmon \
  --pattern "$asset" --pattern SHA256SUMS
grep "  ${asset}$" SHA256SUMS | shasum -a 256 --check
tar -xzf "$asset"
mkdir -p "$HOME/.local/bin"
install -m 0755 "netmon-v${version}-${target}/netmon" "$HOME/.local/bin/netmon"
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

At the library boundary, `read_jsonl` remains strict.
`read_jsonl_recovering_tail` can instead return the valid replay prefix plus a typed
warning when only the final malformed fragment is unterminated; internal or
newline-terminated corruption still fails. `append_jsonl` strictly preflights existing
content, writes each canonical record and its newline from one buffer, and inserts one
separator before a valid final JSON record that lacked a newline. Appends are
fail-closed around known corruption but are not cross-process locking: one writer owns
each log.

The `pcap` command is offline and non-interactive. Its text output reports artifact
identity, observer/acquisition unknowns, Capinfos file type and declared extent,
normalization completeness, packet/quarantine counts, the normalized packet subset,
protocol stacks, capture-wide TCP/UDP conversations with directional
frame/octet counts and observed TCP flags, and the successful run identifier
and emitted-record digest. Conversation output uses canonical endpoint A/B
ordering rather than claiming an initiator, and reports excluded
packet-envelope coverage by typed reason.

`--jsonl` emits the manifest, occurrence-specific successful-run receipt,
packet envelopes, and quarantines. Its receipt deliberately changes across
runs: it includes a run ID, wall-clock interval, elapsed time, and raw tool
output digests. `--records-jsonl` emits exactly the deterministic
normalized-record sequence bound by the receipt's
`normalized_records_sha256`: manifest, packet envelopes, then quarantines. It
omits the run receipt, and equivalent runs using the same artifact, fields,
tools, configuration, limits, and independently supplied provenance produce
byte-identical output. The two flags are mutually exclusive.

The manifest does not infer that a detached artifact was acquired passively or
that it covered a network, channel, or interval completely; observer,
acquisition time, acquisition policy, and acquisition coverage are absent
unless independently supplied. See
[`docs/saved-pcap-normalization.md`](docs/saved-pcap-normalization.md).
The deliberately non-sessionized conversation reducer is specified in
[`docs/design/capture-conversation-reduction.md`](docs/design/capture-conversation-reduction.md).

Saved-PCAP normalization requires compatible `tshark` and `capinfos`
executables at runtime. They are not bundled in release archives. On macOS,
install the Homebrew `wireshark` formula; on Debian or Ubuntu, install the
`tshark` package. `net`, `device`, `here`, and host-path `evidence` replay do
not invoke Wireshark tools.

## Promotion gates

The future reusable core is narrower than “move fusion into netmon.” Each promoted
slice must normalize a named immutable source artifact, preserve observer and coverage
evidence, replay deterministically, and explain why a conclusion was reached or why
the evidence is insufficient.

The long-term boundary is:

- netmon: versioned evidence records, source/coverage provenance, canonical replay,
  reversible candidate mechanics, and explanations;
- deployment consumers: collectors, operational stores, retention, topology,
  runtime health, compatibility rendering, and live projections;
- policy owners: device aliases, assignments, enrolled anchors, consent references,
  and credentials.

### Intended operator value

The future core is justified only if it can answer questions that a single live host
view or raw packet table cannot answer reproducibly:

| Operator circumstance | Netmon job | Linktop projection |
| --- | --- | --- |
| A failure recurs across days or network contexts | replay source records into comparable path- or site-scoped episodes and baselines | show the relevant prior episode or baseline as optional cited evidence |
| Sources disagree about an endpoint binding or role | retain every observation, coverage interval, conflict, and candidate lineage | show the contradiction without replacing the current host observation |
| Encrypted traffic still needs coarse attribution | derive versioned application, service, stack, or role candidates from flow and handshake features, with alternatives and abstention | show a candidate only in a focused evidence view with source and window |
| One host cannot distinguish local, controller, sensor, and remote symptoms | align event and acquisition time across observers and expose the earliest supported change | identify which vantage implicated a segment and what remains unseen |
| An operator needs to hand off an intermittent incident | emit a deterministic, private evidence capsule and an explicitly sanitized projection | link the current session context to that capsule without requiring netmon |

This is not a commitment to one daemon or dashboard. The first useful library slice
is immutable records plus deterministic replay and explanation. Temporal reducers,
entity relationships, episode construction, fingerprint candidates, and query
projections follow only when each has a second consumer or a costly invariant worth
centralizing.

Linktop remains the immediate terminal instrument:

- its default acquisition policy is passive host-local observation;
- its active path probes are explicit, bounded, and independently useful;
- switching a Linktop view never causes netmon or another source to collect more;
- netmon evidence is optional, versioned, and provenance-preserving; and
- multi-source durable fusion, cross-vantage baselines, identity policy, and
  advisory fingerprint mechanics do not move into Linktop. Its explicitly
  configured v0 host-path JSONL is a narrow consumer of Netmon replay, not a
  second fusion plane.

New core implementation is Rust. The Go capture CLI remains compatibility code rather
than a base to port feature by feature.

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
Netmon. Netmon does not automatically label people or maintain a global fingerprint
index over unknown devices.

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
```

The root `just test` also runs the repository's Go lint configuration before tests.
`just pcap-smoke` is opt-in because it invokes the locally installed TShark and
Capinfos against both readable synthetic captures and a small curated public corpus:
radiotap/802.11, RARP, PPPoE discovery, severe snaplen truncation, NTP
conversations, and big-endian PCAPNG. The upstream bytes remain text-reviewable
hex; their manifest pins source commits, blob IDs, decoded digests, licenses,
and stable normalization expectations. See the
[fixture corpus](rust/crates/netmon-adapter-tshark/tests/fixtures/README.md).
`just pcap-smoke-show` prints the finite operator summary from the CLI fixture so
presentation changes can be reviewed without preparing a local capture.
`just rust-check-full` is the release-oriented Rust gate: build, tests, Clippy,
rustdoc, and both installed-tool smoke suites. It does not install or bundle
Wireshark.

## License

Dual-licensed under the [MIT License](LICENSE-MIT) or the
[Unlicense](UNLICENSE).
