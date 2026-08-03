image := "arclabs561/netbraid"
python := env_var_or_default("PYTHON", "python3")
raw_data := "data/raw"
eval_output := "data/derived/eval"

docker: lint test docker-bare

docker-bare:
    docker build -t {{ image }} .

docker-push: lint test
    docker buildx build --platform linux/amd64,linux/arm64 -t {{ image }} --push .

upgrade:
    go get -u ./...
    go install -v ./...
    go mod tidy

lint:
    golangci-lint run

test: lint
    go test ./...

rust-check:
    cargo fmt --manifest-path rust/Cargo.toml --all -- --check
    cargo check --manifest-path rust/fuzz/Cargo.toml --bin parse_saved_capture_jsonl
    cargo test --locked --manifest-path rust/Cargo.toml --no-default-features
    cargo check --locked --manifest-path rust/Cargo.toml --lib --no-default-features --features scenario-fixtures,scenario-fixtures-capture-derived
    cargo build --locked --manifest-path rust/Cargo.toml
    cargo test --locked --manifest-path rust/Cargo.toml
    cargo clippy --locked --manifest-path rust/Cargo.toml --all-targets -- -D warnings
    RUSTDOCFLAGS="-D warnings" cargo doc --locked --manifest-path rust/Cargo.toml --no-deps

scenario-check:
    cargo test --locked --manifest-path rust/Cargo.toml --all-features
    cargo clippy --locked --manifest-path rust/Cargo.toml --all-targets --all-features -- -D warnings
    RUSTDOCFLAGS="-D warnings" cargo doc --locked --manifest-path rust/Cargo.toml --all-features --no-deps
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid | grep -Fqx 'tests/fixtures/replay/scenarios/wifi-hotspot-wifi/scenario.json'
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid | grep -Fqx 'tests/fixtures/replay/scenarios/vpn-overlay-transition/scenario.json'
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid | grep -Fqx 'tests/fixtures/replay/scenarios/cache-source-gap/scenario.json'
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid | grep -Fqx 'tests/fixtures/replay/scenarios/same-ssid-attachment-boundary/scenario.json'
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid | grep -Fqx 'tests/fixtures/replay/scenarios/same-ssid-attachment-boundary/host-path.jsonl'
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid | grep -Fqx 'tests/fixtures/replay/scenarios/same-ssid-attachment-boundary/viewport.txt'
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid | grep -Fqx 'tests/fixtures/replay/scenarios/saved-capture-prefix-boundary/scenario.json'
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid | grep -Fqx 'tests/fixtures/replay/scenarios/saved-capture-prefix-boundary/prefix-6.jsonl'
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid | grep -Fqx 'tests/fixtures/replay/scenarios/saved-capture-prefix-boundary/prefix-7.jsonl'
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid | grep -Fqx 'tests/fixtures/replay/scenarios/saved-capture-prefix-boundary/LICENSE-libpcap-BSD-3-Clause.txt'
    @! cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid | grep -Eq '^tests/(adapter_curated_corpus\.rs$|fixtures/adapter/(third-party-licenses|upstream)/|fixtures/[^/]+\.hex$|pcap_cli\.rs$|scenario_cli\.rs$)'

pcap-smoke:
    cargo test --locked --manifest-path rust/Cargo.toml --test adapter_tshark_smoke --test adapter_curated_corpus -- --ignored
    cargo test --locked --manifest-path rust/Cargo.toml --test pcap_cli -- --ignored

counter-capture-eval-check:
    {{ python }} eval/test-counter-capture-eval.py
    {{ python }} eval/test-counter-capture-campaign.py

hypothesis-frame-check:
    {{ python }} eval/test-hypothesis-frame.py

hypothesis-metrics-check:
    {{ python }} eval/test-hypothesis-metrics.py

relation-split-audit-check:
    {{ python }} eval/test-relation-split-audit.py

wlan-rff-layout-profile-check:
    {{ python }} eval/test-profile-wlan-rff-layout.py

wlan-rff-layout-profile:
    {{ python }} eval/profile-wlan-rff-layout.py

smorffi-fetcher-check:
    uv run --python 3.10 data/tests/test-fetch-smorffi.py

smorffi-status:
    uv run --script data/fetch/fetch-smorffi.py status

smorffi-fetch:
    uv run --script data/fetch/fetch-smorffi.py fetch

controlled-jamming-fetcher-check:
    uv run --python 3.11 data/tests/test-fetch-controlled-jamming.py

controlled-jamming-list record="all":
    uv run --script data/fetch/fetch-controlled-jamming.py list {{ record }}

controlled-jamming-status record="all":
    uv run --script data/fetch/fetch-controlled-jamming.py status {{ record }}

controlled-jamming-fetch record max_total_bytes="137438953472" max_file_bytes="8589934592" workers="2":
    uv run --script data/fetch/fetch-controlled-jamming.py fetch {{ record }} --max-total-bytes {{ max_total_bytes }} --max-file-bytes {{ max_file_bytes }} --workers {{ workers }}

hdf5-window-check:
    uv run --script eval/test_hdf5_window.py

catalog-check:
    {{ python }} data/tests/test-catalogs.py

legacy-derived-migration-check:
    {{ python }} data/tests/test-migrate-legacy-derived.py

# Preserve only the fixed legacy-output allowlist outside the active derived
# tree, then verify its path-free legacy/unknown receipt on every later run.
legacy-derived-migration:
    {{ python }} data/migrate/migrate-legacy-derived.py

derived-artifact-audit-check:
    {{ python }} eval/test-audit-derived-artifacts.py

# Fail if an ignored derived artifact lacks an exact checked-in producer and
# canonical recipe. The audit reads filesystem metadata, not artifact bytes.
derived-artifact-audit:
    {{ python }} eval/audit-derived-artifacts.py

# Evaluate checked, bounded slices from the ignored public archives. Fetch the
# archives first; this target never admits or writes corpus bytes into Git.
public-corpus-eval-check:
    {{ python }} eval/test-evaluate-public-corpus-slices.py

public-corpus-eval:
    cargo build --locked --manifest-path rust/Cargo.toml --bin netbraid
    {{ python }} eval/evaluate-public-corpus-slices.py --report {{ eval_output }}/public-corpus-eval-report.json

# Verify or fetch the exact public allowlist. Existing artifacts are fully
# rehashed; absent artifacts are downloaded through the bounded fetcher.
public-corpus-fetch dataset="all" verify_workers="4":
    uv run --script data/fetch/fetch-public-eval-corpus.py {{ dataset }} --verify-workers {{ verify_workers }}

# Write a path-free central-directory inventory for the selected allowlist.
public-corpus-inventory dataset="all" verify_workers="4":
    uv run --script data/fetch/fetch-public-eval-corpus.py {{ dataset }} --verify-workers {{ verify_workers }} --inspect --inspect-output {{ eval_output }}/public-corpus-inventory.json

# Evaluate the complete admitted capture-fixture manifest through the current
# production binary and retain only the ignored metadata report.
admitted-corpus-eval:
    cargo build --locked --manifest-path rust/Cargo.toml --bin netbraid
    uv run --script eval/evaluate-admitted-corpus.py --out {{ eval_output }}/admitted-corpus-report.json

# Audit the complete Sorbonne 1 m cross-sniffer event oracle. This reports the
# synchronized-time leakage boundary; it does not run a predictive classifier.
sorbonne-same-event-audit:
    {{ python }} eval/evaluate-sorbonne-same-event.py --archive {{ raw_data }}/220211012-SU-Outdoors-Campus.zip --campaign eval/fixtures/sorbonne-same-event-campaign-v0.json --report {{ eval_output }}/sorbonne-same-event-report.json
    {{ python }} eval/evaluate-sorbonne-same-event.py --archive {{ raw_data }}/220211012-SU-Outdoors-Campus.zip --campaign eval/fixtures/sorbonne-same-event-campaign-v0.json --report {{ eval_output }}/sorbonne-same-event-report-repeat.json
    cmp {{ eval_output }}/sorbonne-same-event-report.json {{ eval_output }}/sorbonne-same-event-report-repeat.json

# Normalize the complete Sorbonne 1 m run, join the publisher event labels,
# and exercise the structural reducer once per distinct weighted pair basis.
sorbonne-structural-reducer-eval:
    cargo build --locked --manifest-path rust/Cargo.toml --bin netbraid
    cargo build --locked --manifest-path rust/Cargo.toml --example packet_same_event_jsonl
    {{ python }} eval/evaluate-sorbonne-structural-reducer.py --archive {{ raw_data }}/220211012-SU-Outdoors-Campus.zip --campaign eval/fixtures/sorbonne-structural-reducer-campaign-v0.json --netbraid-bin rust/target/debug/netbraid --reducer-bin rust/target/debug/examples/packet_same_event_jsonl --report {{ eval_output }}/sorbonne-structural-reducer-report.json
    {{ python }} eval/evaluate-sorbonne-structural-reducer.py --archive {{ raw_data }}/220211012-SU-Outdoors-Campus.zip --campaign eval/fixtures/sorbonne-structural-reducer-campaign-v0.json --netbraid-bin rust/target/debug/netbraid --reducer-bin rust/target/debug/examples/packet_same_event_jsonl --report {{ eval_output }}/sorbonne-structural-reducer-report-repeat.json
    cmp {{ eval_output }}/sorbonne-structural-reducer-report.json {{ eval_output }}/sorbonne-structural-reducer-report-repeat.json

# Verify all pinned OPERAnet archives and profile only their ZIP metadata.
# Member payload streams are never opened, extracted, or deserialized.
operanet-layout-profile:
    {{ python }} eval/profile-operanet-layout.py

# Profile a bounded CAEZ CSI shape slice directly from the verified local tar.
# The target never extracts members or deserializes position/model payloads.
caez-csi-profile:
    {{ python }} eval/profile-caez-csi-slices.py

# Stream the publisher position CSV and a fixed frame-metadata sample directly
# from the verified CAEZ tar. Column/time semantics remain explicitly unknown.
caez-alignment-profile:
    {{ python }} eval/test-profile-caez-alignment.py
    {{ python }} eval/profile-caez-alignment.py --report {{ eval_output }}/caez-alignment-profile.json
    {{ python }} eval/profile-caez-alignment.py --report {{ eval_output }}/caez-alignment-profile-repeat.json
    cmp {{ eval_output }}/caez-alignment-profile.json {{ eval_output }}/caez-alignment-profile-repeat.json

# Verify the complete Data4Cyber archive and profile only bounded structural
# evidence needed to assess whether a future cross-layer join is possible.
data4cyber-alignment-profile:
    {{ python }} eval/test-profile-data4cyber-alignment.py
    {{ python }} eval/profile-data4cyber-alignment.py --report {{ eval_output }}/data4cyber-alignment-profile.json
    {{ python }} eval/profile-data4cyber-alignment.py --report {{ eval_output }}/data4cyber-alignment-profile-repeat.json
    cmp {{ eval_output }}/data4cyber-alignment-profile.json {{ eval_output }}/data4cyber-alignment-profile-repeat.json

# Verify the pinned NetsLab archive/databases, using bounded read-only SQLite
# mmap where available, and emit aggregate schema/alignment metadata only.
netslab-alignment-profile:
    {{ python }} eval/test-profile-netslab-alignment.py
    {{ python }} eval/profile-netslab-alignment.py --report {{ eval_output }}/netslab-alignment-profile.json
    {{ python }} eval/profile-netslab-alignment.py --report {{ eval_output }}/netslab-alignment-profile-repeat.json
    cmp {{ eval_output }}/netslab-alignment-profile.json {{ eval_output }}/netslab-alignment-profile-repeat.json

# Exercise the strict packet-to-publisher-flow oracle without requiring the
# ignored IoT-23 corpus. Production use supplies externally sessionized flows.
iot23-flow-lineage-check:
    {{ python }} eval/test-evaluate-iot23-flow-lineage.py
    {{ python }} eval/test-run-iot23-flow-lineage-campaign.py

# Reproduce packet-flow derivation and oracle evaluation twice from the pinned
# ignored IoT-23 pair, then write a path-free deterministic campaign receipt.
iot23-flow-lineage:
    cargo build --locked --manifest-path rust/Cargo.toml --bin netbraid
    {{ python }} eval/run-iot23-flow-lineage-campaign.py --capture {{ raw_data }}/iot23v2-hakai-capture-8-1.pcap --zeek-log {{ raw_data }}/iot23v2-hakai-capture-8-1-zeek.log.labeled --netbraid-bin rust/target/debug/netbraid --output-dir {{ eval_output }}/iot23-flow-lineage-v0

# Fetch pinned XRF55 bundles into the ignored corpus directory. Archives are
# never extracted; a local SHA-256 receipt protects reuse after acquisition.
xrf55-fetcher-check:
    {{ python }} data/tests/test-fetch-xrf55.py

xrf55-fetch dataset="list":
    {{ python }} data/fetch/fetch-xrf55.py {{ dataset }}

# Inventory or explicitly fetch one Oregon State LoRa RFFI setup. The fetcher
# rejects redirects and traversal, and defaults to a 10 GiB aggregate cap.
osu-lora-fetcher-check:
    {{ python }} data/tests/test-fetch-osu-lora.py

osu-lora-discover setup workers="4":
    {{ python }} data/fetch/fetch-osu-lora.py discover {{ setup }} --workers {{ workers }}

# Recompute path-free per-setup and corpus byte bounds from the publisher
# inventory without retaining file paths, URLs, or transport validators.
osu-lora-discover-summary setup="all" workers="4":
    {{ python }} data/fetch/fetch-osu-lora.py summarize {{ setup }} --workers {{ workers }}

osu-lora-fetch setup max_total_bytes="10737418240" max_file_bytes="4294967296" workers="2":
    {{ python }} data/fetch/fetch-osu-lora.py fetch {{ setup }} --max-total-bytes {{ max_total_bytes }} --max-file-bytes {{ max_file_bytes }} --workers {{ workers }}

# Verify or complete all seven publisher setups under explicit corpus-wide and
# per-file ceilings. Reproduce the path-free inventory used to size the bounds
# with `just osu-lora-discover-summary all`; discovery drift fails closed.
osu-lora-fetch-all:
    {{ python }} data/fetch/fetch-osu-lora.py fetch all --max-total-bytes 1099511627776 --max-file-bytes 268435456 --workers 4

# Reproduce the full acquisition-to-oracle metadata pipeline. The profiler and
# oracle compiler never open IQ/FFT payload streams.
osu-lora-corpus: osu-lora-fetch-all
    just osu-lora-profile
    just osu-lora-oracles

# Validate the bounded metadata-only profiler without requiring corpus bytes.
osu-lora-profile-check:
    {{ python }} eval/test-profile-osu-lora-sigmf.py

# Profile the ignored local tree without opening IQ payload streams.
osu-lora-profile:
    {{ python }} eval/profile-osu-lora-sigmf.py

osu-lora-oracles-check:
    {{ python }} eval/test-compile-osu-lora-oracles.py

osu-lora-oracles:
    {{ python }} eval/compile-osu-lora-oracles.py

ruff-uwb-oracles-check:
    {{ python }} eval/test-compile-ruff-uwb-oracles.py

ruff-uwb-oracles:
    {{ python }} eval/compile-ruff-uwb-oracles.py

ruff-uwb-row-adapter-check:
    uv run --script eval/test-compile-ruff-uwb-row-adapter.py

# Verify the pinned one-meter archive and central fetch receipt, then stream its
# waveform member to a private standalone NPY suitable for read-only mmap.
ruff-uwb-row-adapter:
    {{ python }} eval/compile-ruff-uwb-row-adapter.py

# Record the current leakage-safe RUFF-UWB baseline boundary. The aggregate
# oracle cannot yet bind waveform rows, so this succeeds only for that exact
# path-free blocker and never opens the waveform payload.
ruff-uwb-heldout-location-check:
    uv run --script eval/test-evaluate-ruff-uwb-heldout-location.py

ruff-uwb-heldout-location:
    {{ python }} eval/evaluate-ruff-uwb-heldout-location.py --expect-blocked --report {{ eval_output }}/ruff-uwb-heldout-location-blocker.json

ruff-uwb-heldout-location-real: ruff-uwb-row-adapter
    uv run --script eval/evaluate-ruff-uwb-heldout-location.py --row-adapter {{ eval_output }}/ruff-uwb-one-meter-row-adapter.json --waveforms {{ eval_output }}/ruff-uwb-one-meter-waveforms.npy --report {{ eval_output }}/ruff-uwb-heldout-location-report.json

gnss-rff-layout-profile-check:
    {{ python }} eval/test-profile-gnss-rff-layout.py

gnss-rff-layout-profile:
    {{ python }} eval/profile-gnss-rff-layout.py

mmwave-jamming-oracles-check:
    {{ python }} eval/test-compile-mmwave-jamming-oracles.py

mmwave-jamming-oracles:
    {{ python }} eval/compile-mmwave-jamming-oracles.py

indoor-jamming-oracles-check:
    uv run --script eval/test-compile-indoor-jamming-oracles.py

indoor-jamming-oracles integrity="receipt-only":
    uv run --script eval/compile-indoor-jamming-oracles.py --integrity {{ integrity }}

indoor-jamming-controlled-cause-check:
    uv run --script eval/test-evaluate-indoor-jamming-controlled-cause.py
    {{ python }} eval/test-verify-indoor-jamming-experiment.py

# Rehash the complete source set, reconstruct private bindings in memory, and
# read only the preregistered 96 MiB of bounded HDF5 windows.
indoor-jamming-controlled-cause-eval:
    just indoor-jamming-oracles full-digest
    uv run --script eval/evaluate-indoor-jamming-controlled-cause.py
    {{ python }} eval/verify-indoor-jamming-experiment.py

fuzz-smoke:
    cd rust && RUSTUP_TOOLCHAIN=nightly cargo fuzz run parse_saved_capture_jsonl -- -runs=1000

mutation-check:
    cargo mutants --manifest-path rust/Cargo.toml --package netbraid --file src/replay/fingerprint.rs --re 'project_saved_pcap_fingerprint_v0|compare_saved_pcap_fingerprints_v0' --test-package netbraid --jobs 2 --timeout 180 --no-shuffle -v

rust-check-full: rust-check scenario-check pcap-smoke

pcap-smoke-show:
    NETBRAID_SMOKE_SHOW_OUTPUT=1 cargo test --locked --manifest-path rust/Cargo.toml --test pcap_cli -- --ignored --nocapture
