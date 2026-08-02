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

catalog-check:
    {{ python }} data/tests/test-catalogs.py

# Evaluate checked, bounded slices from the ignored public archives. Fetch the
# archives first; this target never admits or writes corpus bytes into Git.
public-corpus-eval:
    cargo build --locked --manifest-path rust/Cargo.toml --bin netbraid
    {{ python }} eval/evaluate-public-corpus-slices.py --report {{ eval_output }}/public-corpus-eval-report.json

# Audit the complete Sorbonne 1 m cross-sniffer event oracle. This reports the
# synchronized-time leakage boundary; it does not run a predictive classifier.
sorbonne-same-event-audit:
    {{ python }} eval/evaluate-sorbonne-same-event.py --archive {{ raw_data }}/220211012-SU-Outdoors-Campus.zip --campaign eval/fixtures/sorbonne-same-event-campaign-v0.json --report {{ eval_output }}/sorbonne-same-event-report.json

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

iot23-flow-lineage zeek_log packet_flows report="data/derived/eval/iot23-flow-lineage-report.json":
    {{ python }} eval/evaluate-iot23-flow-lineage.py --zeek-log {{ zeek_log }} --packet-flows {{ packet_flows }} --report {{ report }}

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

osu-lora-discover setup:
    {{ python }} data/fetch/fetch-osu-lora.py discover {{ setup }}

osu-lora-fetch setup max_total_bytes="10737418240":
    {{ python }} data/fetch/fetch-osu-lora.py fetch {{ setup }} --max-total-bytes {{ max_total_bytes }}

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

fuzz-smoke:
    cd rust && RUSTUP_TOOLCHAIN=nightly cargo fuzz run parse_saved_capture_jsonl -- -runs=1000

mutation-check:
    cargo mutants --manifest-path rust/Cargo.toml --package netbraid --file src/replay/fingerprint.rs --re 'project_saved_pcap_fingerprint_v0|compare_saved_pcap_fingerprints_v0' --test-package netbraid --jobs 2 --timeout 180 --no-shuffle -v

rust-check-full: rust-check scenario-check pcap-smoke

pcap-smoke-show:
    NETBRAID_SMOKE_SHOW_OUTPUT=1 cargo test --locked --manifest-path rust/Cargo.toml --test pcap_cli -- --ignored --nocapture
