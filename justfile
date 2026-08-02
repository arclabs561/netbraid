image := "arclabs561/netbraid"

docker: lint test docker-bare

docker-bare:
    docker buildx build --platform linux/amd64,linux/arm64 -t {{ image }} --push .

upgrade:
    go get -u ./...
    go install -v ./...
    go mod tidy

lint:
    golangci-lint run  # references .golangci.yml

test: lint
    go test ./...

rust-check:
    cargo fmt --manifest-path rust/Cargo.toml --all -- --check
    cargo build --locked --manifest-path rust/Cargo.toml --workspace
    cargo test --locked --manifest-path rust/Cargo.toml --workspace
    cargo clippy --locked --manifest-path rust/Cargo.toml --workspace --all-targets -- -D warnings
    RUSTDOCFLAGS="-D warnings" cargo doc --locked --manifest-path rust/Cargo.toml --workspace --no-deps

scenario-check:
    cargo test --locked --manifest-path rust/Cargo.toml --workspace --all-features
    cargo clippy --locked --manifest-path rust/Cargo.toml --workspace --all-targets --all-features -- -D warnings
    RUSTDOCFLAGS="-D warnings" cargo doc --locked --manifest-path rust/Cargo.toml --workspace --all-features --no-deps
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid-replay | grep -Fqx 'tests/fixtures/scenarios/wifi-hotspot-wifi/scenario.json'
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid-replay | grep -Fqx 'tests/fixtures/scenarios/vpn-overlay-transition/scenario.json'
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid-replay | grep -Fqx 'tests/fixtures/scenarios/cache-source-gap/scenario.json'
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid-replay | grep -Fqx 'tests/fixtures/scenarios/same-ssid-attachment-boundary/scenario.json'
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid-replay | grep -Fqx 'tests/fixtures/scenarios/same-ssid-attachment-boundary/host-path.jsonl'
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid-replay | grep -Fqx 'tests/fixtures/scenarios/same-ssid-attachment-boundary/viewport.txt'
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid-replay | grep -Fqx 'tests/fixtures/scenarios/saved-capture-prefix-boundary/scenario.json'
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid-replay | grep -Fqx 'tests/fixtures/scenarios/saved-capture-prefix-boundary/prefix-6.jsonl'
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid-replay | grep -Fqx 'tests/fixtures/scenarios/saved-capture-prefix-boundary/prefix-7.jsonl'
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid-replay | grep -Fqx 'tests/fixtures/scenarios/saved-capture-prefix-boundary/LICENSE-libpcap-BSD-3-Clause.txt'
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid-adapter-tshark >/dev/null
    @! cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid-adapter-tshark | grep -Eq '^tests/(curated_corpus\.rs|fixtures/(third-party-licenses|upstream)/)'
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid | grep -Fqx 'src/lib.rs'
    @! cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid | grep -Eq '^tests/(fixtures/|pcap_cli\.rs$|scenario_cli\.rs$)'

pcap-smoke:
    cargo test --locked --manifest-path rust/Cargo.toml -p netbraid-adapter-tshark --tests -- --ignored
    cargo test --locked --manifest-path rust/Cargo.toml -p netbraid --test pcap_cli -- --ignored

# Evaluate checked, bounded slices from the ignored public archives. Fetch the
# archives first; this target never admits or writes corpus bytes into Git.
public-corpus-eval:
    cargo build --locked --manifest-path rust/Cargo.toml --bin netbraid
    python3 scripts/evaluate-public-corpus-slices.py --report eval-data/public-corpus-eval-report.json

# Audit the complete Sorbonne 1 m cross-sniffer event oracle. This reports the
# synchronized-time leakage boundary; it does not run a predictive classifier.
sorbonne-same-event-audit:
    python3 scripts/evaluate-sorbonne-same-event.py --archive eval-data/220211012-SU-Outdoors-Campus.zip --campaign scripts/fixtures/sorbonne-same-event-campaign-v0.json --report eval-data/sorbonne-same-event-report.json

# Normalize the complete Sorbonne 1 m run, join the publisher event labels,
# and exercise the structural reducer once per distinct weighted pair basis.
sorbonne-structural-reducer-eval:
    cargo build --locked --manifest-path rust/Cargo.toml --bin netbraid
    cargo build --locked --manifest-path rust/Cargo.toml -p netbraid-replay --example packet_same_event_jsonl
    python3 scripts/evaluate-sorbonne-structural-reducer.py --archive eval-data/220211012-SU-Outdoors-Campus.zip --campaign scripts/fixtures/sorbonne-structural-reducer-campaign-v0.json --netbraid-bin rust/target/debug/netbraid --reducer-bin rust/target/debug/examples/packet_same_event_jsonl --report eval-data/sorbonne-structural-reducer-report.json
    python3 scripts/evaluate-sorbonne-structural-reducer.py --archive eval-data/220211012-SU-Outdoors-Campus.zip --campaign scripts/fixtures/sorbonne-structural-reducer-campaign-v0.json --netbraid-bin rust/target/debug/netbraid --reducer-bin rust/target/debug/examples/packet_same_event_jsonl --report eval-data/sorbonne-structural-reducer-report-repeat.json
    cmp eval-data/sorbonne-structural-reducer-report.json eval-data/sorbonne-structural-reducer-report-repeat.json

# Verify all pinned OPERAnet archives and profile only their ZIP metadata.
# Member payload streams are never opened, extracted, or deserialized.
operanet-layout-profile:
    python3 scripts/profile-operanet-layout.py

# Profile a bounded CAEZ CSI shape slice directly from the verified local tar.
# The target never extracts members or deserializes position/model payloads.
caez-csi-profile:
    python3 scripts/profile-caez-csi-slices.py

# Stream the publisher position CSV and a fixed frame-metadata sample directly
# from the verified CAEZ tar. Column/time semantics remain explicitly unknown.
caez-alignment-profile:
    python3 scripts/test-profile-caez-alignment.py
    python3 scripts/profile-caez-alignment.py --report eval-data/caez-alignment-profile.json
    python3 scripts/profile-caez-alignment.py --report eval-data/caez-alignment-profile-repeat.json
    cmp eval-data/caez-alignment-profile.json eval-data/caez-alignment-profile-repeat.json

# Verify the complete Data4Cyber archive and profile only bounded structural
# evidence needed to assess whether a future cross-layer join is possible.
data4cyber-alignment-profile:
    python3 scripts/test-profile-data4cyber-alignment.py
    python3 scripts/profile-data4cyber-alignment.py --report eval-data/data4cyber-alignment-profile.json
    python3 scripts/profile-data4cyber-alignment.py --report eval-data/data4cyber-alignment-profile-repeat.json
    cmp eval-data/data4cyber-alignment-profile.json eval-data/data4cyber-alignment-profile-repeat.json

# Exercise the strict packet-to-publisher-flow oracle without requiring the
# ignored IoT-23 corpus. Production use supplies externally sessionized flows.
iot23-flow-lineage-check:
    python3 scripts/test-evaluate-iot23-flow-lineage.py

iot23-flow-lineage zeek_log packet_flows report="eval-data/iot23-flow-lineage-report.json":
    python3 scripts/evaluate-iot23-flow-lineage.py --zeek-log {{ zeek_log }} --packet-flows {{ packet_flows }} --report {{ report }}

# Fetch pinned XRF55 bundles into the ignored corpus directory. Archives are
# never extracted; a local SHA-256 receipt protects reuse after acquisition.
xrf55-fetcher-check:
    python3 scripts/test-fetch-xrf55.py

xrf55-fetch dataset="list":
    python3 scripts/fetch-xrf55.py {{ dataset }}

fuzz-smoke:
    cd rust && RUSTUP_TOOLCHAIN=nightly cargo fuzz run parse_saved_capture_jsonl -- -runs=1000

mutation-check:
    cargo mutants --manifest-path rust/Cargo.toml --package netbraid-replay --file crates/netbraid-replay/src/fingerprint.rs --re 'project_saved_pcap_fingerprint_v0|compare_saved_pcap_fingerprints_v0' --test-package netbraid-replay --jobs 2 --timeout 180 --no-shuffle -v

rust-check-full: rust-check scenario-check pcap-smoke

pcap-smoke-show:
    NETBRAID_SMOKE_SHOW_OUTPUT=1 cargo test --locked --manifest-path rust/Cargo.toml -p netbraid --test pcap_cli -- --ignored --nocapture
