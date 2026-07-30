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
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid-replay | grep -Fqx 'tests/fixtures/relation-preflight-v0.json'
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid-replay | grep -Fqx 'tests/relation_preflight.rs'
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid | grep -Fqx 'src/lib.rs'
    @! cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid | grep -Eq '^tests/(fixtures/|pcap_cli\.rs$|scenario_cli\.rs$)'

pcap-smoke:
    cargo test --locked --manifest-path rust/Cargo.toml -p netbraid-adapter-tshark --tests -- --ignored
    cargo test --locked --manifest-path rust/Cargo.toml -p netbraid --test pcap_cli -- --ignored

fuzz-smoke:
    cd rust && RUSTUP_TOOLCHAIN=nightly cargo fuzz run parse_saved_capture_jsonl -- -runs=1000

mutation-check:
    cd rust && cargo mutants --manifest-path crates/netbraid-replay/Cargo.toml --package netbraid-replay --file crates/netbraid-replay/src/relation.rs --test-package netbraid-replay --jobs 2 --timeout 180 --no-shuffle -v

rust-check-full: rust-check scenario-check pcap-smoke

pcap-smoke-show:
    NETBRAID_SMOKE_SHOW_OUTPUT=1 cargo test --locked --manifest-path rust/Cargo.toml -p netbraid --test pcap_cli -- --ignored --nocapture
