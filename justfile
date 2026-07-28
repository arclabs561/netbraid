image := "arclabs561/netbraid"

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

rust-check-full: rust-check scenario-check pcap-smoke

pcap-smoke-show:
    NETBRAID_SMOKE_SHOW_OUTPUT=1 cargo test --locked --manifest-path rust/Cargo.toml --test pcap_cli -- --ignored --nocapture
