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

pcap-smoke:
    cargo test --locked --manifest-path rust/Cargo.toml -p netbraid-adapter-tshark --tests -- --ignored
    cargo test --locked --manifest-path rust/Cargo.toml -p netbraid --test pcap_cli -- --ignored

rust-check-full: rust-check pcap-smoke

pcap-smoke-show:
    NETBRAID_SMOKE_SHOW_OUTPUT=1 cargo test --locked --manifest-path rust/Cargo.toml -p netbraid --test pcap_cli -- --ignored --nocapture
