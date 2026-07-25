image := "henrywalace/netmon"

docker: lint test docker-bare

docker-bare:
	docker buildx build --platform linux/amd64,linux/arm64 -t {{image}} --push .

upgrade:
	go get -u ./...
	go install -v ./...
	go mod tidy

lint:
	golangci-lint run  # references .golangci.yml

test: lint
	go test ./...

rust-check:
	cargo fmt --manifest-path rust/Cargo.toml -- --check
	cargo test --manifest-path rust/Cargo.toml --workspace
	cargo clippy --manifest-path rust/Cargo.toml --workspace --all-targets -- -D warnings
