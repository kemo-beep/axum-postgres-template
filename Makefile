.PHONY: dev run build test

run:
	cargo run

build:
	cargo build

test:
	cargo test

## Start server with live reload (requires: cargo install cargo-watch)
dev:
	cargo watch -q -x run
