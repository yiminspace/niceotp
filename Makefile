.PHONY: check test e2e
check:
	cargo fmt --all --check
	cargo clippy --locked --workspace --all-targets -- -D warnings

test:
	cargo test --locked --workspace

e2e:
	cargo build --locked --workspace
	python3 scripts/e2e.py
