CARGO ?= cargo
PYTHON ?= python3
PREFIX ?= $(HOME)/.local
MUSL_TARGET ?= x86_64-unknown-linux-musl

.PHONY: build release test check musl install
build:
	$(CARGO) build --locked
release:
	$(CARGO) build --locked --release
check:
	$(CARGO) fmt --check
	$(CARGO) clippy --locked --all-targets -- -D warnings
test: build
	$(CARGO) test --locked
	$(PYTHON) tests/integration.py target/debug/marriedsh
	$(PYTHON) tests/background.py target/debug/marriedsh
# Install the Rust target first: rustup target add $(MUSL_TARGET)
# The pure-Rust dependency graph lets rust-lld link the bundled musl CRT.
musl:
	$(CARGO) build --locked --release --target $(MUSL_TARGET) --config 'target.$(MUSL_TARGET).linker="rust-lld"'
install: release
	install -d "$(PREFIX)/bin"
	install -m 755 target/release/marriedsh "$(PREFIX)/bin/marriedsh"
