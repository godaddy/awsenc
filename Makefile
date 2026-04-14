PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

.PHONY: build install uninstall test lint fmt clean

build:
	cargo build --release

install: build
	install -d $(BINDIR)
	install -m 755 target/release/awsenc $(BINDIR)/awsenc

uninstall:
	rm -f $(BINDIR)/awsenc

test:
	cargo test --workspace

lint:
	cargo clippy --workspace --all-targets -- -D warnings

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clean:
	cargo clean

check: fmt-check lint test
