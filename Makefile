PREFIX=/usr/local
BIN_DIR=$(PREFIX)/bin
SERVICE_DIR=/usr/lib/systemd/system
TARGET=
PROFILE=native

target/release/quicdns: src/main.rs Cargo.toml Cargo.lock
	cargo build --release

target/native/quicdns: src/main.rs Cargo.toml Cargo.lock
	RUSTFLAGS="-C target-cpu=native" cargo build --profile native

target/quicdns.service: quicdns.service.in
	sed "s|@BIN_DIR@|$(BIN_DIR)|g" quicdns.service.in > target/quicdns.service

.PHONY: build install clean uninstall

build-bin: target/$(PROFILE)/quicdns
build-service: target/quicdns.service
build: build-bin build-service

install-bin: build
	install -m 755 target/$(PROFILE)/quicdns $(TARGET)$(BIN_DIR)/quicdns
install-service: build-service
	install -m 644 target/quicdns.service $(TARGET)$(SERVICE_DIR)/quicdns.service
install: install-bin install-service

clean:
	rm -f target/release/quicdns target/native/quicdns target/quicdns.service

fmt:
	cargo fmt --all

lint:
	cargo fmt --all -- --check
	cargo clippy --all -- -D warnings

check: lint
	cargo check --all

uninstall:
	rm $(TARGET)$(BIN_DIR)/quicdns
	rm $(TARGET)$(SERVICE_DIR)/quicdns.service