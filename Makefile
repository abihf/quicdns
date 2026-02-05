PREFIX=/usr/local
BIN_DIR=$(PREFIX)/bin
SERVICE_DIR=/usr/lib/systemd/system
TARGET=

target/release/quicdns: src/main.rs Cargo.toml Cargo.lock
	cargo build --release

target/quicdns.service: quicdns.service.in
	sed "s|@BIN_DIR@|$(BIN_DIR)|g" quicdns.service.in > target/quicdns.service

.PHONY: build install clean uninstall

build-bin: target/release/quicdns
build-service: target/quicdns.service
build: build-bin build-service

install-bin: build
	install -m 755 target/release/quicdns $(TARGET)$(BIN_DIR)/quicdns
install-service: build-service
	install -m 644 target/quicdns.service $(TARGET)$(SERVICE_DIR)/quicdns.service
install: install-bin install-service

clean:
	rm target/release/quicdns
	rm target/quicdns.service

uninstall:
	rm $(TARGET)$(BIN_DIR)/quicdns
	rm $(TARGET)$(SERVICE_DIR)/quicdns.service