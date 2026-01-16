
target/release/quicdns: src/main.rs Cargo.toml Cargo.lock
	RUSTFLAGS="-C target-cpu=native" cargo build --release

.PHONY: build install clean uninstall

build: target/release/quicdns

install-bin: build
	install -m 755 target/release/quicdns /usr/local/bin/quicdns
install-service: 
	install -m 644 quicdns.service /usr/lib/systemd/system/quicdns.service
install: install-bin install-service

clean:
	rm target/release/quicdns

uninstall:
	rm /usr/local/bin/quicdns
	rm /usr/lib/systemd/system/quicdns.service