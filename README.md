# quicdns

A high-performance DNS proxy with DNS-over-QUIC (DoQ) support, written in Rust.

## Features

- **DNS-over-QUIC (DoQ)**: Forwards DNS queries over QUIC (RFC 9250) for improved privacy and performance
- **In-Memory Caching**: Built-in cache with configurable TTL to reduce latency and upstream load
- **Connection Management**: Single persistent QUIC connection with multiplexed streams for optimal performance
- **Zero-Copy Mode**: Minimal parsing overhead when debug mode is disabled
- **Systemd Integration**: Production-ready systemd service with security hardening
- **Environment Configuration**: Flexible configuration via environment variables

## Architecture

- Single QUIC connection with auto-reconnect capability
- Multiple bidirectional streams for concurrent queries
- Moka-based async cache (10,000 entries, 5-minute TTL by default)
- Cache key based on DNS question section for efficient deduplication
- SERVFAIL responses on upstream errors

## Requirements

- Rust 2024 edition or later
- Linux with systemd (for service deployment)
- CAP_NET_BIND_SERVICE capability (to bind to port 53 without root)

## Installation

See [INSTALL.md](INSTALL.md) for detailed installation instructions.

Quick install:
```bash
make build
sudo make install
sudo systemctl enable --now quicdns.service
```

## Configuration

Configuration is done via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `UPSTREAM_SERVER` | `dns.adguard-dns.com` | DNS-over-QUIC server hostname |
| `UPSTREAM_PORT` | `853` | DNS-over-QUIC server port |
| `UPSTREAM_IP` | _(resolved)_ | Upstream server IP (avoids DNS resolution at startup) |
| `BIND_ADDR` | `127.0.0.53:53` | Local address to bind the DNS proxy |
| `DEBUG` | `0` | Enable debug logging and DNS message parsing (`1` to enable) |

### Example Configuration

Edit the systemd service:
```bash
sudo systemctl edit quicdns.service
```

Add custom environment variables:
```ini
[Service]
Environment="UPSTREAM_SERVER=dns.adguard-dns.com"
Environment="UPSTREAM_PORT=853"
Environment="UPSTREAM_IP=94.140.14.14"
Environment="BIND_ADDR=127.0.0.10:53"
Environment="DEBUG=0"
```

## Usage

### Running as a Service

```bash
# Start the service
sudo systemctl start quicdns.service

# Check status
systemctl status quicdns.service

# View logs
journalctl -u quicdns -f

# Stop the service
sudo systemctl stop quicdns.service
```

### Testing

```bash
# Test with dig
dig @127.0.0.53 example.com

# Test with nslookup
nslookup example.com 127.0.0.53

# Test with systemd-resolve
systemd-resolve --status
```

### Running Manually

```bash
# Set environment variables
export UPSTREAM_SERVER=dns.adguard-dns.com
export UPSTREAM_PORT=853
export UPSTREAM_IP=94.140.14.14
export BIND_ADDR=127.0.0.10:53
export DEBUG=1

# Run the proxy
cargo run --release
```

## System Configuration

### Disable NetworkManager DNS Management

If you want to use quicdns as your system DNS resolver, you need to prevent NetworkManager from managing `/etc/resolv.conf`:

1. Create NetworkManager configuration:
```bash
sudo mkdir -p /etc/NetworkManager/conf.d
sudo tee /etc/NetworkManager/conf.d/dns.conf > /dev/null << 'EOF'
[main]
dns=none
systemd-resolved=false
EOF
```

2. Restart NetworkManager:
```bash
sudo systemctl restart NetworkManager
```

### Configure System DNS

1. Make `/etc/resolv.conf` writable (if it's a symlink):
```bash
sudo rm /etc/resolv.conf
```

2. Create new `/etc/resolv.conf`:
```bash
sudo tee /etc/resolv.conf > /dev/null << 'EOF'
nameserver 127.0.0.53
options edns0 trust-ad
EOF
```

3. Protect from modification:
```bash
sudo chattr +i /etc/resolv.conf
```

4. To revert protection (if needed):
```bash
sudo chattr -i /etc/resolv.conf
```

**Note**: Make sure quicdns is running and bound to the address specified in `/etc/resolv.conf` before making these changes.

## Security

The systemd service includes several security hardening features:

- **DynamicUser**: Runs as a temporary system user
- **CAP_NET_BIND_SERVICE**: Minimal capabilities (only bind to privileged ports)
- **ProtectSystem**: File system protection
- **ProtectHome**: Home directory isolation
- **PrivateTmp**: Private /tmp and /var/tmp
- **NoNewPrivileges**: Prevents privilege escalation
- **RestrictAddressFamilies**: Limited to AF_INET and AF_INET6

## Performance

- Native CPU optimizations enabled by default (`RUSTFLAGS="-C target-cpu=native"`)
- Zero-copy forwarding in non-debug mode
- Efficient caching reduces upstream queries
- Single QUIC connection minimizes connection overhead
- Async I/O with Tokio for high concurrency

## Dependencies

- [quinn](https://github.com/quinn-rs/quinn) - QUIC implementation
- [rustls](https://github.com/rustls/rustls) - TLS library
- [hickory-proto](https://github.com/hickory-dns/hickory-dns) - DNS protocol library
- [moka](https://github.com/moka-rs/moka) - Fast concurrent cache
- [tokio](https://tokio.rs/) - Async runtime

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.
