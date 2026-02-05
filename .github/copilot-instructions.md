# QuicDNS AI Agent Instructions

## Project Overview
**quicdns** is a high-performance DNS proxy that forwards UDP DNS queries to a DNS-over-QUIC (DoQ) upstream server (RFC 9250). Key design: single QUIC connection with multiplexed streams, minimal parsing in production mode, and aggressive caching.

## Architecture Principles

### Single-File Design
All code lives in [src/main.rs](../src/main.rs) (~500 lines). No modules or library crates. Keep code collocated.

### Connection Strategy
- **One connection, many streams**: `ConnectionManager` maintains a single persistent QUIC connection to the upstream DoQ server
- Multiplexing via `connection.open_bi()` - each DNS query opens its own bidirectional stream
- Auto-reconnect with circuit breaker: 5+ consecutive timeouts trigger reconnection
- Connection reuse is critical - never create multiple connections per query

### Zero-Copy Mode
When `DEBUG=0` (production), the proxy operates in "zero-copy" mode:
- DNS queries forwarded **without parsing** - direct byte-level operations
- Cache keys derived from question section (bytes 12 onward)
- Query ID restoration happens at byte level: `response_buf[0..2] = query_id`
- Only parse DNS messages on errors or when `DEBUG=1`

### Cache Design
Uses `moka::future::Cache` with:
- Key: DNS question section only (excludes 12-byte header)
- Value: Full DNS response (with original query ID)
- Default: 10k entries, 5min TTL
- Query ID swapped on cache hits to match incoming query

## Critical Patterns

### DoQ Wire Protocol
DNS-over-QUIC uses 2-byte length prefix (big-endian):
```rust
// Send: [length u16][dns query bytes]
let len_prefix = (query_data.len() as u16).to_be_bytes();
send.write_all(&len_prefix).await?;
send.write_all(query_data).await?;

// Recv: [length u16][dns response bytes]
let mut len_buf = [0u8; 2];
recv.read_exact(&mut len_buf).await?;
let response_len = u16::from_be_bytes(len_buf) as usize;
```

### Error Handling
All errors return SERVFAIL to the client - never leave queries hanging:
- Parsing errors → SERVFAIL
- Upstream timeout (5s) → SERVFAIL
- Connection errors → SERVFAIL + reconnect

## Build & Development

### Build Commands
```bash
# Development build
cargo build

# Release with CPU optimizations (production)
RUSTFLAGS="-C target-cpu=native" cargo build --release

# Or use Makefile
make build  # Builds with optimizations
```

### Testing Locally
```bash
# Run with debug logging
DEBUG=1 cargo run

# Test queries (in another terminal)
dig @127.0.0.53 example.com
nslookup example.com 127.0.0.53
```

### Environment Variables
- `UPSTREAM_SERVER`: DoQ hostname (default: `dns.adguard-dns.com`)
- `UPSTREAM_PORT`: DoQ port (default: `853`)
- `UPSTREAM_IP`: Skip DNS resolution, use this IP directly
- `BOOTSTRAP_DNS`: Custom DNS resolver for upstream lookup (format: `ip:port`)
- `BIND_ADDR`: Local UDP socket (default: `127.0.0.53:53`)
- `DEBUG`: Enable parsing/logging (`1`) or zero-copy mode (`0`)

## Deployment

### Systemd Service
- Uses `DynamicUser=true` for security (ephemeral user)
- Requires `CAP_NET_BIND_SERVICE` to bind port 53 without root
- Service file generated from [quicdns.service.in](../quicdns.service.in) with `@BIN_DIR@` substitution
- Edit config: `sudo systemctl edit quicdns.service`

### Installation
```bash
sudo make install         # Installs to /usr/local/bin
sudo systemctl enable --now quicdns.service
journalctl -u quicdns -f  # View logs
```

## Dependencies

- **quinn**: QUIC client implementation
- **hickory-proto/resolver**: DNS protocol parsing (only when DEBUG=1 or for SERVFAIL)
- **moka**: Async cache with TTL
- **tokio**: Async runtime with UDP socket
- **webpki-roots**: TLS certificate validation for DoQ

## When Modifying Code

1. **Connection management**: Changes must preserve single-connection semantics
2. **Zero-copy path**: Avoid parsing in hot path; only parse for debug/errors
4. **Cache keys**: Must exclude query ID and transaction-specific headers
5. **Test with DEBUG=0**: Ensure production mode works without parsing overhead
6. **Systemd readiness**: Notify readiness before entering the UDP run loop
