# Installation Instructions

## Quick Install with Make

1. Build and install:
```bash
make build
sudo make install
```

This will:
- Build the binary with native CPU optimizations
- Install binary to `/usr/local/bin/quicdns`
- Install systemd service to `/usr/lib/systemd/system/quicdns.service`

2. Configure environment variables (optional):
```bash
sudo systemctl edit quicdns.service
```

Add your custom configuration:
```ini
[Service]
Environment="UPSTREAM_SERVER=dns.adguard-dns.com"
Environment="UPSTREAM_PORT=853"
Environment="UPSTREAM_IP=94.140.14.140"
Environment="BIND_ADDR=127.0.0.53:53"
Environment="DEBUG=1"
```

3. Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable quicdns.service
sudo systemctl start quicdns.service
```

4. Check status:
```bash
systemctl status quicdns.service
journalctl -u quicdns -f
```

## Uninstall

```bash
sudo systemctl stop quicdns.service
sudo systemctl disable quicdns.service
sudo make uninstall
```

## Security Features

- **DynamicUser**: Service runs as a temporary user created on-the-fly
- **CAP_NET_BIND_SERVICE**: Allows binding to port 53 without running as root
- **Hardened**: Multiple security restrictions enabled (see service file)

## Testing

```bash
# Test DNS query
dig @127.0.0.53 example.com

# Or with nslookup
nslookup example.com 127.0.0.53
```
