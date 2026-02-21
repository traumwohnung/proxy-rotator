# proxy-rotator

A Rust HTTP proxy server that load-balances requests across pools of upstream proxies with least-used rotation and optional session affinity.

## Architecture

```
Client ──HTTP/CONNECT──→ proxy-rotator ──→ upstream proxy pool ──→ Destination
```

- **No TLS termination** — raw bytes are relayed through CONNECT tunnels. The client's own TLS handshake reaches the destination untouched.
- Multiple **proxy sets** — each with its own pool of upstream proxies and rotation strategy.
- **Least-used rotation** — requests go to the proxy with the lowest use count, with random tie-breaking among equally-used proxies.
- **Session affinity** — optionally pin a client IP to the same upstream proxy for a configurable duration.
- **Per-proxy credentials** — each proxy entry includes its own username:password.

## Configuration

All configuration lives in a TOML file (default: `config.toml`):

```toml
bind_addr = "127.0.0.1:8100"
log_level = "info"

[[proxy_set]]
name = "residential"
proxies_file = "proxies/residential.txt"
session_affinity_secs = 300         # same client IP → same proxy for 5 min

[[proxy_set]]
name = "datacenter"
proxies_file = "proxies/datacenter.txt"
session_affinity_secs = 0           # pure least-used rotation
```

### Proxy list files

One proxy per line. Format: `host:port:username:password` or `host:port` (no auth). Comments (`#`) and blank lines are ignored:

```
# Residential static proxies
150.241.111.154:6658:dlipsdjpstaticresidential:epzji8na3wlr
82.23.88.116:7872:dlipsdjpstaticresidential:epzji8na3wlr
91.134.52.73:5432:dlipsdjpstaticresidential:epzji8na3wlr
```

## Usage

```bash
# Build
cargo build --release

# Run (uses ./config.toml by default)
./target/release/proxy-rotator

# Or specify a config file
./target/release/proxy-rotator /path/to/config.toml
```

### Client usage

Clients select a proxy set via the `Proxy-Authorization` header. The **username** is the proxy set name, and the **password** is empty (unused):

```bash
# Use the "residential" proxy set
curl -x http://127.0.0.1:8100 \
  --proxy-user "residential:" \
  https://httpbin.org/ip

# Use the "datacenter" proxy set
curl -x http://127.0.0.1:8100 \
  --proxy-user "datacenter:" \
  https://httpbin.org/ip

# If only one proxy set is configured, auth can be omitted
curl -x http://127.0.0.1:8100 https://httpbin.org/ip
```

### Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `RUST_LOG` | Log level (overrides config) | from config |

## How It Works

1. Client connects and sends an HTTP request or CONNECT tunnel request
2. The proxy set is selected from `Proxy-Authorization: Basic base64(set_name:)`
3. An upstream proxy is chosen using **least-used rotation** (lowest use count, random tie-breaking)
4. Credentials from the proxy entry (`host:port:user:pass`) are forwarded to the upstream proxy
5. For **CONNECT**: a tunnel is established through the upstream proxy, then raw bytes are relayed bidirectionally — no TLS breaking
6. For **plain HTTP**: the request is forwarded through the upstream proxy with the absolute URI

### Least-used rotation

Every proxy tracks a use counter. On each request, the rotator:
1. Finds the minimum use count across all proxies in the set
2. Collects all proxies with that minimum count
3. Picks one at random from the candidates

This ensures even distribution while avoiding predictable patterns.

### Session affinity

When `session_affinity_secs > 0`, the first request from a client IP gets assigned an upstream proxy via least-used selection. Subsequent requests from the same IP reuse that proxy until the affinity window expires. Expired entries are cleaned up every 60 seconds.

## Docker

```bash
docker build -t proxy-rotator .
docker run -p 8100:8100 \
  -v ./config.toml:/data/config/config.toml:ro \
  -v ./proxies:/data/config/proxies:ro \
  proxy-rotator
```

See [`deployment/`](deployment/) for a complete docker-compose example with sample proxy files.

Pre-built images: `ghcr.io/<owner>/proxy-rotator`

## Building

```bash
cargo build --release
```

No special dependencies — pure Rust with tokio/hyper.

## License

MIT
