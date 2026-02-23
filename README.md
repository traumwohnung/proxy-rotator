# proxy-rotator

A Rust HTTP proxy server that load-balances requests across pools of upstream proxies with least-used rotation, per-request session affinity, and a REST API for session inspection.

## Architecture

```
Client ──HTTP/CONNECT──→ proxy-rotator ──→ upstream proxy pool ──→ Destination
```

- **No TLS termination** — raw bytes are relayed through CONNECT tunnels. The client's own TLS handshake reaches the destination untouched.
- Multiple **proxy sets** — each with its own pool of upstream proxies and rotation strategy.
- **Least-used rotation** — requests go to the proxy with the lowest use count, with random tie-breaking among equally-used proxies.
- **Per-request session affinity** — controlled via the username, pin a session key to the same upstream proxy for a specified duration (0–1440 minutes).
- **Per-proxy credentials** — each proxy entry includes its own username:password.
- **REST API** — inspect active sessions and their assigned upstream proxies.

## Configuration

All configuration lives in a TOML file (default: `config.toml`):

```toml
bind_addr = "127.0.0.1:8100"
log_level = "info"

[[proxy_set]]
name = "residential"
proxies_file = "proxies/residential.txt"

[[proxy_set]]
name = "datacenter"
proxies_file = "proxies/datacenter.txt"
```

### Proxy list files

One proxy per line. Format: `host:port:username:password` or `host:port` (no auth). Comments (`#`) and blank lines are ignored:

```
# Residential static proxies
198.51.100.1:6658:exampleuser:examplepass
198.51.100.2:7872:exampleuser:examplepass
198.51.100.3:5432:exampleuser:examplepass
```

### Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `RUST_LOG` | Log level (overrides config) | from config |
| `API_KEY` | Bearer token for the `/api/sessions` endpoints. If unset, session API endpoints are disabled. | _(disabled)_ |

## Usage

```bash
# Build
cargo build --release

# Run (uses ./config.toml by default)
./target/release/proxy-rotator

# Or specify a config file
./target/release/proxy-rotator /path/to/config.toml

# Run with API enabled
API_KEY=mysecretkey ./target/release/proxy-rotator
```

### Client usage

Clients select a proxy set and control session affinity via the `Proxy-Authorization` header. The **username** format is strictly:

```
<proxyset>-<minutes>-<sessionkey>
```

| Part | Rules | Description |
|------|-------|-------------|
| `proxyset` | Alphanumeric only | Name of the proxy set to use |
| `minutes` | Number 0–1440 | Sticky session duration. `0` = new IP every request, `1440` = 24 hours |
| `sessionkey` | Alphanumeric only | Session identifier for affinity grouping |

The **password** is empty (unused). All three parts are required. No hyphens allowed within any part.

```bash
# Rotate every request (minutes=0) — each request gets a different proxy
curl -x http://127.0.0.1:8100 \
  --proxy-user "residential-0-req1:" \
  https://httpbin.org/ip

# 5-minute sticky session — same session key reuses the same proxy for 5 min
curl -x http://127.0.0.1:8100 \
  --proxy-user "residential-5-abc123:" \
  https://httpbin.org/ip

# Different session key → independent proxy assignment
curl -x http://127.0.0.1:8100 \
  --proxy-user "residential-5-xyz789:" \
  https://httpbin.org/ip

# Use the "datacenter" proxy set with 10-minute affinity
curl -x http://127.0.0.1:8100 \
  --proxy-user "datacenter-10-mysess:" \
  https://httpbin.org/ip

# 24-hour sticky session
curl -x http://127.0.0.1:8100 \
  --proxy-user "residential-1440-longrun:" \
  https://httpbin.org/ip
```

## REST API

The API allows inspecting active sticky sessions. All session endpoints require the `API_KEY` environment variable to be set and a matching `Authorization: Bearer <key>` header.

The OpenAPI spec is available at `/api/openapi.json` (no auth required).

### Endpoints

#### `GET /api/openapi.json`

Returns the OpenAPI 3.1 specification. **No authentication required.**

```bash
curl http://127.0.0.1:8100/api/openapi.json
```

#### `GET /api/sessions`

List all active sticky sessions across all proxy sets.

```bash
curl -H "Authorization: Bearer mysecretkey" \
  http://127.0.0.1:8100/api/sessions
```

Response:
```json
[
  {
    "username": "residential-5-abc123",
    "proxy_set": "residential",
    "upstream": "198.51.100.1:6658",
    "start_date": "2026-02-23T21:00:00Z",
    "end_date": "2026-02-23T21:05:00Z"
  }
]
```

#### `GET /api/sessions/{username}`

Get details of a specific active session by its full username.

```bash
curl -H "Authorization: Bearer mysecretkey" \
  http://127.0.0.1:8100/api/sessions/residential-5-abc123
```

Response:
```json
{
  "username": "residential-5-abc123",
  "proxy_set": "residential",
  "upstream": "198.51.100.1:6658",
  "start_date": "2026-02-23T21:00:00Z",
  "end_date": "2026-02-23T21:05:00Z"
}
```

Returns `404` if the session doesn't exist or has expired. Sessions with `minutes=0` are never tracked.

### OpenAPI spec generation

The `openapi.json` file can be regenerated with:

```bash
cargo run --bin gen-openapi
```

## How It Works

1. Client connects and sends an HTTP request or CONNECT tunnel request
2. The username is parsed from `Proxy-Authorization: Basic base64(<proxyset>-<minutes>-<sessionkey>:)`
3. An upstream proxy is chosen using **least-used rotation** (lowest use count, random tie-breaking)
4. If `minutes > 0`, the session key is pinned to that proxy for the specified duration
5. Credentials from the proxy entry (`host:port:user:pass`) are forwarded to the upstream proxy
6. For **CONNECT**: a tunnel is established through the upstream proxy, then raw bytes are relayed bidirectionally — no TLS breaking
7. For **plain HTTP**: the request is forwarded through the upstream proxy with the absolute URI

### Least-used rotation

Every proxy tracks a use counter. On each request, the rotator:
1. Finds the minimum use count across all proxies in the set
2. Collects all proxies with that minimum count
3. Picks one at random from the candidates

This ensures even distribution while avoiding predictable patterns.

### Session affinity

When `minutes > 0`, the first request with a given session key gets assigned an upstream proxy via least-used selection. Subsequent requests with the same session key and minutes value reuse that proxy until the affinity window expires. Different session keys get independent upstream proxy assignments, allowing one client to maintain multiple concurrent sessions through different proxies. Expired entries are cleaned up every 60 seconds.

When `minutes = 0`, every request goes through pure least-used rotation with no stickiness.

## Docker

```bash
docker build -t proxy-rotator .
docker run -p 8100:8100 \
  -e API_KEY=mysecretkey \
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
