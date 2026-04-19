# proxy-gateway

A Go HTTP/SOCKS5 proxy server that load-balances requests across pools of upstream proxies with least-used rotation, per-request session affinity, TLS fingerprint spoofing, and a REST API for session inspection.

Pre-built Docker images: `ghcr.io/traumwohnung/proxy-gateway`  
TypeScript client: [`@traumwohnung/proxy-gateway-client-ts`](https://github.com/traumwohnung/proxy-gateway/pkgs/npm/proxy-gateway-client-ts)  
Go client: [`proxy-gateway-client-go`](proxy-gateway-client-go/)

## Repository layout

```
proxy-gateway/            # Go server binary (wires everything together)
proxy-kit/                # Go proxy framework library (core types, middleware, sources)
proxy-gateway-client-go/  # Go client package
proxy-gateway-client-ts/  # TypeScript/Node client package
tls-fingerprint-echo/     # TLS fingerprint echo server (submodule, for testing)
deployment/               # Docker Compose + example configs
```

## Architecture

```
Client ──HTTP/CONNECT──→ proxy-gateway ──→ upstream proxy pool ──→ Destination
Client ──SOCKS5────────→

With httpcloak (MITM mode):
Client ──CONNECT──→ proxy-gateway ──TLS termination──→ httpcloak ──browser TLS──→ Destination
                    (forged cert)                      (Chrome/Firefox/Safari fingerprint)
```

- **TLS fingerprint spoofing** — optional per-request MITM that re-establishes the upstream TLS connection with a browser-like fingerprint (JA3/JA4, HTTP/2 Akamai, TCP/IP stack) using [httpcloak](https://github.com/sardanioss/httpcloak). Supports Chrome, Firefox, and Safari presets.
- **HTTP/2 MITM** — client-facing H2 support via ALPN negotiation. Clients that prefer H2 get multiplexed streams through the MITM.
- **WebSocket through MITM** — WebSocket upgrades are detected and relayed with fingerprinted TLS (utls) to the upstream.
- **ECH (Encrypted Client Hello)** — hides the target hostname from network observers. Auto-fetches ECH config from DNS, configurable per request.
- **Streaming** — SSE, chunked responses, and large downloads stream through without buffering.
- **Session-aware connection reuse** — httpcloak sessions are cached per affinity key for TLS session resumption and HTTP/2 connection reuse.
- **Multi-protocol** — listens for both HTTP proxy (CONNECT + plain HTTP forwarding) and SOCKS5 on separate ports.
- **Pluggable proxy sources** — each proxy set declares a `source_type`. Supported: `static_file`, `bottingtools`, `proxyingio`, `webshare`, `geonode`, `none` (direct).
- **Multiple proxy sets** — each with its own source and rotation strategy.
- **Least-used rotation** — requests go to the proxy with the lowest use count.
- **Session affinity** — pin a session to the same upstream proxy for a configurable duration (0–1440 minutes), encoded in the username.
- **Per-proxy credentials** — each proxy entry includes its own username:password.
- **REST admin API** — inspect active sessions and force-rotate sessions (separate `admin_addr`).

## Configuration

Config can be TOML (default), YAML, or JSON. Pass the path as the first CLI argument (default: `config.toml`).

```toml
bind_addr    = "127.0.0.1:8100"   # HTTP proxy port
socks5_addr  = "127.0.0.1:1080"   # SOCKS5 port (optional)
admin_addr   = "127.0.0.1:9000"   # Admin API port (optional, requires API_KEY env var)
log_level    = "info"

# MITM CA for TLS fingerprint spoofing (optional).
# When omitted, a new CA is generated at startup.
mitm_ca_cert = "mitm-ca.crt"
mitm_ca_key  = "mitm-ca.key"

[[proxy_set]]
name        = "residential"
source_type = "static_file"

[proxy_set.static_file]
proxies_file = "proxies/residential.txt"

[[proxy_set]]
name        = "datacenter"
source_type = "static_file"

[proxy_set.static_file]
proxies_file = "proxies/datacenter.txt"

# Direct connections (no upstream proxy) — useful with httpcloak
[[proxy_set]]
name        = "direct"
source_type = "none"
```

### Source types

#### `static_file`

Loads proxies from a plain-text file at startup.

| Parameter | Description |
|-----------|-------------|
| `proxies_file` | Path to the proxy list file (relative to config file directory) |

One proxy per line. Format: `host:port:username:password` or `host:port` (no auth). Comments (`#`) and blank lines are ignored.

#### `bottingtools`

Fetches proxies from the Bottingtools API.

```toml
[proxy_set.bottingtools]
api_key = "..."
```

#### `proxyingio`

Builds proxying.io credentials from a fixed upstream username plus a password suffix. Sticky requests include `session-*` and `lifetime-*`; non-sticky requests omit them. Optional `country-*` and `quality-high` can be appended in either mode, and multiple countries are encoded as a comma-separated list like `country-AQ,AD`.

```toml
[proxy_set.proxyingio]
username         = "Swu2HZpm"
password_env     = "PROXYINGIO_PASSWORD"
host             = "proxy.proxying.io" # optional, default shown
protocol         = "http"              # optional: "http" (default) or "socks5"
port             = 8080                # optional; defaults to 8080 for http, 1080 for socks5
countries        = ["DE"]              # optional
high_quality     = true                # optional; omit for no quality filter
default_lifetime = 60
```

#### `webshare`

Generates a fixed Webshare pool from sequential usernames on `p.webshare.io:80`.

```toml
[proxy_set.webshare]
username     = "trlvvxfs"
amount       = 20
password_env = "WEBSHARE_PASSWORD"
```

#### `geonode`

Fetches proxies from the Geonode API.

```toml
[proxy_set.geonode]
username = "..."
password = "..."
protocol = "http"        # "http" or "socks5" (default: "http")

[proxy_set.geonode.session]
type = "rotating"        # "rotating" or "sticky" (default: "rotating")
```

#### `none`

Direct connections to the target — no upstream proxy. Useful when you only want httpcloak TLS fingerprint spoofing without routing through a proxy pool.

### Environment variables

| Variable | Description |
|----------|-------------|
| `LOG_LEVEL` | Override log level (`debug`, `info`, `warn`, `error`) |
| `API_KEY` | Bearer token for the admin API. If unset, the admin server is not started even if `admin_addr` is set. |
| `PROXY_PASSWORD` | If set, clients must supply this as their proxy password. |
| `PROXY_MITM_INSECURE_UPSTREAM` | Set to `true` to skip upstream TLS cert verification in MITM mode (testing only). |

## Username format

The `Proxy-Authorization` username is a **JSON object** encoded as base64:

```json
{ "set": "residential", "minutes": 60, "meta": { "platform": "myapp", "user": "alice" } }
```

| Field | Type | Description |
|-------|------|-------------|
| `set` | string | Proxy set name — must match a `[[proxy_set]] name` in config |
| `minutes` | integer 0–1440 | Affinity duration. `0` = new proxy every request, `1440` = 24 h sticky |
| `meta` | object | Arbitrary key/value pairs that identify the session (used for affinity key) |
| `httpcloak` | object | TLS fingerprint spoofing config (optional, see below) |

The base64-encoded JSON string is the affinity key — identical inputs always map to the same session for the duration of `minutes`.

### HTTPCloak (TLS fingerprint spoofing)

When the `httpcloak` field is present, the proxy-gateway activates MITM mode: it terminates the client's TLS, then re-establishes the upstream connection with a browser-like TLS fingerprint.

```json
{
  "set": "direct",
  "minutes": 60,
  "meta": {},
  "httpcloak": {
    "preset": "chrome-latest",
    "user_agent": "preset",
    "ech": true
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `preset` | string | required | Browser fingerprint: `"chrome-latest"`, `"firefox-latest"`, `"safari-latest"` |
| `user_agent` | string | `"ignore"` | `"ignore"` = pass through, `"preset"` = use preset's UA, `"check"` = reject mismatched UA |
| `ech` | bool/string | `true` | ECH: `true` = auto-fetch from DNS, `false` = disable, `"domain"` = fetch from alternate domain |
| `ja3` | string | | Custom TLS fingerprint override (advanced) |
| `akamai` | string | | Custom HTTP/2 fingerprint override (advanced) |

**What httpcloak covers:**
- TLS fingerprint (JA3/JA4) — cipher suites, extensions, curves, extension shuffling
- HTTP/2 fingerprint — SETTINGS, WINDOW_UPDATE, PRIORITY, pseudo-header order, HPACK
- TCP/IP stack — TTL, MSS, window size, window scale, DF bit
- Header order — browser-correct header ordering on upstream requests
- ECH — Encrypted Client Hello to hide SNI from network observers

### Examples

```bash
# Standard proxy (no fingerprint spoofing)
USERNAME=$(echo -n '{"set":"residential","minutes":60,"meta":{"user":"alice"}}' | base64)
curl -x http://127.0.0.1:8100 --proxy-user "$USERNAME:x" https://httpbin.org/ip

# With TLS fingerprint spoofing (Chrome)
USERNAME=$(echo -n '{"set":"direct","minutes":0,"meta":{},"httpcloak":{"preset":"chrome-latest"}}' | base64)
curl -x http://127.0.0.1:8100 --proxy-user "$USERNAME:x" -k https://httpbin.org/ip

# SOCKS5
USERNAME=$(echo -n '{"set":"residential","minutes":60,"meta":{"user":"alice"}}' | base64)
curl --socks5 127.0.0.1:1080 --proxy-user "$USERNAME:x" https://httpbin.org/ip
```

Note: when using httpcloak, the client must trust the MITM CA certificate (or use `-k` / `InsecureSkipVerify`).

Use the [Go client](#go-client) or [TypeScript client](#typescript-client) to build usernames programmatically.

## Admin REST API

Runs on a **separate port** (`admin_addr`). Requires `Authorization: Bearer <API_KEY>` on all endpoints.

Only available when both `admin_addr` is set in config and `API_KEY` is set in the environment.

### `GET /api/sessions`

List all active sticky sessions.

```bash
curl -H "Authorization: Bearer mysecretkey" http://127.0.0.1:9000/api/sessions
```

```json
[
  {
    "session_id": 0,
    "username": "eyJzZXQiOiJyZXNpZGVudGlhbCIs...",
    "proxy_set": "residential",
    "upstream": "198.51.100.1:6658",
    "created_at": "2026-03-01T12:00:00Z",
    "next_rotation_at": "2026-03-01T13:00:00Z",
    "last_rotation_at": "2026-03-01T12:00:00Z",
    "metadata": { "platform": "myapp" }
  }
]
```

### `GET /api/sessions/{username}`

Get a specific active session by its base64 username. Returns `404` if not found or expired. Sessions with `minutes=0` are never tracked.

### `POST /api/sessions/{username}/rotate`

Force-rotate the upstream proxy for an existing session. Picks a new upstream, resets `next_rotation_at`, and updates `last_rotation_at`. Returns `404` if no active session exists.

```bash
curl -X POST -H "Authorization: Bearer mysecretkey" \
  http://127.0.0.1:9000/api/sessions/eyJzZXQiOiJyZXNpZGVudGlhbCIs.../rotate
```

## TypeScript client

`@traumwohnung/proxy-gateway-client-ts` is published to GitHub Packages.

### Installation

Add to `.npmrc`:
```
@traumwohnung:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```

```bash
npm install @traumwohnung/proxy-gateway-client-ts
```

### API

| Export | Description |
|--------|-------------|
| `configureProxy({ proxyUrl, apiKey })` | Call once at startup. Required for `buildAndVerifyProxyUsername`. |
| `buildAndVerifyProxyUsername(set, minutes, meta)` | Encodes username and verifies it via `/api/verify`. Throws on failure. |
| `buildProxyUsername(opts)` | Pure sync encoder — no verification. Accepts options object with `httpcloak`. |
| `parseProxyUsername(username)` | Decode a username back to its components. |
| `ProxyGatewayClient` | Raw API client: `listSessions`, `getSession`, `forceRotate`. |

### Usage

```ts
import { buildProxyUsername } from "@traumwohnung/proxy-gateway-client-ts";

// Standard proxy
const username = buildProxyUsername({
  proxySet: "residential",
  affinityMinutes: 60,
  metadata: { platform: "myapp", user: "alice" },
});

// With TLS fingerprint spoofing
const spoofedUsername = buildProxyUsername({
  proxySet: "direct",
  affinityMinutes: 0,
  metadata: {},
  httpcloak: { preset: "chrome-latest", user_agent: "preset" },
});
```

## Go client

```go
import proxygatewayclient "github.com/traumwohnung/proxy-gateway/proxy-gateway-client-go"

// Standard proxy
username, _ := proxygatewayclient.BuildUsername(proxygatewayclient.UsernameParams{
    Set:     "residential",
    Minutes: 60,
    Meta:    map[string]any{"user": "alice"},
})

// With TLS fingerprint spoofing
username, _ := proxygatewayclient.BuildUsername(proxygatewayclient.UsernameParams{
    Set: "direct",
    HTTPCloak: &proxygatewayclient.HTTPCloakSpec{
        Preset:    "chrome-latest",
        UserAgent: "preset",
    },
})
```

## Docker

```bash
# Build
docker build -t proxy-gateway .

# Run
docker run -p 8100:8100 -p 9000:9000 \
  -e API_KEY=mysecretkey \
  -v ./config.toml:/data/config/config.toml:ro \
  -v ./proxies:/data/config/proxies:ro \
  proxy-gateway
```

Pre-built image:

```bash
docker run -p 8100:8100 \
  -e API_KEY=mysecretkey \
  -v ./config.toml:/data/config/config.toml:ro \
  -v ./proxies:/data/config/proxies:ro \
  ghcr.io/traumwohnung/proxy-gateway:latest
```

See [`deployment/`](deployment/) for a Docker Compose example.

## Building & running

```bash
# Run server
cd proxy-gateway
go run . ../config.toml

# Build binary
go build -o proxy-gateway-server .

# TypeScript client
cd proxy-gateway-client-ts && npm install
```

## License

MIT
