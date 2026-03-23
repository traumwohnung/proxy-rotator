# proxy-rotator

A Rust HTTP proxy server that load-balances requests across pools of upstream proxies with least-used rotation, per-request session affinity, and a REST API for session inspection.

Pre-built Docker images: `ghcr.io/1cedsoda/proxy-rotator`  
TypeScript client: [`@1cedsoda/proxy-rotator-client`](https://github.com/1cedsoda/proxy-rotator/pkgs/npm/proxy-rotator-client)

## Repository layout

```
proxy-rotator/          # Rust crate — the proxy server
proxy-rotator-client/   # TypeScript/Node client package (@1cedsoda/proxy-rotator-client)
```

## Architecture

```
Client ──HTTP/CONNECT──→ proxy-rotator ──→ upstream proxy pool ──→ Destination
```

- **No TLS termination** — raw bytes are relayed through CONNECT tunnels. The client's own TLS handshake reaches the destination untouched.
- **Pluggable proxy sources** — each proxy set declares a `source_type` that controls how upstream endpoints are obtained. Currently supported: `static_file` (load from a text file). The source abstraction makes it straightforward to add API-based, algorithmically-generated, or other source types in the future.
- Multiple **proxy sets** — each with its own source and rotation strategy.
- **Least-used rotation** — requests go to the proxy with the lowest use count, with random tie-breaking among equally-used proxies.
- **Session affinity** — pin a session to the same upstream proxy for a configurable duration (0–1440 minutes), encoded in the username.
- **Per-proxy credentials** — each proxy entry includes its own username:password.
- **REST API** — inspect active sessions, verify usernames, and force-rotate sessions.

## Configuration

All configuration lives in a TOML file (default: `config.toml`).

Each `[[proxy_set]]` has a `name`, a `source_type` that selects the proxy source implementation, and a `[proxy_set.source]` table with the source-specific parameters:

```toml
bind_addr = "127.0.0.1:8100"
log_level = "info"

[[proxy_set]]
name = "residential"
source_type = "static_file"

[proxy_set.source]
proxies_file = "proxies/residential.txt"

[[proxy_set]]
name = "datacenter"
source_type = "static_file"

[proxy_set.source]
proxies_file = "proxies/datacenter.txt"
```

### Source types

#### `static_file`

Loads proxies from a plain-text file at startup.

| Source parameter | Description |
|------------------|-------------|
| `proxies_file` | Path to the proxy list file (relative to config file directory) |

One proxy per line. Format: `host:port:username:password` or `host:port` (no auth). Comments (`#`) and blank lines are ignored:

```
# Residential static proxies
198.51.100.1:6658:exampleuser:examplepass
198.51.100.2:7872:exampleuser:examplepass
198.51.100.3:5432:exampleuser:examplepass
```

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | from config | Log level |
| `API_KEY` | _(disabled)_ | Bearer token for the `/api/` endpoints. If unset, all API endpoints except `/api/openapi.json` are disabled. |

## Username format

The `Proxy-Authorization` username is a **base64-encoded JSON object** with three fields:

```json
{ "meta": { "platform": "myapp", "user": "alice" }, "minutes": 60, "set": "residential" }
```

| Field | Type | Description |
|-------|------|-------------|
| `set` | string | Proxy set name — must match a `[[proxy_set]] name` in config |
| `minutes` | integer 0–1440 | Affinity duration. `0` = rotate every request, `1440` = 24 h |
| `meta` | object | Arbitrary string metadata identifying the session (e.g. platform, user) |

The base64 string itself is the affinity key — identical inputs always map to the same session.
The password is always `x` (ignored by the server).

### Example

```bash
USERNAME=$(echo -n '{"meta":{"platform":"myapp","user":"alice"},"minutes":60,"set":"residential"}' | base64)

curl -x http://127.0.0.1:8100 \
  --proxy-user "$USERNAME:x" \
  https://httpbin.org/ip
```

Use the [TypeScript client](#typescript-client) to build usernames programmatically.

## REST API

All endpoints require `Authorization: Bearer <API_KEY>`. The OpenAPI spec is at `/api/openapi.json` (no auth required).

### `GET /api/openapi.json`

Returns the OpenAPI 3.1 specification.

### `GET /api/sessions`

List all active sticky sessions.

```bash
curl -H "Authorization: Bearer mysecretkey" http://127.0.0.1:8100/api/sessions
```

```json
[
  {
    "session_id": 0,
    "username": "eyJtZXRhIjp7InBsYXRmb3JtIjoibXlhcHAifSwibWludXRlcyI6NjAsInNldCI6InJlc2lkZW50aWFsIn0=",
    "proxy_set": "residential",
    "upstream": "198.51.100.1:6658",
    "created_at": "2026-03-01T12:00:00Z",
    "next_rotation_at": "2026-03-01T13:00:00Z",
    "last_rotation_at": "2026-03-01T12:00:00Z",
    "metadata": { "platform": "myapp" }
  }
]
```

| Field | Description |
|-------|-------------|
| `created_at` | When the session was first created. Never changes. |
| `next_rotation_at` | When the current proxy assignment expires. Reset by `force_rotate`. |
| `last_rotation_at` | When the proxy was last assigned. Equals `created_at` unless `force_rotate` was called. |

### `GET /api/sessions/{username}`

Get a specific active session by its base64 username (percent-encoded in the path). Returns `404` if not found or expired. Sessions with `minutes=0` are never tracked.

### `POST /api/sessions/{username}/rotate`

Force-rotate the upstream proxy for an existing session. Picks a new upstream via least-used selection, resets `next_rotation_at` to `now + duration`, and updates `last_rotation_at`. The `session_id`, `created_at`, duration, and metadata are preserved.

```bash
curl -X POST -H "Authorization: Bearer mysecretkey" \
  http://127.0.0.1:8100/api/sessions/eyJtZXRhIjp.../rotate
```

Returns the updated `SessionInfo`. Returns `404` if no active session exists.

### `GET /api/verify/{username}`

Pre-flight check — parses the username, verifies the proxy set exists, picks an upstream **without creating a session**, and fetches the outbound IP via `api.ipify.org`. Always returns HTTP 200; check the `ok` field.

```bash
curl -H "Authorization: Bearer mysecretkey" \
  http://127.0.0.1:8100/api/verify/eyJtZXRhIjp...
```

```json
{
  "ok": true,
  "proxy_set": "residential",
  "minutes": 60,
  "metadata": { "platform": "myapp" },
  "upstream": "198.51.100.1:6658",
  "ip": "198.51.100.1"
}
```

### OpenAPI spec generation

```bash
cargo run --bin gen-openapi --manifest-path proxy-rotator/Cargo.toml
```

## TypeScript client

`@1cedsoda/proxy-rotator-client` is published to GitHub Packages.

### Installation

Add to `.npmrc`:
```
@1cedsoda:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```

```bash
npm install @1cedsoda/proxy-rotator-client
```

### API

| Export | Description |
|--------|-------------|
| `configureProxy({ proxyUrl, apiKey })` | Call once at startup. Required for `buildAndVerifyProxyUsername`. |
| `buildAndVerifyProxyUsername(set, minutes, meta)` | Encodes username and verifies it via `/api/verify`. Throws on failure. |
| `buildProxyUsername(set, minutes, meta)` | Pure sync encoder — no verification. |
| `parseProxyUsername(username)` | Decode a username back to its components. |
| `ProxyRotatorClient` | Raw API client: `listSessions`, `getSession`, `verifyUsername`, `forceRotate`. |

### Usage

```ts
import { configureProxy, buildAndVerifyProxyUsername } from "@1cedsoda/proxy-rotator-client";

// Call once at startup
configureProxy({ proxyUrl: "http://proxy-rotator:8100", apiKey: "mysecretkey" });

// Build + verify (throws if set is wrong or upstream is unreachable)
const username = await buildAndVerifyProxyUsername("residential", 60, { platform: "myapp", user: "alice" });

// Use as proxy credentials (password is always "x")
const proxyUrl = new URL("http://proxy-rotator:8100");
proxyUrl.username = username;
proxyUrl.password = "x";
```

## How it works

1. Client sends an HTTP request or CONNECT tunnel with `Proxy-Authorization: Basic <base64>`
2. The base64 string is decoded and parsed to extract `set`, `minutes`, and `meta`
3. The proxy set's source is asked for an upstream endpoint (e.g. `static_file` uses least-used rotation)
4. If `minutes > 0`, the base64 string is used as the affinity key — the same username always maps to the same proxy until the session expires
5. Upstream credentials from the proxy entry are forwarded to the upstream
6. **CONNECT**: a tunnel is established and bytes are relayed bidirectionally — no TLS termination
7. **Plain HTTP**: request is forwarded through the upstream with the absolute URI
8. Expired affinity entries are cleaned up every 60 seconds

## Adding a new source type

The proxy source abstraction (`ProxySource` trait in `source.rs`) makes it easy to add new ways of obtaining upstream endpoints:

1. Add a config struct and a new variant to `ProxySourceConfig` in `source.rs`
2. Create a struct that implements the `ProxySource` trait (`request_endpoint`, `describe`, `len`)
3. Add a match arm in `ProxySourceConfig::from_type_and_table` and `build_source`

The rotator, API, and all routing code are source-agnostic — no changes needed there.

## Docker

```bash
# Build from workspace root
docker build -f proxy-rotator/Dockerfile -t proxy-rotator .

docker run -p 8100:8100 \
  -e API_KEY=mysecretkey \
  -v ./config.toml:/data/config/config.toml:ro \
  -v ./proxies:/data/config/proxies:ro \
  proxy-rotator
```

Pre-built image:

```bash
docker run -p 8100:8100 \
  -e API_KEY=mysecretkey \
  -v ./config.toml:/data/config/config.toml:ro \
  -v ./proxies:/data/config/proxies:ro \
  ghcr.io/1cedsoda/proxy-rotator:0.7.0
```

See [`deployment/`](deployment/) for docker-compose examples.

## Building

```bash
cargo build --release                  # Rust server
cd proxy-rotator-client && pnpm install  # TypeScript client
```

## License

MIT
