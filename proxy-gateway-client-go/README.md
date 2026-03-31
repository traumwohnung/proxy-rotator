# proxy-gateway-client-go

Go client for the [proxy-gateway](https://github.com/traumwohnung/proxy-gateway) admin API, plus helpers for building and parsing proxy usernames.

## Installation

```bash
go get github.com/traumwohnung/proxy-gateway/proxy-gateway-client-go
```

## Usage

```go
import proxygatewayclient "github.com/traumwohnung/proxy-gateway/proxy-gateway-client-go"

// Build a proxy username (base64-encoded JSON)
username, err := proxygatewayclient.BuildUsername(proxygatewayclient.UsernameParams{
    Set:     "residential",
    Minutes: 60,
    Meta:    map[string]any{"platform": "myapp", "user": "alice"},
})

// Use as Proxy-Authorization credentials (password is always "x")
proxyURL, _ := url.Parse("http://" + url.UserPassword(username, "x").String() + "@proxy-gateway:8100")

// Admin API client
client := proxygatewayclient.New(proxygatewayclient.ClientOptions{
    BaseURL: "http://proxy-gateway:9000",
    APIKey:  "mysecretkey",
})

sessions, err := client.ListSessions(ctx)
info, err    := client.GetSession(ctx, username)
rotated, err := client.ForceRotate(ctx, username)
```

## API

### Username helpers

| Function | Description |
|----------|-------------|
| `BuildUsername(UsernameParams)` | Encode params into a base64 proxy username |
| `MustBuildUsername(UsernameParams)` | Like `BuildUsername` but panics on error |
| `ParseUsername(string)` | Decode a base64 username back to its params |

### Admin client

| Method | Description |
|--------|-------------|
| `ListSessions(ctx)` | List all active sticky sessions |
| `GetSession(ctx, username)` | Get a session by base64 username (nil if not found) |
| `ForceRotate(ctx, username)` | Force-rotate the upstream for a session (nil if not found) |
