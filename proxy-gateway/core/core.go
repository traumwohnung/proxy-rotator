// Package core defines the fundamental types for the proxy gateway pipeline.
//
// The entire system is built around one interface: Handler. Everything —
// authentication, rate limiting, session affinity, proxy source selection —
// is a Handler that either enriches the Request context and delegates to
// the next handler, or terminates the chain by returning a Proxy.
//
// Usage as an HTTP proxy server:
//
//	pipeline := middleware.Auth(simple.New("alice","pw"),
//	    middleware.Sticky(5*time.Minute,
//	        sources.StaticFile("proxies.txt"),
//	    ),
//	)
//	gateway.Run(":8100", pipeline)
//
// Usage as a Go library (no HTTP):
//
//	proxy, err := pipeline.Resolve(ctx, &core.Request{
//	    Sub: "alice", Password: "pw",
//	    Meta: core.Meta{"app": "crawler"},
//	})
//	// use proxy.Host, proxy.Username, etc.
package core

import (
	"context"
)

// Handler resolves an inbound proxy request to an upstream Proxy.
// Implementations form a composable pipeline: each handler can inspect/enrich
// the Request, delegate to an inner handler, or return a Proxy directly.
type Handler interface {
	Resolve(ctx context.Context, req *Request) (*Proxy, error)
}

// HandlerFunc adapts a function to the Handler interface.
type HandlerFunc func(ctx context.Context, req *Request) (*Proxy, error)

func (f HandlerFunc) Resolve(ctx context.Context, req *Request) (*Proxy, error) {
	return f(ctx, req)
}

// Request carries all information about an inbound proxy request.
// Middleware enriches it as the request flows through the pipeline.
type Request struct {
	// Sub is the subscriber/user identity (from "sub" in the username JSON,
	// or set programmatically).
	Sub string

	// Password is the raw password from Basic auth (empty for library usage).
	Password string

	// Set is the proxy set name to route through.
	Set string

	// Meta is flat key-value metadata from the "meta" field.
	Meta Meta

	// SessionKey is the stable key used for sticky-session affinity.
	// If empty, no affinity is applied.
	SessionKey string

	// SessionTTL is how long a sticky session should last.
	// Zero means no affinity (new proxy every request).
	SessionTTL int // minutes
}

// Meta is a flat map of string/number metadata values.
type Meta map[string]interface{}

// GetString returns the string value for key, or "" if absent/not-a-string.
func (m Meta) GetString(key string) string {
	v, _ := m[key].(string)
	return v
}

// Protocol is the proxy protocol used to connect to the upstream.
type Protocol string

const (
	ProtocolHTTP   Protocol = "http"
	ProtocolSOCKS5 Protocol = "socks5"
)

// Proxy is a resolved upstream proxy endpoint.
type Proxy struct {
	Host     string
	Port     uint16
	Username string
	Password string
	// Protocol determines how to connect through this upstream proxy.
	// Defaults to ProtocolHTTP if empty.
	Protocol Protocol
}

// GetProtocol returns the protocol, defaulting to HTTP if empty.
func (p *Proxy) GetProtocol() Protocol {
	if p.Protocol == "" {
		return ProtocolHTTP
	}
	return p.Protocol
}

// ConnHandle tracks a single active proxied connection for traffic accounting
// and mid-connection enforcement. Returned by ConnectionTracker.OpenConnection.
type ConnHandle interface {
	// RecordTraffic is called with incremental byte counts as data flows.
	// upstream=true → client→proxy, false → proxy→client.
	// Calling cancel() tears down the connection immediately.
	RecordTraffic(upstream bool, delta int64, cancel func())

	// Close is called exactly once when the connection ends.
	Close(sentTotal, receivedTotal int64)
}

// ConnectionTracker is an optional interface that Handlers can implement
// (checked via type assertion by the gateway) to observe and control
// individual proxied connections — e.g. for rate limiting, bandwidth caps,
// or concurrent connection enforcement.
type ConnectionTracker interface {
	OpenConnection(sub string) (ConnHandle, error)
}
