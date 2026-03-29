// Package core defines the fundamental types for the proxy gateway pipeline.
//
// The entire system is built around one interface: Handler. Everything —
// credential parsing, authentication, rate limiting, session affinity,
// TLS interception, request blocking/modification, proxy source selection —
// is a Handler that either enriches the Request and delegates to the next
// handler, or terminates by returning a Proxy (or nil to signal "I handled it").
//
// The gateway transport layer populates only the raw fields (RawUsername,
// RawPassword, Target, Conn). All semantic parsing and interception is
// performed by middleware.
package core

import (
	"context"
	"net"
	"net/http"
)

// Handler resolves an inbound proxy request to an upstream Proxy.
type Handler interface {
	Resolve(ctx context.Context, req *Request) (*Proxy, error)
}

// HandlerFunc adapts a function to the Handler interface.
type HandlerFunc func(ctx context.Context, req *Request) (*Proxy, error)

func (f HandlerFunc) Resolve(ctx context.Context, req *Request) (*Proxy, error) {
	return f(ctx, req)
}

// Request carries all information about an inbound proxy request.
// The gateway populates only the raw/transport fields. Middleware enriches
// the rest progressively as the request flows through the pipeline.
type Request struct {
	// ---- Raw transport fields (set by gateway) ----

	// RawUsername is the raw username from the transport (Basic auth / SOCKS5).
	RawUsername string

	// RawPassword is the raw password from the transport.
	RawPassword string

	// Target is the destination host:port (from CONNECT or request URI).
	Target string

	// Conn is the raw client connection. Set by the gateway for CONNECT
	// requests (after hijack) and for SOCKS5 connections. Nil for plain HTTP.
	//
	// Middleware that wants to take over the connection (e.g. MITM TLS
	// interception) reads/writes this directly and returns nil Proxy to
	// signal "I handled it — don't tunnel."
	Conn net.Conn

	// ---- TLS state ----

	// TLSBroken is true if a middleware has terminated the client's TLS
	// (MITM interception). Downstream middleware can check this to avoid
	// double-breaking and to know they're seeing plaintext.
	TLSBroken bool

	// TLSServerName is the SNI hostname from the client's TLS ClientHello.
	// Set by MITM middleware when TLSBroken is true.
	TLSServerName string

	// ---- HTTP layer (set by MITM middleware for intercepted requests) ----

	// HTTPRequest is the decoded HTTP request inside a broken TLS tunnel.
	// Set by MITM middleware for each request in the decrypted stream.
	// Also set by the gateway for plain (non-CONNECT) HTTP requests.
	// Nil when the connection is an opaque tunnel.
	HTTPRequest *http.Request

	// HTTPResponse is set by middleware that wants to provide a synthetic
	// response (e.g. blocking, caching). When non-nil the MITM layer
	// sends this to the client instead of forwarding to upstream.
	HTTPResponse *http.Response

	// ResponseHook is called after the upstream responds, before sending
	// to the client. Middleware can inspect/modify/replace the response.
	// Multiple middleware can chain hooks by wrapping the previous one.
	ResponseHook func(resp *http.Response) *http.Response

	// ---- Structured fields (set by middleware) ----

	// Sub is the subscriber/user identity, parsed from RawUsername by middleware.
	Sub string

	// Password is the credential, typically copied from RawPassword.
	Password string

	// Set is the proxy set name to route through.
	Set string

	// Meta is flat key-value metadata.
	Meta Meta

	// SessionKey is the stable key for sticky-session affinity.
	SessionKey string

	// SessionTTL is how long a sticky session lasts (minutes). 0 = no affinity.
	SessionTTL int
}

// Meta is a flat map of string/number metadata values.
type Meta map[string]interface{}

// GetString returns the string value for key, or "".
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
	Protocol Protocol
}

// GetProtocol returns the protocol, defaulting to HTTP if empty.
func (p *Proxy) GetProtocol() Protocol {
	if p.Protocol == "" {
		return ProtocolHTTP
	}
	return p.Protocol
}

// ConnHandle tracks a single active proxied connection.
type ConnHandle interface {
	RecordTraffic(upstream bool, delta int64, cancel func())
	Close(sentTotal, receivedTotal int64)
}

// ConnectionTracker is an optional interface that Handlers can implement
// to observe and control individual proxied connections.
type ConnectionTracker interface {
	OpenConnection(sub string) (ConnHandle, error)
}
