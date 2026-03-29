// Package core defines the fundamental types for the proxy gateway pipeline.
//
// The entire system is built around one interface: Handler. Everything —
// credential parsing, authentication, rate limiting, session affinity,
// TLS interception, request blocking/modification, proxy source selection —
// is a Handler that either enriches the context and delegates to the next
// handler, or terminates by returning a Result.
//
// The gateway transport layer populates only the raw fields (RawUsername,
// RawPassword, Target, Conn). All semantic data (user identity, proxy set,
// session affinity) flows through context.Context, set by middleware.
package core

import (
	"context"
	"net"
	"net/http"
)

// ---------------------------------------------------------------------------
// Handler — the one interface
// ---------------------------------------------------------------------------

// Handler resolves an inbound proxy request to a Result.
type Handler interface {
	Resolve(ctx context.Context, req *Request) (*Result, error)
}

// HandlerFunc adapts a function to the Handler interface.
type HandlerFunc func(ctx context.Context, req *Request) (*Result, error)

func (f HandlerFunc) Resolve(ctx context.Context, req *Request) (*Result, error) {
	return f(ctx, req)
}

// ---------------------------------------------------------------------------
// Request — only what the transport layer knows
// ---------------------------------------------------------------------------

// Request carries the transport-level facts about an inbound proxy request.
// The gateway populates these fields. Middleware adds semantic data to
// context.Context, not to this struct.
type Request struct {
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
	// interception) reads/writes this directly and returns nil Result to
	// signal "I handled it — don't tunnel."
	Conn net.Conn

	// HTTPRequest is the decoded HTTP request. Set by the gateway for plain
	// (non-CONNECT) HTTP requests, and by MITM middleware for each request
	// inside a decrypted TLS tunnel. Nil for opaque tunnels.
	HTTPRequest *http.Request
}

// ---------------------------------------------------------------------------
// Result — what the pipeline returns
// ---------------------------------------------------------------------------

// Result carries everything the gateway needs after pipeline resolution.
type Result struct {
	// Proxy is the upstream proxy to connect through. Nil means the
	// middleware handled the connection directly (e.g. MITM, synthetic
	// response) or wants to reject.
	Proxy *Proxy

	// ConnHandle tracks the connection lifecycle (bytes, limits).
	// May be nil if no rate limiting is in the pipeline.
	ConnHandle ConnHandle

	// ResponseHook is called after the upstream responds, before sending
	// to the client. Multiple middleware can chain hooks.
	ResponseHook func(resp *http.Response) *http.Response

	// HTTPResponse is set by middleware that provides a synthetic response
	// (blocking, caching). When non-nil the gateway sends this to the
	// client instead of forwarding to upstream.
	HTTPResponse *http.Response

	// UpstreamConn is a pre-dialed connection to the upstream proxy.
	// When set, the gateway uses this instead of dialing itself.
	// Used by MITM middleware that needs to manage the upstream TLS.
	UpstreamConn net.Conn
}

// ProxyResult is a convenience for handlers that just return a proxy.
func ProxyResult(p *Proxy) *Result {
	return &Result{Proxy: p}
}

// ---------------------------------------------------------------------------
// Proxy
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// ConnHandle — connection lifecycle tracking
// ---------------------------------------------------------------------------

// ConnHandle tracks a single active proxied connection.
type ConnHandle interface {
	RecordTraffic(upstream bool, delta int64, cancel func())
	Close(sentTotal, receivedTotal int64)
}

// ChainHandles returns a ConnHandle that delegates to both a and b.
// Either may be nil (the non-nil one is returned as-is).
func ChainHandles(a, b ConnHandle) ConnHandle {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	return &chainedHandle{a, b}
}

type chainedHandle struct{ a, b ConnHandle }

func (c *chainedHandle) RecordTraffic(upstream bool, delta int64, cancel func()) {
	c.a.RecordTraffic(upstream, delta, cancel)
	c.b.RecordTraffic(upstream, delta, cancel)
}
func (c *chainedHandle) Close(sent, received int64) {
	c.a.Close(sent, received)
	c.b.Close(sent, received)
}

// ---------------------------------------------------------------------------
// Downstream — accepts client connections
// ---------------------------------------------------------------------------

// Downstream is a listener that accepts client connections and dispatches
// them through a Handler pipeline.
type Downstream interface {
	Serve(addr string, handler Handler) error
}

// ---------------------------------------------------------------------------
// Upstream — dials through an upstream proxy
// ---------------------------------------------------------------------------

// Upstream dials a target through an upstream proxy.
type Upstream interface {
	Dial(ctx context.Context, proxy *Proxy, target string) (net.Conn, error)
}

// UpstreamFunc adapts a function to the Upstream interface.
type UpstreamFunc func(ctx context.Context, proxy *Proxy, target string) (net.Conn, error)

func (f UpstreamFunc) Dial(ctx context.Context, proxy *Proxy, target string) (net.Conn, error) {
	return f(ctx, proxy, target)
}

// ---------------------------------------------------------------------------
// Context helpers — middleware sets these, handlers read them
// ---------------------------------------------------------------------------

type ctxKey int

const (
	ctxSub ctxKey = iota
	ctxPassword
	ctxSet
	ctxMeta
	ctxSessionKey
	ctxSessionTTL
	ctxTLSState
)

// WithSub stores the subscriber identity in context.
func WithSub(ctx context.Context, sub string) context.Context {
	return context.WithValue(ctx, ctxSub, sub)
}

// Sub reads the subscriber identity from context.
func Sub(ctx context.Context) string {
	v, _ := ctx.Value(ctxSub).(string)
	return v
}

// WithPassword stores the credential in context.
func WithPassword(ctx context.Context, pw string) context.Context {
	return context.WithValue(ctx, ctxPassword, pw)
}

// Password reads the credential from context.
func Password(ctx context.Context) string {
	v, _ := ctx.Value(ctxPassword).(string)
	return v
}

// WithSet stores the proxy set name in context.
func WithSet(ctx context.Context, set string) context.Context {
	return context.WithValue(ctx, ctxSet, set)
}

// Set reads the proxy set name from context.
func Set(ctx context.Context) string {
	v, _ := ctx.Value(ctxSet).(string)
	return v
}

// WithMeta stores metadata in context.
func WithMeta(ctx context.Context, m Meta) context.Context {
	return context.WithValue(ctx, ctxMeta, m)
}

// GetMeta reads metadata from context.
func GetMeta(ctx context.Context) Meta {
	v, _ := ctx.Value(ctxMeta).(Meta)
	return v
}

// WithSessionKey stores the session affinity key in context.
func WithSessionKey(ctx context.Context, key string) context.Context {
	return context.WithValue(ctx, ctxSessionKey, key)
}

// SessionKey reads the session affinity key from context.
func SessionKey(ctx context.Context) string {
	v, _ := ctx.Value(ctxSessionKey).(string)
	return v
}

// WithSessionTTL stores the session TTL (minutes) in context.
func WithSessionTTL(ctx context.Context, minutes int) context.Context {
	return context.WithValue(ctx, ctxSessionTTL, minutes)
}

// SessionTTL reads the session TTL (minutes) from context.
func SessionTTL(ctx context.Context) int {
	v, _ := ctx.Value(ctxSessionTTL).(int)
	return v
}

// TLSState holds MITM TLS interception state.
type TLSState struct {
	Broken     bool   // TLS has been terminated by MITM
	ServerName string // SNI hostname
}

// WithTLSState stores TLS interception state in context.
func WithTLSState(ctx context.Context, state TLSState) context.Context {
	return context.WithValue(ctx, ctxTLSState, state)
}

// GetTLSState reads TLS interception state from context.
func GetTLSState(ctx context.Context) TLSState {
	v, _ := ctx.Value(ctxTLSState).(TLSState)
	return v
}

// Meta is a flat map of string/number metadata values.
type Meta map[string]interface{}

// GetString returns the string value for key, or "".
func (m Meta) GetString(key string) string {
	v, _ := m[key].(string)
	return v
}
