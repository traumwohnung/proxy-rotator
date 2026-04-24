package utils

import (
	"context"
	"errors"
	"strings"
	"time"
)

// ErrorKind classifies MITM upstream errors into coarse categories. Retry
// policy, cache-eviction policy, and alerting all key off Kind rather than
// substring-matching error messages.
//
// Detection is currently by string match on the underlying httpcloak error
// because httpcloak doesn't expose structured errors. Centralising that
// matching here means new error shapes from httpcloak only require touching
// this one file instead of three scattered classifiers.
type ErrorKind string

const (
	// KindUnknown is the fallback for errors we haven't classified. Treat as
	// non-retryable and worth flagging for investigation.
	KindUnknown ErrorKind = "unknown"

	// KindUpstreamProxyDial covers failures establishing a TCP connection to
	// the upstream residential proxy (DNS, refused, timeout). Target server
	// saw nothing.
	KindUpstreamProxyDial ErrorKind = "upstream_proxy_dial"

	// KindUpstreamProxy5xx is the upstream proxy rejecting our CONNECT with a
	// 5xx status. Target server saw nothing. Retrying with the same sticky
	// credentials should preserve exit-IP affinity if the provider honors it.
	KindUpstreamProxy5xx ErrorKind = "upstream_proxy_5xx"

	// KindUpstreamProxyAuth is 407/403 from the upstream proxy. Credentials
	// are wrong — retry won't help.
	KindUpstreamProxyAuth ErrorKind = "upstream_proxy_auth"

	// KindTargetTLS is a failure negotiating TLS with the target server
	// inside the CONNECT tunnel. Target saw ClientHello but no HTTP yet.
	// Usually indicates a stale tunnel from the upstream proxy.
	KindTargetTLS ErrorKind = "target_tls"

	// KindPooledConnDead is the case where we tried to reuse a pooled
	// connection and it had been closed by the peer. After our no-silent-
	// fallback patch, this surfaces as an error instead of a silent
	// reconnect. Target server may or may not have seen bytes depending on
	// exactly where in the write the peer close happened — treat as
	// possibly-delivered and NOT retry non-idempotent requests.
	KindPooledConnDead ErrorKind = "pooled_conn_dead"

	// KindTargetReadTimeout is the target response didn't arrive within the
	// transport read deadline. Request was definitely sent.
	KindTargetReadTimeout ErrorKind = "target_read_timeout"

	// KindContextCanceled is the caller canceled the request context —
	// usually the MITM client disconnected. Not an upstream problem.
	KindContextCanceled ErrorKind = "context_canceled"
)

// ClassifyError maps a raw error from the MITM/httpcloak layer to an
// ErrorKind. Callers should use the Kind for retry/evict/alert decisions,
// not the error message string.
func ClassifyError(err error) ErrorKind {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return KindContextCanceled
	}
	msg := err.Error()

	// Ordered most-specific-first.
	switch {
	case strings.Contains(msg, "dial_proxy") &&
		(strings.Contains(msg, "proxy CONNECT failed: 5") ||
			strings.Contains(msg, "proxy CONNECT failed: 502") ||
			strings.Contains(msg, "proxy CONNECT failed: 503") ||
			strings.Contains(msg, "proxy CONNECT failed: 504") ||
			strings.Contains(msg, "proxy CONNECT failed: 500")):
		return KindUpstreamProxy5xx
	case strings.Contains(msg, "proxy CONNECT failed: 407") ||
		strings.Contains(msg, "proxy CONNECT failed: 403"):
		return KindUpstreamProxyAuth
	case strings.Contains(msg, "dial_proxy"):
		// Any other dial_proxy failure (refused, timeout, DNS) — the dial
		// itself failed before any CONNECT response.
		return KindUpstreamProxyDial
	case strings.Contains(msg, "tls_handshake"):
		return KindTargetTLS
	case strings.Contains(msg, "pooled_request"):
		return KindPooledConnDead
	case strings.Contains(msg, "i/o timeout") || strings.Contains(msg, "deadline exceeded"):
		return KindTargetReadTimeout
	}
	return KindUnknown
}

// IsSafeToRetry reports whether an error kind is safe to retry without risk
// of duplicate delivery to the target server. Only errors where we can
// prove the target saw zero bytes qualify.
func (k ErrorKind) IsSafeToRetry() bool {
	switch k {
	case KindUpstreamProxyDial, KindUpstreamProxy5xx, KindTargetTLS:
		return true
	}
	return false
}

// MITMRequestEvent is the structured shape of one MITM request observation.
// Emit exactly once per request (success or failure) via logMITMRequestEvent
// so logs and future metrics share the same field names.
type MITMRequestEvent struct {
	// Client-tunnel identity
	Host       string // target host (no port)
	TunnelReq  int    // which request this is within the MITM tunnel (1, 2, ...)
	Seed       uint64 // affinity seed — determines upstream sticky session
	StickyID   string // extracted from proxy auth if available
	Preset     string // httpcloak browser preset
	SessionSrc string // "fresh" | "cached" | "tunnel-scoped"

	// Request shape
	Method  string
	Path    string
	BodyLen int

	// Outcome
	Status     int           // HTTP status if response returned, else 0
	Protocol   string        // "h1" | "h2" | "" if no response
	Elapsed    time.Duration // total RoundTrip time
	ContentLen int64         // response content length if known
	Err        error
	ErrKind    ErrorKind // classification of Err if non-nil
}
