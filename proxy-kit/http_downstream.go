package proxykit

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

// HTTPDownstream is an HTTP proxy listener. It accepts both CONNECT tunnels and
// plain HTTP forwarding requests.
//
// Timeouts:
//   - ReadHeaderTimeout: how long to wait for the client to send request headers.
//     Defaults to 10s. Protects against Slowloris / slow-header attacks.
//   - MaxRequestBodyBytes: max size of a plain-HTTP request body forwarded to
//     the upstream. Defaults to 10 MiB. CONNECT tunnels are not limited.
type HTTPDownstream struct {
	Upstream Upstream

	// ReadHeaderTimeout is the maximum time allowed to read request headers.
	// Zero means use DefaultReadHeaderTimeout (10s).
	ReadHeaderTimeout time.Duration

	// MaxRequestBodyBytes limits plain-HTTP request bodies. Zero means use
	// DefaultMaxRequestBodyBytes (10 MiB). Set to -1 to disable.
	MaxRequestBodyBytes int64
}

const (
	DefaultReadHeaderTimeout   = 10 * time.Second
	DefaultMaxRequestBodyBytes = 10 << 20 // 10 MiB
)

func (d *HTTPDownstream) SetUpstream(u Upstream) { d.Upstream = u }

func (d *HTTPDownstream) readHeaderTimeout() time.Duration {
	if d.ReadHeaderTimeout != 0 {
		return d.ReadHeaderTimeout
	}
	return DefaultReadHeaderTimeout
}

func (d *HTTPDownstream) maxBodyBytes() int64 {
	if d.MaxRequestBodyBytes != 0 {
		return d.MaxRequestBodyBytes
	}
	return DefaultMaxRequestBodyBytes
}

func (d *HTTPDownstream) Serve(addr string, handler Handler) error {
	slog.Info("HTTP proxy gateway listening", "addr", addr)
	srv := &http.Server{
		Addr:              addr,
		Handler:           d.httpHandler(handler),
		ReadHeaderTimeout: d.readHeaderTimeout(),
	}
	return srv.ListenAndServe()
}

type httpConnectCtxKey struct{}

// withHTTPConnect marks a context as originating from an HTTP CONNECT request.
// MITM and other middleware use this to distinguish a real hijackable CONNECT
// from a direct Resolve call (e.g. from tests or SOCKS5).
func withHTTPConnect(ctx context.Context) context.Context {
	return context.WithValue(ctx, httpConnectCtxKey{}, true)
}

// IsHTTPConnect reports whether the context originated from an HTTP CONNECT request.
func IsHTTPConnect(ctx context.Context) bool {
	v, _ := ctx.Value(httpConnectCtxKey{}).(bool)
	return v
}

func (d *HTTPDownstream) httpHandler(handler Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)

		rawUsername, rawPassword, err := extractBasicAuth(r.Header.Get("Proxy-Authorization"))
		if err != nil {
			slog.Warn("auth error", "method", r.Method, "uri", r.RequestURI, "client", clientIP, "err", err)
			w.Header().Set("Proxy-Authenticate", `Basic realm="proxy-gateway"`)
			http.Error(w, err.Error(), http.StatusProxyAuthRequired)
			return
		}

		if r.Method == http.MethodConnect {
			d.serveConnect(w, r, rawUsername, rawPassword, handler)
		} else {
			d.servePlainHTTP(w, r, rawUsername, rawPassword, handler)
		}
	})
}

func (d *HTTPDownstream) serveConnect(w http.ResponseWriter, r *http.Request, rawUser, rawPass string, handler Handler) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	// Phase 1: resolve WITHOUT the client conn so auth/routing errors can be
	// returned as proper HTTP responses instead of a silent post-200 drop.
	// Mark context so middleware can distinguish a real CONNECT from a direct call.
	connectCtx := withHTTPConnect(r.Context())
	req := &Request{
		RawUsername: rawUser,
		RawPassword: rawPass,
		Target:      r.Host,
	}
	result, err := handler.Resolve(connectCtx, req)
	if err != nil {
		slog.Warn("resolve error", "target", r.Host, "err", err)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	// NeedsConn: middleware (e.g. MITM) requires the raw client connection
	// before it can resolve. Hijack first, send 200, then re-resolve with conn.
	if result != nil && result.NeedsConn {
		w.WriteHeader(http.StatusOK)
		clientConn, _, err := hj.Hijack()
		if err != nil {
			slog.Error("hijack failed", "err", err)
			return
		}
		defer clientConn.Close()
		req.Conn = clientConn
		result, err = handler.Resolve(connectCtx, req)
		if err != nil {
			slog.Warn("resolve error (post-hijack)", "target", r.Host, "err", err)
			return
		}
		if result == nil || result.Proxy == nil {
			return // handler fully managed the connection (e.g. MITM)
		}
		upstreamConn, err := d.Upstream.Dial(r.Context(), result.Proxy, r.Host)
		if err != nil {
			slog.Error("upstream dial failed", "target", r.Host, "err", err)
			if result.ConnTracker != nil {
				result.ConnTracker.Close(0, 0)
			}
			return
		}
		defer upstreamConn.Close()
		slog.Info("tunneling",
			"target", r.Host,
			"upstream", fmt.Sprintf("%s:%d", result.Proxy.Host, result.Proxy.Port),
			"upstream_proto", result.Proxy.Proto(),
		)
		sent, received := relay(clientConn, upstreamConn, result.ConnTracker)
		if result.ConnTracker != nil {
			result.ConnTracker.Close(sent, received)
		}
		return
	}

	if result == nil || result.Proxy == nil {
		http.Error(w, "no proxy available", http.StatusServiceUnavailable)
		return
	}

	// Phase 2: dial the upstream before hijacking so we can still return an
	// HTTP error response if the upstream is unreachable.
	proxy := result.Proxy
	upstreamConn, err := d.Upstream.Dial(r.Context(), proxy, r.Host)
	if err != nil {
		slog.Error("upstream dial failed", "target", r.Host, "err", err)
		if result.ConnTracker != nil {
			result.ConnTracker.Close(0, 0)
		}
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}

	// Everything is good — now hijack and send 200.
	w.WriteHeader(http.StatusOK)
	clientConn, _, err := hj.Hijack()
	if err != nil {
		slog.Error("hijack failed", "err", err)
		upstreamConn.Close()
		return
	}
	defer clientConn.Close()
	defer upstreamConn.Close()

	slog.Info("tunneling",
		"target", r.Host,
		"upstream", fmt.Sprintf("%s:%d", proxy.Host, proxy.Port),
		"upstream_proto", proxy.Proto(),
	)

	sent, received := relay(clientConn, upstreamConn, result.ConnTracker)
	if result.ConnTracker != nil {
		result.ConnTracker.Close(sent, received)
	}
}

func (d *HTTPDownstream) servePlainHTTP(w http.ResponseWriter, r *http.Request, rawUser, rawPass string, handler Handler) {
	// Limit request body size to guard against oversized forwarded payloads.
	if max := d.maxBodyBytes(); max > 0 && r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, max)
	}

	req := &Request{
		RawUsername: rawUser,
		RawPassword: rawPass,
		Target:      r.Host,
		HTTPRequest: r,
	}

	result, err := handler.Resolve(r.Context(), req)
	if err != nil {
		slog.Warn("resolve error", "target", r.Host, "err", err)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	if result != nil && result.HTTPResponse != nil {
		resp := result.HTTPResponse
		if result.ResponseHook != nil {
			resp = result.ResponseHook(resp)
		}
		writeHTTPResponse(w, resp)
		return
	}

	if result == nil || result.Proxy == nil {
		http.Error(w, "no proxy available", http.StatusServiceUnavailable)
		return
	}

	proxy := result.Proxy
	slog.Info("forwarding",
		"method", r.Method,
		"uri", r.RequestURI,
		"upstream", fmt.Sprintf("%s:%d", proxy.Host, proxy.Port),
	)

	resp, err := ForwardPlainHTTP(r, proxy)
	if err != nil {
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		if result.ConnTracker != nil {
			result.ConnTracker.Close(0, 0)
		}
		return
	}
	defer resp.Body.Close()

	if result.ResponseHook != nil {
		resp = result.ResponseHook(resp)
	}

	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	var sent, received int64
	if r.ContentLength > 0 {
		sent = r.ContentLength
	}
	buf := make([]byte, 32*1024)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			received += int64(n)
			w.Write(buf[:n])
		}
		if rerr != nil {
			break
		}
	}

	if result.ConnTracker != nil {
		result.ConnTracker.RecordTraffic(true, sent, func() {})
		result.ConnTracker.RecordTraffic(false, received, func() {})
		result.ConnTracker.Close(sent, received)
	}
}

// ListenHTTP starts a standalone HTTP proxy on addr with default settings.
func ListenHTTP(addr string, handler Handler) error {
	d := &HTTPDownstream{Upstream: AutoUpstream()}
	return d.Serve(addr, handler)
}

// HTTPProxyHandler returns an http.Handler for embedding in an existing
// http.Server. The caller is responsible for setting server-level timeouts.
func HTTPProxyHandler(handler Handler) http.Handler {
	d := &HTTPDownstream{Upstream: AutoUpstream()}
	return d.httpHandler(handler)
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

func extractBasicAuth(headerVal string) (username, password string, err error) {
	b64, ok := strings.CutPrefix(headerVal, "Basic ")
	if !ok {
		return "", "", fmt.Errorf("Proxy-Authorization must use Basic scheme")
	}
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", "", fmt.Errorf("invalid base64 in Proxy-Authorization")
	}
	raw := string(decoded)
	colonIdx := strings.LastIndex(raw, ":")
	if colonIdx < 0 {
		return raw, "", nil
	}
	return raw[:colonIdx], raw[colonIdx+1:], nil
}

func writeHTTPResponse(w http.ResponseWriter, resp *http.Response) {
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if resp.Body != nil {
		defer resp.Body.Close()
		buf := make([]byte, 32*1024)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				w.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
	}
}
