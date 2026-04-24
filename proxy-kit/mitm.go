package proxykit

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// ---------------------------------------------------------------------------
// Interceptor — how decrypted requests reach the target
// ---------------------------------------------------------------------------

// Interceptor controls how a decrypted HTTP request is forwarded to the
// target server through an upstream proxy.
//
// Built-in:
//   - StandardInterceptor: Go crypto/tls via core.Upstream
//
// Custom implementations can use httpcloak for TLS fingerprint spoofing,
// a custom HTTP client, or anything else that produces an *http.Response.
type Interceptor interface {
	RoundTrip(ctx context.Context, req *http.Request, host string, proxy *Proxy) (*http.Response, error)
}

// WebSocketDialer is an optional interface that Interceptors can implement to
// support WebSocket upgrades through MITM. DialTLS returns a TLS connection
// to the target (optionally through an upstream proxy) with a browser-like
// TLS fingerprint. The caller owns the returned connection.
//
// target is "host:port" (e.g. "example.com:443" or "127.0.0.1:8443").
type WebSocketDialer interface {
	DialTLS(ctx context.Context, target string, proxy *Proxy) (net.Conn, error)
}

// InterceptorFunc adapts a function to the Interceptor interface.
type InterceptorFunc func(ctx context.Context, req *http.Request, host string, proxy *Proxy) (*http.Response, error)

func (f InterceptorFunc) RoundTrip(ctx context.Context, req *http.Request, host string, proxy *Proxy) (*http.Response, error) {
	return f(ctx, req, host, proxy)
}

// StandardInterceptor forwards decrypted requests using Go's crypto/tls
// through a core.Upstream dialer. This is the default.
type StandardInterceptor struct {
	Upstream Upstream
}

func (s *StandardInterceptor) RoundTrip(ctx context.Context, httpReq *http.Request, host string, proxy *Proxy) (*http.Response, error) {
	target := host + ":443"
	upstreamConn, err := s.Upstream.Dial(ctx, proxy, target)
	if err != nil {
		return nil, err
	}
	defer upstreamConn.Close()

	tlsUp := tls.Client(upstreamConn, &tls.Config{ServerName: host})
	if err := tlsUp.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS to target %s: %w", host, err)
	}
	defer tlsUp.Close()

	// Clone to avoid mutating the caller's request.
	out := httpReq.Clone(ctx)
	out.URL.Scheme = ""
	out.URL.Host = ""
	out.RequestURI = ""

	if err := out.Write(tlsUp); err != nil {
		return nil, fmt.Errorf("writing request to target: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsUp), out)
	if err != nil {
		return nil, fmt.Errorf("reading response from target: %w", err)
	}
	return resp, nil
}

// DialTLS implements WebSocketDialer for StandardInterceptor.
func (s *StandardInterceptor) DialTLS(ctx context.Context, target string, proxy *Proxy) (net.Conn, error) {
	host := targetHost(target)
	upstreamConn, err := s.Upstream.Dial(ctx, proxy, target)
	if err != nil {
		return nil, err
	}
	tlsUp := tls.Client(upstreamConn, &tls.Config{ServerName: host})
	if err := tlsUp.Handshake(); err != nil {
		upstreamConn.Close()
		return nil, fmt.Errorf("TLS to target %s: %w", host, err)
	}
	return tlsUp, nil
}

// ---------------------------------------------------------------------------
// CertProvider — how client-facing TLS certs are obtained
// ---------------------------------------------------------------------------

// CertProvider returns a TLS certificate to present to the client for a
// given hostname.
type CertProvider interface {
	CertForHost(host string) (*tls.Certificate, error)
}

// ForgedCertProvider forges certificates on-the-fly signed by a CA.
type ForgedCertProvider struct {
	CA     tls.Certificate
	caCert *x509.Certificate
	cache  *CertCache
}

// NewForgedCertProvider creates a CertProvider that forges per-host certs.
func NewForgedCertProvider(ca tls.Certificate) (*ForgedCertProvider, error) {
	caCert, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parsing CA certificate: %w", err)
	}
	return &ForgedCertProvider{
		CA:     ca,
		caCert: caCert,
		cache:  &CertCache{},
	}, nil
}

func (p *ForgedCertProvider) CertForHost(host string) (*tls.Certificate, error) {
	return p.cache.Get(host, p.caCert, &p.CA), nil
}

// StaticCertProvider always returns the same certificate.
type StaticCertProvider struct {
	Cert tls.Certificate
}

func (p *StaticCertProvider) CertForHost(_ string) (*tls.Certificate, error) {
	return &p.Cert, nil
}

// ---------------------------------------------------------------------------
// MITM — TLS termination loop
// ---------------------------------------------------------------------------

// MITM creates TLS-interception middleware. It terminates the client's TLS,
// reads each HTTP request, resolves an upstream proxy through the inner
// Handler pipeline, and forwards the request via the Interceptor.
//
// The inner Handler pipeline handles everything else — auth, rate limiting,
// logging, request blocking, response modification. Each decrypted HTTP
// request is fed through inner.Resolve() as a child Request with TLSState
// set in context.
//
// Basic usage:
//
//	ca, _ := core.NewCA()
//	certs, _ := core.NewForgedCertProvider(ca)
//	interceptor := &core.StandardInterceptor{Upstream: upstream}
//	pipeline := core.MITM(certs, interceptor, inner)
//
// With logging middleware in the inner pipeline:
//
//	pipeline := core.MITM(certs, interceptor,
//	    myLogger(               // logs every decrypted request
//	        core.Auth(auth,
//	            core.Session(source),
//	        ),
//	    ),
//	)
//
// With request blocking in the inner pipeline:
//
//	blocker := core.HandlerFunc(func(ctx context.Context, req *core.Request) (*core.Result, error) {
//	    if req.HTTPRequest != nil && isBlocked(req.HTTPRequest.URL.Host) {
//	        return &core.Result{HTTPResponse: blocked403()}, nil
//	    }
//	    return inner.Resolve(ctx, req)
//	})
//	pipeline := core.MITM(certs, interceptor, blocker)
func MITM(certs CertProvider, interceptor Interceptor, inner Handler) Handler {
	return &mitmHandler{
		inner:       inner,
		certs:       certs,
		interceptor: interceptor,
	}
}

// QuickMITM is a convenience for the common case: forged certs from a CA
// + standard Go TLS forwarding via Upstream.
func QuickMITM(ca tls.Certificate, upstream Upstream, inner Handler) Handler {
	certs, err := NewForgedCertProvider(ca)
	if err != nil {
		panic(fmt.Sprintf("mitm: %v", err))
	}
	return MITM(certs, &StandardInterceptor{Upstream: upstream}, inner)
}

type mitmHandler struct {
	inner       Handler
	certs       CertProvider
	interceptor Interceptor
}

// TunnelScope is a per-client-tunnel value bag that interceptors can use to
// scope state (e.g. upstream HTTP sessions) to one MITM tunnel's lifetime.
// mitmHandler.Resolve populates this in ctx before serveH1/serveH2 and calls
// cleanup on every registered closer when the tunnel ends.
//
// This prevents state bleed across tunnels. The old pattern of caching state
// by affinity seed across tunnels caused cookies, cached TLS sessions, and
// connection pools from one flow to silently contaminate the next flow —
// for example, a successful authentication leaving session cookies that
// make the target server short-circuit the next login attempt past the
// login form because the user appears already authenticated.
type TunnelScope struct {
	mu       sync.Mutex
	values   map[any]any
	cleanups []func()
}

// GetOrSet returns an existing value for the key, or creates one via factory
// and stores it. factory returns (value, cleanup). cleanup (if non-nil) runs
// when the tunnel ends.
func (ts *TunnelScope) GetOrSet(key any, factory func() (any, func())) any {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.values == nil {
		ts.values = make(map[any]any)
	}
	if v, ok := ts.values[key]; ok {
		return v
	}
	v, cleanup := factory()
	ts.values[key] = v
	if cleanup != nil {
		ts.cleanups = append(ts.cleanups, cleanup)
	}
	return v
}

// close runs all registered cleanups in reverse order (LIFO). Idempotent.
func (ts *TunnelScope) close() {
	ts.mu.Lock()
	cleanups := ts.cleanups
	ts.cleanups = nil
	ts.values = nil
	ts.mu.Unlock()
	for i := len(cleanups) - 1; i >= 0; i-- {
		cleanups[i]()
	}
}

type tunnelScopeKey struct{}

// WithTunnelScope returns a child context carrying a fresh TunnelScope and a
// close function that must be deferred by the caller.
func WithTunnelScope(ctx context.Context) (context.Context, func()) {
	ts := &TunnelScope{}
	return context.WithValue(ctx, tunnelScopeKey{}, ts), ts.close
}

// GetTunnelScope returns the TunnelScope from ctx, or nil if the caller isn't
// inside a tunnel (e.g. direct call path, SOCKS5 without MITM).
func GetTunnelScope(ctx context.Context) *TunnelScope {
	ts, _ := ctx.Value(tunnelScopeKey{}).(*TunnelScope)
	return ts
}

func (m *mitmHandler) Resolve(ctx context.Context, req *Request) (*Result, error) {
	// Don't intercept plain HTTP (HTTPRequest is set) or already-broken TLS.
	if req.HTTPRequest != nil {
		return m.inner.Resolve(ctx, req)
	}
	if ts := GetTLSState(ctx); ts.Broken {
		return m.inner.Resolve(ctx, req)
	}

	// Only intercept CONNECT tunnels. If we don't have the client conn yet but
	// we know we're in an HTTP CONNECT context, signal HTTPDownstream to hijack
	// and call us again with req.Conn set. Otherwise (SOCKS5 or direct call)
	// pass through to inner.
	if req.Conn == nil {
		if IsHTTPConnect(ctx) {
			return WantsConn(), nil
		}
		return m.inner.Resolve(ctx, req)
	}

	host := targetHost(req.Target)

	cert, err := m.certs.CertForHost(host)
	if err != nil {
		slog.Debug("MITM cert error", "host", host, "err", err)
		req.Conn.Close()
		return nil, nil
	}

	tlsConn := tls.Server(req.Conn, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		slog.Debug("MITM TLS handshake failed", "host", host, "err", err)
		req.Conn.Close()
		return nil, nil
	}

	negotiated := tlsConn.ConnectionState().NegotiatedProtocol
	slog.Debug("MITM intercepting", "host", host, "proto", negotiated)

	childCtx := WithTLSState(ctx, TLSState{
		Broken:     true,
		ServerName: host,
	})

	// Scope interceptor state (upstream httpcloak sessions, cookie jars, etc.)
	// to this client tunnel's lifetime. When the tunnel ends, every cleanup
	// registered via TunnelScope.GetOrSet runs — preventing cookie/pool bleed
	// into the next tunnel that happens to share an affinity seed.
	tunnelCtx, closeScope := WithTunnelScope(childCtx)
	defer closeScope()

	if negotiated == "h2" {
		m.serveH2(tunnelCtx, tlsConn, req, host)
	} else {
		m.serveH1(tunnelCtx, tlsConn, req, host)
	}

	tlsConn.Close()
	return nil, nil
}

// serveH1 handles HTTP/1.1 requests on the MITM'd TLS connection.
func (m *mitmHandler) serveH1(ctx context.Context, tlsConn *tls.Conn, outerReq *Request, host string) {
	br := bufio.NewReader(tlsConn)
	requestNum := 0
	tunnelStart := time.Now()
	for {
		httpReq, err := http.ReadRequest(br)
		if err != nil {
			slog.Debug("MITM H1 tunnel closed",
				"host", host,
				"requests_served", requestNum,
				"tunnel_elapsed_ms", time.Since(tunnelStart).Milliseconds(),
				"read_err", err)
			break
		}
		requestNum++
		reqStart := time.Now()

		slog.Debug("MITM H1 request read",
			"host", host,
			"req_num", requestNum,
			"method", httpReq.Method,
			"path", httpReq.URL.RequestURI(),
			"content_length", httpReq.ContentLength,
			"transfer_encoding", httpReq.TransferEncoding)

		if isWebSocketUpgrade(httpReq) {
			slog.Debug("MITM H1 websocket upgrade", "host", host, "req_num", requestNum)
			m.handleWebSocketUpgrade(ctx, tlsConn, br, httpReq, outerReq, host)
			return // WebSocket takes over the connection
		}

		resp := m.roundTripMITM(ctx, httpReq, outerReq, host)

		// Drain any unread request body before writing the response.
		// If the interceptor didn't fully consume httpReq.Body, leftover
		// bytes would corrupt the next request on this keep-alive connection.
		if httpReq.Body != nil {
			drained, _ := io.Copy(io.Discard, httpReq.Body)
			if drained > 0 {
				slog.Debug("MITM drained unread request body",
					"host", host, "req_num", requestNum, "bytes", drained)
			}
			httpReq.Body.Close()
		}

		writeStart := time.Now()
		writeErr := resp.Write(tlsConn)
		writeElapsed := time.Since(writeStart)

		// Drain any unread response body (defense-in-depth for partial writes)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		slog.Debug("MITM H1 request complete",
			"host", host,
			"req_num", requestNum,
			"method", httpReq.Method,
			"path", httpReq.URL.RequestURI(),
			"resp_status", resp.StatusCode,
			"resp_content_length", resp.ContentLength,
			"total_ms", time.Since(reqStart).Milliseconds(),
			"write_ms", writeElapsed.Milliseconds(),
			"write_err", writeErr)
	}
}

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

// handleWebSocketUpgrade dials the upstream with a fingerprinted TLS
// connection, forwards the upgrade request, relays the 101 response, then
// enters bidirectional relay for WebSocket frames.
func (m *mitmHandler) handleWebSocketUpgrade(ctx context.Context, clientConn net.Conn, clientBuf *bufio.Reader, httpReq *http.Request, outerReq *Request, host string) {
	// Use the original CONNECT target (host:port) so non-443 ports work.
	target := outerReq.Target
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = host + ":443"
	}

	// Resolve upstream proxy.
	childReq := &Request{
		RawUsername:  outerReq.RawUsername,
		RawPassword: outerReq.RawPassword,
		Target:      target,
		HTTPRequest: httpReq,
	}
	result, err := m.inner.Resolve(ctx, childReq)
	if err != nil || result == nil || result.Proxy == nil {
		msg := "websocket: no upstream"
		if err != nil {
			msg = "websocket: " + err.Error()
		}
		errorResponse(http.StatusBadGateway, msg).Write(clientConn)
		return
	}

	// Dial upstream with fingerprinted TLS if the interceptor supports it.
	wsDialer, ok := m.interceptor.(WebSocketDialer)
	if !ok {
		errorResponse(http.StatusBadGateway, "websocket: interceptor does not support upgrades").Write(clientConn)
		return
	}
	upstreamConn, err := wsDialer.DialTLS(ctx, target, result.Proxy)
	if err != nil {
		errorResponse(http.StatusBadGateway, "websocket: "+err.Error()).Write(clientConn)
		return
	}
	defer upstreamConn.Close()

	// Forward the upgrade request to upstream.
	if err := httpReq.Write(upstreamConn); err != nil {
		errorResponse(http.StatusBadGateway, "websocket: "+err.Error()).Write(clientConn)
		return
	}

	// Read the upgrade response from upstream.
	upstreamBuf := bufio.NewReader(upstreamConn)
	resp, err := http.ReadResponse(upstreamBuf, httpReq)
	if err != nil {
		errorResponse(http.StatusBadGateway, "websocket: "+err.Error()).Write(clientConn)
		return
	}

	// Forward the response to the client.
	resp.Write(clientConn)

	if resp.StatusCode != http.StatusSwitchingProtocols {
		resp.Body.Close()
		return // Upgrade rejected; connection is done.
	}

	slog.Debug("MITM websocket upgrade", "host", host)

	// Bidirectional relay. Both bufio.Readers may hold buffered bytes from
	// the HTTP parsing, so we read from them (which drain the buffer first,
	// then read from the underlying conn).
	done := make(chan struct{}, 2)
	go func() { io.Copy(upstreamConn, clientBuf); done <- struct{}{} }()
	go func() { io.Copy(clientConn, upstreamBuf); done <- struct{}{} }()
	<-done
}

// serveH2 handles HTTP/2 streams on the MITM'd TLS connection.
func (m *mitmHandler) serveH2(ctx context.Context, tlsConn *tls.Conn, outerReq *Request, host string) {
	h2srv := &http2.Server{}
	h2srv.ServeConn(tlsConn, &http2.ServeConnOpts{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := m.roundTripMITM(ctx, r, outerReq, host)
			copyResponse(w, resp)
			resp.Body.Close()
		}),
	})
}

// roundTripMITM resolves the upstream proxy and forwards the request through
// the interceptor. Used by both H1 and H2 paths.
func (m *mitmHandler) roundTripMITM(ctx context.Context, httpReq *http.Request, outerReq *Request, host string) *http.Response {
	childReq := &Request{
		RawUsername:  outerReq.RawUsername,
		RawPassword: outerReq.RawPassword,
		Target:      host + ":443",
		HTTPRequest: httpReq,
	}

	result, resolveErr := m.inner.Resolve(ctx, childReq)

	if result != nil && result.HTTPResponse != nil {
		return result.HTTPResponse
	}
	if resolveErr != nil {
		return errorResponse(http.StatusForbidden, resolveErr.Error())
	}
	if result == nil || result.Proxy == nil {
		return errorResponse(http.StatusServiceUnavailable, "no proxy available")
	}

	resp, fwdErr := m.interceptor.RoundTrip(ctx, httpReq, host, result.Proxy)
	if fwdErr != nil {
		slog.Warn("MITM roundtrip failed", "host", host, "method", httpReq.Method, "path", httpReq.URL.RequestURI(), "err", fwdErr)
		return errorResponse(http.StatusBadGateway, fwdErr.Error())
	}

	if result.ResponseHook != nil {
		resp = result.ResponseHook(resp)
	}
	return resp
}

// copyResponse writes an *http.Response to an http.ResponseWriter, flushing
// after each chunk to support streaming (SSE, chunked responses) over H2.
func copyResponse(w http.ResponseWriter, resp *http.Response) {
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if resp.Body == nil {
		return
	}
	if flusher, ok := w.(http.Flusher); ok {
		buf := make([]byte, 32*1024)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				w.Write(buf[:n])
				flusher.Flush()
			}
			if err != nil {
				break
			}
		}
	} else {
		io.Copy(w, resp.Body)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func targetHost(target string) string {
	h, _, err := net.SplitHostPort(target)
	if err != nil {
		return target
	}
	return h
}

func errorResponse(status int, msg string) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"text/plain"}},
		Body:          io.NopCloser(strings.NewReader(msg)),
		ContentLength: int64(len(msg)),
	}
}

// ---------------------------------------------------------------------------
// Certificate cache
// ---------------------------------------------------------------------------

// CertCache caches TLS certificates keyed by hostname.
type CertCache struct {
	mu    sync.RWMutex
	certs map[string]*tls.Certificate
}

// Get returns a cached cert or forges a new one.
func (c *CertCache) Get(host string, caCert *x509.Certificate, caKey *tls.Certificate) *tls.Certificate {
	if c.certs == nil {
		c.mu.Lock()
		if c.certs == nil {
			c.certs = make(map[string]*tls.Certificate)
		}
		c.mu.Unlock()
	}

	c.mu.RLock()
	cert, ok := c.certs[host]
	c.mu.RUnlock()
	if ok {
		return cert
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if cert, ok = c.certs[host]; ok {
		return cert
	}
	cert = forgeCert(host, caCert, caKey)
	c.certs[host] = cert
	return cert
}

func forgeCert(host string, caCert *x509.Certificate, ca *tls.Certificate) *tls.Certificate {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}

	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
		tmpl.DNSNames = nil
	}

	caPriv := ca.PrivateKey
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &privKey.PublicKey, caPriv)
	if err != nil {
		panic(err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privKey,
	}
}

// NewCA creates a self-signed CA certificate for MITM interception.
func NewCA() (tls.Certificate, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "proxy-gateway MITM CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &privKey.PublicKey, privKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privKey,
	}, nil
}
