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
	})
	if err := tlsConn.Handshake(); err != nil {
		slog.Debug("MITM TLS handshake failed", "host", host, "err", err)
		req.Conn.Close()
		return nil, nil
	}

	slog.Debug("MITM intercepting", "host", host)

	childCtx := WithTLSState(ctx, TLSState{
		Broken:     true,
		ServerName: host,
	})

	br := bufio.NewReader(tlsConn)
	for {
		httpReq, err := http.ReadRequest(br)
		if err != nil {
			break
		}

		childReq := &Request{
			RawUsername: req.RawUsername,
			RawPassword: req.RawPassword,
			Target:      host + ":443",
			HTTPRequest: httpReq,
		}

		result, resolveErr := m.inner.Resolve(childCtx, childReq)

		// Synthetic response from pipeline middleware.
		if result != nil && result.HTTPResponse != nil {
			result.HTTPResponse.Write(tlsConn)
			continue
		}

		if resolveErr != nil {
			writeErrorResponse(tlsConn, http.StatusForbidden, resolveErr.Error())
			continue
		}
		if result == nil || result.Proxy == nil {
			writeErrorResponse(tlsConn, http.StatusServiceUnavailable, "no proxy available")
			continue
		}

		// Forward through the interceptor.
		resp, fwdErr := m.interceptor.RoundTrip(childCtx, httpReq, host, result.Proxy)
		if fwdErr != nil {
			writeErrorResponse(tlsConn, http.StatusBadGateway, fwdErr.Error())
			continue
		}

		// Pipeline response hooks.
		if result.ResponseHook != nil {
			resp = result.ResponseHook(resp)
		}

		resp.Write(tlsConn)
	}

	tlsConn.Close()
	return nil, nil
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

func writeErrorResponse(w io.Writer, status int, msg string) {
	resp := &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Content-Type": {"text/plain"}},
		Body:       io.NopCloser(strings.NewReader(msg)),
	}
	resp.Write(w)
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
