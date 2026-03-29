package middleware

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

	"proxy-gateway/core"
)

// MITM creates TLS-interception middleware. It terminates the client's TLS
// using a forged certificate, reads each HTTP request from the decrypted
// stream, and resolves it through the inner handler pipeline.
//
// The upstream parameter is used to dial the target through the resolved proxy.
// This eliminates the duplicated upstream dialer code.
//
// Usage:
//
//	ca, _ := middleware.GenerateCA()
//	upstream := gateway.DefaultUpstream()   // or custom
//	pipeline := core.Auth(auth,
//	    MITM(ca, upstream,
//	        core.Sticky(source),
//	    ),
//	)
func MITM(ca tls.Certificate, upstream core.Upstream, inner core.Handler) core.Handler {
	caCert, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		panic(fmt.Sprintf("mitm: failed to parse CA certificate: %v", err))
	}
	return &mitmHandler{
		inner:    inner,
		upstream: upstream,
		ca:       ca,
		caCert:   caCert,
		cache:    &CertCache{},
	}
}

type mitmHandler struct {
	inner    core.Handler
	upstream core.Upstream
	ca       tls.Certificate
	caCert   *x509.Certificate
	cache    *CertCache
}

func (m *mitmHandler) Resolve(ctx context.Context, req *core.Request) (*core.Result, error) {
	// Only intercept tunnel connections (CONNECT / SOCKS5).
	if req.Conn == nil {
		return m.inner.Resolve(ctx, req)
	}

	// Don't double-intercept.
	if ts := core.GetTLSState(ctx); ts.Broken {
		return m.inner.Resolve(ctx, req)
	}

	host := targetHost(req.Target)
	cert := m.cache.GetOrCreate(host, m.caCert, &m.ca)

	tlsConn := tls.Server(req.Conn, &tls.Config{
		Certificates: []tls.Certificate{*cert},
	})
	if err := tlsConn.Handshake(); err != nil {
		slog.Debug("MITM TLS handshake failed", "host", host, "err", err)
		req.Conn.Close()
		return nil, nil // handled (failed)
	}

	slog.Debug("MITM TLS intercepting", "host", host)

	// Set TLS state in context for child requests.
	childCtx := core.WithTLSState(ctx, core.TLSState{
		Broken:     true,
		ServerName: host,
	})

	br := bufio.NewReader(tlsConn)
	for {
		httpReq, err := http.ReadRequest(br)
		if err != nil {
			break // client closed or error
		}

		childReq := &core.Request{
			RawUsername: req.RawUsername,
			RawPassword: req.RawPassword,
			Target:      host + ":443",
			HTTPRequest: httpReq,
		}

		result, resolveErr := m.inner.Resolve(childCtx, childReq)

		// Synthetic response from middleware.
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

		resp, fwdErr := m.forwardHTTPRequest(ctx, httpReq, host, result.Proxy)
		if fwdErr != nil {
			writeErrorResponse(tlsConn, http.StatusBadGateway, fwdErr.Error())
			continue
		}

		if result.ResponseHook != nil {
			resp = result.ResponseHook(resp)
		}

		resp.Write(tlsConn)
	}

	tlsConn.Close()
	return nil, nil // we handled it
}

func (m *mitmHandler) forwardHTTPRequest(ctx context.Context, httpReq *http.Request, host string, proxy *core.Proxy) (*http.Response, error) {
	target := host + ":443"
	upstreamConn, err := m.upstream.Dial(ctx, proxy, target)
	if err != nil {
		return nil, err
	}
	defer upstreamConn.Close()

	tlsUp := tls.Client(upstreamConn, &tls.Config{ServerName: host})
	if err := tlsUp.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS to target %s: %w", host, err)
	}
	defer tlsUp.Close()

	httpReq.URL.Scheme = ""
	httpReq.URL.Host = ""
	httpReq.RequestURI = ""

	if err := httpReq.Write(tlsUp); err != nil {
		return nil, fmt.Errorf("writing request to target: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsUp), httpReq)
	if err != nil {
		return nil, fmt.Errorf("reading response from target: %w", err)
	}
	return resp, nil
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

// CertCache caches forged TLS certificates keyed by hostname.
type CertCache struct {
	mu    sync.RWMutex
	certs map[string]*tls.Certificate
}

// GetOrCreate returns a cached cert or forges a new one.
func (c *CertCache) GetOrCreate(host string, caCert *x509.Certificate, caKey *tls.Certificate) *tls.Certificate {
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

// GenerateCA creates a self-signed CA certificate for MITM interception.
func GenerateCA() (tls.Certificate, error) {
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
