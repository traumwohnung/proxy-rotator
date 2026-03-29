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
	"encoding/base64"
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

// MITM returns middleware that performs TLS interception (man-in-the-middle).
//
// When a CONNECT request arrives (req.Conn != nil and req.TLSBroken == false):
//  1. Performs a TLS handshake with the client using a forged certificate
//     signed by the provided CA.
//  2. Reads HTTP requests from the decrypted stream.
//  3. For each inner request, creates a child core.Request with HTTPRequest
//     set and calls inner.Resolve. The inner pipeline sees a plain HTTP
//     request and can inspect, modify, block, or forward it.
//  4. If inner returns a Proxy, the MITM layer forwards the request through
//     that proxy and sends the response back (applying ResponseHook if set).
//     If inner sets req.HTTPResponse, that synthetic response is sent instead.
//  5. Returns nil Proxy to signal the gateway "I handled it."
//
// When TLS is already broken (req.TLSBroken == true) or there is no Conn
// (plain HTTP), the request passes through to inner unchanged.
//
// Usage:
//
//	ca := mitm.MustLoadCA("ca.crt", "ca.key")
//	pipeline := middleware.ParseJSONCreds(
//	    core.Auth(auth,
//	        middleware.MITM(ca,
//	            core.Sticky(source),
//	        ),
//	    ),
//	)
func MITM(ca tls.Certificate, inner core.Handler) core.Handler {
	caCert, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		panic(fmt.Sprintf("mitm: failed to parse CA certificate: %v", err))
	}
	m := &mitmHandler{
		inner:  inner,
		ca:     ca,
		caCert: caCert,
		cache:  &CertCache{},
	}
	return m
}

type mitmHandler struct {
	inner  core.Handler
	ca     tls.Certificate
	caCert *x509.Certificate
	cache  *CertCache
}

func (m *mitmHandler) Resolve(ctx context.Context, req *core.Request) (*core.Proxy, error) {
	// Only intercept CONNECT with a raw connection and TLS not already broken.
	if req.Conn == nil || req.TLSBroken {
		return m.inner.Resolve(ctx, req)
	}

	// TLS handshake with client using a forged cert for the target host.
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

	// Read HTTP requests from decrypted stream.
	br := bufio.NewReader(tlsConn)
	for {
		httpReq, err := http.ReadRequest(br)
		if err != nil {
			break // client closed or error
		}

		// Build a child request inheriting the parent's auth context.
		child := &core.Request{
			RawUsername:   req.RawUsername,
			RawPassword:   req.RawPassword,
			Sub:           req.Sub,
			Password:      req.Password,
			Set:           req.Set,
			Meta:          req.Meta,
			SessionKey:    req.SessionKey,
			SessionTTL:    req.SessionTTL,
			Target:        host + ":443",
			TLSBroken:     true,
			TLSServerName: host,
			HTTPRequest:   httpReq,
		}

		proxy, resolveErr := m.inner.Resolve(ctx, child)

		// Middleware set a synthetic response → send it.
		if child.HTTPResponse != nil {
			child.HTTPResponse.Write(tlsConn)
			continue
		}

		if resolveErr != nil {
			writeErrorResponse(tlsConn, http.StatusForbidden, resolveErr.Error())
			continue
		}
		if proxy == nil {
			writeErrorResponse(tlsConn, http.StatusServiceUnavailable, "no proxy available")
			continue
		}

		// Forward through the resolved upstream proxy.
		resp, fwdErr := forwardHTTPRequest(httpReq, host, proxy)
		if fwdErr != nil {
			writeErrorResponse(tlsConn, http.StatusBadGateway, fwdErr.Error())
			continue
		}

		// Apply response hook if set.
		if child.ResponseHook != nil {
			resp = child.ResponseHook(resp)
		}

		resp.Write(tlsConn)
	}

	tlsConn.Close()
	return nil, nil // we handled it
}

// forwardHTTPRequest sends an HTTP request through the upstream proxy to the target.
func forwardHTTPRequest(httpReq *http.Request, host string, proxy *core.Proxy) (*http.Response, error) {
	// Dial upstream — for intercepted HTTPS we need to establish a tunnel
	// to the original target through the proxy, then send the request.
	target := host + ":443"
	upstreamConn, err := dialUpstreamForMITM(proxy, target)
	if err != nil {
		return nil, err
	}
	defer upstreamConn.Close()

	// TLS to the real target through the upstream tunnel.
	tlsUp := tls.Client(upstreamConn, &tls.Config{ServerName: host})
	if err := tlsUp.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS to target %s: %w", host, err)
	}
	defer tlsUp.Close()

	// Rewrite the request to be relative (not absolute URI).
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

// dialUpstreamForMITM is a package-level function so MITM can use the
// gateway's upstream dialing. We duplicate the import to avoid a cycle.
func dialUpstreamForMITM(proxy *core.Proxy, target string) (net.Conn, error) {
	// We need to connect through the upstream proxy to the target.
	// For HTTP proxy: CONNECT to target through proxy.
	// For SOCKS5 proxy: SOCKS5 CONNECT through proxy.
	// We reuse the same logic but inline it minimally here to avoid
	// importing gateway (which would be a cycle).

	addr := net.JoinHostPort(proxy.Host, fmt.Sprintf("%d", proxy.Port))
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connecting to upstream %s: %w", addr, err)
	}

	switch proxy.GetProtocol() {
	case core.ProtocolSOCKS5:
		host, port := splitTarget(target)
		if err := socks5HandshakeMITM(conn, host, port, proxy.Username, proxy.Password); err != nil {
			conn.Close()
			return nil, err
		}
	default: // HTTP CONNECT
		if err := httpConnectHandshakeMITM(conn, target, proxy.Username, proxy.Password); err != nil {
			conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

func httpConnectHandshakeMITM(conn net.Conn, target, user, pass string) error {
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if user != "" {
		creds := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		req += "Proxy-Authorization: Basic " + creds + "\r\n"
	}
	req += "\r\n"
	if _, err := fmt.Fprint(conn, req); err != nil {
		return err
	}
	var buf []byte
	tmp := make([]byte, 1024)
	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			return fmt.Errorf("reading CONNECT response: %w", err)
		}
		if containsCRLFCRLF(buf) {
			break
		}
	}
	if len(buf) < 12 || (string(buf[:12]) != "HTTP/1.1 200" && string(buf[:12]) != "HTTP/1.0 200") {
		return fmt.Errorf("upstream rejected CONNECT: %s", string(buf))
	}
	return nil
}

func socks5HandshakeMITM(conn net.Conn, host string, port uint16, user, pass string) error {
	// Minimal SOCKS5 handshake for MITM upstream.
	needsAuth := user != ""
	if needsAuth {
		conn.Write([]byte{0x05, 0x02, 0x00, 0x02})
	} else {
		conn.Write([]byte{0x05, 0x01, 0x00})
	}
	var methodResp [2]byte
	io.ReadFull(conn, methodResp[:])

	if methodResp[1] == 0x02 && needsAuth {
		authReq := []byte{0x01, byte(len(user))}
		authReq = append(authReq, []byte(user)...)
		authReq = append(authReq, byte(len(pass)))
		authReq = append(authReq, []byte(pass)...)
		conn.Write(authReq)
		var authResp [2]byte
		io.ReadFull(conn, authResp[:])
		if authResp[1] != 0x00 {
			return fmt.Errorf("SOCKS5 auth failed")
		}
	}

	connectReq := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	connectReq = append(connectReq, []byte(host)...)
	connectReq = append(connectReq, byte(port>>8), byte(port))
	conn.Write(connectReq)

	var respHeader [4]byte
	io.ReadFull(conn, respHeader[:])
	if respHeader[1] != 0x00 {
		return fmt.Errorf("SOCKS5 CONNECT failed (status %d)", respHeader[1])
	}
	// Consume bound address.
	switch respHeader[3] {
	case 0x01:
		var skip [6]byte
		io.ReadFull(conn, skip[:])
	case 0x04:
		var skip [18]byte
		io.ReadFull(conn, skip[:])
	case 0x03:
		var dLen [1]byte
		io.ReadFull(conn, dLen[:])
		skip := make([]byte, int(dLen[0])+2)
		io.ReadFull(conn, skip)
	}
	return nil
}

func splitTarget(target string) (string, uint16) {
	h, p, err := net.SplitHostPort(target)
	if err != nil {
		return target, 443
	}
	var port uint16
	fmt.Sscanf(p, "%d", &port)
	return h, port
}

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

func containsCRLFCRLF(b []byte) bool {
	for i := 0; i+3 < len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' && b[i+2] == '\r' && b[i+3] == '\n' {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Certificate cache — forges per-host certs signed by the CA
// ---------------------------------------------------------------------------

// CertCache caches forged per-host TLS certificates.
type CertCache struct {
	mu    sync.RWMutex
	certs map[string]*tls.Certificate
}

// GetOrCreate returns a cached certificate for host, or forges a new one.
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

// GenerateCA creates an in-memory CA certificate and key pair.
// Useful for testing and development.
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
