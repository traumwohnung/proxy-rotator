// Package examples contains example middleware for the proxy gateway pipeline.
//
// The TLS fingerprint middleware demonstrates how to use httpcloak with
// the MITM infrastructure to make upstream connections look like a real browser.
package examples

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sardanioss/httpcloak/client"

	"proxy-gateway/core"
	"proxy-gateway/middleware"
)

// Fingerprint returns middleware that performs TLS interception and re-connects
// to the target using httpcloak with a browser-identical TLS/HTTP2 fingerprint.
//
// This is a full MITM that:
//  1. Terminates the client's TLS using a forged certificate (same as MITM middleware).
//  2. Reads each HTTP request from the decrypted stream.
//  3. Resolves the upstream proxy via the inner pipeline.
//  4. Re-sends the request to the target through the upstream proxy using
//     httpcloak with the chosen browser preset — so the target sees a
//     Chrome/Firefox/Safari TLS fingerprint (JA3/JA4, ALPN, extensions, etc.)
//     instead of Go's default crypto/tls fingerprint.
//
// Usage:
//
//	ca, _ := middleware.GenerateCA()
//	pipeline := core.Auth(auth,
//	    examples.Fingerprint(ca, "chrome-latest",
//	        core.Sticky(source),
//	    ),
//	)
//	gateway.Run(":8100", pipeline)
//
// Presets: "chrome-latest", "firefox-latest", "safari-latest", or any preset
// string supported by httpcloak.
func Fingerprint(ca tls.Certificate, preset string, inner core.Handler) core.Handler {
	caCert, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		panic(fmt.Sprintf("fingerprint: failed to parse CA certificate: %v", err))
	}
	return &fingerprintHandler{
		inner:  inner,
		ca:     ca,
		caCert: caCert,
		preset: preset,
		cache:  &middleware.CertCache{},
	}
}

type fingerprintHandler struct {
	inner  core.Handler
	ca     tls.Certificate
	caCert *x509.Certificate
	preset string
	cache  *middleware.CertCache
}

func (h *fingerprintHandler) Resolve(ctx context.Context, req *core.Request) (*core.Proxy, error) {
	// Only intercept CONNECT with a raw connection and TLS not already broken.
	if req.Conn == nil || req.TLSBroken {
		return h.inner.Resolve(ctx, req)
	}

	host := targetHost(req.Target)
	cert := h.cache.GetOrCreate(host, h.caCert, &h.ca)

	// TLS handshake with client using forged cert.
	tlsConn := tls.Server(req.Conn, &tls.Config{
		Certificates: []tls.Certificate{*cert},
	})
	if err := tlsConn.Handshake(); err != nil {
		slog.Debug("fingerprint: TLS handshake failed", "host", host, "err", err)
		req.Conn.Close()
		return nil, nil
	}

	slog.Debug("fingerprint: intercepting", "host", host, "preset", h.preset)

	br := bufio.NewReader(tlsConn)
	for {
		httpReq, err := http.ReadRequest(br)
		if err != nil {
			break
		}

		// Build child request inheriting auth context.
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

		proxy, resolveErr := h.inner.Resolve(ctx, child)

		// Synthetic response from middleware (e.g. blocker).
		if child.HTTPResponse != nil {
			child.HTTPResponse.Write(tlsConn)
			continue
		}
		if resolveErr != nil {
			writeErr(tlsConn, http.StatusForbidden, resolveErr.Error())
			continue
		}
		if proxy == nil {
			writeErr(tlsConn, http.StatusServiceUnavailable, "no proxy available")
			continue
		}

		// Forward using httpcloak with the browser fingerprint preset.
		resp, fwdErr := forwardWithFingerprint(ctx, httpReq, host, proxy, h.preset)
		if fwdErr != nil {
			writeErr(tlsConn, http.StatusBadGateway, fwdErr.Error())
			continue
		}

		// Apply response hook if set.
		if child.ResponseHook != nil {
			resp = child.ResponseHook(resp)
		}

		resp.Write(tlsConn)
	}

	tlsConn.Close()
	return nil, nil
}

// forwardWithFingerprint sends the request through the upstream proxy using
// httpcloak with the specified browser preset.
func forwardWithFingerprint(ctx context.Context, httpReq *http.Request, host string, proxy *core.Proxy, preset string) (*http.Response, error) {
	// Build the proxy URL for httpcloak.
	var proxyURL string
	switch proxy.GetProtocol() {
	case core.ProtocolSOCKS5:
		if proxy.Username != "" {
			proxyURL = fmt.Sprintf("socks5://%s:%s@%s:%d", proxy.Username, proxy.Password, proxy.Host, proxy.Port)
		} else {
			proxyURL = fmt.Sprintf("socks5://%s:%d", proxy.Host, proxy.Port)
		}
	default:
		if proxy.Username != "" {
			proxyURL = fmt.Sprintf("http://%s:%s@%s:%d", proxy.Username, proxy.Password, proxy.Host, proxy.Port)
		} else {
			proxyURL = fmt.Sprintf("http://%s:%d", proxy.Host, proxy.Port)
		}
	}

	// Create an httpcloak client with the browser preset and proxy.
	opts := []client.Option{
		client.WithTimeout(30 * time.Second),
	}
	if proxyURL != "" {
		opts = append(opts, client.WithProxy(proxyURL))
	}
	c := client.NewClient(preset, opts...)
	defer c.Close()

	// Build the target URL.
	targetURL := fmt.Sprintf("https://%s%s", host, httpReq.URL.RequestURI())

	// Convert headers.
	headers := make(map[string][]string)
	for k, vs := range httpReq.Header {
		lower := strings.ToLower(k)
		// Skip hop-by-hop headers.
		if lower == "connection" || lower == "proxy-authorization" || lower == "proxy-connection" {
			continue
		}
		headers[k] = vs
	}

	// Build httpcloak request.
	cloakReq := &client.Request{
		Method:  httpReq.Method,
		URL:     targetURL,
		Headers: headers,
	}
	if httpReq.Body != nil && httpReq.Method != http.MethodGet && httpReq.Method != http.MethodHead {
		cloakReq.Body = httpReq.Body
	}

	resp, err := c.Do(ctx, cloakReq)
	if err != nil {
		return nil, fmt.Errorf("httpcloak request to %s: %w", targetURL, err)
	}

	// Convert httpcloak response to *http.Response.
	body, _ := resp.Bytes()
	httpResp := &http.Response{
		StatusCode: resp.StatusCode,
		Status:     fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode)),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(string(body))),
	}
	for k, vs := range resp.Headers {
		for _, v := range vs {
			httpResp.Header.Add(k, v)
		}
	}

	return httpResp, nil
}

func writeErr(w io.Writer, status int, msg string) {
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

func targetHost(target string) string {
	h, _, err := net.SplitHostPort(target)
	if err != nil {
		return target
	}
	return h
}

// clientPool reuses httpcloak clients keyed by proxy+preset to avoid
// creating a new TLS session for every request.
var clientPool = struct {
	mu      sync.Mutex
	clients map[string]*client.Client
}{
	clients: make(map[string]*client.Client),
}

// getPooledClient returns a reusable httpcloak client for the given proxy+preset.
// In production use you'd want an LRU eviction policy.
func getPooledClient(proxyURL, preset string) *client.Client {
	key := proxyURL + "|" + preset
	clientPool.mu.Lock()
	defer clientPool.mu.Unlock()
	if c, ok := clientPool.clients[key]; ok {
		return c
	}
	opts := []client.Option{
		client.WithTimeout(30 * time.Second),
	}
	if proxyURL != "" {
		opts = append(opts, client.WithProxy(proxyURL))
	}
	c := client.NewClient(preset, opts...)
	clientPool.clients[key] = c
	return c
}
