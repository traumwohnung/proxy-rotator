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
	"time"

	"github.com/sardanioss/httpcloak/client"

	"proxy-gateway/core"
	"proxy-gateway/middleware"
)

// Fingerprint returns middleware that performs TLS interception and re-connects
// to the target using httpcloak with a browser-identical TLS/HTTP2 fingerprint.
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

func (h *fingerprintHandler) Resolve(ctx context.Context, req *core.Request) (*core.Result, error) {
	// Only intercept CONNECT with a raw connection and TLS not already broken.
	if req.Conn == nil {
		return h.inner.Resolve(ctx, req)
	}
	if ts := core.GetTLSState(ctx); ts.Broken {
		return h.inner.Resolve(ctx, req)
	}

	host := targetHost(req.Target)
	cert := h.cache.GetOrCreate(host, h.caCert, &h.ca)

	tlsConn := tls.Server(req.Conn, &tls.Config{
		Certificates: []tls.Certificate{*cert},
	})
	if err := tlsConn.Handshake(); err != nil {
		slog.Debug("fingerprint: TLS handshake failed", "host", host, "err", err)
		req.Conn.Close()
		return nil, nil
	}

	slog.Debug("fingerprint: intercepting", "host", host, "preset", h.preset)

	childCtx := core.WithTLSState(ctx, core.TLSState{
		Broken:     true,
		ServerName: host,
	})

	br := bufio.NewReader(tlsConn)
	for {
		httpReq, err := http.ReadRequest(br)
		if err != nil {
			break
		}

		child := &core.Request{
			RawUsername: req.RawUsername,
			RawPassword: req.RawPassword,
			Target:      host + ":443",
			HTTPRequest: httpReq,
		}

		result, resolveErr := h.inner.Resolve(childCtx, child)

		if result != nil && result.HTTPResponse != nil {
			result.HTTPResponse.Write(tlsConn)
			continue
		}
		if resolveErr != nil {
			writeErr(tlsConn, http.StatusForbidden, resolveErr.Error())
			continue
		}
		if result == nil || result.Proxy == nil {
			writeErr(tlsConn, http.StatusServiceUnavailable, "no proxy available")
			continue
		}

		resp, fwdErr := forwardWithFingerprint(ctx, httpReq, host, result.Proxy, h.preset)
		if fwdErr != nil {
			writeErr(tlsConn, http.StatusBadGateway, fwdErr.Error())
			continue
		}

		if result.ResponseHook != nil {
			resp = result.ResponseHook(resp)
		}

		resp.Write(tlsConn)
	}

	tlsConn.Close()
	return nil, nil
}

func forwardWithFingerprint(ctx context.Context, httpReq *http.Request, host string, proxy *core.Proxy, preset string) (*http.Response, error) {
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

	opts := []client.Option{
		client.WithTimeout(30 * time.Second),
	}
	if proxyURL != "" {
		opts = append(opts, client.WithProxy(proxyURL))
	}
	c := client.NewClient(preset, opts...)
	defer c.Close()

	targetURL := fmt.Sprintf("https://%s%s", host, httpReq.URL.RequestURI())

	headers := make(map[string][]string)
	for k, vs := range httpReq.Header {
		lower := strings.ToLower(k)
		if lower == "connection" || lower == "proxy-authorization" || lower == "proxy-connection" {
			continue
		}
		headers[k] = vs
	}

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
