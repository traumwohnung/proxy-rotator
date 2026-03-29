package utils

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sardanioss/httpcloak/client"

	"proxy-gateway/core"
)

// TLSFingerprintSpoofing returns MITM middleware that forwards decrypted
// requests using httpcloak, making the upstream TLS handshake look like a
// real browser instead of Go's crypto/tls.
//
// It builds on core.MITM: the TLS termination, cert forging, and pipeline
// dispatch are all handled by MITM. This only provides the Interceptor —
// the part that actually sends the request onward.
//
// Usage:
//
//	ca, _ := core.NewCA()
//	pipeline := utils.TLSFingerprintSpoofing(ca, "chrome-latest",
//	    core.Auth(auth,
//	        core.Session(source),
//	    ),
//	)
//	core.ListenHTTP(":8100", pipeline)
//
// Preset examples: "chrome-latest", "firefox-latest", "safari-latest"
func TLSFingerprintSpoofing(ca tls.Certificate, preset string, inner core.Handler) core.Handler {
	certs, err := core.NewForgedCertProvider(ca)
	if err != nil {
		panic(fmt.Sprintf("tls_fingerprint_spoofing: %v", err))
	}
	return core.MITM(certs, &tlsFingerprintInterceptor{preset: preset}, inner)
}

// tlsFingerprintInterceptor implements core.Interceptor using httpcloak
// to spoof the upstream TLS fingerprint as a real browser.
type tlsFingerprintInterceptor struct {
	preset string
}

func (f *tlsFingerprintInterceptor) RoundTrip(ctx context.Context, httpReq *http.Request, host string, proxy *core.Proxy) (*http.Response, error) {
	proxyURL := proxyToURL(proxy)

	opts := []client.Option{
		client.WithTimeout(30 * time.Second),
	}
	if proxyURL != "" {
		opts = append(opts, client.WithProxy(proxyURL))
	}
	c := client.NewClient(f.preset, opts...)
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
		return nil, fmt.Errorf("httpcloak %s: %w", targetURL, err)
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

// proxyToURL converts a core.Proxy to a URL string for httpcloak.
func proxyToURL(proxy *core.Proxy) string {
	var scheme string
	switch proxy.Proto() {
	case core.ProtocolSOCKS5:
		scheme = "socks5"
	default:
		scheme = "http"
	}
	if proxy.Username != "" {
		return fmt.Sprintf("%s://%s:%s@%s:%d", scheme, proxy.Username, proxy.Password, proxy.Host, proxy.Port)
	}
	return fmt.Sprintf("%s://%s:%d", scheme, proxy.Host, proxy.Port)
}
