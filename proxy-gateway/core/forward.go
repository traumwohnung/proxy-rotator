package core

import (
	"fmt"
	"net/http"
	"net/url"
)

// ForwardPlainHTTP forwards a plain (non-CONNECT) HTTP request through an
// upstream proxy and streams the response back to the caller.
//
// Uses net/http.Transport for proper streaming — the response body is NOT
// buffered in memory. The caller is responsible for closing resp.Body.
func ForwardPlainHTTP(r *http.Request, proxy *Proxy) (*http.Response, error) {
	proxyURL := &url.URL{
		Scheme: "http",
		Host:   hostPort(proxy.Host, proxy.Port),
	}
	if proxy.Username != "" {
		proxyURL.User = url.UserPassword(proxy.Username, proxy.Password)
	}
	if proxy.Proto() == ProtocolSOCKS5 {
		proxyURL.Scheme = "socks5"
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}

	// Strip hop-by-hop headers and ensure absolute URI.
	out := r.Clone(r.Context())
	out.RequestURI = ""
	if out.URL.Host == "" {
		out.URL.Host = r.Host
	}
	if out.URL.Scheme == "" {
		out.URL.Scheme = "http"
	}
	for h := range hopByHopHeaders {
		out.Header.Del(h)
	}

	resp, err := transport.RoundTrip(out)
	if err != nil {
		return nil, fmt.Errorf("forwarding to %s via %s: %w", r.Host, proxy.Host, err)
	}
	return resp, nil
}

// hopByHopHeaders lists headers that must not be forwarded.
var hopByHopHeaders = map[string]struct{}{
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailers":            {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}
