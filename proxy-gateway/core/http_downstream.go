package core

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

// ---------------------------------------------------------------------------
// HTTPDownstream — implements Downstream for HTTP proxy protocol
// ---------------------------------------------------------------------------

// HTTPDownstream accepts HTTP proxy connections (CONNECT + plain HTTP).
type HTTPDownstream struct {
	Upstream Upstream
}

// SetUpstream implements UpstreamAware.
func (d *HTTPDownstream) SetUpstream(u Upstream) { d.Upstream = u }

// Serve implements Downstream.
func (d *HTTPDownstream) Serve(addr string, handler Handler) error {
	slog.Info("HTTP proxy gateway listening", "addr", addr)
	return http.ListenAndServe(addr, d.httpHandler(handler))
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
	w.WriteHeader(http.StatusOK)
	clientConn, _, err := hj.Hijack()
	if err != nil {
		slog.Error("hijack failed", "err", err)
		return
	}

	req := &Request{
		RawUsername: rawUser,
		RawPassword: rawPass,
		Target:      r.Host,
		Conn:        clientConn,
	}

	result, err := handler.Resolve(r.Context(), req)
	if err != nil {
		slog.Warn("resolve error", "target", r.Host, "err", err)
		clientConn.Close()
		return
	}

	// nil result or nil proxy = middleware handled it (e.g. MITM).
	if result == nil || result.Proxy == nil {
		return
	}

	defer clientConn.Close()

	proxy := result.Proxy
	slog.Info("tunneling",
		"target", r.Host,
		"upstream", fmt.Sprintf("%s:%d", proxy.Host, proxy.Port),
		"upstream_proto", proxy.Proto(),
	)

	upstreamConn, err := d.Upstream.Dial(r.Context(), proxy, r.Host)
	if err != nil {
		slog.Error("upstream dial failed", "err", err)
		if result.ConnTracker != nil {
			result.ConnTracker.Close(0, 0)
		}
		return
	}
	defer upstreamConn.Close()

	sent, received := relay(clientConn, upstreamConn, result.ConnTracker)
	if result.ConnTracker != nil {
		result.ConnTracker.Close(sent, received)
	}
}

func (d *HTTPDownstream) servePlainHTTP(w http.ResponseWriter, r *http.Request, rawUser, rawPass string, handler Handler) {
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

	// Synthetic response from middleware.
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

	// Stream response to client.
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

// ---------------------------------------------------------------------------
// Legacy compatibility — Run / HTTPProxyHandler
// ---------------------------------------------------------------------------

// Run starts an HTTP proxy gateway with the default upstream dialer.
func ListenHTTP(addr string, handler Handler) error {
	d := &HTTPDownstream{Upstream: AutoUpstream()}
	return d.Serve(addr, handler)
}

// HTTPProxyHandler returns an http.Handler for mounting in a chi router or
// similar. Uses the default upstream dialer.
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
